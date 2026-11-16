---
name: hunt-dns-network
description: Hunting skill for DNS / NETWORK SECURITY findings on internet-facing enterprise infrastructure. Built from 1 curated source skill (hunt-ntlm-info) covering anonymous NTLMSSP Type-2 AV-pair information disclosure — internal AD domain / parent-forest topology leakage, default Windows hostname disclosure, and timestamp leakage from IIS / SharePoint / Exchange / OWA / Citrix / VMware Horizon edge services. Use when probing DNS-linked and network-auth surfaces for topology and identity reconnaissance that chains into auth-bypass and password-spray chains. OOB/Collaborator is NOT required for this finding class — the leak is synchronous in the NTLM Type-2 response.
sources: internal_skill_library
report_count: 0
full_reports_read: 0
source_skills: 1
---

> **Provenance & scope.** This skill is a documentation extract built from **1 curated source skill** (`hunt-skills/hunt-ntlm-info/SKILL.md`), with **0 full bug-bounty reports** read and **0 report IDs/URLs** cited. Every technical claim below is grounded in that single source. The complete extracted source knowledge is preserved at:
>
> `E:\webt\skill-setup\skills-extract-from-reports\hunt-dns-network\references\source-knowledge.md`
>
> Do **not** fabricate HackerOne IDs, report URLs, dollar amounts, or CVEs when using this skill. Cite the skill path above instead.

**Reading guide.** Work top-to-bottom. The Crown Jewel Targets and Attack Surface Signals sections tell you *where* to look; Discovery Patterns tells you *what a reportable result looks like*; Step-by-Step Methodology and Payload & Detection Patterns give you the exact probe and decoder; Common Root Causes, Bypass Techniques, and Gate 0 Validation help you decide severity and avoid false positives; Real Impact Examples shows how the source framed three outcomes. Sections covering DNS rebinding, AXFR, TLS probing, and pivoting are explicitly marked as out of scope for this source set so that no unsourced payloads are implied. Treat the skill as a reconnaissance front end, not a standalone exploitation chain.

---

## Crown Jewel Targets

The curated source defines one high-value finding family: **NTLM information disclosure via anonymous NTLMSSP Type-2 challenge**. The leak itself is RFC-compliant protocol behavior (a standard NTLM challenge), but on internet-exposed enterprise infrastructure it hands an attacker exact reconnaissance for the next stage of an attack. It is a **Medium-severity finding when chained to context** — on its own, often Low/Informational.

Highest-value targets from the source:

- **Internet-reachable IIS / SharePoint / Exchange / OWA** with dual-auth configured (Forms + NTLM, or NTLM + Kerberos).
- **Citrix NetScaler / VMware Horizon View** internet-facing gateways that use NTLM-backed Active Directory authentication.
- **Lync / Skype for Business / Teams On-Prem** edge servers.
- **WSUS / Windows Update Services** with NTLM-protected admin paths.
- **CIFS-style fileshare proxies** (HCL Sametime, IBM Notes Domino) that proxy NTLM.
- **Legacy SharePoint farms** that left NTLM enabled on the public-zone IIS binding.

**Priority ordering.** Among these, SharePoint Web Front Ends and Exchange edge transports are the most reliable: the source notes SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default, and Exchange edge servers are domain-joined by design. Citrix / VMware Horizon gateways and Lync/Skype edges are next — they put an AD-backed NTLM endpoint directly on the internet perimeter. CIFS-style proxies and WSUS admin paths are opportunistic finds. Any target that is clearly intranet-only drops to Informational regardless of product (see Scenario C and Gate 0).

**What makes this pay** (directly from the source):

- **Internal AD domain disclosure** — parent-forest mapping, e.g. `customer.parent-corp.example` revealing a tenant that lives *inside* a corporate-AD tree rather than as a separate tenant. This is the single strongest severity driver in the source.
- **Default-Windows-hostname disclosure** — the `WIN-XXXXXXXXXXX` pattern signals rushed provisioning, which in turn suggests likely default service-account passwords on attached services (SQL backend, WSUS, etc.). It is a maturity signal, not just a name.
- **Timestamp leak** — the Type-2 `AV[7]` FILETIME is useful for NTLMv2 hash cracking acceleration and for checking whether the system clock is synced to the HTTP `Date:` header.
- **Direct attack-map enrichment** for credential spraying, combined with `hunt-auth-bypass` Legacy-Protocol Matrix findings.

The pay-off is not the raw leak; it is that the leak supplies the **missing identity primitives** (UPN format, AD domain, forest root, hostname pattern) that turn a blind password spray into a targeted one. Severity escalates when the same host also exposes an anonymous credential-submission endpoint — the source notes a chain where NTLM info + an anonymous brute-force endpoint on `/_vti_bin/Authentication.asmx` becomes a combined Critical finding.

**How to think about severity here.** The source is careful to distinguish protocol behavior from impact. A Type-2 challenge is something an NTLM server does for *any* client that asks; that alone is not a bug. It becomes a finding when (a) the interface is internet-reachable, (b) the disclosed values are sensitive AD topology or a provisioning tell, and (c) the receiving program accepts information-disclosure findings or you can chain to a Tier-A issue. All three conditions are evaluated in Gate 0.

### Target triage order

When time is limited, spend it in this order:

1. **SharePoint WFEs with `/_vti_bin/` or `/_api/web/CurrentUser` exposed** — the source's most reliable anonymous Type-2 emitter, and the one tied to the Critical chain in Scenario A.
2. **Exchange edges with EWS / Autodiscover / OWA exposed** — domain-joined by design, so a Type-2 almost always yields forest topology (Scenario B).
3. **Citrix NetScaler / VMware Horizon View gateways** — internet-facing NTLM-backed AD auth.
4. **Lync / Skype for Business / Teams On-Prem edges** — same AD-backed pattern on a different product.
5. **WSUS admin paths and CIFS-style proxies** — opportunistic; check after the higher-yield products.

Skip any target you can only reach from inside the VPN unless you are explicitly testing intranet behavior — that is Scenario C territory and is not reportable.

---

## Attack Surface Signals

### Response headers signaling NTLM availability

A vanilla anonymous GET that returns any of the following `WWW-Authenticate` values means NTLM is offered and the Type-1 probe is worth sending:

```
WWW-Authenticate: NTLM
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM, Negotiate
WWW-Authenticate: Negotiate, NTLM
```

The presence of `Negotiate` alone still matters — it indicates the IIS/Negotiate stack is active, and a Type-1 NTLM message is generally still accepted. The ordering of `NTLM` versus `Negotiate` in a combined header is not significant for this finding; what matters is that NTLM is among the offered schemes.

### URL patterns where NTLM is commonly exposed

```
/_api/web/CurrentUser                  (SharePoint REST)
/_vti_bin/*.asmx                       (SharePoint legacy SOAP)
/EWS/Exchange.asmx                     (Exchange Web Services)
/Autodiscover/Autodiscover.xml         (Exchange autodiscover)
/owa/                                  (Outlook Web App)
/Microsoft-Server-ActiveSync           (ActiveSync)
/PowerShell                            (Exchange Mgmt Shell over HTTPS)
/api/v3/                               (TeamCity, Atlassian)
/wsus/                                 (Windows Server Update Services)
/manager/html                          (some Tomcat behind IIS)
/iisstart.htm                          (default IIS, sometimes reveals NTLM upstream)
```

Wildcards in the source (`/_vti_bin/*.asmx`) are literal guidance — the legacy SOAP endpoints under that directory are the reliable ones. When a specific service name is unknown, prefer `/_api/web/CurrentUser` on SharePoint and `/EWS/Exchange.asmx` on Exchange as the highest-yield anonymous probes.

### Tech-stack signals

- **IIS on the public internet** — almost always NTLM-capable, even when Forms auth is the visible front door.
- **SharePoint Web Front End** — almost always dual-auth (Forms + NTLM).
- **Exchange edge transport** — domain-joined by design; leaks forest topology.
- **Server header** values: `Microsoft-HTTPAPI/2.0`, `Microsoft-IIS/*`, `IIS/*`.

### Signal-to-action quick reference

| Observed signal | What it tells you | Next action |
|---|---|---|
| `WWW-Authenticate: NTLM` on an anonymous GET | NTLM is offered; anonymous Type-1 will be accepted | Send the canonical Type-1 over keep-alive |
| `WWW-Authenticate: Negotiate` only | Negotiate/IIS stack is active | Still try a Type-1 NTLM probe |
| `Server: Microsoft-IIS/*` or `Microsoft-HTTPAPI/2.0` | Windows/IIS family host | Prioritize this target |
| SharePoint `/_api/web/CurrentUser`, `/_vti_bin/*` | Domain-joined SharePoint WFE | Highest-yield anonymous probe |
| Exchange `/EWS/Exchange.asmx`, `/Autodiscover/*` | Domain-joined Exchange edge | Type-2 should reveal forest topology |
| `Server: ...` absent but NTLM offered | AD context unconfirmed | Decode AV-pairs before assigning severity |

### Interpreting the signal combination

No single signal is sufficient. A `WWW-Authenticate: NTLM` header on a non-IIS host with no AD context is just an auth scheme. The reportable setup requires the header **plus** an IIS-family `Server` header **plus** a path that is part of a domain-joined enterprise service (SharePoint REST/SOAP, Exchange EWS/Autodiscover/OWA, WSUS, or a gateway). That combination is what makes the Type-2 challenge worth decoding.

### Anonymous-probe workflow at a glance

1. Send a vanilla GET to each candidate path and record whether `WWW-Authenticate` advertises NTLM/Negotiate.
2. Note the `Server` header and the `Date:` header (the latter is needed for the clock-sync check in Methodology step 7).
3. For any host that passes step 1–2, send the canonical Type-1 message over a keep-alive connection.
4. Capture the `WWW-Authenticate: NTLM <base64>` Type-2 value and decode its AV-pairs.
5. Only after seeing DNS-domain / DNS-tree values or the default-hostname pattern do you have a potential finding — see Discovery Patterns.

---

## Discovery Patterns From Curated Source Skills

The single curated source (`hunt-ntlm-info`) yields four distinct discovery patterns. Each is a different way the same Type-2 AV-pair data becomes reportable. They are not four separate bugs — they are four lenses for deciding whether the captured challenge is worth reporting and at what severity.

### Cross-pattern decision tree

Use this to route a captured Type-2 challenge into the right pattern(s):

1. **Is the host internet-reachable?** If no → Pattern 4 evidence only, and treat as Informational / Scenario C. If yes → continue.
2. **Did the decoder return `AV[4]` / `AV[5]` (DNS domain / tree)?** If no → you have NetBIOS data only; Low at best. If yes → continue.
3. **Is `AV[5]` a parent of the probed domain (e.g. `customer.parent-corp.example`)?** If yes → Pattern 3 is active — the strongest severity driver.
4. **Does `AV[1]` / `AV[3]` match `WIN-XXXXXXXXXXX`?** If yes → Pattern 2 is active — combine with Pattern 3 for Medium.
5. **Does `AV[7]` sit within ~5s of the `Date:` header?** If yes → Pattern 4 note for the report (supporting, not decisive).
6. **Same host exposes an anonymous credential endpoint?** If yes → escalate the chained finding per Gate 0 / Scenario A.

A single host can trigger several patterns at once; Scenario A triggers 2, 3, and 4 simultaneously. Report them as one finding with a composite impact narrative, not as separate duplicates.

### Pattern 1 — Internet-Facing Dual-Auth IIS / SharePoint / Exchange Endpoint

**Signal:** An internet-reachable host returns `WWW-Authenticate: NTLM` (or `Negotiate`) on an anonymous GET to a SharePoint REST/SOAP path, Exchange EWS/Autodiscover/OWA path, or a generic IIS management path. The `Server` header confirms `Microsoft-IIS/*` or `Microsoft-HTTPAPI/2.0`.

**Why it matters:** Administrators leave NTLM enabled on the public-facing IIS binding even when Forms auth is the intended entry point. Internal users get SSO; external attackers get the AD topology leak. This is the most reliable discovery pattern in the source set — SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default, and Exchange edge transports are domain-joined by design.

**Confirmation:** Send the canonical Type-1 message and check that a Type-2 challenge comes back over a keep-alive connection. If it does, decode the AV-pairs (Methodology steps 4–5). If only NetBIOS data comes back with no DNS Tree name, severity drops.

**Evidence to capture:** The anonymous GET response headers (showing `WWW-Authenticate`), the `Server` and `Date` headers, and the decoded AV-pair output from the Type-2 challenge. Together these prove the endpoint is external, IIS-based, and leaking topology.

**False-positive guard:** If the host is an internal-only service reachable solely via VPN, this is intended behavior — drop it (Scenario C). An auth scheme alone, with no decoded AD data, is not a finding.

**Severity mapping:** Internet-exposed + default hostname + corporate-AD-tree disclosure → **Medium**. Internet-exposed + named-server hostname + corporate-AD-tree → **Low-Medium**.

### Pattern 2 — Default / Unrenamed Windows Hostname (`WIN-XXXXXXXXXXX`)

**Signal:** The Type-2 `AV[1]` (NetBIOS Computer Name) or `AV[3]` (DNS Computer Name) matches Microsoft's Windows-installer-generated 11-character pattern `WIN-XXXXXXXXXXX`. Older boxes may show `WORKGROUP\WIN-...` in place of a domain prefix.

**Why it matters:** The server was never renamed after OS install — an immediate tell of lazy provisioning. The source treats this as a maturity signal: strong indicator of default service-account passwords on the SQL backend, default WSUS config, and other first-boot defaults. It is also an independent recon pivot — `offensive-osint` deep recon is high-yield on organizations that exhibit this pattern.

**Confirmation:** Decode `AV[1]` and `AV[3]` from the Type-2 TargetInfo blob and check the pattern. Note that renaming the host removes *this tell* but does not stop the underlying leak, so it is not itself a remediation.

**Evidence to capture:** The literal `AV[1]` / `AV[3]` values from the decoder, plus any cross-referenced subdomain that confirms the host is externally reachable.

**False-positive guard:** Some deliberately provisioned lab or test hosts use generated names without implying weak credentials on production systems. Treat the pattern as a severity amplifier, not a standalone claim.

**Severity mapping:** This pattern is what pushes an otherwise Low topology disclosure into **Medium** when combined with corporate-forest disclosure (Pattern 3).

### Pattern 3 — Parent-Forest / DNS Tree Topology Disclosure

**Signal:** The Type-2 `AV[5]` (DNS Tree Name) reveals an AD forest root such as `customer.parent-corp.example`, where the probed host is a child domain inside a larger corporate AD tree.

**Why it matters:** This is the privacy/topology-disclosure escalation the source calls out. A customer may intend `customer.parent-corp.example` to be operationally separate — a test mirror or a subsidiary — but the NTLM Type-2 reveals forest membership to anyone who probes. A compromise of that test farm has potential cross-trust into the corporate parent. Programs sometimes accept this as **Medium** on topology-disclosure grounds alone; others reject pure info disclosure.

**Confirmation:** Decode `AV[4]` (DNS Domain) and `AV[5]` (DNS Tree Name), then cross-reference with subdomain enumeration. If the tree name is a parent of the tested domain, you have parent-forest disclosure. Combine with an OpenID configuration lookup on the resolved domain (see Related Skills) to tie the forest to an Entra tenant.

**Evidence to capture:** `AV[4]`, `AV[5]`, the probed hostname, and the subdomain-enumeration result showing the relationship. The source's Scenario A shows the exact four-line output to expect.

**False-positive guard:** If the DNS tree name equals the probed domain with no larger parent, there is no parent-forest disclosure — you only have a domain name, which is Low at best.

**Severity mapping:** Disclosure of a parent forest to an internet-facing interface is the single strongest driver of Medium severity in the source.

### Pattern 4 — TargetInfo AV-Pair Timestamp & Challenge Fingerprinting

**Signal:** The Type-2 `AV[7]` (Timestamp, FILETIME) and the 8-byte server challenge at bytes 24–31 decode to useful secondary intel.

**Why it matters:** The source notes two uses. First, the timestamp accelerates NTLMv2 hash cracking / relay. Second, if `AV[7]` returns a current FILETIME within ~5 seconds of the HTTP `Date:` header, the system clock is synced — useful intel for Kerberos golden-ticket forging (red-team relevant, out of bug-bounty scope). The 8-byte server challenge is the standard offline-cracking input.

**Confirmation:** Parse the Type-2 blob per MS-NLMP (bytes 24–31 for the challenge; `AV[7]` FILETIME conversion for the timestamp) using the decoder in the Payload section. Compare the decoded timestamp to the `Date:` response header you recorded during the anonymous probe.

**Evidence to capture:** The decoded `AV[7]` value in ISO form, the response `Date:` header, and the raw 8-byte challenge if you are handing off to a cracking workflow.

**False-positive guard:** This is supporting evidence, not a standalone finding. Do not report a timestamp alone; lean on Patterns 1–3 for the core claim.

**Severity mapping:** Enriches a report but does not by itself raise severity.

---

## Step-by-Step Hunting Methodology

1. **Probe every anonymous endpoint for `WWW-Authenticate: NTLM`.** Send a vanilla GET and inspect response headers. If NTLM is offered, proceed. Prioritize the URL patterns in the Attack Surface Signals section and any host with an IIS/SharePoint/Exchange server header. Record the `Date:` header at this stage for the later clock-sync check.

2. **Send a valid NTLMSSP Type-1 message anonymously.** Use the canonical base64 below. It requests NetBIOS-domain and Workstation info from the server:
   ```
   Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
   ```
   This is the standard test Type-1 with negotiate flags `NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_TARGET_INFO`. The `OS Version` field (`06 01 B1 1D 00 00 00 0F`) is Windows 7 build 7601 — accepted by virtually every NTLM responder, so you do not need to tailor it per target.

3. **Use a keep-alive raw socket, not Python requests / curl one-shot.** Most HTTP libraries close the connection between the Type-1 send and Type-2 reception, so you will miss the challenge and conclude (incorrectly) that NTLM is not leaking. Use one of:
   - Burp Repeater with `Connection: keep-alive` set explicitly.
   - Burp `mcp__burp__send_http1_request` (handles keep-alive natively).
   - Python raw `socket` + `ssl.wrap_socket` (full decoder in the Payload section).

   Expected result: a `401 Unauthorized` response whose `WWW-Authenticate` header carries a long base64 Type-2 blob. If you get a bare `401` with no `NTLM <base64>` value, your transport closed the connection — fix that before drawing conclusions.

4. **Parse the Type-2 challenge from the `WWW-Authenticate: NTLM <base64>` response header.** Base64-decode the value. The structure is NTLMSSP per MS-NLMP:
   - Bytes 0-7: literal `NTLMSSP\0`
   - Bytes 8-11: MessageType = `\x02\x00\x00\x00`
   - Bytes 12-19: TargetName SecurityBuffer (len, alloc, offset)
   - Bytes 20-23: NegotiateFlags
   - Bytes 24-31: Server Challenge (8 bytes — useful for offline cracking)
   - Bytes 40-47: TargetInfo SecurityBuffer (len, alloc, offset)
   - TargetInfo body: `AV_PAIRS` array of (AvId u16, AvLen u16, Value)

   The decoder in the Payload section performs all of these offsets for you; understanding the map matters for verifying that the output is a genuine Type-2 and not a different NTLM message type.

5. **Decode the AV_PAIRS.** The AvIds you care about:
   - `1` = NetBIOS Computer Name
   - `2` = NetBIOS Domain Name
   - `3` = DNS Computer Name (FQDN of the responding server)
   - `4` = DNS Domain Name (the AD domain)
   - `5` = DNS Tree Name (the AD forest root)
   - `7` = Timestamp (FILETIME, useful for NTLMv2 hash relay / cracking)
   - `9` = Target Name (in newer NTLMSSP)

   Stop parsing when `AvId == 0` (EOL). The decoder prints each labeled value in UTF-16LE; names and domains use that encoding, while `AV[7]` is a binary FILETIME requiring the epoch conversion.

6. **Map findings to severity tier:**
   - Internet-exposed + default `WIN-XXXXXXXXXXX` hostname + corporate-AD-tree disclosure → **Medium**
   - Internet-exposed + named-server hostname (`SPWEB01.corp.example`) + corporate-AD-tree → **Low-Medium**
   - Intranet-only + any disclosure → **Informational**
   - Combine with `hunt-auth-bypass` Legacy-Protocol Matrix findings on the same host → **upgrade the auth-bypass finding's severity** since the attacker has UPN/SAM format ready.

7. **Check the timestamp.** If `AV[7]` returns a current FILETIME within ~5s of `Date:` header, the system clock is synced — useful intel for Kerberos golden-ticket forging (out of bug-bounty scope but red-team relevant). The FILETIME-to-epoch conversion is `secs = (ts - 116444736000000000) / 10000000`; the decoder applies this and prints an ISO-8601 UTC timestamp.

8. **Cross-reference with subdomain enum.** The DNS Tree name often reveals the *parent forest* — e.g. `customer.parent-corp.example` reveals the customer is a sub-domain INSIDE corporate-parent AD, not a separate tenant. This is a privacy / topology-disclosure escalation that programs sometimes accept as Medium. Fold this into the final impact narrative.

9. **Run the program-scope check before writing up.** Many programs (Microsoft, large enterprise VDPs) accept info disclosure when it includes internal AD topology; many (Shopify, GitHub) reject info disclosure without a chained impact. If borderline, chain with a Tier-A finding from `hunt-auth-bypass` (Gate 0, question 2).

### Troubleshooting the Type-2 capture

| Symptom | Likely cause | Fix |
|---|---|---|
| No `WWW-Authenticate` header at all | NTLM not offered on that path | Try other paths in Attack Surface Signals |
| Bare `401`, no base64 Type-2 | Connection closed between Type-1 and Type-2 | Switch to Burp Repeater / raw socket with keep-alive |
| `assert b[:8] == "NTLMSSP\x00"` fails | Wrong header captured or wrong message type | Re-run regex against the raw response |
| AV list contains only `AV[0]` | Empty TargetInfo from responder | Try a different endpoint on the same host |
| Decoded names are garbled | Wrong encoding assumption | Names are UTF-16LE; `AV[7]` is binary FILETIME |
| Timestamp far from `Date:` | Clock not synced | Drop the clock-sync observation; keep other findings |

The overwhelming majority of failed captures are transport failures, not missing vulnerabilities. Exhaust the keep-alive methods in step 3 before concluding a target does not leak.

---

## Payload & Detection Patterns

### NTLM / NTLM-info (grounded in curated source)

This is the only payload family present in the curated source. All content below is taken from `hunt-skills/hunt-ntlm-info/SKILL.md`.

**Generic NTLM Type-1 anonymous probe (curl quick check):**

```bash
# Use this as a quick probe to confirm NTLM is offered:
curl -sk -I -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "https://target.example/_api/web/CurrentUser" 2>&1 | grep -i "WWW-Authenticate"
```

This confirms NTLM availability but does not reliably capture the Type-2 because curl closes the connection. Use a keep-alive method for the full challenge. The `-k` flag disables certificate verification (fine for a probe against a test target); do not treat a certificate warning as part of this finding.

**Burp `send_http1_request` (recommended for full Type-2 capture):**

```
GET /_api/web/CurrentUser HTTP/1.1
Host: target.example
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
Connection: keep-alive
User-Agent: Mozilla/5.0
```

**Python raw socket + AV_PAIR decoder (canonical reproduction — include verbatim in reports):**

```python
import socket, ssl, base64, struct, re
from datetime import datetime, timezone

HOST = "target.example"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(
    f"GET /_api/web/CurrentUser HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n"
    "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()
)
data = b""
while True:
    chunk = s.recv(8192)
    if not chunk: break
    data += chunk
    if b"\r\n\r\n" in data: break

m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)
if m:
    b = base64.b64decode(m.group(1).decode("ascii"))
    assert b[:8] == b"NTLMSSP\x00"
    tn_len, _, tn_off = struct.unpack_from('<HHI', b, 12)
    ti_len, _, ti_off = struct.unpack_from('<HHI', b, 40)
    print(f"TargetName: {b[tn_off:tn_off+tn_len].decode('utf-16-le', errors='ignore')!r}")
    av_types = {1:'NetBIOS Computer Name', 2:'NetBIOS Domain Name',
                3:'DNS Computer Name', 4:'DNS Domain Name',
                5:'DNS Tree Name', 7:'Timestamp', 9:'Target Name'}
    i = 0
    ti = b[ti_off:ti_off+ti_len]
    while i < len(ti):
        av_id, av_len = struct.unpack_from('<HH', ti, i)
        if av_id == 0: break
        val = ti[i+4:i+4+av_len]
        if av_id == 7:
            ts = struct.unpack('<Q', val[:8])[0]
            secs = (ts - 116444736000000000) / 10000000
            vs = datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
        else:
            vs = val.decode('utf-16-le', errors='ignore')
        print(f"  AV[{av_id}] {av_types.get(av_id, '?'):28s}: {vs!r}")
        i += 4 + av_len
```

**AV_PAIR decoding reference (from the source):**

| AvId | Meaning | Reporting use |
|---|---|---|
| 1 | NetBIOS Computer Name | Default-hostname tell (`WIN-XXXXXXXXXXX`) |
| 2 | NetBIOS Domain Name | Short domain / UPN `DOMAIN\user` format |
| 3 | DNS Computer Name | FQDN of responding server |
| 4 | DNS Domain Name | The AD domain |
| 5 | DNS Tree Name | The AD forest root / parent-forest disclosure |
| 7 | Timestamp | FILETIME — cracking acceleration, clock-sync check |
| 9 | Target Name | Present in newer NTLMSSP |

### Walking the Type-2 blob

The decoder is short enough to audit line by line, which matters when you are presenting it as reproduction evidence:

- `re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)` pulls the base64 Type-2 value from the raw response. The `{20,}` length guard avoids matching a stray short token.
- `assert b[:8] == b"NTLMSSP\x00"` verifies the decoded blob really is an NTLMSSP message. If this fails, you captured the wrong header or a different message.
- `struct.unpack_from('<HHI', b, 12)` reads the TargetName SecurityBuffer (length, allocated, offset) described in Methodology step 4; `struct.unpack_from('<HHI', b, 40)` does the same for TargetInfo.
- `struct.unpack_from('<HH', ti, i)` walks the AV_PAIRS two bytes at a time (AvId, AvLen). `AvId == 0` terminates the list.
- `AV[7]` is special-cased: the 8-byte FILETIME is converted with the Windows-to-Unix epoch delta `116444736000000000` and a `10000000` (100 ns) divisor, then formatted as ISO-8601 UTC.

**Interpreting decoder output (example from Scenario A).** A successful run produces a labeled list like the one in the source:

```
NetBIOS Domain Name:    <CustomerName>
NetBIOS Computer Name:  WIN-XXXXXXXXXXX
DNS Domain Name:        customer.parent-corp.example
DNS Computer Name:      WIN-XXXXXXXXXXX.customer.parent-corp.example
DNS Tree Name:          customer.parent-corp.example
Timestamp:              2026-05-13T15:55:37.922Z
```

Read it as three findings in one: the `WIN-XXXXXXXXXXX` hostname (Pattern 2), the `customer.parent-corp.example` tree (Pattern 3), and the timestamp (Pattern 4). If the timestamp is within ~5s of the `Date:` header, note the clock-sync observation explicitly in the report.

**Parsing pitfalls to avoid:**

- Forgetting keep-alive and seeing no Type-2 at all — fix transport before interpreting output.
- Using a one-shot HTTP library that closes the socket between Type-1 and Type-2 — same failure mode.
- Assuming `AV[9]` is always present; it appears only in newer NTLMSSP. Its absence is normal.
- Treating an internal/VPN-only host's full AV-pair set as a finding — that is intended behavior (Scenario C).

**Evidence to include in the report:** the exact anonymous GET headers, the canonical Type-1 probe, the decoder script verbatim, the decoded AV-pair output, and the `Date:` header used for the clock-sync comparison. There is no Collaborator/OOB artifact — the evidence is entirely synchronous.

**Burp Collaborator is NOT needed** for this finding class — the data leak is in the synchronous response, not via OOB. There is no callback, no listener, and no DNS/HTTP interaction to confirm; the Type-2 header itself is the evidence.

### Reporting template (grounded fields only)

When writing up a finding from this skill, populate these fields. No field requires a report ID or URL:

- **Affected endpoint:** the URL pattern that returned `WWW-Authenticate: NTLM` (e.g. `/_api/web/CurrentUser`).
- **Exposure:** evidence the host is internet-reachable, not VPN/intranet-only.
- **Stack evidence:** `Server` header confirming IIS / `Microsoft-HTTPAPI/2.0`.
- **Probe:** the canonical Type-1 base64 and the keep-alive request used.
- **Captured challenge:** the base64 Type-2 value (or the decoded AV-pair block).
- **Decoded values:** `AV[1]`–`AV[5]`, `AV[7]` as applicable.
- **Severity rationale:** internet exposure + hostname tell + forest disclosure per Gate 0.
- **Chain:** the second-stage skill (`hunt-auth-bypass`, `m365-entra-attack`) if one exists.
- **Remediation:** disable NTLM on the public binding or set `extendedProtection=Required` (Bypass Techniques matrix).

If a field cannot be filled from actual observations, leave it out — do not substitute an invented value.

### DNS rebinding (adjacent family — not in curated source)

No content on DNS rebinding exists in this skill's single curated source (`hunt-ntlm-info`). The source set for `hunt-dns-network` contains only NTLMSSP Type-2 AV-pair disclosure. No rebinder domains, TTL rotation sequences, or validation-vs-fetch race payloads can be attributed to a source here, so none are asserted. Do not claim a DNS-rebinding finding from this skill. Consult the full corpus path in the provenance note and the related skills below if a parent session backfills this family.

### DNS zone transfer / AXFR (adjacent family — not in curated source)

Zone-transfer (AXFR) reconnaissance is not covered by the curated source. No nameserver targets, transfer commands, or zone-data interpretation guidance appear in `hunt-ntlm-info`. This subsection is a structural placeholder only; no AXFR payloads are fabricated here. Treat any AXFR claim as out of scope for this skill until a source skill covering it is added to the library.

### TLS / network probing (adjacent family — not in curated source)

TLS/cipher/network probing is outside the curated source. The only network-level observation the source makes is protocol-adjacent: identifying an IIS stack via `Server: Microsoft-HTTPAPI/2.0`, `Microsoft-IIS/*`, or `IIS/*` headers and delivering the Type-1 probe over a keep-alive TLS socket (`ssl.wrap_socket` with verification disabled for testing). No TLS-version, cipher-suite, or certificate-validation findings are grounded here — do not assert them from this skill.

### Pivoting primitives (adjacent family — not in curated source)

The source does not describe network pivoting primitives (tunnels, relays, proxies). What it *does* provide is the **identity material that enables a pivot chain**: leaked AD domain, forest root, hostname pattern, and UPN/SAM format. Those values are inputs to the chains in `hunt-auth-bypass`, `m365-entra-attack`, and `offensive-osint` (see Related Skills). The pivot itself belongs to those skills; this skill supplies the reconnaissance step only.

**Boundary reminder.** The four subsections above (DNS rebinding, AXFR, TLS probing, pivoting) exist to define the boundary of this skill's knowledge, not to provide tradecraft. If a parent session adds source skills covering those families, this document should be regenerated from those sources rather than extended with unsourced defaults.

---

## Common Root Causes

1. **Dual-auth IIS bindings on the public zone.** Administrators leave NTLM enabled on the public-facing IIS site even when Forms auth is the intended entry point. Internal users get SSO; external attackers get the AD topology leak.
2. **Default IIS Application Pool identity left as `ApplicationPoolIdentity`.** Combined with a default hostname, this signals provisioning never went past first-boot.
3. **Server never renamed from Windows-installer-generated hostname.** Microsoft's default `WIN-XXXXXXXXXXX` 11-character pattern is the immediate tell. Sometimes also `WORKGROUP\WIN-...` in older boxes.
4. **Sub-domain joined to corporate forest without zone-isolation.** European-integrator case: a European importer's SharePoint test environment is a child domain inside a corporate global AD, disclosed via NTLM DNS Tree Name. The customer probably intends `customer.parent-corp.example` to be operationally separate, but the NTLM Type-2 reveals the forest membership to anyone who probes.
5. **IIS Extended Protection NOT enabled.** When `<system.webServer><security><authentication><windowsAuthentication extendedProtection>` is `None` (the default), the NTLM challenge is sent to any anonymous client. When set to `Required`, NTLM is restricted to authenticated callers — and the AV-pair leak is mitigated.
6. **No `WindowsAuthentication` removed from `applicationHost.config` for internet-exposed sites.** SharePoint Central Admin sometimes leaves this enabled even when SP zone configuration only enables Forms.

### Verification checklist per root cause

- **Dual-auth binding:** confirm the internet-facing zone advertises NTLM even though Forms is the intended front door (Pattern 1).
- **Default app-pool identity:** corroborate the `WIN-XXXXXXXXXXX` hostname tell with other first-boot defaults observed on the host.
- **Unrenamed host:** check `AV[1]` and `AV[3]` against the 11-character installer pattern (Pattern 2).
- **Forest without zone isolation:** check whether `AV[5]` is a parent of the probed domain (Pattern 3) and whether subdomain enumeration agrees.
- **Extended Protection off:** note that the Type-2 was delivered to an *anonymous* caller — direct evidence that `extendedProtection` is not restricting challenges.
- **`WindowsAuthentication` left enabled:** note an internet-exposed management path still offering NTLM despite a Forms-only zone configuration.

The common thread across all six is **configuration drift on internet-facing Windows services**: NTLM remains available to anonymous callers where only Forms auth was intended, and the host was never hardened or renamed. Remediation should target the configuration (disable NTLM on the public binding, set `extendedProtection=Required`, remove `WindowsAuthentication`, isolate the forest), not the symptom (the hostname).

---

## Bypass Techniques

This skill describes a disclosure leak, not an authentication bypass. The "bypass" question is therefore: *how do defenders block this AV-pair leak while still allowing legitimate NTLM auth?* The source provides the following defense matrix:

| Defense | Effectiveness |
|---|---|
| **Disable NTLM on the public IIS binding entirely** (Forms-only) | Best — eliminates the surface |
| **IIS Extended Protection = Required** | Restricts NTLM challenge to authenticated callers; AV-pair leak mitigated |
| **Reverse-proxy strip `WWW-Authenticate` from anonymous responses** | Sometimes works but breaks legitimate clients |
| **Rate-limit the Type-1 → Type-2 endpoint** | Doesn't prevent disclosure, only slows enumeration |
| **Rename the Windows host from `WIN-XXXXXXXXXXX`** | Removes the "lazy provisioning" tell; doesn't stop the leak |
| **Move the SP/Exchange farm to a child AD with no cross-trust to corporate** | Mitigates the *forest disclosure*; doesn't stop the leak |

**Reading the matrix.** Only the first two rows actually fix the leak. Disabling NTLM on the public binding removes the surface entirely; Extended Protection = Required restricts the challenge to authenticated callers and mitigates the AV-pair disclosure. The reverse-proxy strip is brittle because it can break legitimate clients that rely on NTLM. Rate-limiting slows enumeration but an attacker needs only one successful Type-1 → Type-2 exchange, so it does not prevent disclosure. Renaming the host and moving the farm to a child AD address only the *tells* (hostname pattern, forest disclosure), not the leak itself.

**For the attacker:** there is no "bypass" needed — the leak is the finding. The Type-1 message is a standard protocol message accepted by virtually every responder; the only friction is transport (use a keep-alive socket, Methodology step 3), not filtering.

**For report writing:** note which defenses are absent, because that is what lets the client fix the root cause. If the host is simply renamed, the leak persists — call that out explicitly so the remediation targets `extendedProtection=Required` or Forms-only rather than cosmetics.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker do RIGHT NOW with this disclosure?**
   - Internet-exposed + default hostname + corporate forest disclosed → **Medium**: attacker has UPN format for `hunt-auth-bypass` matrix probes, plus knows the server has likely-default service accounts.
   - Intranet-only or only NetBIOS name → **Informational**.
   - If the Type-2 challenge was not actually captured (connection closed, no AV-pairs), you have nothing — re-run with the keep-alive decoder.
   - Quantify the chain: is there an anonymous credential-submission endpoint on the same host (Scenario A's `/_vti_bin/Authentication.asmx`)? That is what turns a Medium disclosure into a Critical chain.

2. **Does the program accept information-disclosure findings without a chained impact?**
   - Many programs (Microsoft, large enterprise VDPs) DO accept this when the leaked info includes internal AD topology.
   - Many programs (Shopify, GitHub) reject info disclosure without a chained impact.
   - Read the program scope before submitting; if borderline, chain with a Tier-A finding from `hunt-auth-bypass`.
   - Pure topology disclosure with no chain is the most common reason these reports are closed as N/A.

3. **Can you reproduce in <5 minutes from a fresh shell?**
   - The Python raw-socket decoder in the Payload section is the canonical reproduction. Include it verbatim in the report.
   - Confirm the decoded AV-pairs are stable across two runs, and that the target path still returns the Type-2 challenge.
   - A second person should be able to paste the script, change `HOST`, and get the same AV-pair output without prior context.

### Evidence checklist

- [ ] Anonymous GET response showing `WWW-Authenticate: NTLM` or `Negotiate`.
- [ ] `Server` header confirming an IIS-family stack.
- [ ] Keep-alive Type-1 → Type-2 capture with a base64 challenge.
- [ ] Decoded AV-pairs (at minimum `AV[1]`/`AV[3]` for hostname, `AV[4]`/`AV[5]` for domain/forest).
- [ ] `Date:` header plus decoded `AV[7]` if asserting the clock-sync observation.
- [ ] Program-scope note: info disclosure accepted, or a chained Tier-A finding identified.
- [ ] Two-run reproduction confirming the AV-pair output is stable and not a one-off responder quirk.

### Severity calibration quick reference

| Conditions | Severity |
|---|---|
| Internet-exposed + default hostname + corporate-AD-tree | Medium |
| Internet-exposed + named-server hostname + corporate-AD-tree | Low-Medium |
| Internet-exposed, NetBIOS/domain only, no tree or hostname tell | Low |
| Intranet-only, any disclosure | Informational |
| Disclosure + anonymous brute-force endpoint on same host | Upgrade chain to Critical |

### Common triage objections and grounded responses

- **"NTLM challenges are protocol behavior, not a vulnerability."** Correct — which is why the report must hinge on the *context* (internet exposure, AD topology, provisioning tell), not the challenge itself. The source explicitly frames this as a Medium-when-chained finding.
- **"This is only information disclosure."** True for many programs; check scope. If the program rejects standalone info disclosure, chain with a Tier-A finding from `hunt-auth-bypass` before submitting.
- **"An attacker needs credentials to reach the same data."** On an intranet, yes (Scenario C). On an internet-facing binding, the anonymous Type-1 probe demonstrates the data is available to unauthenticated callers — that is the distinguishing evidence.
- **"Renaming the host fixes it."** No — that only removes the `WIN-XXXXXXXXXXX` tell. The AV-pair leak persists; cite the defense matrix.
- **"The timestamp is stale."** Drop only the clock-sync observation (Pattern 4). The forest/hostname findings stand independently.

**Drop conditions — recognize and discard:**

- **Intranet-only intentional leak** (Scenario C): a clearly internal host behind VPN returning the full AV-pair set. This is intended NTLM behavior; authenticated VPN users already see the same data via `nltest /dsgetdc:<domain>`. Not a finding.
- **NetBIOS-only disclosure with no DNS Tree name and no internet exposure** → Informational; below most program thresholds.
- **Pure topology disclosure on a program that rejects info disclosure** with no chain → do not submit standalone.

---

## Real Impact Examples

The following scenarios are drawn directly from the curated source. Hostnames and domains are illustrative placeholders from the source; no real report IDs or URLs are implied.

### Scenario A — Enterprise SharePoint inside parent corporate AD (Medium → Critical when chained)

Target: `https://target-portal.example/` — an enterprise dealer portal (test mirror) operated by a system integrator. Sending the anonymous Type-1 message to `/_api/web/CurrentUser` returned a Type-2 challenge whose AV_PAIRS decoded to:

```
NetBIOS Domain Name:    <CustomerName>
NetBIOS Computer Name:  WIN-XXXXXXXXXXX
DNS Domain Name:        customer.parent-corp.example
DNS Computer Name:      WIN-XXXXXXXXXXX.customer.parent-corp.example
DNS Tree Name:          customer.parent-corp.example
Timestamp:              2026-05-13T15:55:37.922Z
```

Three escalation paths:

1. **Default Windows-installer hostname (`WIN-XXXXXXXXXXX`)** — server was never renamed after OS install; strong signal of lazy provisioning. Likely default service-account passwords on the SQL backend, default WSUS config, etc.
2. **Sub-domain inside corporate-parent AD (`customer.parent-corp.example`)** — the customer is a child domain inside <ParentCorp>'s global Active Directory. A compromise of this test farm has potential cross-trust to corporate-parent.
3. **UPN format known** — combined with `hunt-auth-bypass`'s discovery of an anonymous brute-force endpoint on `/_vti_bin/Authentication.asmx`, the attacker has both the credential format (`firstname.lastname@customer.parent-corp.example` or `<CustomerName>\firstname.lastname`) and the unlimited submission endpoint.

**Attack path:** anonymous Type-1 capture → Type-2 AV-pair decode → default-hostname + parent-forest identification → UPN format derived → credential format applied to the anonymous brute-force endpoint. The NTLM finding supplies steps 1–4; `hunt-auth-bypass` supplies step 5.

**Evidence to include:** the decoded AV-pair block above, the anonymous GET headers, and the observed brute-force endpoint. Reported severity: **Medium**, with a note that the chain with the Authentication.asmx anonymous brute-force makes the combined attack **Critical**.

### Scenario B — Exchange edge with NTLM-protected EWS (Low-Medium)

Target: `https://mail.example.com/EWS/Exchange.asmx`. A Type-1 probe returns a Type-2 with DNS Tree Name `corp.example.com` and DNS Computer Name `MAIL01.corp.example.com`. This confirms the Exchange edge is domain-joined to corporate AD (rather than running in a DMZ-isolated AD). For an attacker with the matching `hunt-mfa-bypass` / `hunt-auth-bypass` chain, the leaked UPN format and server-name format accelerate credential spraying by removing the recon step.

**Attack path:** anonymous Type-1 capture on EWS → Type-2 shows `corp.example.com` tree and `MAIL01` computer name → attacker concludes the edge is domain-joined, not DMZ-isolated → leaked UPN/server formats feed a spray. Reported severity: **Low-Medium** depending on program.

### Scenario C — Intranet-only intentional leak (not a finding)

Target: `https://intranet.corp.example` (clearly internal, behind VPN). A Type-1 probe returns the full AV-pair set. **Not reportable** — this is intended NTLM behavior on an intranet, and the disclosure is to authenticated VPN users who already see the same data via `nltest /dsgetdc:corp.example.com`. Recognize and drop. Including this scenario prevents false positives at triage.

**Why it is dropped:** the recipient of the "leak" is an authenticated user who already has legitimate access to the same topology via standard domain tools. There is no unauthorized disclosure and no internet exposure.

### What the source does NOT support

To keep reports defensible, note the boundaries of the curated material:

- No claim about DNS rebinding, AXFR zone transfers, TLS cipher weakness, or network pivoting is grounded here — those families are absent from the source skill.
- No report IDs, write-up URLs, bounty amounts, or CVE numbers are available; cite `hunt-skills/hunt-ntlm-info/SKILL.md` as the provenance.
- The scenarios use illustrative hostnames (`target-portal.example`, `mail.example.com`, `intranet.corp.example`) and placeholders (`<CustomerName>`, `<ParentCorp>`). Do not present them as real targets.
- A full AV-pair set on an intranet/VPN host is explicitly *not* a finding (Scenario C). Reporting it would be a false positive.

### Cross-cutting impact narrative

Across all scenarios, the reportable harm is the **reconnaissance multiplier**: the Type-2 leak removes the guesswork from identity attacks (domain format, forest layout, hostname maturity, clock sync). The strongest reports pair the leak with a concrete second stage from `hunt-auth-bypass` or `m365-entra-attack`, as in Scenario A, where a Medium disclosure plus an anonymous brute-force endpoint becomes a Critical chain. The weakest reports present raw AV-pairs with no context — those die at triage.

---

## Source Skill Lineage

This skill is derived from exactly **one** curated source:

- **`hunt-skills/hunt-ntlm-info/SKILL.md`** — sole source of all technical content in this document. **Unique contribution:** the complete anonymous NTLMSSP Type-2 AV-pair disclosure methodology — the canonical Type-1 base64 probe, the keep-alive transport requirement, the MS-NLMP Type-2 byte-layer parsing map, the AvId 1/2/3/4/5/7/9 decoding table, the Python raw-socket + AV_PAIR decoder reproduced verbatim in the Payload section, the six-item root-cause list, the defender-side bypass/defense matrix, the three-step Gate 0 validation, Scenarios A–C, and the related-skill chain primitives. Every other section in this SKILL.md is a reorganization or expansion of this single source.

### Expansion method

This document preserves the source's facts verbatim where they are load-bearing (target list, Type-1 probe, byte map, AvId table, decoder script, root causes, defense matrix, Gate 0 questions, and Scenarios A–C). Material labeled "quick reference," "decision tree," "troubleshooting," "checklist," "calibration," "template," and "chain diagram" is a reorganization of those same facts into operator-facing form — no new technical assertions are introduced in those blocks. Adjacent technique families with no source coverage are called out explicitly rather than filled with generic payloads.

### Contribution map

| Section in this SKILL.md | Origin in source skill |
|---|---|
| Crown Jewel Targets | Source "Crown Jewel Targets" (target list + "what makes this pay") |
| Attack Surface Signals | Source "Attack Surface Signals" (headers, URL patterns, tech signals) |
| Discovery Patterns (4) | Derived from source methodology severity tiers + AV_PAIR AvIds |
| Step-by-Step Methodology | Source "Step-by-Step Hunting Methodology" (8 steps, expanded to 9) |
| Payload & Detection Patterns | Source "Payload & Detection Patterns" (probes + decoder verbatim) |
| Common Root Causes | Source "Common Root Causes" (6 items) |
| Bypass Techniques | Source "Bypass Techniques" (defense matrix) |
| Gate 0 Validation | Source "Gate 0 Validation" (3 questions) |
| Real Impact Examples | Source Scenarios A–C |
| Related Skills & Chains | Source "Related Skills & Chains" |

**Attribution rules carried forward:**
- **0 full reports** were read; **0 HackerOne IDs, report URLs, bounty amounts, or CVEs** are cited. No such identifiers were present in the source, and none have been invented.
- Skill paths are cited in place of report identifiers (e.g. `hunt-skills/hunt-ntlm-info/SKILL.md`).
- The full extracted corpus is preserved at `E:\webt\skill-setup\skills-extract-from-reports\hunt-dns-network\references\source-knowledge.md`.
- The source line "12 unique sections from 1 source files" is preserved verbatim in the corpus header; this document reorganizes those 12 sections into the 12-part skill structure required by the library, with a plain-text summary at the end.

---

## Related Skills & Chains

- **`hunt-sharepoint`** — SharePoint farms emit anonymous Type-2 challenges on `/_vti_bin/` by default; this is one of the most reliable ways to get internal AD topology. Chain primitive: SharePoint discovered → NTLM Type-2 capture on `/_vti_bin/Lists.asmx` → `hunt-ntlm-info` AV_PAIR decode → internal forest name → `m365-entra-attack` ROPC spray on Entra tenant tied to that forest.

- **`m365-entra-attack`** — Leaked NetBIOS domain + UPN suffix is the missing piece for a credible password spray. Chain primitive: NTLM Type-2 yields `corp.example.com` DNS tree → cross-reference Entra tenant via `https://login.microsoftonline.com/corp.example.com/.well-known/openid-configuration` → `m365-entra-attack` AADSTS error-differential username enumeration on resolved tenant.

- **`hunt-aspnet`** — IIS sites running ASP.NET frequently expose NTLM on management paths. Chain primitive: NTLM Type-2 on `/owa/`, `/ecp/`, `/rpc/`, `/aspnet_client/` → confirm IIS + ASP.NET version → `hunt-aspnet` ViewState / `.axd` enumeration on same host.

- **`offensive-osint`** — The hostname pattern `WIN-XXXXXXXXXXX` signals lazy provisioning and predicts other weak hygiene. Chain primitive: NTLM Type-2 returns default-installer hostname → flag as low-maturity environment → `offensive-osint` deep recon (cert transparency, GitHub leakage, breach corpus correlation) is high-yield on this org.

- **`triage-validation`** — Most NTLM info-disclosure findings die at the 7-Question Gate on "is this exploitable" — pure topology disclosure is Low/Informational. Chain primitive: pull every NTLM-info finding through `triage-validation` BEFORE writing it up; only report if (a) leaks UPN format that accelerates spray, or (b) leaks production hostname mapping (`redteam-report-template` for the chain-narrative).

- **`hunt-auth-bypass`** — The Legacy-Protocol Matrix is the natural second stage for the leaked UPN/SAM format. A Type-2 disclosure on the same host upgrades an auth-bypass finding's severity because the attacker already has the credential format.

### Chain diagram (from the source chain primitives)

```
Internet-facing IIS/SharePoint discovery
  -> anonymous Type-1 probe (this skill)
  -> Type-2 AV-pair decode (this skill)
  -> forest / hostname / UPN-format intel (this skill)
  -> [ SharePoint: /_vti_bin/ capture  |  ASP.NET: /owa/,/ecp/  |  Entra: openid-config lookup ]
  -> hunt-auth-bypass / m365-entra-attack second stage
  -> triage-validation gate before write-up
```

### What this skill hands to each downstream skill

- **`hunt-sharepoint` / `hunt-aspnet`** receive a confirmed IIS-family host plus the exact management path that produced the Type-2, so their follow-on enumeration targets a live NTLM endpoint.
- **`m365-entra-attack`** receives the DNS tree / UPN suffix needed to resolve an Entra tenant and format a spray; without it, the spray is blind.
- **`hunt-auth-bypass`** receives the credential format (`firstname.lastname@<domain>` or `<DOMAIN>\firstname.lastname`) that the Legacy-Protocol Matrix probes consume.
- **`offensive-osint`** receives the low-maturity signal (`WIN-XXXXXXXXXXX`) that prioritizes deep recon on the organization.
- **`triage-validation`** receives the full evidence packet and applies the exploitability gate before write-up.

The recurring pattern is that this skill is an **identity-reconnaissance front end**: it does not exploit the disclosure on its own but supplies the exact strings (domain, forest, hostname, UPN format) that make downstream auth attacks credible and specific. Route every finding through `triage-validation` before reporting, per the source.

---

**Summary.** `hunt-dns-network` is a documentation extract built from a single curated source — `hunt-skills/hunt-ntlm-info/SKILL.md` — covering anonymous NTLMSSP Type-2 AV-pair information disclosure on internet-facing IIS, SharePoint, Exchange, and gateway infrastructure. It provides the crown-jewel target list, attack-surface signals, four discovery patterns, a nine-step hunting methodology, the canonical Type-1 probe and Python AV-pair decoder, a Type-2 blob walkthrough, root causes with a verification checklist, the defender-side defense matrix, Gate 0 validation with an evidence checklist and severity calibration, three real impact scenarios, source lineage with a contribution map, and related-skill chains. DNS rebinding, zone transfer, TLS probing, and pivoting families are explicitly marked as out of scope for this source set rather than fabricated. No report IDs, URLs, or bounty figures are asserted; the full extracted corpus is linked at `E:\webt\skill-setup\skills-extract-from-reports\hunt-dns-network\references\source-knowledge.md`.
