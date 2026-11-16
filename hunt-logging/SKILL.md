---
name: hunt-logging
description: Hunting skill for log injection (CWE-117), insufficient logging & monitoring (CWE-778), and log-based attack-detection bypass. Built from 24 full disclosed reports — overwhelmingly AWS VDP CloudTrail failures (silent permission enumeration through non-production API endpoints: #3418966 AI Ops, #2926361 SSM, #3068422 Neptune Graph, #3092085 Route 53, #2951803 Bedrock, #3780277 S3 Tables, #3014785 Datazone; and "AWS Internal" user-agent / source-IP masking on FIPS and specific endpoints: #3419587 Auto Scaling, #3072841 Pinpoint SMS & Voice, #2979238 Comprehend Medical, #3044471 Kendra) plus Monero ZMQ RPC log injection / untrusted payload persistence (#3621606). Use when hunting log forging, audit-trail gaps, or evasion of log-based detection on any target.
sources: hackerone_public, aws_vdp, monero, sysdig_research, datadog_security_labs
report_count: 25
full_reports_read: 24
---

## Crown Jewel Targets

Logging bugs are high-value because they are the *last line of defense*. A vulnerability that deletes, forges, or never creates the forensic record converts every other bug into an unattributable one — and, where a log-based detection is the compensating control for a weaker preventative control, into an undetectable one. The 24 reports in this pack split into three concrete target classes.

### Class 1 — Cloud audit-trail endpoints (dominant corpus: 23 of 24 reports)

These are not "a web app forgot a log line." They are API endpoints whose calls are *never written to CloudTrail*, or whose calls are written with attacker-controllable / meaningless attribution fields. Priority targets:

- **Non-production / staging / "internal-only" API endpoints** that still accept production SigV4 credentials. Reports #3418966, #2926361, #3068422, #3092085, #2951803, #3029552, #3042588, #2981210, #2800091, #3021618, #3009411, #3031512, #3022516, #2972435, #2999116, #3021451, #3014785, #3780277, #3775702 all describe the same primitive: a `--endpoint-url` override to a non-prod host executes `List*` / `Describe*` calls with zero CloudTrail events. The researcher enumerates IAM permissions *silently*.
- **FIPS and "special" endpoints** that report `AWS Internal` for the `userAgent` and `sourceIPAddress` fields (#3072841, #2979238, #3044471, #3419587). An adversary calls these endpoints with stolen credentials and the resulting event cannot tell defenders who or where.
- **Newly-created endpoints discovered via Certificate Transparency monitoring** (#3014785). Fresh hostnames are the highest-yield because they have not yet been folded into the logging control plane — the reporter found 3 such endpoints within 24 hours of issuance.
- **Narrowly-scoped endpoints that expose only a single sensitive action**, e.g. the endpoint that "can only perform the `neptune-graph:ListGraphSnapshots` action" (#3068422). These are easy to miss in a service-wide audit review.

For this class, the "crown jewel" is not the endpoint itself — it is the *silence*. The finding is the gap between "this action affects the account" and "no event records it."

### Class 2 — Raw-request logging sinks (log injection)

- **RPC daemons that log the request body before semantic validation.** #3621606 (Monero `monerod`, ZMQ RPC on `tcp://host:18082`) logs untrusted `params.note` content *before* validation, letting a remote party inject `\n` and control characters into daemon logs — forging entries and persisting attacker-chosen text.
- **Any sink where user input reaches a line-oriented or structured log**: syslog / journald, Nginx / Apache access logs, application `log.info(user_input)`, `console.log`, audit exporters, SIEM forwarders, JSON / key-value log writers.
- **Log *viewers*** — admin dashboards that render stored log lines. A forged line that survives into an HTML / CSV / terminal renderer upgrades to stored XSS, CSV injection, or ANSI escape-sequence attacks.
- **Log exports** — the `export-feature` and `comment-injection` tags in #3014785, #3780277, #3775702 hint at a secondary sink: forged lines laundered into downloadable reports.

### Class 3 — Detection-pipeline blind spots

Any environment where a "log-based detection" is the compensating control for weaker prevention: WAF alerting, failed-login detection, IAM `Deny` monitoring, anomaly detection on `userAgent` / source IP, UEBA. If the attacker can suppress or poison the event, the detection is bypassed even though the underlying action still executes. This is the "log-based attack detection bypass" half of the skill, and it is what elevates an "informational logging gap" into a real security finding.

### What makes these findings reportable

A logging bug is worth submitting only when you can point to a **concrete control that fails**: an expected CloudTrail event that never appears, an attribution field that is deliberately meaningless, or a forged line that changes the meaning of the log. Highest impact lands where the gap enables **silent credential-permission enumeration** (the reported AWS pattern, directly linked to Scarleteel 2.0 tradecraft in #3092085), **attribution evasion** during an intrusion, or **log forging that frames an innocent principal**.

### Priority matrix

| Target class | Representative reports | Core primitive | Severity driver |
|---|---|---|---|
| Non-prod endpoint, no events | #3418966, #3068422, #3014785, #3780277 | Omission | Number of sensitive `List*`/`Describe*` actions reachable silently |
| FIPS / special endpoint, masked UA+IP | #3419587, #3072841, #2979238, #3044471 | Corruption | Whether a detection rule keys on the poisoned fields |
| Raw request logging before validation | #3621606 | Injection | Whether forged lines persist and reach a viewer / export |
| Newly-issued CT hostnames | #3014785 | Omission | Speed of endpoint churn vs. logging onboarding |

Rank a candidate by (a) how privileged the action is, (b) how completely the record is suppressed, and (c) whether a named detection or compliance control is defeated. An unlogged low-privilege `Get*` is weaker than an unlogged `List*` on IAM, which is weaker than a forged line that actively misdirects responders.

---

## Attack Surface Signals

### Endpoint / CLI patterns (insufficient-logging hunt)
```
aws <service> <action> --endpoint-url https://<non-prod-or-fips-host>
aws <service> <action> --endpoint-url https://fips.<service>.<region>.amazonaws.com
aws <service> <action> --endpoint-url https://<service>.<region>.amazonaws.com.cn
aws <service> list-* --endpoint-url ...           # enumeration verbs are the payload
aws <service> describe-* --endpoint-url ...
AWS_PROFILE=<profile> aws <service> <action>      # admin vs noperm differential
AWS_DEFAULT_REGION=<region> aws <service> <action> --endpoint-url ...
```
Look for endpoint overrides pointing at hosts that are *reachable but unmonitored*: staging, beta, `graph`, `api.internal`, `.dev`, newly-issued certificates. In #3014785 the reporter states the 3 extra endpoints "came down through my certificate transparency monitoring" — recon over CT logs, not over the application UI.

### Request / field patterns (log-injection hunt)
```
User-Agent: ...%0AFAKE_ADMIN_LOGIN_SUCCESS
X-Forwarded-For: 1.2.3.4%0d%0a<forged line>
X-Real-IP, X-Client-IP, Referer, X-Requested-With, Via
?note=ATTACKER_MARKER_BEGIN%0A...
?msg=, ?comment=, ?reason=, ?description=, ?name=, ?q=    # any echoed input
JSON body: {"params":{"note":"...\n..."}}                # #3621606 pattern
Multipart form filenames, URL paths, cookie values, HTTP method strings
```

### Log-sink / consumer signals
```
Line-oriented logs:   syslog, /var/log/*, journald, nginx access.log
Structured logs:      JSON lines, logfmt, key=value, OpenTelemetry spans
Viewers:              /admin/logs, Kibana / Grafana / Splunk dashboards
Exports:              CSV / PDF / HTML of log data (secondary injection sink)
RPC surfaces:         tcp://host:18082 (ZMQ), gRPC, JSON-RPC, XML-RPC
```

### Log-format signals (what the writer does with your bytes)
| Behavior | Signal to look for | Probe implication |
|---|---|---|
| Raw concatenation | `std::string + user_input`, Python `%s`, JS template literals | Newline survives verbatim → clean log forging |
| JSON serialization with `ensure_ascii=False` | `\n` becomes a real newline inside a string | May break line-delimited JSON parsers |
| Control chars stripped | `replace('\n','')`, regex allowlist | Try `\r`, `\u2028`, `\x00`, double-encoding |
| Field escaped but length-truncated | `substr(0, 200)` after escaping | Forge within the kept prefix |
| Log written before validation | any `log(...)` above the validation branch | #3621606's exact defect |

### Tech-stack signals
- **AWS SDK / CLI anywhere** — every `List*`, `Describe*`, `Get*` action is a candidate for a logging gap; VDP scope means you test AWS's own endpoints, not just a customer app.
- **Certificate Transparency visibility** — newly minted `<service>.amazonaws.com` or partner hostnames are recon inputs (#3014785).
- **C/C++ daemons with raw request logging** — e.g. `src/rpc/daemon_handler.cpp` in #3621606; C++ string building with unescaped `\n` is the canonical log-injection source.
- **XML / SOAP / XML-RPC parsers** — tagged `xml-parser` in 18 of 24 reports (AWS Query protocol is XML over HTTP); these APIs are both a logging-gap surface and an injection surface.
- **Caching / proxy layers** — `cache-layer` appears in 10 reports; a cache hit may short-circuit the audit path.
- **SIEM / EDR / WAF that depends on log fidelity** — the detection is only as good as the event it receives.

### Detection-stack signals
- A documented guardrail, alert, or compliance control that claims "all admin actions are logged" — this is the claim you disprove.
- Rules keyed on `userAgent`, `sourceIPAddress`, or `userIdentity.arn` — exactly the fields poisoned by the "AWS Internal" class.
- Log-retention / audit-dashboard UIs that defenders actually watch — forging here has real misdirection value.

### Severity calibration (read before scoring)

Not every logging gap is a critical finding. The disclosed reports were all rated **medium**, and the reason is instructive: the weakness is a *control failure*, not direct data loss. Scoring should reflect the downstream attack the gap enables.

| Evidence you can show | Likely severity band |
|---|---|
| An unlogged endpoint exists but no sensitive action is reachable | Low / informational |
| Read-only `List*` / `Describe*` enumeration is silent | Low–medium (matches the corpus) |
| Silent enumeration plus a documented detection that fails | Medium |
| Forged lines persist in a log that feeds an alerting pipeline | Medium |
| Forged lines reach an HTML viewer → stored XSS | Escalate per the XSS impact |
| Silent action + poisoned record defeats incident response entirely | High, if impact is demonstrated |

The corpus itself is a useful anchor: 23 AWS VDP reports and 1 Monero report were all disclosed at **medium** with undisclosed bounties. Do not inflate; instead, make the *demonstrated* detection bypass the centerpiece of the write-up.

---

## Discovery Patterns From 24 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Cloud-provider API endpoint inventories / `--endpoint-url` overrides** (highest signal — ~19 of 24 reports). *What to look for:* the existence of a non-prod, FIPS, beta, or regional endpoint that accepts the same SigV4 credentials as production. Then ask: when I call it, does a CloudTrail event appear 5–10 minutes later? #3419587's reproduction is the template: establish a baseline on the default endpoint ("wait 5-10 minutes for this event to appear in CloudTrail… see that the UserAgent field is populated, as well as the source IP address"), then switch endpoints and compare.

2. **Certificate Transparency logs** (#3014785 explicitly). *What to look for:* newly issued certificates for service endpoints. The reporter found 3 more vulnerable endpoints within 24 hours of issuance. CT monitoring is a discovery engine for audit-trail gaps because new endpoints are provisioned before logging is wired up.

3. **Public code search / documentation diffs** (`public-code-search` in #3092085, #3780277, #3775702). *What to look for:* endpoint hostnames in AWS SDK endpoint metadata, CLI docs, GitHub examples, and `botocore` endpoint JSON. Any host you can address is a host you can test for a logging gap.

4. **Source-code review of the log write path** (the #3621606 pattern). *What to look for:* the exact line where an external string is concatenated into a log call with no `\n` / `\r` escaping, and *where validation sits relative to that line*. #3621606 pinpoints it to commit `77986023c3` ("json serialization for rpc-relevant monero types"), which "added raw request logging in `src/rpc/daemon_handler.cpp`."

5. **Local daemon RPC ports** (#3621606: `tcp://127.0.0.1:18082`). *What to look for:* ZMQ / JSON-RPC / XML-RPC services reachable from a test host with request tracing enabled. Send a request whose string field contains a newline marker and read the daemon log.

6. **Log viewers / admin dashboards.** *What to look for:* a UI that renders stored log lines. Inject a canary with `\r\n` and see whether a *new line* appears in the viewer — that is log forging made visible. Check whether the same line survives CSV / PDF export.

7. **The "AWS Internal" field pattern** (4 reports). *What to look for:* CloudTrail events where `userAgent` and `sourceIPAddress` are the literal string `AWS Internal`. Compare across endpoints of the *same* service: one endpoint logs correctly, a FIPS sibling does not (#3072841, #2979238, #3044471).

8. **Permission-enumeration differential** (#3014785). *What to look for:* call with an `admin` profile vs a `noperm` profile against the same non-prod endpoint. The admin call returns `Invalid endpoint or operation type` while the noperm call returns a real `AccessDeniedException` naming the action — a foil that reveals the endpoint is live but unlogged.

### Recon tooling (the actual commands)

```bash
# Certificate Transparency — the exact discovery engine behind #3014785
curl -s "https://crt.sh/?q=%25.<service>.amazonaws.com&output=json" \
  | jq -r '.[].name_value' | sort -u | grep -Ei 'dev|beta|staging|graph|int'

# Extract candidate endpoints from botocore SDK metadata
python3 - <<'EOF'
import json, botocore.session
s = botocore.session.get_session()
for svc in s.get_available_services():
    m = s.get_service_model(svc)
    for ep in [e for e in dir(m) if 'endpoint' in e.lower()]:
        pass
    print(svc, m.endpoint_prefix)
EOF

# Free-text code search for endpoint overrides (public-code-search tag)
#   query: "endpoint-url" "<service>" site:github.com
#   query: "fips.<service>" language:json

# Confirm an endpoint resolves before you spend time on it
dig +short <candidate-endpoint>
curl -sS -o /dev/null -w '%{http_code} %{remote_ip}\n' https://<candidate-endpoint>
```

The workflow is: **CT / code search yields hostnames → reachability check narrows them → CloudTrail diff decides which are vulnerable.** #3014785 found extra endpoints "created in the past 24 hours" purely by watching new certificates, so a CT feed is the single highest-leverage recon input in this corpus.

### Feature-Based Discovery Signals (frequency-ranked, from the 24-report corpus)

Counts are the literal tag frequencies in the study pack. The tags are imperfect miner output, but the ranking is informative: the top four signals appear in nearly every report. "Why it matters / what to probe" translates each tag into a logging-hunt action.

| Signal tag | Count | Why it matters / what to probe |
|---|---|---|
| `search-filter-sort` | 24 | Every report involved search/list/describe verbs. Probe `List*`, `Describe*`, `Get*`, `Search*` across alternate endpoints and check for the corresponding audit event. |
| `api-endpoint` | 24 | The whole corpus is API-level. Enumerate every hostname/endpoint for a service, not just the default one; each may have a different logging pipeline. |
| `filter-bypass` | 22 | Bypass of the "log to CloudTrail" control itself. Probe endpoint overrides (`--endpoint-url`), FIPS variants, and routing that slips past the logging filter. |
| `xml-parser` | 18 | AWS Query/SOAP APIs are XML-over-HTTP. Probe these endpoints for both missing audit events and unescaped content reaching XML-backed log writers. |
| `cache-layer` | 10 | Caching/proxy layers can short-circuit the audit path. Probe whether a cached/hit response bypasses event generation; compare cold vs warm calls. |
| `admin-internal` | 5 | Internal/admin planes are where privilege lives and where logs should be loudest. Probe internal hostnames and admin actions for silence. |
| `sso-oauth` | 3 | Identity events are detection-critical. Probe whether auth/token calls on alternate endpoints emit log events. |
| `redirect-handling` | 3 | A redirect from a logged to an unlogged host can hide the real action. Probe 30x chains and endpoint aliases. |
| `public-code-search` | 3 | Endpoint hostnames leak in SDK metadata and docs. Probe GitHub / botocore / source for undiscovered endpoints. |
| `comment-injection` | 3 | Free-text fields are injection sinks. Probe `note`, `comment`, `reason`, `description` for newline/control chars (directly corroborated by #3621606). |
| `cloud-metadata` | 2 | Cloud control-plane context matters for attribution fields; probe `userAgent`/`sourceIP` provenance. |
| `import-feature` | 2 | Import/ingest paths often log raw payloads before validation. Probe import endpoints with newline markers. |
| `export-feature` | 1 | Exports are a *secondary* sink: forged log lines can be laundered into CSV/PDF. Probe log-export functions. |
| `image-processing` | 1 | A pipeline that logs metadata is a logging surface. Probe metadata fields for raw echo. |
| `debug-error-leak` | 1 | Debug/error logs frequently echo unescaped input. Probe error paths with control chars. |
| `internal-network` | 1 | Internal RPC reachability (ZMQ). Probe `tcp://127.0.0.1:18082`-style services. |
| `request-smuggling` | 1 | Smuggled/ambiguous requests can deserialize into a log line differently than the validator saw. Probe delimiters. |
| `dependency-confusion` | 1 | Supply-chain paths can pick up raw-logging code (as commit `77986023c3` did). Review logging introduced by dependencies. |

### Verbatim Discovery Clues

All quotes below are verbatim from the disclosed-report text in the study pack (redactions shown as `█` where the pack redacted them). These are the researchers' own "how I found it / what I found" lines.

- **[#3418966]** "There are many categories of CloudTrail bypass. The specific variant we will be focussed on in this report has been referred to as 'non-production endpoint permission enumeration CloudTrail bypass'. If you would like to learn more about it, you can find more details here."

- **[#3418966]** "Typically, when an adversary gains access to stolen AWS IAM credentials they will frequently test those credentials to see what access they have. They do this by performing API calls and seeing which succeed and which fail. There are even automated tools to make this possible."

- **[#3068422]** "In addition to the above 6, we found another non-production endpoint which can only perform the `neptune-graph:ListGraphSnapshots` action."

- **[#3014785]** "Hey friends, I'm terribly sorry to do this to you, but just minutes ago I found 3 more endpoints which exhibit the vulnerable behavior. They just came down through my certificate transparency monitoring so I think they were created in the past 24 hours. It is otherwise identical to that previous report."

- **[#3014785]** "An error occurred (AccessDeniedException) when calling the ListDomains operation: Invalid endpoint or operation type" — returned with the `admin` profile; versus, with the `noperm` profile, "User: arn:aws:sts::█████████:assumed-role/noperm/noperm is not authorized to perform: datazone:ListDomains on resource: arn:aws:datazone:us-east-1:████:domain/*".

- **[#3419587]** "We have found 6 API endpoints for the AWS Auto Scaling service that incorrectly report the user-agent and network information as 'AWS Internal'. As a result of this, an adversary can perform API calls using these endpoints and evade the logging of their IP address/operating system information."

- **[#3419587]** "This is similar to previous bugs we've submitted for the following services: Pinpoint SMS and Voice, Kendra, Comprehend Medical."

- **[#3072841]** "We have found 5 API endpoints for the Amazon Pinpoint SMS and Voice, version 2 service that incorrectly report the user-agent and network information as 'AWS Internal'. As a coincidence, these 5 API endpoints are all FIPS endpoints."

- **[#2979238]** "We have found 8 API endpoints for the Comprehend Medical service that incorrectly report the user-agent and network information as 'AWS Internal'. As a coincidence, these 8 API endpoints are all FIPS endpoints. It's entirely possible that this was an intentional decision, however I haven't run into it before and therefore wanted to report it in case that was not the case."

- **[#3044471]** "We have found 4 API endpoints for the Kendra Intelligent Ranking service that incorrectly report the user-agent and network information as 'AWS Internal'. As a coincidence, these 4 API endpoints are all FIPS endpoints."

- **[#3621606]** "The ZMQ RPC request path logs untrusted request content before semantic validation. A remote party with access to the ZMQ endpoint can inject newline and control-character content into daemon logs, enabling log forging and persistence of attacker-controlled text."

- **[#3621606]** "Introduced in commit 77986023c3 ('json serialization for rpc-relevant monero types'), which added raw request logging in src/rpc/daemon_handler.cpp."

- **[#3621606]** "PoC: ZMQ RPC request-body log injection / payload logging in monerod." Inline payload: `{"jsonrpc":"2.0","id":1,"method":"get_info","params":{"note":"ATTACKER_MARKER_BEGIN\n...` with the step "Sending crafted payload with newline markers."

- **[#3092085]** "There are many categories of CloudTrail bypass. The specific variant we will be focussed on in this report has been referred to as 'non-production endpoint permission enumeration CloudTrail bypass'." — the report links `https://sysdig.com/blog/scarleteel-2-0/` and `https://securitylabs.datadoghq.com/...` as background tradecraft.

### Probe Checklist (15 concrete probes)

1. **Baseline log timing.** Issue one normal `aws <service> <action>` call, wait 5–10 minutes, confirm the event appears with a populated `userAgent` and `sourceIPAddress` (#3419587 method). *Success signal:* you now know what "correct" looks like.
2. **Endpoint-override sweep.** Run the same call against every alternate endpoint hostname you enumerated; diff which ones produce a CloudTrail event. *Success signal:* at least one host returns data but no event.
3. **Non-prod / beta / graph host test.** Target `*.dev`, `beta`, `graph`, `staging` variants with a real read verb; check for silence. *Success signal:* identical response, different audit outcome.
4. **FIPS-sibling test.** Call the FIPS endpoint of a service and inspect the resulting event's `userAgent` / `sourceIPAddress` for the literal `AWS Internal` (#3072841 / #2979238 / #3044471).
5. **Certificate-Transparency sweep.** Pull newly issued certificates for the service and test each new hostname within 24–72 hours (#3014785).
6. **Admin-vs-noperm differential.** Call the suspect endpoint under two profiles; look for the `Invalid endpoint or operation type` vs real `AccessDeniedException` divergence (#3014785).
7. **Permission-enumeration harness.** With a "stolen" low-priv credential, script a list of `List*` / `Describe*` / `Get*` actions against the endpoint; confirm each succeeds/fails silently.
8. **Newline-in-string-field canary.** Send `note=ATTACKER_MARKER_BEGIN%0AFAKE_LINE` (and `\r\n`, `\r`, `\u000a`, `%0d%0a`) to any RPC/API that logs the field (#3621606).
9. **Raw-body log review.** If local/source access exists, grep the daemon log for your marker appearing as a new line; confirm injection landed *before* validation.
10. **Viewer reflection.** Open the admin log viewer and verify the forged line renders as a distinct entry; check HTML / CSV / PDF export for secondary injection.
11. **ANSI / terminal-escape probe.** Inject `\x1b[2J\x1b[31m` and control characters (`\x00`, `\x08`, `\x7f`) into the same field; check terminal/SIEM rendering.
12. **Structured-log break.** If logs are JSON lines, inject `"}`, `\`, `\n`, and U+2028 / U+2029 to break or forge key-value pairs.
13. **Header injection.** Try `%0d%0a`-laden `User-Agent`, `X-Forwarded-For`, `Referer`, and `X-Real-IP` values where access logs record them.
14. **Cache / warm-call check.** Repeat a call twice; compare whether the second (cached) response skips event generation (`cache-layer` in 10 reports).
15. **Detection-rule test.** After bypass, query CloudTrail / SIEM for your principal, source IP, and action; prove the expected alert did not fire — the "detection bypass" half of the finding.

---

## Step-by-Step Hunting Methodology

### Part A — Insufficient logging / CloudTrail bypass

1. **Define the control being bypassed.** State precisely: "CloudTrail should record action X with correct `userAgent` and `sourceIPAddress`." The whole corpus is about that control failing, either by *omission* (no event) or *corruption* (meaningless attribution fields). Without this statement, you have no baseline to prove a violation against.

2. **Establish a clean baseline.** On the default endpoint, call a known action, wait 5–10 minutes, and record what a correct event looks like — fields, latency, source IP, user agent. #3419587's reproduction steps are the literal template. Do not skip the wait: a too-early query is not evidence of absence.

3. **Enumerate alternate endpoints.** Pull service endpoint metadata from SDK source, docs, public code search, and CT logs. For each candidate host, ask three questions: is it reachable? does it accept SigV4 credentials? is it *supposed* to be logged? Capture the evidence for the third (documentation, support pages, naming).

4. **Test for omission.** Execute a representative `List*` / `Describe*` action against each candidate. Wait the propagation window. Query CloudTrail by `eventSource`, `eventName`, `userIdentity.arn`, or `sourceIPAddress`. Absence of an event = silent-enumeration primitive (#3418966 et al.). Re-query once more after another interval to rule out lag.

5. **Test for corrupted attribution.** Where events do appear, inspect `userAgent` and `sourceIPAddress`. The literal `AWS Internal` on a FIPS or "special" endpoint = attribution-evasion primitive (#3419587, #3072841, #2979238, #3044471). Compare against the baseline from step 2 for the same service.

6. **Weaponize the primitive.** Demonstrate the *attack the gap enables*, not just the gap. Use a low-privilege / "stolen" credential to run a permission-enumeration loop against the unlogged endpoint and show you can map allowed actions with zero forensic trace. #3014785's admin/noperm differential is a compact proof that the endpoint is both live and actionable.

7. **Confirm the detection failure.** If the target advertises a log-based control (guardrail, alert, SIEM rule), show that yours did not fire. This converts "insufficient logging" into "log-based detection bypass" — the difference between an informational finding and a real one.

8. **Scope the blast radius.** Repeat across services. The same reporter found the pattern across dozens of services; #3419587 explicitly cross-references Pinpoint, Kendra, and Comprehend Medical, implying a systemic class rather than an isolated endpoint. More affected endpoints = higher severity.

### Part B — Log injection (CRLF / control-character forging)

9. **Locate the log write path.** Search source (or infer from behavior) for request fields echoed into logs: `note`, `comment`, `reason`, `message`, filenames, headers. #3621606's root cause is "logs untrusted request content before semantic validation" — note the ordering; that is the bug, not merely the presence of logging.

10. **Choose a marker and injection form.** Use a unique `ATTACKER_MARKER_BEGIN` / `_END` pair. Try `\n`, `\r\n`, URL-encoded `%0A` / `%0D%0A`, JSON `\u000a`, and raw control bytes. Match the encoding to the sink (URL param, JSON field, ZMQ string). A unique marker avoids confusing your line with the target's own noise.

11. **Send the request.** For #3621606-style targets: `python poc_zmq_log_injection.py --target 127.0.0.1:18082` against a reachable ZMQ endpoint with request tracing enabled. Confirm at the transport level that the request was accepted before inspecting logs.

12. **Read the log.** Confirm the marker appears on a *new line* with attacker-chosen prefix (e.g., a fake `INFO admin login success`). Confirm the text persists — #3621606 is titled "Untrusted Payload Persistence," meaning the forged text is stored, not just transiently echoed. Repeat twice to prove persistence.

13. **Escalate the sink.** If the log is displayed in a UI or exported, test for stored XSS (`<img src=x onerror=...>`), CSV injection (`=cmd|...`), or ANSI escape abuse. A log line that reaches a renderer is a second vulnerability class sitting on top of the first.

14. **Check validation ordering.** Determine whether validation exists at all and whether it happens before or after the log call. "Log before validate" is the specific defect in #3621606 (introduced in commit `77986023c3`). If validation happens first but misses your encoding, the root cause is incomplete sanitization instead — describe it accurately.

15. **Document end-to-end.** Capture: the crafted request, the raw log excerpt showing the forged line, the viewer / export rendering if applicable, and a clean before / after. Tie it to a concrete harm (framing a user, hiding an action, breaking an alert).

16. **Generalize.** Test sibling fields and sibling daemons. A raw-logging helper introduced by one commit is often copied elsewhere; #3621606's commit-level attribution is a strong hint that the same pattern may exist in other handlers.

### Part C — Proving the detection-bypass claim

17. **Identify the specific detection.** Quote the documented rule, dashboard, or alert that depends on the log. "Insufficient logging" alone is weak; "this named control no longer sees the action" is the finding.

18. **Run the benign control case.** With logging intact, execute the action and show the alert firing (or the event appearing). This proves the detection works when the log is trustworthy.

19. **Run the bypass case.** Repeat the identical action through the unlogged / attribution-masked / forged-log path. Show that the same action now produces no alert — or produces a misleading one.

20. **Rule out alternate correlation.** Check whether the control correlates on another signal (VPC Flow Logs, CloudTrail `eventSource` in a different trail, EDR telemetry). If it does, the bypass is incomplete — say so, and look for a path that evades that signal too.

21. **Capture the delta.** A side-by-side of the two cases (control fires vs. control silent) is the most persuasive artifact in the entire report.

22. **State the residual risk.** Even if some independent telemetry exists, quantify what is lost: attribution, per-principal audit trail, alert fidelity, or compliance evidence.

---

## Payload & Detection Patterns

### Log-injection payloads (CRLF / control chars)
```bash
# Basic newline forging in a free-text field
curl -s 'https://target/api/note?note=ATTACKER_MARKER_BEGIN%0aFAKE_ADMIN_LOGIN_SUCCESS'

# CRLF variant
curl -s 'https://target/api/comment' \
  -d 'comment=%0d%0a2026-01-01 INFO user=admin action=DELETE_ALL'

# JSON field (matches #3621606 shape)
python3 - <<'EOF'
import zmq
ctx = zmq.Context()
s = ctx.socket(zmq.REQ)
s.connect("tcp://127.0.0.1:18082")   # #3621606 ZMQ RPC endpoint
payload = ('{"jsonrpc":"2.0","id":1,"method":"get_info",'
           '"params":{"note":"ATTACKER_MARKER_BEGIN\\n'
           '2026-01-01 INFO root authenticated from 1.2.3.4\\n"}}')
s.send_string(payload)
print(s.recv_string())
EOF

# Unicode/JSON-escaped newlines (bypass naive \n filters)
{"note":"line1\u000aline2"}
{"note":"line1\u2028line2"}
{"note":"line1\u2029line2"}
```

### Terminal / renderer escalation payloads
```
# ANSI escape (clears screen, red text in terminal viewers)
\x1b[2J\x1b[31mFORGED

# Stored XSS if the log viewer renders HTML
<img src=x onerror=alert(document.domain)>

# CSV injection in log export
=HYPERLINK("http://attacker/","click")

# Key-value log forgery: create plausible fields
"action=login_success user=root src=1.2.3.4\n"
```

### Insufficient-logging flows (AWS CLI)
```bash
# 1. Baseline — event SHOULD appear with real userAgent/sourceIP
aws cloudwatch describe-alarms
# wait 5-10 min; confirm event in CloudTrail

# 2. Non-production endpoint bypass — event is absent (#3418966 pattern)
export AWS_PROFILE=stolen-creds
aws aiops list-operations --endpoint-url https://<non-prod-endpoint>

# 3. Admin-vs-noperm differential (#3014785)
export AWS_PROFILE=admin
aws datazone list-domains --endpoint-url <suspect-endpoint>
#   -> "AccessDeniedException: Invalid endpoint or operation type"
export AWS_PROFILE=noperm
aws datazone list-domains --endpoint-url <suspect-endpoint>
#   -> "User: arn:aws:sts::...:assumed-role/noperm is not authorized to perform: datazone:ListDomains"

# 4. FIPS "AWS Internal" attribution masking (#3072841/#2979238/#3044471)
aws pinpoint-sms-voice-v2 describe-pools --endpoint-url <fips-endpoint>
aws comprehendmedical list-phi-detection-jobs --endpoint-url <fips-endpoint>
aws kendra-ranking list-rescore-executions --endpoint-url <fips-endpoint>
aws autoscaling describe-auto-scaling-groups --endpoint-url <specific-endpoint>
# inspect CloudTrail: userAgent == "AWS Internal", sourceIPAddress == "AWS Internal"

# 5. Silent permission-enumeration loop against an unlogged endpoint
for action in list-domains list-projects list-profiles describe-accounts; do
  aws datazone "$action" --endpoint-url <suspect-endpoint> 2>&1 | head -1
done
# map allowed vs denied with zero CloudTrail events
```

### Detection / verification queries
```sql
-- CloudTrail: find events with masked attribution
SELECT eventtime, eventname, useridentity.arn, useragent, sourceipaddress
FROM cloudtrail_logs
WHERE useragent = 'AWS Internal' OR sourceipaddress = 'AWS Internal'

-- CloudTrail: prove absence of events for an action on a principal
SELECT count(*) FROM cloudtrail_logs
WHERE useridentity.arn = 'arn:aws:sts::...:assumed-role/noperm/...'
  AND eventname IN ('ListDomains','ListGraphSnapshots')
  AND eventtime >= '<test-window>'
-- expected >=1; observed 0 => silent enumeration
```

```yaml
# Sigma-style rule that a log-forging payload would defeat / poison
title: Suspicious Newline In Request Field
logsource: { product: monero, service: zmq_rpc }
detection:
  selection:
    request_body|contains: '\n'
  condition: selection
# A forged 'ATTACKER_MARKER_BEGIN\n...' both triggers noise and can
# inject a fake 'authentication success' line that buries the real alert.
```

```bash
# Raw-log confirmation after injection
grep -n "ATTACKER_MARKER_BEGIN" /var/log/monerod.log
# Expect the marker on its own line if forging succeeded
```

### CloudTrail evidence collection (boto3 / jq)
```python
# Prove absence of events for a specific principal + action window
import boto3, datetime
ct = boto3.client('cloudtrail', region_name='us-east-1')
now = datetime.datetime.now(datetime.timezone.utc)
resp = ct.lookup_events(
    LookupAttributes=[
        {'AttributeKey': 'EventName', 'AttributeValue': 'ListDomains'},
    ],
    StartTime=now - datetime.timedelta(minutes=30),
    EndTime=now,
    MaxResults=50,
)
events = resp.get('Events', [])
print('event count:', len(events))
for e in events:
    print(e['EventTime'], e.get('Username'), e.get('Eventsource'), e['EventName'])
# Count of 0 after the propagation window = silent-enumeration evidence.
```

```bash
# Inspect the two attribution fields called out in #3419587 / #3072841
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribePools \
  --query 'Events[].{time:EventTime,user:Username,cloudtrail:CloudTrailEvent}' \
  --output json | jq -r '.[].cloudtrail | fromjson |
    {eventSource, eventName, userAgent, sourceIPAddress}'
# Look for userAgent == "AWS Internal" on FIPS endpoints.
```

Note: `lookup_events` is regional and has a propagation delay. Query every region the endpoint could be in, and re-query after the 5–10 minute window (#3419587) before asserting absence.

### Source-code grep patterns
```bash
# Find unescaped request data written to logs (the #3621606 shape)
grep -rniE "(log|logger|LOG|print|trace|spdlog|BOOST_LOG).*(req|request|params|body|input|note|comment)" src/
grep -rniE "(std::cout|fprintf|syslog|write_log).*\.c_str\(\)" src/

# Find log-before-validate ordering
grep -rn "raw request logging\|log.*before.*valid\|request logging" \
  --include="*.cpp" --include="*.go" --include="*.py"

# Find endpoint overrides / alternate hosts in SDK config
grep -rniE "endpoint[-_]?url|fips\.[a-z0-9-]+|non[-_]?prod|beta|staging" \
  --include="*.json" --include="*.py" --include="*.md" .
```

### Git-history pivot (as used in #3621606)
```bash
# The reporter attributed the bug to a specific commit
git log --oneline -- src/rpc/daemon_handler.cpp | head
git show 77986023c3 --stat     # "json serialization for rpc-relevant monero types"
```
Citing the introducing commit turns a "we found a bug" into a precise, reproducible root-cause statement — exactly what #3621606 did.

---

## Common Root Causes

1. **Log written before semantic validation.** #3621606's exact defect. Untrusted request content reaches the log sink first; validation (if any) happens later, so the forged text is already persisted. Fix: move the log call after validation, or log the *validated* representation.

2. **No escaping of control characters.** Newline, CR, ANSI, and Unicode line separators are concatenated raw into line-oriented or structured logs (CWE-117). C/C++ string handling (`std::string` + `.c_str()`) is a common source; the fix is contextual escaping at the log boundary, not input filtering alone.

3. **Audit logging wired only to the default endpoint.** Alternate, staging, beta, or newly-created endpoints (#3014785) are reachable and authenticated but sit outside the CloudTrail control plane. The endpoint owner assumed "logging happens upstream."

4. **Attribution fields derived from the endpoint, not the caller.** FIPS / special endpoints hard-code `AWS Internal` into `userAgent` / `sourceIPAddress` (#3072841, #2979238, #3044471), destroying accountability while still emitting an event. The event's existence masks its uselessness.

5. **New endpoints onboarded before logging controls.** CT-observed hosts created within 24 hours were already vulnerable in #3014785; the deployment pipeline provisions compute before it wires observability. This is an orchestration-order defect, not a code defect.

6. **Assuming transport variant changes attribution.** The FIPS reports show the mistaken belief that a FIPS endpoint is "internal infrastructure" and need not carry caller identity. Encryption and attribution are orthogonal.

7. **Detection designed on the assumption logs are trustworthy.** Any SIEM rule, WAF alert, or anomaly detector that treats the log as ground truth is bypassable when the event is omitted or forged. Detections need independent corroboration.

8. **Free-text fields trusted as data.** `note`, `comment`, `reason`, `description` are treated as inert strings even though they are rendered in log viewers and exports. The #3621606 payload abused exactly a `note` field.

9. **Helper functions introduced by one commit reused widely.** `77986023c3` added raw request logging in one file; the same helper pattern is often copied across handlers, multiplying the injection surface.

10. **Audit scope defined by hostname, not by effect.** When "what gets logged" is decided by which host answered, any new host automatically inherits a logging blind spot. #3014785's CT-discovered endpoints are the direct consequence.

11. **No negative testing of logging controls.** Teams verify that logs are produced for happy-path calls, never that they are produced for the *same* call routed through every alternate endpoint. The FIPS reports (#2979238, #3044471) survived because only the default endpoint was tested.

12. **Confusing "an event exists" with "an event is useful."** A CloudTrail record whose `userAgent` and `sourceIPAddress` are both `AWS Internal` passes a naive "is logging enabled?" check while being forensically worthless — the core insight of four reports in this pack.

---

## Bypass Techniques

### Log-injection encoding bypasses
- **Newline variants:** `\n`, `\r\n`, lone `\r`, `%0A`, `%0D%0A`, `&#10;`, `\u000a` via JSON, U+2028 / U+2029 line separators. Try each against the same field; allowlists commonly cover only `\n`.
- **Control-character smuggling:** `\x00` (null truncation), `\x08` (backspace to overwrite preceding text), `\x1b` (ANSI), `\x7f` (DEL).
- **Filter sees one thing, sink sees another:** double-encode (`%250A`) when a WAF decodes once and the app decodes again; put the newline in a JSON string that the logger serializes verbatim; use a multipart filename where the log records the raw header.
- **Validation-order bypass:** if validation strips `\n` from the *displayed* field but the logger records the *raw* bytes, inject into a secondary field the validator ignores (metadata, headers, JSON keys).
- **Log-parser forgery:** in key-value logs inject ` fakekey=fakevalue\n` to create plausible fields; in JSON lines inject `","user":"admin","action":"login_success","x":"` to rewrite the record.
- **Length-truncation bypass:** if escaping happens after truncation, or truncation cuts off an escape sequence, craft a payload whose useful part survives the cut.

### Log-based-detection bypasses
- **Omission:** route the action through an endpoint that never emits an event (the entire non-production corpus). No event = no alert.
- **Attribution poisoning:** use a FIPS / special endpoint so the event records `AWS Internal`, defeating rules keyed on `userAgent` or `sourceIPAddress` (#3419587 et al.).
- **Log flooding:** inject thousands of forged lines so the genuine alert is buried — the "persistence of attacker-controlled text" in #3621606 supplies the primitive.
- **Framing:** forge a log line attributing the real action to another principal, so responders chase the wrong identity.
- **Time-window abuse:** exploit the 5–10 minute log-propagation delay (#3419587 reproduction) to act before alerting matures.
- **CT-driven endpoint churn:** target endpoints created within 24 hours (#3014785), before detection rules or log pipelines are updated to cover them.

### Differential / scoping tricks
- Compare default vs FIPS endpoints of the *same* service to isolate the attribution bug (the method behind #2979238 / #3044471).
- Use admin vs `noperm` profiles to prove a silent endpoint is live and actionable (#3014785).
- Cross-reference sibling services: once one service is confirmed vulnerable, test the same endpoint class elsewhere — #3419587 lists three prior services, and #3014785 is explicitly "Part 2" of an earlier report.

### Evasion of time-based and behavioral detections
- **Propagation-window racing:** exploit the 5–10 minute CloudTrail delay documented in #3419587. A short burst of actions completed inside the window may land before an alerting pipeline polls.
- **Low-and-slow enumeration:** spread `List*` / `Describe*` probes across many unlogged endpoints so no single trail crosses a threshold.
- **Field-shape mimicry:** after forging a line, copy the target's exact timestamp format, severity label, and key order so the forged record passes a parser's schema check. #3621606's `ATTACKER_MARKER_BEGIN` PoC demonstrates that arbitrary text is accepted verbatim.
- **Dual-path laundering:** perform the sensitive action on an unlogged endpoint, then write a benign-looking record of an unrelated action through the injectable sink — the timeline appears complete while hiding the real event.
- **Principal confusion:** combine masked `userAgent` / `sourceIPAddress` with forged in-app log lines that name a different principal, so the two data sources disagree and responders cannot reconstruct the chain.

### Defensive takeaway (why triage accepts these)
Each bypass maps to a missing invariant: **every** endpoint emits **complete** attribution, and **every** log line is **immutable by untrusted input**. When either invariant is violated, the detection built on top of it is unsound. Frame the report in terms of the broken invariant, not just the odd-looking log.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - For insufficient logging: show a real action executed against an unlogged endpoint AND prove the expected CloudTrail event is absent (query by ARN / action / time window, after the propagation wait). Or show an event whose `userAgent` / `sourceIPAddress` is `AWS Internal` where a normal endpoint logs them correctly.
   - For log injection: show the crafted request AND the resulting forged line in the actual log, with a unique marker. A marker that only echoes in the HTTP response but never reaches the log is *not* log injection.
   - A "we think logging might be incomplete" claim is insufficient — demonstrate the concrete gap with evidence.

2. **What does the victim LOSE?**
   - Ability to silently enumerate IAM permissions from stolen credentials → attacker maps the account with zero forensic trace (#3418966 class).
   - Ability to act without attribution → incident response cannot identify source IP or user agent (#3419587 class).
   - Ability to forge / persist log entries → frame users, hide actions, poison or flood detection (#3621606 class).
   - Quantify: which detection rules or compliance obligations (audit retention, PCI, SOC 2) does this defeat?

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the endpoint reachable with ordinary credentials and does the log query return the same absence / corruption?
   - Does the injection marker reliably appear as a new line in the log (not intermittently)?
   - Remember the 5–10 minute CloudTrail propagation window — document the wait; do not call a too-early query "confirmation of absence."
   - For source-level log injection, does the target run with request tracing / logging enabled (#3621606 step 1)? If not, state the precondition explicitly.

| Claim | Minimum acceptable evidence |
|---|---|
| "Endpoint is unlogged" | Successful action + CloudTrail query returning zero events for the right principal/action/window |
| "Attribution is masked" | Side-by-side events: default endpoint has real UA/IP, suspect endpoint says `AWS Internal` |
| "Log injection works" | Crafted request + raw log showing a new, attacker-authored line with unique marker |
| "Detection is bypassed" | Documented rule + proof it did not fire after the bypass action |

### Triage pitfalls to pre-empt

- **"We queried too early."** CloudTrail propagation is 5–10 minutes (#3419587). A zero-event result before that window is not evidence. Re-query and record both timestamps.
- **"Wrong region / wrong trail."** `lookup_events` is regional; an event may be in another region or a different trail. Show which regions you checked.
- **"The value is intentional."** #2979238's reporter explicitly raises this possibility for FIPS endpoints. Bring documentation (or the absence of any) and a same-service baseline to rebut it.
- **"It's just an echo."** A newline appearing in an HTTP error response is not log injection. Show the raw on-disk / SIEM log, not the response body.
- **"Logging is enabled globally."** Global enablement does not imply per-endpoint coverage. The 19 non-production reports are proof that the two are different questions.
- **"No impact."** Attach the downstream primitive: silent permission enumeration, attribution loss, or forged-record misdirection. Impact is the attack you can now run, not the config oddity itself.

**Do NOT report when:** the "missing" log is actually emitted to a different trail / region / lag window you did not query; the `AWS Internal` value is documented / intentional for that endpoint class; or the newline only appears in an error echo, not in the stored log. #2979238's reporter explicitly flags the intentional-decision caveat — pre-empt it with evidence rather than letting triage raise it.

---

## Real Impact Examples

### Scenario A: Silent permission enumeration from stolen credentials (AWS VDP class)
An attacker obtains a low-privilege IAM credential. Against the default endpoint, every `List*` / `Describe*` call would produce a CloudTrail event — a defender alerting on "credential-testing behavior" would catch them (the tradecraft referenced via Scarleteel 2.0 in #3092085). But the attacker points the AWS CLI at a *non-production* endpoint via `--endpoint-url`. The endpoint executes the same actions and returns the same `AccessDeniedException` / success signals, yet no CloudTrail event is written. The attacker scripts hundreds of permission probes and maps the entire account's IAM surface while leaving no audit trail. Reporter #3014785 showed the endpoint is live and clearly distinct from prod by the admin-vs-noperm error divergence, and #3068422 found an endpoint granting only `neptune-graph:ListGraphSnapshots` — a narrowly-scoped, easy-to-miss audit hole.

### Scenario B: Attribution evasion via "AWS Internal" endpoints (FIPS class)
A defender has a detection rule: alert on `userAgent` values associated with offensive tooling, or on source IPs outside the corporate range. The attacker calls the affected service through a FIPS endpoint (#3072841 Pinpoint, #2979238 Comprehend Medical, #3044471 Kendra) or a specific endpoint (#3419587 Auto Scaling, 6 endpoints). The action is logged, but `userAgent` and `sourceIPAddress` both read `AWS Internal`. The event exists yet carries no caller identity, so the detection never fires and the responder cannot attribute the action. The baseline comparison — default endpoint logs a real IP and UA, FIPS sibling says "AWS Internal" — is the proof that makes this reportable rather than a documentation dispute.

### Scenario C: Log forging and persistence via ZMQ RPC (Monero #3621606)
A remote party with access to `monerod`'s ZMQ RPC endpoint (`tcp://host:18082`) sends a JSON-RPC request whose `params.note` contains `ATTACKER_MARKER_BEGIN\n2026-01-01 INFO root authenticated from 1.2.3.4\n`. Because commit `77986023c3` added raw request logging in `src/rpc/daemon_handler.cpp` *before semantic validation*, the daemon writes the attacker's string verbatim into its log — creating a new line that looks like a legitimate authentication event and persisting it. The forged entry can bury a real alert, frame an administrator, or serve as a stored payload if the log is later rendered in a viewer. The fix requires escaping control characters and moving the log call after validation.

### Scenario D: Detection poisoning at scale (combined class)
An attacker first uses an unlogged endpoint to enumerate permissions, then — through a separate log-injection sink in the target's own admin tooling — injects a burst of forged "successful login" lines under a legitimate service account. Responders reviewing the SIEM see a noisy but benign-looking timeline and no CloudTrail events for the enumeration, so the intrusion is both invisible in the audit trail and misdirected in the application log. This is why the two halves of this skill belong together: silent action + poisoned record = effective detection bypass.

### Impact quantification checklist

Use these questions to convert a logging gap into a severity argument:

- **Which actions are affected?** A single read verb vs. a full `List*` / `Describe*` family changes the scale of silent enumeration (#3068422's single-action endpoint is the narrow case).
- **How many endpoints / services?** #3419587 found 6, #3072841 found 5, #2979238 found 8, #3044471 found 4 — counts make a systemic pattern undeniable.
- **Who loses attribution?** Named `userAgent` and source IP replaced by `AWS Internal` means incident responders cannot identify the caller.
- **Is the forged text persistent?** #3621606's "persistence" wording is the difference between a transient echo and a durable forensic artifact.
- **Does a control depend on the log?** If yes, name it. If no, the finding is an audit weakness rather than a detection bypass.
- **What is the blast radius of the enabled attack?** Silent permission enumeration → full IAM map; forged admin line → framed principal; log flood → blinded alerting.

---

## Disclosed Report Citations

All 24 reports below are real, verified disclosures from the study pack. No IDs or URLs are invented.

1. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the AI Ops Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3418966](https://hackerone.com/reports/3418966)) — Insufficient Logging, non-production endpoint CloudTrail bypass / silent permission enumeration, 2026 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, sso-oauth, redirect-handling, xml-parser, cache-layer, admin-internal, filter-bypass.

2. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the ssm Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2926361](https://hackerone.com/reports/2926361)) — Insufficient Logging, non-production endpoint CloudTrail bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cloud-metadata, filter-bypass.

3. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Neptune Graph Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3068422](https://hackerone.com/reports/3068422)) — Insufficient Logging, non-production endpoint bypass (also `neptune-graph:ListGraphSnapshots`), 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

4. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Route 53 Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3092085](https://hackerone.com/reports/3092085)) — Insufficient Logging, non-production endpoint bypass (cites Scarleteel 2.0 / Datadog Security Labs), 2025 / bounty undisclosed. Techniques: public-code-search, search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

5. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the bedrock Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2951803](https://hackerone.com/reports/2951803)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: import-feature, search-filter-sort, api-endpoint, xml-parser, filter-bypass.

6. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Global Accelerator Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3029552](https://hackerone.com/reports/3029552)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

7. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Health Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3042588](https://hackerone.com/reports/3042588)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

8. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Datazone Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2981210](https://hackerone.com/reports/2981210)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, filter-bypass.

9. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the bedrock-agent Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2800091](https://hackerone.com/reports/2800091)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, filter-bypass.

10. **Amazon Web Services (AWS VDP) — Non-Production API Endpoint for the EventBridge Service Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3021618](https://hackerone.com/reports/3021618)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

11. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the DocumentDB Elastic Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3009411](https://hackerone.com/reports/3009411)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, filter-bypass.

12. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Glue Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3031512](https://hackerone.com/reports/3031512)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

13. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Forecast Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3022516](https://hackerone.com/reports/3022516)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

14. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the cloudwatch Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2972435](https://hackerone.com/reports/2972435)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, filter-bypass.

15. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Device Farm Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #2999116](https://hackerone.com/reports/2999116)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, filter-bypass.

16. **Amazon Web Services (AWS VDP) — Non-Production API Endpoint for the ElastiCache Service Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3021451](https://hackerone.com/reports/3021451)) — Insufficient Logging, non-production endpoint bypass, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, xml-parser, cache-layer, filter-bypass.

17. **Amazon Web Services (AWS VDP) — (Part 2) Non-Production API Endpoints for the Datazone Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3014785](https://hackerone.com/reports/3014785)) — Insufficient Logging, CT-discovered new non-production endpoints; admin-vs-noperm differential, 2025 / bounty undisclosed. Techniques: export-feature, search-filter-sort, api-endpoint, admin-internal, comment-injection.

18. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Amazon S3 Tables Service Fail to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3780277](https://hackerone.com/reports/3780277)) — Insufficient Logging, non-production endpoint bypass, 2026 / bounty undisclosed. Techniques: public-code-search, search-filter-sort, api-endpoint, sso-oauth, redirect-handling, xml-parser, admin-internal, filter-bypass, comment-injection.

19. **Amazon Web Services (AWS VDP) — Non-Production API Endpoints for the Amazon Cloudwatch Fails to Log to CloudTrail Resulting in Silent Permission Enumeration** ([H1 #3775702](https://hackerone.com/reports/3775702)) — Insufficient Logging, non-production endpoint bypass, 2026 / bounty undisclosed. Techniques: public-code-search, search-filter-sort, api-endpoint, sso-oauth, redirect-handling, xml-parser, cache-layer, admin-internal, filter-bypass, comment-injection.

20. **Monero — ZMQ RPC Log Injection and Untrusted Payload Persistence** ([H1 #3621606](https://hackerone.com/reports/3621606)) — CRLF / Log Injection, raw request logging before semantic validation; introduced in commit `77986023c3` (`src/rpc/daemon_handler.cpp`), 2026 / bounty undisclosed. Techniques: import-feature, image-processing, search-filter-sort, api-endpoint, debug-error-leak, admin-internal, cloud-metadata, internal-network, request-smuggling, dependency-confusion.

21. **Amazon Web Services (AWS VDP) — AWS Auto Scaling Service Reporting "AWS Internal" for CloudTrail Events Generated from Specific Endpoints** ([H1 #3419587](https://hackerone.com/reports/3419587)) — Insufficient Logging, false `userAgent` / `sourceIPAddress` attribution on 6 endpoints, 2026 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, filter-bypass.

22. **Amazon Web Services (AWS VDP) — Amazon Pinpoint SMS and Voice, version 2 Service Reporting "AWS Internal" for CloudTrail Events Generated from FIPS Endpoints** ([H1 #3072841](https://hackerone.com/reports/3072841)) — Insufficient Logging, attribution masking on 5 FIPS endpoints, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, filter-bypass.

23. **Amazon Web Services (AWS VDP) — Amazon Comprehend Medical Service Reporting "AWS Internal" for CloudTrail Events Generated from FIPS Endpoints** ([H1 #2979238](https://hackerone.com/reports/2979238)) — Insufficient Logging, attribution masking on 8 FIPS endpoints, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, filter-bypass.

24. **Amazon Web Services (AWS VDP) — Amazon Kendra Intelligent Ranking Service Reporting "AWS Internal" for CloudTrail Events Generated from FIPS Endpoints** ([H1 #3044471](https://hackerone.com/reports/3044471)) — Insufficient Logging, attribution masking on 4 FIPS endpoints, 2025 / bounty undisclosed. Techniques: search-filter-sort, api-endpoint, filter-bypass.

---

## Related Skills & Chains

- **`hunt-iam` / `cloud-iam-deep`** — the payload of silent permission enumeration is an IAM map. Chain primitive: unlogged endpoint → scripted `List*` / `Describe*` → full principal/permission graph with no CloudTrail trace.
- **`hunt-api`** — every alternate endpoint is an API surface; combine endpoint discovery with the logging-gap check before scoring severity.
- **`hunt-xss`** — a forged log line that reaches an HTML log viewer becomes stored XSS. Chain primitive: log injection → log-viewer render → session theft.
- **`hunt-command-injection` / `hunt-rce`** — control characters in logs can corrupt SIEM parsers or shell-based log processors; treat terminal-escape injection as a foothold for deeper attacks.
- **`hunt-info-disclosure`** — a log viewer or exported log file is a data source; injection can also be used to exfiltrate other users' log lines.
- **`triage-validation`** — adapt the "OOB-or-it-didn't-happen" discipline: a logging claim needs positive evidence (absence of event proven by a correctly-scoped CloudTrail query; forged line proven in the raw log), not an assumed gap.
- **`hunt-ssrf`** — both classes share an evasion theme: SSRF hides the *network* origin; logging bypass hides the *attribution*. Chain them when an SSRF lands on an internal endpoint whose logging is also weak.


---

## Merged Source Knowledge

This section consolidates **3 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (3 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-13-program-management/fv-anc-13-cl4-log-truncation-hiding-critical-security-events.md`

## TLDR

Solana transactions are limited in total compute units per transaction. When a program emits extensive logs near the compute limit, the Solana runtime truncates log output silently. Security-critical events emitted near or after the compute budget is exhausted will not appear in the transaction logs, making off-chain monitoring systems blind to them. An attacker can intentionally exhaust compute budget before a security event to prevent its detection.

## Detection Heuristics

**Security Events Emitted Late in Instruction**
- Critical `msg!` or `emit!` calls (failed access checks, unusual amounts, emergency flags) placed near the end of an instruction after expensive computation that consumes most of the compute budget
- Log emission order not reviewed against compute budget consumption; a long iteration loop before a security event log may truncate the event

**No Compute Budget Reservation for Logging**
- Program does not reserve a compute budget margin (e.g., `request_heap_frame` or early return if remaining compute < threshold) to ensure logging calls are not truncated
- Off-chain indexer or monitoring system relies exclusively on transaction logs without checking for log truncation indicators in the transaction metadata

**Event Emission via emit! Macro**
- Anchor `emit!` macro calls placed after large account iteration loops; the macro incurs CPI cost and can be truncated if budget is exhausted
- No fallback mechanism (e.g., storing the event in account state) for critical events that must be observable even under compute pressure

## False Positives

- All security-critical events emitted at the very beginning of the instruction before any expensive computation, ensuring they are never truncated
- Protocol uses account-state-based event recording rather than log emission; events are always readable from account data regardless of compute budget
