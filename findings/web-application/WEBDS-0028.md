---
tags: [security, flash, advisories, appsec, cache-poisoning, proxy, open-redirect, webds]
updated: 2026-08-16
sources:
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-fjgc-3mj7-8rg8, accessed 2026-08-16"
---

# WEBDS-0028: Etherpad reflects a proxy header into admin pages and forgets to say Vary

```yaml
id: WEBDS-0028
component:
  type: package
  ecosystem: npm
  name: ep_etherpad-lite
  version_scope: "the admin static serving handler, and the timeslider redirect"
affected:
  introduced: "the admin reflection at 2.1.0, from commit 63e9b2d in pull request 6399. The open redirect at 3.0.0, from commit 451bd9c in pull request 7710"
  fixed_in: "3.1.0"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-55087
  ghsa: GHSA-fjgc-3mj7-8rg8
  osv: "___, api.osv.dev returned 404 for this id on 2026-08-16"
  snyk: ___
  vendor_id: "PR 7784, fix commit 8c6104c"
class:
  owasp_2025: "injection, and security misconfiguration"
  owasp_api: n/a
  owasp_llm: n/a
  cwe: "CWE-79 cross site scripting, CWE-601 open redirect, CWE-444 inconsistent interpretation of HTTP requests"
  family: cache poisoning through an unkeyed input
  corpus_directory: 07-protocol-cache-routing/
auth_required: none
entry_point: "the x-proxy-path request header, on GET /admin/index.html and on GET /p/{pad}/timeslider"
root_cause: >
  Two missing decisions, in two files, sharing one input. In
  src/node/hooks/express/admin.ts the value of x-proxy-path is written into the HTML, JS and
  CSS response bodies without sanitisation, and the response carries neither Vary nor
  Cache-Control. In src/node/hooks/express/specialpages.ts the same value is concatenated
  into the Location header of the timeslider redirect with no check that the result is a
  path, so a value beginning with two slashes becomes a protocol relative absolute URL.
  The cache piece is the part that turns a reflected bug into a stored one: the header
  changes the body and is not part of the cache key, so the poisoned copy is served to
  everyone who asks for the same path.
signal: >
  Any header whose name contains proxy, forwarded, host, prefix, base or path. These exist
  because somebody is deploying the app behind a reverse proxy and needed to tell it where
  it lives. That means the value reaches URL building and template output, which is exactly
  the two places you care about. The second signal is a response that varies by a header and
  carries no Vary line. Send the request twice with two different header values and diff the
  bodies; if they differ and Vary is absent, you have an unkeyed input.
safe_proof: >
  Lab instance only, behind a lab cache. Send the request with a marker value in the header,
  something inert like a fixed nonsense string, and confirm the string appears in the body.
  Then request the same URL with no header at all, from a clean client, and see whether the
  marker is still there. The marker coming back without the header is the whole proof, and it
  never needs a script tag. For the redirect, a marker hostname in the Location value is
  enough; never follow it.
controls: >
  Negative control: the same request with the header removed, to establish the clean body.
  Differential control: two different marker values in quick succession, to prove the body
  tracks the header rather than a coincidence. Cache control: confirm your test cache is
  actually caching by checking for an age or hit header, otherwise a marker that persists
  may just be your own connection being reused. False positive to rule out: many reverse
  proxies strip or rewrite this header before it reaches the app, so a negative result at
  the edge does not mean the app is safe. Test the app directly as well as through the edge.
fix:
  commit_url: "https://github.com/ether/etherpad-lite/commit/8c6104c, referenced in the advisory as the fix for pull request 7784. Commit page not opened this run"
  invariant: "___. The advisory names the patch commit and describes the two defects, but does not state what the patch enforces. The diff was not read this run and this is recorded as debt"
hardening: >
  The control that kills the class is refusing to take deployment topology from the request.
  The proxy prefix belongs in configuration on the server, where an attacker has no vote.
  If it must come from a header, terminate it at the edge: the reverse proxy overwrites the
  header on every inbound request so the client's value never reaches the app. Second layer,
  independent of the first: any response whose body depends on a header must send Vary with
  that header name, which at least stops the poisoning even if the reflection survives.
detection: >
  Cache logs showing one URL with several distinct body lengths or ETags. Access logs
  carrying an x-proxy-path header from a client address, rather than from the reverse proxy,
  which should be impossible in a correct deployment. A WAF keyed on script tags catches the
  loud version and misses the quiet one, because the damaging payload here can be a bare
  attribute break rather than a tag.
variant_rule: >
  Every unkeyed input is the same bug. X-Forwarded-Host, X-Forwarded-Scheme,
  X-Forwarded-Proto, X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix, and any vendor
  specific base path header. Then the second family: query parameters the cache ignores in
  its key but the application reads. Ask two questions of every input, always in this order.
  Does the response change when it changes, and is it in the cache key. A yes and a no is a
  finding.
lab:
  install: "ep_etherpad-lite at 3.0.0 in docker, with a caching reverse proxy in front of it inside the same lab network"
  snapshot: "container snapshot before the first poisoned request"
  teardown: "remove both containers and the network. Nothing outside the lab is contacted"
provenance:
  source: "https://github.com/ether/etherpad-lite/security/advisories/GHSA-fjgc-3mj7-8rg8"
  accessed: 2026-08-16
  license_note: >
    The advisory publishes two runnable curl commands as proof of concept. They were read
    and summarised, and neither was executed, in a sandbox or otherwise, per the lane rules.
```

## What happens

Etherpad supports being installed under a sub path, like `example.com/pads/`. To make that
work it accepts a request header, `x-proxy-path`, saying what the prefix is.

Whatever you put in that header gets printed into the admin pages. Nothing is escaped. And the
response has no `Vary` header, so a cache in front of the site stores that response under the
URL alone and serves your version to the next person who asks for it.

The same header also gets glued onto a redirect. Start it with two slashes and the redirect
points at another site entirely.

## Why it works

There are two ideas here and the second one is the one worth learning.

The first is ordinary. A value from the request is printed into a page without escaping. That is
reflected cross site scripting, and on its own it only affects the person who sends the request.

The second is what makes it serious. A cache decides what counts as "the same request". By
default it looks at the URL. It does not look at your headers unless the response tells it to,
using `Vary`. So here you have a response whose body depends on a header, sitting behind a cache
that does not know that. The name for that is an unkeyed input.

Once you poison the cache, you do not have to convince anybody to click anything. They ask for
the normal admin page, by the normal URL, and the cache hands them your version.

That is the whole difference between reflected and stored. Not where the code writes the value,
but whether something in the path stores it.

## How you would reproduce it

Send the request with a harmless marker string in the header and see the marker in the body.
Then ask for the same URL again from a clean client, with no header, and see whether the marker
is still there. If it is, the cache has stored it.

You never need a script tag to prove this. The marker is the evidence.

## What the fix is, and why the obvious fix would not work

The advisory names the fix commit and does not say what it enforces. That is recorded as debt in
`fix.invariant` and in the ledger; the diff was not read this run.

The obvious fix is to escape the header value before printing it. That closes the cross site
scripting and leaves the open redirect, because the redirect is a `Location` header and HTML
escaping does nothing to it. It also leaves the cache confusion: the body still varies by a
header the cache is not keying on, so a future feature that reflects the value somewhere else
reopens the same hole.

The fix that actually kills it is to stop taking deployment topology from the request at all.
The prefix is a property of how the server is installed. The client has no business having an
opinion about it.

Related: WEBDS-0003, Nuxt caching a payload under
a path only key, which is the same unkeyed input idea from the other direction, and
WEBDS-0007, a forwarded header trusted from
anyone. MTH-WEB-002 covers the proxy
disagreement family.
