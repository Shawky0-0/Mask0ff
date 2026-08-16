---
tags: [security, flash, advisories, appsec, business-logic, resource-limits, dos, webds]
updated: 2026-08-16
sources:
  - "https://api.osv.dev/v1/vulns/CVE-2026-53653, accessed 2026-08-16"
  - "https://github.com/advisories?query=sort%3Apublished-desc+ecosystem%3Acomposer, accessed 2026-08-16"
---

# WEBDS-0032: Grav will resize an image to any size you name in the URL

```yaml
id: WEBDS-0032
component:
  type: framework
  ecosystem: composer
  name: getgrav/grav
  version_scope: "the ImageMedium magic actions, reached through Grav::fallbackUrl"
affected:
  introduced: "___, the OSV record gives the affected 1.7 range as 0 through 1.7.52, so the introducing version is not narrowed"
  fixed_in: "1.7.53, and 2.0.0-rc.8 on the 2 branch"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-53653
  ghsa: GHSA-4x9g-vw65-vvf9
  osv: CVE-2026-53653
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "security misconfiguration, and insecure design"
  owasp_api: "API4, unrestricted resource consumption"
  owasp_llm: n/a
  cwe: CWE-770, allocation of resources without limits or throttling
  family: caller controlled work size
  corpus_directory: 08-business-logic-race-operations/
auth_required: none
entry_point: "an image URL carrying derivative query parameters, for example forceResize, handled by Grav::fallbackUrl"
root_cause: >
  The image derivative parameters arrive in the URL query string and are passed to the
  ImageMedium magic actions, which allocate and process an image of the requested dimensions.
  Per the OSV record no dimension limit and no pixel count limit is enforced. The missing
  decision lives at the boundary between parsing the URL and doing the work: the numbers are
  read and used, and nothing between those two steps asks whether the requested amount of
  work is reasonable. Note that a small change in the input produces a very large change in
  the work, because cost grows with width multiplied by height.
signal: >
  A number in a URL that becomes an amount of work rather than an identifier. Image width and
  height, page size and per_page, limit, zoom level, quality, iteration or round counts, PDF
  page ranges, export row counts, and any "generate a thumbnail at" path segment. The
  question to ask of each is not "is it validated" but "what is the largest value that is
  accepted, and what does the server do at that value". A parameter that is only checked for
  being a number is not checked.
safe_proof: >
  Lab instance only, and this one needs care because the safe proof and the damage are the
  same action at different scales. Measure response time and process memory at a normal size,
  then at a modestly larger size, two or three steps up. The canary is the shape of the curve,
  not a crash: if time and memory grow with the pixel count and nothing clamps, the finding is
  proven. Never run the large value. Never run this anywhere but a lab you own.
controls: >
  Negative control: request an obviously invalid dimension such as a negative number or a
  string, to confirm the parameter is being read at all and that your growth curve is not
  coming from something else. Differential control: the same size requested twice, to show
  the second is served from a derivative cache. If it is cached, a single request is cheap to
  repeat but expensive to vary, which changes what an attacker would actually do: they would
  vary the size every time to defeat the cache. Environment control: confirm the PHP memory
  limit and any upstream request timeout, because either can mask the growth and make a real
  finding look bounded.
fix:
  commit_url: >
    https://github.com/getgrav/grav/commit/d9f9f0369a07ae5c96cde700c7949e1237b29cf6 and
    https://github.com/getgrav/grav/commit/f4c0f42eea755cedad6f626b342c88d4cba72174, both
    named in the OSV references. Neither diff was opened this run
  invariant: "___, not read"
hardening: >
  Two limits, not one. A maximum for each dimension, and a maximum for the product, because
  10000 by 10 passes a per dimension check of 10000 and 10 by 10000 does too, while 10000 by
  10000 is a hundred million pixels. Then an allow list of permitted sizes, which is the
  control that actually kills the class: a site has perhaps six thumbnail sizes, and anything
  not on the list is a 400. Rate limiting is a third layer and not a substitute for either.
detection: >
  Long running requests on image paths, memory limit fatals in the PHP error log, and a
  derivative cache directory growing quickly with a wide spread of sizes. The spread is the
  tell: real traffic clusters on a handful of sizes, an attack does not repeat one.
variant_rule: >
  Every place a caller names the size of the work. Image and video transcoding, PDF page
  ranges and rendering DPI, CSV and report exports with a row count, GraphQL query depth and
  page size (which is why this pairs with the API class), regular expressions built from user
  input, archive extraction with a declared uncompressed size, and any pagination parameter
  that is passed to a database without a ceiling. The general form is: the attacker chooses a
  number, the server chooses how much that number costs, and nobody compares the two.
lab:
  install: "getgrav/grav 1.7.52 in docker with a sample image, PHP memory limit left at the distribution default and recorded"
  snapshot: "container snapshot before the first derivative request"
  teardown: "remove the container and its volume"
provenance:
  source: "https://api.osv.dev/v1/vulns/CVE-2026-53653"
  accessed: 2026-08-16
  license_note: >
    OSV record, open data, read only. Note a date disagreement: OSV gives published
    2026-07-10, the GitHub advisory listing gives 2026-08-14. Both are recorded and neither is
    treated as authoritative over the other
```

## What happens

Grav generates resized copies of images on demand. You ask for an image with some size
parameters in the URL and the server makes that version and caches it.

There is no upper limit on the size you may ask for. Ask for something enormous and the server
tries to build it, spending memory and processor time until it runs out or gives up. No login
is needed, so anybody can do it.

## Why it works

A resize is one of the few web operations where a tiny input controls a huge amount of work. The
URL grows by four characters when you change 1000 to 100000. The work grows by a factor of ten
thousand, because the cost follows width times height.

That asymmetry is the whole bug. Everything else about the request looks completely normal: a GET
for an image path with query parameters, which is what image URLs look like.

This is why the class is filed under business logic and operations rather than under injection.
Nothing is injected. Every value is a valid number in a parameter that is meant to hold numbers.
The application does precisely what it was asked. The defect is that nobody wrote down what a
reasonable request looks like.

## How you would reproduce it

In a lab, measure the time and memory for a normal size, then for a size two or three steps
larger. If the curve keeps climbing and nothing clamps it, that is the finding.

You do not need to run the huge value, and you should not. A demonstration that takes the server
down is not a better demonstration, it is the same finding plus an outage.

## What the fix is, and why the obvious fix would not work

Two commits are named in the OSV references and neither was opened this run, so the invariant is
`___` and it is on the debt list.

The obvious fix is a maximum width and a maximum height. That is not enough on its own, and the
reason is worth remembering: a check of 10000 per side still allows 10000 by 10000, which is a
hundred million pixels. You need the limit on the product, not only on each factor.

The second obvious fix is rate limiting, and it is weaker than it looks here. One request can be
expensive enough to matter, and the attacker can vary the size every time so the derivative
cache never helps the server. Rate limiting reduces the volume; it does not reduce the cost of
one request.

What actually ends the class is an allow list. A site uses a small fixed set of image sizes.
Anything else is a 400. That turns an open ended parameter into a closed one, and closed
parameters cannot be abused by size.

Related: WEBDS-0020, the other business logic and
operations entry, and WEBDS-0022, where a small
input change also moved a routine onto an expensive path.
