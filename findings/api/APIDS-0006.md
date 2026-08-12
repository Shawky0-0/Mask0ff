---
tags: [security, flash, advisories, entry, apids, api, resource-consumption, api4]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-9pgf-384g-p7mv accessed 2026-08-12"
---

# APIDS-0006: Nuxt island endpoint parses and hashes attacker input before it validates it

**The API4 pattern in its clearest published form: work done before the check that would have
refused it.** Related: the API folder,
the ledger,
APIDS-0007.

```yaml
id: APIDS-0006
component:
  type: framework
  ecosystem: npm
  name: nuxt
  version_scope: "the internal island renderer endpoint"
affected:
  introduced: "3.1.0 for the 3.x line, 4.0.0 for the 4.x line"
  fixed_in: "4.5.1 and 3.21.10"
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: "4.0.0 to < 4.5.1, and 3.1.0 to < 3.21.10"
identifiers:
  cve: CVE-2026-71321
  ghsa: GHSA-9pgf-384g-p7mv
  osv: ___
  vendor_id: ___
class:
  owasp_api: "API4:2023 unrestricted resource consumption"
  owasp_2025: "___ , no clean mapping. The 2021 web list called this A04 insecure design at best."
  cwe: "CWE-407 inefficient algorithmic complexity, and CWE-770 allocation of resources without limits or throttling"
  family: expensive work performed before the cheap check that would have rejected it
protocol: rest
auth_required: none
entry_point:
  route: "/__nuxt_island/<name>_<anything>.json"
  method: POST
  parameter: "the JSON request body"
  header: n/a
object_graph:
  which_request_creates_the_object: >
    Not an ownership bug, so the graph is thin by nature. Recorded anyway because the absence
    is itself informative: there is no object and no owner, which is exactly why authorisation
    testing never finds this class.
  who_owns_it: n/a
  who_should_reach_it: >
    The island endpoint is internal to the framework's rendering, so arguably no external
    caller at all. It was reachable unauthenticated.
  what_the_tested_account_got: >
    An anonymous caller got the server to fully parse and hash a roughly 4.6 MB body with about
    150k keys, and only then received a 400 rejection.
root_cause:
  where: "the internal island renderer endpoint"
  the_missing_decision: >
    The endpoint decodes and hashes attacker controlled request input before it validates the
    hash carried in the URL. The validation exists and it works; it simply runs second. So the
    server performs the whole expensive operation on input it is about to refuse. Under Nitro's
    single event loop, that CPU time delays every other concurrent request, which is how one
    request's waste becomes everyone's latency. The missing decision is ordering: cheap
    rejection first, expensive work second.
signal: >
  The signal is a rejection that costs more than an acceptance should. In testing: a request
  that is refused, but slowly, and whose refusal time scales with the size or nesting of the
  body you sent. That scaling is the whole tell. In review, the signal is any handler where
  body parsing, decoding, decompression, hashing or signature computation appears above the
  authorisation or validation check in the same function.
safe_proof: >
  Read only in this sweep, and this class needs unusual care because the safe proof and the
  attack are the same action at different volumes. In a disposable lab, and never against
  anything shared: send a small body and a moderately larger one, both invalid, and compare
  rejection latency. If refusal time grows with input size, the ordering is wrong. Two requests
  are enough. Do not scale up to demonstrate impact; the scaling relationship is the finding.
controls:
  negative: >
    Send the same two sizes to an endpoint known to validate first. If refusal time is flat
    there and scaling here, the difference is real and not just network variance.
  differential: >
    Repeat on 4.5.1 or 3.21.10, where oversized input should be refused with 413 and deeply
    nested input with 400, both cheaply.
  false_positive: >
    Latency measurement is noisy and it is very easy to convince yourself of a trend that is
    not there. Repeat each size several times, compare medians not single samples, and confirm
    the difference is far larger than the run to run spread. Also rule out the network: a
    larger body takes longer to upload regardless, so measure from the end of the upload, or
    compare bodies of the same byte size with different nesting depth.
fix:
  commit_url: "https://github.com/nuxt/nuxt/commit/4e35ae9 and https://github.com/nuxt/nuxt/commit/668cdfd"
  invariant: >
    Per the advisory, the patch enforces constraints "before parsing or hashing, so oversized
    or deeply nested input is rejected cheaply": a raw body size cap returning 413, and a JSON
    nesting depth limit returning 400.
hardening: >
  The class killer is a rule about ordering, not a limit value: every check that can reject a
  request must run before any work whose cost the caller controls. Body size caps and depth
  limits are the mechanism, but the invariant is the ordering. Enforcing size limits at the
  gateway or web server, above the application, is the operational version of the same idea.
detection: >
  Repeated large or deeply nested bodies to internal or undocumented routes, answered with 400.
  A rising ratio of rejected requests to CPU time is the metric that actually catches this
  class, and almost nobody graphs it.
variant_rule: >
  Everywhere expensive work precedes a check. Webhook handlers that parse JSON before verifying
  the signature are the single most common instance in the wild, and they are directly relevant
  (zip bombs), image decoding before size limits, JWT payload parsing before signature
  verification, and GraphQL query parsing before depth and complexity limits.
lab:
  snapshot: "not required"
  teardown: "delete the install"
provenance:
  source: "GitHub Security Advisory"
  accessed: 2026-08-12
  license_note: "summarised from public advisory"
```

## What happens

Nuxt has an internal endpoint used to render page fragments called islands. The URL carries a
hash, and the endpoint is supposed to check that hash before doing anything with the request.

It checked it second. First it decoded and hashed the body the caller sent, then it compared
the URL hash and returned 400. So an anonymous caller could send a large, deeply nested JSON
body, have the server chew through all of it, and be refused afterwards.

The advisory's figure is a body of about 4.6 MB with roughly 150k keys. Nitro runs a single
event loop, so while the server is working through that, it is not serving anyone else.

## Why it works

The check was never missing. It was in the wrong place.

This is what makes API4 different from the authorisation classes and much harder to find. There
is no object, no owner and no privilege boundary crossed. Nothing in the response is wrong. The
correct answer comes back, and it costs too much. An authorisation matrix will never surface
this, because every cell in it is correct.

The cost asymmetry is the finding: a cheap request for the caller, an expensive one for the
server, with no authentication in between.

## How you would reproduce it

In a lab, and carefully, because at volume this stops being a test and becomes an attack. Send
an invalid request at two different body sizes and compare how long the rejection takes. If the
refusal gets slower as the body grows, work is happening before the check.

Two requests prove the ordering. Nothing is gained by sending more, and sending more against

## What the fix is, and why the obvious fix would not work

The patch adds a raw body size cap returning 413 and a JSON nesting depth limit returning 400,
both enforced before parsing or hashing.

The obvious fix is a rate limit. It is the reflex answer for anything that looks like resource
exhaustion, and here it is close to useless. A rate limit caps how many requests arrive; it does
nothing about the cost of each one. If a single request can occupy the event loop, an attacker
inside the rate limit still wins, and you have paid a latency and complexity tax for nothing.

The second obvious fix is to lower the body size limit globally. That breaks legitimate large
requests elsewhere and still leaves the ordering wrong, so a body that is small but deeply
nested keeps working. The advisory's two limits are size **and** depth for exactly that reason:
those are two independent ways for cheap input to buy expensive work.
