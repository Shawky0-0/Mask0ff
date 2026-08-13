---
tags: [security, flash, advisories, api, entry, api5, api9, batch, parse-server]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-p84r-h6rx-f2xr, accessed 2026-08-13"
---

# APIDS-0020: the allowlist ran on the envelope, and the batch handler opened it afterwards

**The same defect as APIDS-0002, in a completely
unrelated product.** Two independent implementations of batch made the identical mistake, which
promotes this from a bug to a pattern. Related:
MTH-API-002, the batch method,
MTH-API-008, the guard placement method.

```yaml
id: APIDS-0020
component:
  type: framework
  ecosystem: npm
  name: parse-server
  version_scope: ">= 9.8.0, < 9.9.1-alpha.3"
affected:
  introduced: 9.8.0, which is when routeAllowList was added. v8 LTS is unaffected because the
    option does not exist there
  fixed_in: 9.9.1-alpha.3
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-50008
  ghsa: GHSA-p84r-h6rx-f2xr
  osv: ___
  vendor_id: ___
class:
  owasp_api: API5:2023 broken function level authorisation, with API9:2023 improper inventory
    management as secondary, since the point of routeAllowList is to shrink the exposed surface
  owasp_2025: ___
  cwe: CWE-863
  family: a guard installed at the wrong layer of the stack
protocol: rest
auth_required: none
entry_point:
  route: POST /batch, where batch itself is in the allowlist
  parameter: the path of each sub request inside the batch body
  mechanism: routeAllowList is "only enforced as Express middleware against the outer HTTP
    request URL, so the /batch handler dispatches each sub-request to the internal router
    without re-running the allow-list check"
object_graph:
  creates_the_object: the administrator writes routeAllowList to restrict which REST routes
    external clients may reach
  owns_it: the deployment
  should_reach_it: external clients may reach only the listed routes
  tested_account_got: any REST route at all, by wrapping it in a batch whose outer path is the
    one allowed path
root_cause: >
  The check is real, correct, and installed in Express middleware, which by construction only
  ever sees the outer request URL. The batch handler then dispatches sub requests straight into
  the internal router, below the middleware layer, so the check is structurally unreachable for
  them. Nothing was forgotten in the sense of a missing line. The guard was mounted at a layer
  the inner requests never pass through.
signal: >
  Ask where a guard is installed, not whether it exists. Middleware sees requests that arrive
  over HTTP. Anything the application dispatches internally, batch, GraphQL resolvers, queued
  jobs, server side includes, webhooks fired by cron, bypasses middleware entirely and by
  design. So: list every way a handler can be invoked, and check the guard covers all of them.
  A guard in middleware protects the front door and nothing behind it.
safe_proof: >
  Lab only. Affected version, routeAllowList configured to permit batch and one harmless class.
  Confirm a direct call to an unlisted route is refused. Then send the identical operation as a
  sub request inside a batch and confirm it is accepted. The proof is the pair. Use a class
  created for the test holding a canary value only, so nothing real is read or written.
controls:
  negative: >
    send a batch containing an operation the ACL or CLP would refuse anyway. It should still be
    refused, because the advisory is explicit that authentication, ACL and CLP remain effective.
    If that also succeeds, the finding is larger than the allowlist bypass and needs re scoping
  differential: >
    the direct call to the same route must be refused in the same session. Without that line
    there is no evidence the route was restricted at all
  attribution: >
    confirm no master key or maintenance key is in play. Both bypass the allowlist legitimately,
    at the outer layer too, so a test run with either proves nothing
fix:
  commit_url: https://github.com/parse-community/parse-server/pull/10482, referenced in the
    advisory, not opened by this sweep
  invariant: >
    Stated by the advisory: the patch "re-enforces routeAllowList checks for each batch
    sub-request inside the batch handler before dispatch, mirroring existing per-sub-request
    rate-limit enforcement patterns". The invariant: a restriction expressed per route must be
    evaluated at every point a route is entered, including internal dispatch, not only where the
    request enters the process.
hardening: >
  Put the check in the router or the handler rather than in transport middleware, so every path
  to the handler crosses it. The advisory's own note is the tell: the rate limiter was already
  enforced per sub request. One control had been moved to the right layer and the other had not,
  in the same file.
detection: >
  Batch requests whose sub request paths do not appear in the allowlist. A gateway or WAF keying
  on the outer URL sees only /batch and cannot help, which is worth stating plainly in any
  report: this bug is invisible to path based edge filtering.
variant_rule: >
  Every batch, bulk, multi, or composite endpoint. Also GraphQL, where one HTTP request carries
  many field resolutions past any per URL control. Read across to APIDS-0002, the WordPress
  REST batch endpoint, which is the same mistake, and to APIDS-0022, where the guard is missing
  on one GraphQL field while the others have it.
  **Ahmed's fleet: the WordPress REST batch endpoint is present on every WordPress site,**
  which is why APIDS-0002 exists. Any edge rule written to block a path is worth testing through
  /wp-json/batch/v1.
lab:
  install: disposable parse-server in the affected range with routeAllowList set
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-p84r-h6rx-f2xr
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by offset, coordinated by mtrezza
```

## What happens

Parse Server has a setting that lists which REST routes outside clients may use. Everything not
on the list is refused.

The refusal happens in middleware, which is code that runs when a request first arrives and
looks at the URL. That works fine for ordinary requests.

Parse Server also has a batch endpoint. You post one request containing a list of operations,
and the server runs each one internally.

The middleware sees the outer URL, `/batch`, which is on the list, and waves it through. The
batch handler then runs each inner operation by calling the router directly. Those inner calls
never travel over HTTP, so they never touch middleware, so the list never applies to them.

Put `/batch` on your allowlist and you have allowed everything.

## Why it works

Nobody wrote a bad check. The check is correct. It is mounted somewhere the inner requests do
not go.

This is worth sitting with, because it is a different kind of bug from a forgotten permission
callback. A forgotten check is found by reading the handler. This one is invisible in the
handler and invisible in the middleware. You only see it by drawing the request's route through
the stack and noticing that one path enters halfway down.

The most damning detail is in the fix note: the rate limiter was **already** applied per sub
request inside that handler. Somebody had solved this exact layering problem for one control
and had not carried it across to the other.

## How you would reproduce it

Lab. Restrict the routes. Show a direct call being refused. Show the same call succeeding inside
a batch. Two lines of evidence, and the first one is what makes the second mean something.

## What the fix is, and why the obvious fix would not work

The advisory offers a workaround, and it is a good illustration of why the obvious fix is wrong.
The workaround is to list every inner route you intend to allow, explicitly. It works, and it
widens your allowlist, which is the opposite of what the allowlist is for.

The real fix moves the check into the batch handler so each sub request is evaluated before
dispatch. Stated generally: a per route rule has to be applied wherever routes are entered.
If your application can enter a route without going over HTTP, then an HTTP layer control is
not a security boundary, it is a convenience.

## Why this one is worth more than its severity score

Moderate, 6.9, and only affects deployments that configured `routeAllowList` at all. Low reach.

The reason it is here is the read across. APIDS-0002
is WordPress core's batch endpoint dispatching sub requests against the wrong handler, and it is
KEV listed and exploited in the wild. Different language, different project, no shared code,
same structural error. **Two independent instances is the evidence that batch dispatch is a
place to look on any product, not a quirk of one codebase.**
