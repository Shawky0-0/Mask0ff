---
tags: [security, flash, advisories, api, entry, api4, rate-limit, strapi, fix-commit-read]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-7mqx-wwh4-f9fw, accessed 2026-08-13"
  - "https://github.com/strapi/strapi/commit/5e0d243cba9830e6f791de6a94798bcde51468db, accessed 2026-08-13"
---

# APIDS-0018: Strapi built the rate limit key out of a field the attacker fills in

**The fix commit was read directly for this entry**, so the invariant below is the patch's own
and not an inference. Related: APIDS-0017, the
same class keyed on an address instead of a field,
MTH-API-007, the method.

```yaml
id: APIDS-0018
component:
  type: library
  ecosystem: npm
  name: "@strapi/plugin-users-permissions"
  version_scope: "<= 5.44.0"
affected:
  introduced: ___
  fixed_in: 5.45.0
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2025-64526
  ghsa: GHSA-7mqx-wwh4-f9fw
  osv: ___
  vendor_id: ___
class:
  owasp_api: API4:2023 unrestricted resource consumption
  owasp_2025: ___
  cwe: CWE-307
  family: the rate limit key is chosen by the caller
protocol: rest
auth_required: none
entry_point:
  routes: /auth/local, /auth/reset-password, /auth/change-password
  parameter: the email field in the request body, which is not part of the schema these three
    routes actually use
  function: the users-permissions rate limit middleware, which built its key as
    "${userIdentifier}:${requestPath}:${ctx.request.ip}" with userIdentifier taken from
    ctx.request.body.email
object_graph:
  creates_the_object: the rate limit counter, created per key
  owns_it: nominally the caller
  should_reach_it: every attempt by that caller against that route
  tested_account_got: a fresh counter per request, by writing a new email value each time into
    a field the route does not otherwise read
root_cause: >
  The middleware always pulled email out of the request body to build the key, without asking
  whether the route in question uses email at all. On these three routes it does not, so the
  field was pure attacker input that nothing else consumed. The advisory: "An unauthenticated
  attacker could include an arbitrary email value in the request body to obtain a fresh
  rate-limit key per request, effectively bypassing per-IP throttling."
signal: >
  The strongest version of the signal in MTH-API-007. The key contained a body field. A body
  field is caller input by definition. The extra twist worth noticing is that the field was not
  even used by the route, so no validation touched it and no test would have missed it.
safe_proof: >
  Lab only, wrong credentials only. Affected version, low limit. Send requests to /auth/local
  with the same wrong password and a different email value each time, and confirm the limit
  never fires. Then send the same number with a constant email and confirm it does. The
  difference between the two runs is the finding.
controls:
  negative: >
    constant email run must be refused. If it is not, the limiter is disabled and this proves
    nothing
  differential: >
    run the same test against a route that legitimately keys on email, such as an OAuth connect
    path, and confirm the behaviour differs. That distinguishes "the key is wrong here" from
    "the limiter does not work"
  attribution: >
    all attempts must use credentials known to be invalid, so no account is ever authenticated
    and no reset email is ever delivered to a real address
fix:
  commit_url: https://github.com/strapi/strapi/commit/5e0d243cba9830e6f791de6a94798bcde51468db
  invariant: >
    Read from the diff. The patch adds
    ROUTES_WITHOUT_IDENTIFIER = ['/auth/local', '/auth/reset-password', '/auth/change-password']
    and a routeUsesEmailIdentifier() predicate that also returns false for OAuth callback paths
    under /connect/*. Where the predicate is false the key becomes
    "noIdentifier:{path}:{ip}" instead of "{email}:{path}:{ip}". Paths are normalised for
    traversal, duplicate slashes and case before the allowlist is matched.
    **The invariant in one line: a request field may appear in a rate limit key only on the
    routes where the server itself uses that field, and the route must be identified by a
    normalised path so the allowlist cannot be sidestepped.**
hardening: >
  Default the key to something the caller cannot choose, then opt individual routes into a
  richer key. That is the shape the patch takes, and it is the right way round: the safe key is
  the default and the caller influenced key is the exception that has to be justified.
detection: >
  Repeated failures on one authentication path from one IP, each carrying a different email,
  most of which correspond to no account. Keyed by IP alone it is obvious. Keyed the way the
  bug keyed it, it is invisible.
variant_rule: >
  Any key built by string concatenation of request attributes. Look at each attribute and ask
  who writes it. The path normalisation in the patch is its own lesson: an allowlist matched
  against a raw path can be walked around with /../ or a double slash or a capital letter, so a
  route allowlist is only as good as the normalisation in front of it. Read across to
  APIDS-0020, where a route allowlist fails for a different reason entirely.
lab:
  install: disposable Strapi at 5.44.0 or below
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-7mqx-wwh4-f9fw
  accessed: 2026-08-13
  fix_commit_read: yes, 2026-08-13, three files changed, rateLimit.js plus a new rateLimit.test.js
    plus one line in auth.js
  license_note: short quoted fragments and the diff's identifier names, for the technical
    description only
  credit: reported by adriatikii, remediation by derrickmehaffy
```

## What happens

Strapi throttled its login and password routes. To count attempts it built a key out of three
things joined together: the email in the request, the path, and the IP.

On the login route, email is not something the route uses. The route reads `identifier` and
`password`. But the middleware sitting in front of it reached into the body for `email` anyway,
and put whatever it found into the key.

So you send your login attempt with an extra field, `email`, set to a random string. You get a
counter nobody has ever used. Do it again with a different random string. Another fresh counter.
The throttle never counts to two.

## Why it works

The middleware was written once and applied to several routes. On some of those routes email is
the natural identity, so keying on it is sensible. On these three it is not, and nobody checked
per route.

The detail that makes this worth reading twice: the vulnerable field was one the route ignored.
There was no validation on it, because nothing consumed it. Input nobody uses gets no scrutiny,
and here it silently steered a security control.

## How you would reproduce it

Lab, always with a password you know is wrong. Two runs of the same size. Run one, vary the
email each request: no refusals. Run two, keep the email constant: refusals. Report the pair,
not just run one, because run two is what proves the limiter was working and the key was the
defect.

## What the fix is, and why the obvious fix would not work

The obvious fix is to strip unexpected fields from the body. Reasonable hygiene, and it does not
address the bug: on the routes that legitimately key on email, the email is expected, and it is
still caller supplied.

The fix that shipped decides per route whether email belongs in the key at all, and where it
does not, replaces it with the constant `noIdentifier`. Then it normalises the path before
matching the route list, which closes the door the first fix would have left open. Without
normalisation, `/auth//local` or `/AUTH/local` misses the allowlist, falls through to the
email keyed branch, and the bypass is back.

That last step is the part most people would skip, and it is why reading the diff was worth it.
An allowlist keyed on a raw path is a defence with a typo shaped hole in it.
