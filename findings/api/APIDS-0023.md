---
tags: [security, flash, advisories, api, entry, api6, rate-limit, business-flow, craft-commerce]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-h5gm-x9wr-vhcm, accessed 2026-08-13"
---

# APIDS-0023: the coupon rate limit only ran if you sent an optional parameter

**The folder's second `API6`, and the first one with a named product and version range.**
APIDS-0013 was filed as a pattern. This one has a
CVE, a version range and a fix commit. Related:
MTH-API-007,
MTH-API-004, the one time flow method,
APIDS-0008, the other Craft entry.

```yaml
id: APIDS-0023
component:
  type: framework
  ecosystem: composer
  name: craftcms/commerce
  version_scope: "5.0.0 through 5.6.4, and 4.0.0 through 4.11.1"
affected:
  introduced: ___
  fixed_in: 5.6.5 on the 5 line, 4.11.2 on the 4 line
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-55795
  ghsa: GHSA-h5gm-x9wr-vhcm
  osv: ___
  vendor_id: ___
class:
  owasp_api: API6:2023 unrestricted access to sensitive business flows, primary.
    API4:2023 secondary, since the mechanism is a rate limit that does not run
  owasp_2025: ___
  cwe: CWE-307
  family: a guard whose activation is conditional on caller supplied input
protocol: rest
auth_required: none
entry_point:
  route: CartController actionUpdateCart
  parameter: >
    the coupon code, submitted for guessing. The guard's trigger is a *different* parameter,
    'number', accepted as POST or GET. The rate limiter engages only when 'number' is present
  mechanism: omit 'number' entirely and the rate limiting branch is never entered
object_graph:
  creates_the_object: a merchant creates discount codes, each intended for a specific campaign
    or recipient
  owns_it: the store
  should_reach_it: a customer who was given a code, using it a bounded number of times
  tested_account_got: >
    unlimited unauthenticated guesses against a session cart, and therefore the full set of
    valid coupon codes and their discount values. This is a business flow finding rather than
    an object access one: no single request is unauthorised, and the volume is
root_cause: >
  The missing decision is unconditional application of the limiter. The rate limiter in
  CartController activates only when the 'number' parameter is explicitly provided. Coupon
  submission does not require 'number'. So the request that most needs throttling is precisely
  the one that does not get it, and the attacker chooses this by leaving a field out rather
  than by putting anything in.
signal: >
  **Omission is an input.** Most testing varies the values of the parameters that are sent.
  This bug is only reachable by not sending one. So for any conditional security control, ask
  what the condition depends on and whether the caller controls it, including by absence.
  A second signal: the coupon flow is a business flow with a correct answer that can be
  searched for, which is the API6 shape. Nothing malfunctions. It just runs unlimited times.
safe_proof: >
  Lab only, on a disposable store with codes the tester created. Create one known coupon.
  Send N attempts with wrong codes and no 'number' parameter, and confirm none are refused.
  Then send N with 'number' present and confirm refusal begins. **Never run this against a real
  store**, including a staging store carrying real campaign codes: valid guesses may consume
  single use codes and the redemption is a real business event.
controls:
  negative: >
    the run with 'number' present must be refused. That is what shows a limiter exists and the
    condition is the defect, rather than there being no limiter at all
  differential: >
    confirm the guesses actually reach coupon validation, by including the one known good code
    in the sequence and seeing it accepted. Unlimited requests that are all being discarded
    before validation are not a brute force channel
  attribution: >
    count attempts server side. A client that sees no error is not proof the server processed
    every attempt
fix:
  commit_url: craftcms/commerce commit df22c4f, referenced in the advisory, not opened by this
    sweep
  invariant: >
    Stated by the advisory as the remediation: apply rate limiting unconditionally on
    actionUpdateCart regardless of whether the 'number' parameter is present. The invariant:
    a security control's activation must not depend on optional caller supplied input.
hardening: >
  Limit the flow rather than the request. Cap failed coupon attempts per cart, per session and
  per IP prefix, and make the cap a property of the coupon redemption flow rather than of the
  controller action that happens to host it. That survives someone adding a second route to the
  same flow later, which is the failure in APIDS-0019.
detection: >
  A high ratio of invalid to valid coupon submissions from one session or one address. Distinct
  code values tried in sequence. Merchants often see this first as an unexplained spike in
  discount redemptions rather than as an attack.
variant_rule: >
  Every guessable secret with a business meaning: coupon and promotion codes, gift card numbers,
  referral codes, invitation tokens, order lookup numbers, tracking references. Also every
  conditional guard anywhere, which is the more transferable half.
  **Ahmed's fleet: Tutor LMS carries coupon redemption, enrolment and certificate claims**, all
  one time or limited flows, and none have been reviewed. This entry plus MTH-API-004 give two
  distinct ways in: guess the code, or redeem the right one many times at once.
lab:
  install: disposable Craft Commerce in an affected range, tester created coupons only
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-h5gm-x9wr-vhcm
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by gonzaless95
```

## What happens

A shop lets you type a discount code into your cart. Wrong codes should be limited, or you can
simply try them all until something works.

Craft Commerce has that limit. It only switches on when the request contains a parameter called
`number`.

Submitting a coupon does not need `number`. Leave it out and the limiter never runs. Guess
forever, unauthenticated, against a session cart.

## Why it works

Somebody wrote the limiter for one situation, a request carrying an order number, and attached
it to that situation instead of to the controller action. Every other way of reaching the same
action inherited no limit.

What makes this hard to catch is that the attacker adds nothing. They remove something. A test
suite exercising the normal flow always sends the normal parameters, so the guarded branch is
the only one anyone ever runs.

## Why this is API6 and not just a missing rate limit

The distinction matters because it changes what you look for.

`API4` asks whether the server can be made to do too much work. Here the work is trivial: check
a string against a table.

`API6` asks whether a business process can be run more times than the business intends. Coupon
redemption is a process with a designed frequency, once per customer, or a hundred times for a
campaign. The flow works perfectly on every single request. **The damage is entirely in the
count.** No individual request in the attack is unauthorised or malformed, which is why no
scanner and no WAF signature finds this class, and why it is worth a method card rather than a
signature.

## How you would reproduce it

Lab store, tester's own coupons. Two runs, with and without `number`. Include one known good
code so you can show the guesses were really being evaluated.

And a warning that is not theoretical: do not point this at a staging store that carries real
campaign codes. A successful guess in a coupon brute force is a redemption. You would be
spending the client's discount budget to prove a point.

## What the fix is, and why the obvious fix would not work

The obvious fix is to make `number` required. It changes the API for every existing client and
does not stop anything, because a guesser will happily send a constant `number` value once it
is mandatory.

The fix is to stop making the guard conditional. Rate limit `actionUpdateCart` always.

The deeper fix binds the limit to the coupon redemption flow rather than to a controller method,
so that when a second route reaches that flow, a GraphQL mutation, a mobile endpoint, a bulk
import, the limit is already there. Attaching controls to routes means re attaching them every
time a route is added.
