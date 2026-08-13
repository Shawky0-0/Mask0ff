---
tags: [security, flash, advisories, webds, business-logic, rate-limiting, craft-commerce, php, fix-diff]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-h5gm-x9wr-vhcm, accessed 2026-08-13"
  - "https://github.com/craftcms/commerce/commit/df22c4f9c4ea7fb7857d833f755e49ea6f9f5bb5, accessed 2026-08-13"
---

# WEBDS-0020, Craft Commerce only rate limits the cart when you tell it which cart

**The first entry in the business logic, races and operations class.** That class
had one method card and no entry for three runs. Related:
the web advisories folder,
MTH-WEB-005, the guard whose condition the attacker controls,
MTH-WEB-007, did the patch fix the bug or the class.

```yaml
id: WEBDS-0020
component:
  type: package
  ecosystem: composer
  name: craftcms/commerce
  version_scope: "the front end CartController"
affected:
  introduced: "5.0.0 and 4.0.0"
  fixed_in: "5.6.5 and 4.11.2"
  tested_on: ___
identifiers:
  cve: CVE-2026-55795
  ghsa: GHSA-h5gm-x9wr-vhcm
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "identification and authentication failures, by the CWE. In practice this is a business flow abuse"
  owasp_api: "API6, unrestricted access to sensitive business flows"
  owasp_llm: not applicable
  cwe: "CWE-307, improper restriction of excessive authentication attempts"
  family: guard applied on a condition the client controls
  corpus_directory: 08-business-logic-race-operations/
auth_required: none
entry_point: >
  actionUpdateCart on the front end CartController, the ordinary "apply a coupon"
  form post. The controlled input is which parameters you include: the guard
  keys off whether a number parameter is present in the body or the query.
root_cause: >
  The RateLimiter behavior was attached conditionally, and the condition was
  "did the request include a number parameter". That parameter names a specific
  cart. A shopper working on their own session cart does not need to send it. So
  the whole rate limiter could be switched off by leaving a field out. The
  missing decision is: nobody decided which action is sensitive. They decided
  which parameter is sensitive, and the attacker chooses the parameters.
signal: >
  A form that is clearly rate limited on one path and clearly not on another.
  Concretely: submit a wrong coupon repeatedly with the optional identifier
  present, get throttled, then submit the same wrong coupon without it and keep
  going. Any response that changes behaviour when you remove an optional field
  is worth ten minutes.
safe_proof: >
  In a disposable Craft Commerce install of your own, create one coupon with a
  known code. Submit fifteen wrong codes with the number parameter present and
  record where the throttle starts. Submit fifteen more without it and record
  that no throttle appears. The canary is the throttle response itself, a 429 or
  the vendor's equivalent. Fifteen requests against your own lab is the whole
  proof, and no real store is touched.
controls: >
  Negative control: the run that includes the number parameter must actually get
  throttled. If it does not, rate limiting was never enabled in this install and
  you have proved nothing. Differential control: the two runs must be identical
  apart from that one field, same source address, same session, same interval,
  because IP based limiters are stateful and the order of your runs can produce
  the result on its own. Run them in both orders. Third control: confirm your
  wrong codes really are wrong, so a success is a bypass and not a lucky guess.
fix:
  commit_url: "https://github.com/craftcms/commerce/commit/df22c4f9c4ea7fb7857d833f755e49ea6f9f5bb5"
  invariant: >
    Read the diff carefully, because it does not say what the advisory says. The
    advisory text recommends applying rate limiting unconditionally on
    actionUpdateCart. The patch does not do that. It keeps the conditional
    structure and introduces a constant,
    RATE_LIMITED_PARAMS = ['number', 'couponCode'], then triggers the limiter if
    any parameter in that list is present. The key prefix changes from
    cart-number-rate-limit to cart-rate-limit. So the enforced invariant is
    narrower than the stated one: the limiter now fires for two named parameters
    instead of one, rather than for the action.
hardening: >
  Rate limit the action, not the parameter. Anything that compares a user
  supplied secret against a stored one, coupon codes, gift card numbers,
  referral codes, promo codes, is a guessing surface and deserves a limit that
  does not depend on the request's shape. Then make the secret not worth
  guessing: enough entropy that brute force is pointless, and a per code
  redemption cap so a leaked code cannot be spent at scale.
detection: >
  A high count of cart update requests from one address or session with a high
  ratio of coupon rejections. The fingerprint is a run of POSTs to the cart
  endpoint that all carry couponCode and never carry the cart identifier, which
  is the reverse of what a browser does.
variant_rule: >
  Any guard attached by a condition rather than to a route. Look for middleware
  or behaviours registered with an if, filters that check for the presence of a
  field, and validation applied inside one branch of a controller. Then the
  specific guessing surfaces: gift card balance lookup, referral and invite
  codes, order tracking by number, password reset token check, one time codes,
  and unsubscribe or download tokens. In Laravel terms the same question is
  whether throttle: is on the route or inside a conditional in the controller.
lab:
  install: "composer create-project craftcms/craft plus craftcms/commerce pinned below 5.6.5, in a throwaway container"
  snapshot: "database snapshot before the runs, so the throttle state is reset between them"
  teardown: "drop the container and the database, no payment provider connected at any point"
provenance:
  source: "GitHub Security Advisory GHSA-h5gm-x9wr-vhcm and the linked patch commit, reported by gonzaless95"
  accessed: 2026-08-13
  license_note: "public advisory and public commit, no licence restriction on reading"
```

**A date disagreement, recorded rather than resolved.** The advisory page shows
published 2026-06-16. A GitHub advisory search listing showed 2026-06-19 for the
same identifier. Both were read on 2026-08-13. The two disagree by three days
and nothing here depends on which is right.

## What happens

A shop lets you type a discount code into your basket. Type a wrong one too many
times and the shop stops answering, which is what stops people from guessing
codes all day.

That stopping only switches on when the request includes a field naming which
basket you mean. You do not need that field, because the shop already knows your
basket from your session. Leave it out and the guessing never stops.

## Why it works

The limiter was wired to a **parameter**, not to an **action**.

Somebody wrote, roughly: if this request names a cart, apply the limit. That was
probably a performance decision, or a way to avoid throttling ordinary browsing.
Either way, the condition is a property of the request, and the request is
written by the person you are limiting.

This is the third time this exact shape has landed in this reference. Krayin's
installer guard skipped itself when the request looked like AJAX
(WEBDS-0014). Winter CMS validated
handler names on the AJAX path and not the postback path
(WEBDS-0021). Now a rate limiter
switches off when a field is absent. The rule from
MTH-WEB-005 keeps holding:

**When a security guard's condition mentions anything about the incoming
request, the attacker has a vote on whether the guard runs.**

## What it is worth

Coupon codes are usually short and often guessable, and a working one is money.
That is why this is a business logic bug and not a technical one: nothing here
is malformed, no parser is confused, no memory is corrupted. Every request is a
perfectly ordinary shopper request. The defect is that the shop's own rule about
how many guesses a person gets was written in a way that lets the guesser opt
out.

This is exactly why scanners miss this class. There is nothing anomalous to
match on.

## How you would reproduce it

Stand up your own Craft Commerce below the fixed version with one real coupon.
Submit wrong codes with the cart identifier present until you get throttled,
note the count. Reset. Submit wrong codes without it and watch the count go past
that number without stopping. Run it in both orders so you know the limiter
state is not producing the result by itself.

## What the fix is, and why the obvious fix would not work

The patch adds `couponCode` alongside `number` in a list of parameters that
switch the limiter on.

That is worth stopping on, because it is not what the advisory says the fix is.
The advisory says apply the limit unconditionally. The code keeps the condition
and lengthens the list. Both are defensible engineering, but they are not the
same repair. The list version fixes this instance. It leaves the shape intact,
so the next sensitive parameter added to that controller starts life outside the
limiter, and nobody will notice until somebody guesses at it.

The obvious fix that would not work is the one that got shipped, generalised:
keep enumerating sensitive parameters. Enumeration fails the way every denial
list fails, only here it fails in the other direction. It is an allow list of
things that get protected, and anything not yet on it is unprotected by default.

The fix that would kill the class is to attach the limiter to the action, and to
make the limit key the session or the address rather than a supplied identifier,
so that leaving a field out cannot change which bucket you are counted in.
