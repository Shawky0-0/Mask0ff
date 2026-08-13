---
tags: [security, flash, advisories, api, method, api4, api6, rate-limit, keying]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-p6v2-xcpg-h6xw, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-7mqx-wwh4-f9fw, accessed 2026-08-13"
  - "https://github.com/strapi/strapi/commit/5e0d243cba9830e6f791de6a94798bcde51468db, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-h5gm-x9wr-vhcm, accessed 2026-08-13"
  - "https://github.com/advisories?query=rate+limit+bypass, accessed 2026-08-13"
---

# MTH-API-007: attack the rate limiter's key, never its number

Related: APIDS-0017,
APIDS-0018,
APIDS-0023,
MTH-API-004, the one time flow method that this
one sits underneath, the API folder.

## The technique in one line

A rate limit is a counter with a name on it. Find out what the name is made of, and if the
caller controls any part of it, the caller gets a fresh counter whenever they want one.

## The discovery signal

**Nobody writes down the rate limit key, so nobody checks it.** Documentation says "5 attempts
per minute". It does not say per what. That missing word is the whole attack surface.

The signal in source is a key built by joining strings together. In Strapi it was literally
`` `${userIdentifier}:${requestPath}:${ctx.request.ip}` ``. Read each piece and ask who writes
it. In that one, `userIdentifier` came from `ctx.request.body.email`, which is the caller.

The signal in a black box test is subtler and better: **the limit is documented, and you never
hit it.** Most testers conclude the limit is generous and move on. The right conclusion is that
you might be getting a new counter every request.

## The mechanism

Every limiter does the same two things. Compute a key from the request. Increment the count
under that key and compare it to a threshold.

All the attention goes to the threshold, because that is the number in the configuration file
and the number in the requirements document. The key is derived in a helper nobody reviews.

There are exactly three ways a key fails, and this run found all three:

**One, the key contains caller supplied data.** Strapi, CVE-2025-64526. The key included an
email taken from the request body. On `/auth/local` the route does not even use email, so it
was unvalidated input steering a security control. Send a different one each time, get a
different counter each time.

**Two, the key is finer grained than the identity it is supposed to track.** better-auth,
CVE-2026-45364. Keyed on the exact IPv6 address. A client is allocated a /64, so it holds
2^64 addresses. Every one is a fresh counter. The key was not wrong about who you are, it was
wrong about how many names you have.

**Three, the key is never computed, because the limiter did not run.** Craft Commerce,
CVE-2026-55795. The limiter engaged only when an optional `number` parameter was present.
Omit it and there is no counter at all. **Omission is an input**, and it is the one a test suite
never sends.

There is a fourth, weaker variant that showed up repeatedly in the same advisory listing and is
worth naming: the key is taken from a header the caller can forge. `X-Forwarded-For` and
`X-Real-IP` spoofing appeared in Fleet twice, in go-chi twice, in gofiber and in 9router, all in
one page of results. That one is well known and well documented, so it is the least interesting
and the most common.

## Which OWASP API class

`API4:2023` unrestricted resource consumption is the direct fit, since a limit that never fires
is no limit.

But the harm usually lands in `API6:2023`, unrestricted access to sensitive business flows. The
limiter was the only thing stopping a business process being run a million times. That is what
APIDS-0023 is: the defect is a rate limit key, the damage is coupon enumeration.

Follow the flow, not the class. **Ask what the limiter was protecting, and file the finding
there.**

## Which protocols

All of them. REST, GraphQL, WebSocket message rates, gRPC. Keys are computed the same way
everywhere. GraphQL deserves a specific warning: a per request limit is nearly meaningless
there, because one request can carry unbounded work, which is
APIDS-0021.

## Whether it reaches Ahmed's surface, and how

Yes, in four places, and none has been checked.

* **WordPress login throttling plugins.** Every one keys on something. Behind Cloudflare or any
  reverse proxy the question of which header is trusted is live, and misconfiguration here is
  extremely common.
* **Laravel `throttle` middleware.** Named in the company stack. It keys on the route and the
  authenticated user, falling back to IP. The fallback is the interesting branch.
* **Tutor LMS coupon and enrolment flows.** Directly APIDS-0023's shape, and never reviewed.
* **The AI provider routes.** A limiter keyed on something forgeable in front of a metered model
  call is money, not availability. This is the version with a bill attached.

## A safe way to test for it

Read only first, always. Find the key in source. That answers it in minutes with no traffic.

Where source is not available, in a lab only, with credentials known to be invalid so nothing
authenticates:

1. Send requests, identical in every respect, until refused. Record the count. **This run
   establishes the limiter exists.** Skipping it is the most common way to report a non finding.
2. Repeat, varying one candidate key component per run: the IP, a body field, a header, an
   optional parameter's presence.
3. The component whose variation removes the refusal is the key, and the finding.

Never against production, and never against a staging system carrying real data, because
"unlimited attempts" on a business flow means real redemptions and real emails sent to real
people.

## The control that catches a false positive

**The negative control is mandatory here and it is the one people skip.** You must show the
limiter refusing you under constant conditions. Without that line, "I sent 500 requests and none
were refused" has an obvious alternative explanation: there was never a limiter, and you have
reported a missing feature as a bypass.

The second control is about the deployment, not the code. If a proxy or CDN in front overwrites
the header the key uses, the caller does not control the key and the bypass does not exist on
that deployment even though it exists in the library. **Check the edge before writing it up.**

## Where else this shape appears

Anything with a counter and a name: login throttles, one time password verification, password
reset, signup, invitation acceptance, coupon redemption, referral bonuses, free tier quotas,
API usage plans, and abuse limits on messaging.

And one generalisation worth keeping, because it reaches past rate limiting entirely. This is
the same error as APIDS-0024 and
APIDS-0005, where a cache key was narrower than
the value it labelled. **Both are a key that does not capture everything it needs to
distinguish.** Rate limiter keys and cache keys are the same question asked about different
machinery, so when you find one worth reviewing on a product, review the other in the same
sitting.
