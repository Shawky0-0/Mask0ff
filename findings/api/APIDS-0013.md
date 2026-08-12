---
tags: [security, flash, advisories, api, entry, api6, business-flow, race, idempotency, pattern]
updated: 2026-08-12
sources:
  - "https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption, accessed 2026-08-12"
---

# APIDS-0013: the one time offer accepted thirty times at once

**The folder's first `API6`**, the class the ledger named as the top priority and the one
tooling never finds. Filed as a pattern rather than a version range, which the selection
criteria allow. Related:
MTH-API-004, replaying a one time flow,
the API folder,
the ledger.

```yaml
id: APIDS-0013
component:
  type: pattern
  ecosystem: any. Observed against a payments platform, applies to any transactional API
  name: a one time business flow whose acceptance step has no idempotency or state guard
  version_scope: not version bound. This is a design defect class, and the affected pattern is stated below rather than a range
affected:
  introduced: not applicable. Present whenever the pattern is present
  fixed_in: not applicable. Note that the vendor's first fix did not hold, see below
  tested_on: not tested by this sweep. The public writeup is the source
identifiers:
  cve: none. Bug bounty finding, disclosed through HackerOne
  ghsa: ___
  osv: ___
  vendor_id: ___
class:
  owasp_api: API6 unrestricted access to sensitive business flows, primary. API4 unrestricted resource consumption, adjacent but not the same thing, see below
  owasp_2025: ___
  cwe: >
    ___ as stated by the source. The mechanism is a check then act race, which is CWE-362 with
    CWE-367, and the absent control is idempotency. Recorded as inferred, not as published.
  family: business flow replay through a concurrency window
protocol: rest
auth_required: user. The researcher was a legitimate customer, entitled to the offer once
entry_point: >
  The discount acceptance endpoint, reached from a dashboard prompt. The exact route is not
  named in the public writeup. What matters is its shape: a POST that transitions an offer from
  pending to accepted and credits value, sent once by the user interface, with the transition
  guarded by a read of current state rather than by a unique constraint.
object_graph: >
  Unusual for this folder, and the reason the entry is worth writing.
  Which request creates the object: the vendor creates the offer out of band, and support
  attaches it to the account.
  Who owns it: the researcher. Genuinely. This is not a case of reaching someone else's object.
  Who should reach it: exactly that account, exactly once.
  What the tested account actually got: the same object, thirty times, applied cumulatively.
  So every ownership check in the system passed, correctly, thirty times. There is no
  authorisation bug here at all, which is precisely why the object graph method cannot see this
  class and why it needs its own method card. The missing constraint is not who, it is how many.
root_cause: >
  The acceptance handler decides whether to apply the discount by reading the current state and
  then writing the new one, with no unique constraint, no row lock and no idempotency key across
  the two steps. Thirty concurrent requests all read "not yet accepted" before any of them
  writes "accepted", so all thirty proceed. The missing decision is a uniqueness guarantee at
  the point of the state transition, which belongs in the database or in an idempotency key, and
  not in application logic that reads before it writes.
signal: >
  A flow that grants something of value and is expected to happen once. Anything described as a
  one time offer, a single use code, a welcome bonus, a referral credit, a first order discount,
  a trial activation. The discovery signal is not a strange response: it is noticing that the
  user interface only ever sends the request once, and asking what enforces that on the server.
safe_proof: >
  Lab only, on a researcher-controlled system, and this one needs stating carefully because the naive
  proof is destructive.
  The safe demonstration is the smallest concurrency that shows the window: send exactly two
  parallel requests, not thirty, and observe whether the value is applied twice. Two is enough
  to prove a race exists and is the difference between a demonstration and an abuse. Against a
  quantity, prove it with a canary account holding a canary balance, and record before and
  after. Never run this against anything with real money, real inventory or a third party
  behind it, and never in production. The researcher's thirty requests were authorised under a
  bug bounty programme; never assume that permission exists outside an explicit authorization.
controls: >
  Negative control: send the same two requests sequentially rather than in parallel, waiting
  for the first response. If the second is rejected, the guard exists and only the concurrency
  window defeats it, which is a race. If the second succeeds too, there is no guard at all,
  which is a simpler and more serious finding and should be written up as such. Distinguishing
  these two is the whole value of the control and most writeups skip it.
  Second control: confirm the effect is cumulative rather than merely repeated acknowledgement.
  An endpoint may return 200 thirty times and still apply the change once. Read the resulting
  balance or state, not the response codes. This is the most common false positive in the class.
fix:
  commit_url: ___ . Vendor fix, not public
  invariant: >
    A one time transition must be enforced by something that cannot be raced: a unique
    constraint on the transition, a conditional update that matches on the prior state, or a
    server issued idempotency key. Reading the state and then writing it is not an enforcement.
hardening: >
  Make the uniqueness a property of the data rather than of the code path. A unique index on
  the acceptance record means every concurrent duplicate fails at the database, regardless of
  how many application servers are running or how the handler is written later.
detection: >
  Several requests to the same endpoint, from the same account, for the same object,
  within a few milliseconds. That pattern is close to unmistakable in an access log and is a
  cheap alert to build. It is one of the few places where rate limiting genuinely does help,
  though it treats the symptom, not the missing constraint.
variant_rule: >
  Every flow that grants something once: enrolment in a course, redemption
  of a voucher or coupon, a trial or free tier activation, a referral credit, and any
  "claim your certificate" step on an LMS. Tutor LMS is the obvious hunting ground. Also the
  reverse direction, where the same window lets a cancel or refund run twice.
  And one worth naming separately: an AI route that is metered or quota limited per user is
  this same shape, where the thing granted more times than intended is model spend.
lab:
  install: A researcher-controlled lab application with a one time flow, or a WordPress sandbox with a coupon plugin
  snapshot: Snapshot before, since the point of the test is to change state
  teardown: Revert the snapshot. Never against a live production system, never against a third party
provenance:
  source: HackerOne blog, "How a Business Logic Vulnerability Led to Unlimited Discount Redemption"
  accessed: 2026-08-12
  license_note: Mechanism and figures summarised from the public writeup. No text reproduced at length
```

## What happens

A customer is offered a one time fee discount worth twenty thousand dollars. The dashboard
shows a prompt: accept it. Accepting credits the discount to the account.

The researcher sent the acceptance request thirty times in parallel instead of once. All thirty
were applied. Six hundred thousand dollars of fee free transactions, from a flow that was
supposed to run once. The bounty was five thousand dollars.

## Why it works

The server checks whether the offer has already been accepted, and then accepts it. Those are
two steps, and between them there is a gap.

Send one request and the gap does not matter: the check happens, the write happens, and the
next request sees the new state. Send thirty at once and all thirty perform their check before
any of them performs its write. Every one of them sees "not yet accepted", correctly, and every
one proceeds.

Nothing about this is an authorisation failure. The account was entitled to the offer. Every
permission check in the system passed and passed correctly. What was missing was a constraint on
**how many times**, and there is no such thing as a permission check for that.

This is why `API6` is the class that tooling does not find. A scanner looks for requests that
should have been refused. Here every individual request was legitimate. Only the aggregate was
wrong, and the aggregate is not visible in any single request.

## How you would reproduce it

Not the way the cited researcher did, unless it is a controlled lab. Two parallel requests, not thirty.
Two prove the window exists. Thirty is abuse dressed as a demonstration, and outside a bug
bounty scope it is not defensible.

Then the control that separates a race from a plain missing check: repeat it sequentially. If
the second sequential request is refused, there is a guard and concurrency defeats it. If it
succeeds, there was never a guard, which is worse and needs describing differently.

Then read the resulting balance rather than counting HTTP 200s. An endpoint can cheerfully
answer thirty times and still apply the change once.

## What the fix is, and why the obvious fix would not work

The fix is a constraint that cannot be raced: a unique index on the acceptance, a conditional
update that only matches when the prior state is still pending, or a server issued idempotency
key.

The obvious fix is to check harder in the application, or to add a lock around the handler, and
the writeup contains the evidence that this does not hold. **The vendor's first fix failed.**
The researcher demonstrated the race again and it took another iteration to close. That detail
is the most instructive thing in the whole finding, and it is worth carrying into any review:
when somebody proposes fixing a race in application logic, the answer is that the guarantee
belongs in the database, because that is the only place where concurrent writers meet.

The second wrong fix is a rate limit. It makes the attack slower and does not make it
impossible, and it leaves a system that is still correct only by luck.

**Deployment relevance must be established per target.** This is filed because the class was
previously underrepresented, because it is difficult to find deliberately, and because one-time
flows such as enrolment, vouchers, and certificates are broadly reusable hunting surfaces.
