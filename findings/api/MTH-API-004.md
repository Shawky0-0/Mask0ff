---
tags: [security, flash, advisories, api, method, api6, business-flow, race, idempotency]
updated: 2026-08-12
sources:
  - "https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption, accessed 2026-08-12"
---

# MTH-API-004: send the one time request twice at once

**The method for `API6`**, the class that was at zero in this folder and the one no scanner
finds. Related: APIDS-0013, the worked case,
MTH-API-001, the object graph,
the API folder.

## The technique in one line

Find a request the user interface only ever sends once, send two at the same instant, and see
whether the effect lands twice.

## The discovery signal

This is the field most writeups bury, and here it is unusually specific.

**You are not looking for a suspicious response. You are looking for a promise made by the user
interface.** Any wording along the lines of one time offer, single use, claim once, welcome
bonus, first order only, redeem, activate trial, accept, is a promise that something happens
exactly once. The interface keeps that promise by only drawing the button once, or by greying it
out after the click.

The question is what keeps it on the server.

That reframing is the method. The signal is not an error message or an odd status code, it is
noticing that the only visible enforcement is in a screen you control.

A second, weaker signal: an endpoint that returns 200 with no body, or returns the same object
whether or not the change was applied. That often means the handler is not distinguishing "I
did this" from "this was already done", which is the same confusion that leaves the race open.

## The mechanism

The handler does two things in order. It reads the current state to decide whether the action is
allowed, then it writes the new state.

```
read state      -> "not yet accepted"
                                          <- gap
write state     -> "accepted", apply the value
```

One request at a time and the gap is invisible, because the next request's read happens after
the previous write. Send several at once and every one of them reads before any of them writes.
All of them see "not yet accepted". All of them proceed. All of them are individually correct.

That last sentence is the whole reason this class is hard. There is no request in the capture
that should have been refused. Every permission check passed and passed correctly. What was
missing is a constraint on quantity, and quantity is not a property of any single request.

In the Stripe case, thirty parallel acceptances of a twenty thousand dollar discount produced
six hundred thousand dollars of fee free transactions.

## Which OWASP API class

`API6`, unrestricted access to sensitive business flows, primary. The flow is not broken. It
works. It works too many times, which is exactly how the OWASP text describes the class.

Adjacent but distinct from `API4`, unrestricted resource consumption. `API4` is about volume
costing resources. `API6` is about a flow with business meaning being exercised more times than
the business intended. A flow can be rate limited, and therefore fine under `API4`, and still be
racy under `API6`, because two requests is not a volume problem.

## Which protocols

All of them. REST most obviously. GraphQL is worse, because aliasing lets a caller put many
copies of the same mutation in a single request, which defeats naive per request guards without
even needing concurrency. Also applies to gRPC and to any queue consumer that can receive a
duplicate delivery, which is most of them.

## Whether it reaches Ahmed's surface, and how

Directly, and this is the most fleet relevant method card in the folder so far.

* **Tutor LMS**, the largest unexamined API surface on the fleet. Enrolment, claiming a
  certificate, submitting an assignment that is meant to be submitted once, redeeming a course
  coupon. Every one of those is a one time flow.
* **WooCommerce and any coupon or voucher logic**, wherever the fleet has it.
* **Anything metered per user against an AI provider.** If a route gives a user a number of
  model calls, that quota is a one time or limited flow and the same window applies. The EduAi
  `.env` holds live Anthropic, Groq and ZAI keys, so exceeding a quota is spend, not just an
  availability question. This is the point where `API6` and `API4` meet on Ahmed's own fleet.
* **Account registration and password reset**, where a single use token that can be consumed
  twice is the same defect in a security critical flow.

## A safe way to test for it

Lab only, on systems Ahmed owns, and the safety here is mostly about restraint.

1. **Two requests, not thirty.** Two proves the window exists. Thirty is abuse wearing the
   costume of a demonstration. The researcher's thirty were authorised under a bug bounty
   programme, which is a permission that does not exist outside Ahmed's own labs.
2. **Snapshot first**, because unlike most tests in this lane, the point is to change state.
3. **Plant a canary account with a known balance or a known enrolment state**, so before and
   after are unambiguous.
4. **Read the resulting state, not the response codes.**
5. Never against a live company system, never against a third party, never where real money,
   real inventory or a real person's record is involved.

## The control that catches a false positive

Two, and the first one is the one that separates a real finding from a wasted afternoon.

**Repeat it sequentially.** Send the second request only after the first has fully responded.

* Second request refused: a guard exists and only concurrency defeats it. That is a race, and
  the fix belongs in the database.
* Second request accepted: there was never a guard at all. That is simpler, more serious, and a
  different write up. Calling it a race would be wrong.

**Read the effect, not the acknowledgement.** An endpoint can return 200 thirty times and still
apply the change once, because the write was idempotent even though the response was not
informative. Counting successful responses is the most common false positive in this class.
Check the balance, the enrolment row, the credit.

## Where else this shape appears

* Any check then act pair, which is the general form. File existence then write, uniqueness
  check then insert, balance check then debit.
* Cancel and refund flows, where running twice in the other direction is just as wrong.
* Multi step flows where a step can be replayed out of order: completing checkout twice, or
  re submitting the final step of a wizard.
* Rate limit resets and quota top ups.

**The single most instructive detail in the source, and the reason this card exists:** the
vendor's first fix did not hold. The researcher raced it again and it took another iteration to
close. When somebody proposes fixing this class inside application logic, that is the fact to
cite. The guarantee has to live where concurrent writers actually meet, which is the database,
as a unique constraint or a conditional update, or in a server issued idempotency key. A lock
in the handler does not survive a second application server.

## Provenance

HackerOne blog, "How a Business Logic Vulnerability Led to Unlimited Discount Redemption",
accessed 2026-08-12. Mechanism and figures summarised from the public writeup.
**This is the first material this folder has taken from HackerOne**, a source both earlier runs
flagged as never opened.
