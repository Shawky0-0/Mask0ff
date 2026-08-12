---
tags: [security, flash, advisories, method, race-condition, business-logic, http2]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/smashing-the-state-machine, accessed 2026-08-12"
---

# MTH-WEB-004, benchmark first: finding race conditions by looking for sub states

**First method card in the business logic, races and operations class, which was at
zero.** The ledger says this class will never arrive through an advisory feed, and it
did not. It came from a writeup. Related:
the web advisories folder,
MTH-WEB-001,
the watchlist.

## The technique in one line

Treat every request as if it passes through several hidden intermediate states,
then send a batch of requests engineered to arrive during one of them, and judge
the result against a sequential benchmark rather than against your expectations.

## The discovery signal

This is the field the brief calls most valuable and most buried, and here it is
unusually clear.

James Kettle was looking at a Facebook vulnerability from 2016 in which two
simultaneous email change requests produced two confirmation codes that pointed
at different targets. The anomaly sat unexplained for months. What made him look
was not a scanner result and not a hunch about that feature. It was an
unexplained inconsistency that nobody had bothered to account for.

The generalised signal is: **a system produced two answers to the same question
and nobody knows why.** That is the thing to chase. In practice it shows up as an
occasional duplicate record, a support ticket about a coupon that applied twice,
a log line that appears out of order, an "it happened once and we could not
reproduce it".

The research reframes that from a flake into a hypothesis. The paper's own
framing is that every HTTP request may move an application through "multiple
fleeting, hidden states, which I'll refer to as sub-states", typically lasting
around a millisecond.

## The mechanism

An application looks atomic from outside. Inside, a single request is a sequence:
read the current value, decide, write the new value, send the response. Between
the read and the write there is a window where the decision has been made but not
yet recorded. A second request arriving inside that window reads the old value and
makes the same decision again.

The obstacle was always delivery. Network jitter "erratically delays the arrival
of TCP packets, making it tricky to get multiple requests to arrive close
together", so results were unreliable and testers gave up on the class.

The single packet attack removes the obstacle. It bundles 20 to 30 HTTP/2 requests
into one TCP packet by withholding the final frame of each, then releasing them
together. If the requests are in the same packet, they arrive together by
construction, and the network no longer gets a vote. Measured medians were 4ms of
spread for last byte sync against 1ms for the single packet attack, described as
four to ten times more effective.

## The four shapes to look for

* **Limit overrun.** The classic. Beat a numeric limit: redeem a gift card more
  than once, apply one discount code repeatedly, withdraw more than the balance.
* **Multi endpoint.** Two different endpoints touch the same object and reach
  their vulnerable sub state at different moments, so the requests must be
  staggered rather than simultaneous. The GitLab case sent a change email and a
  confirm email at once.
* **Single endpoint.** One complicated endpoint passes through several hidden
  states by itself. In the Devise case a token was queued to one address while
  the message body was built from database state that already read another.
* **Deferred.** The window is opened by batch processing, so it can be minutes or
  hours wide rather than milliseconds. The application's own schedule triggers it,
  not the attacker's timing. This one is easy to miss precisely because it does
  not look like a race.

## Which class it belongs to, and which stacks

Business logic, races and operations, corpus directory
`08-business-logic-race-operations/`.

It is stack independent, because the mechanism is in the application's state
handling rather than in any framework. Anything
with a balance, a quota, a seat count, a coupon, a one time token, a "you may only
do this once" rule is in scope. On an education product that means enrolment
limits, course seat counts, quiz attempt limits, certificate issuance, and any
discount or voucher logic.

One PHP-specific trap matters for Laravel and WordPress applications:
**PHP session locking serialises requests that share a session**, which
hides database level races completely. If you test with one logged in session you
will find nothing and conclude the application is safe. The paper's instruction is
to use "a separate session for every request".

## A safe way to test for it

The three steps, in order, and the order is the point.

1. **Predict.** Pick objects that carry a security control, a balance, a limit, a
   single use flag. Map every endpoint that reads or writes them.
2. **Benchmark, then probe.** Send a synchronised batch, then send the same
   requests sequentially, and compare. The deviation between the two is the
   signal, not the batch result on its own.
3. **Prove.** Cut down to the fewest requests that still demonstrate it.

Safety rules for this lane specifically. Labs only, on something the researcher controls
outright. Use a canary value, for example a voucher created for the test worth
nothing. Never race anything that moves money, sends mail, or touches another
person's record, even in a lab, because the failure mode of a race test is doing
the action several times.

## The control that would catch a false positive

**The sequential benchmark is the control, and skipping it is the standard
failure.** The paper is blunt that "if you skip the benchmark step, you'll miss
vulnerabilities" because "clues can be subtle and counterintuitive".

Run the same requests one after another and record the responses. Then run them
in parallel. If the parallel run differs, you have something. If both runs show
the same oddity, you have found ordinary application behaviour and nearly written
it up as a race.

The second control is repetition. A race is probabilistic by nature, so a single
success is not evidence. Repeat, count how often it lands, and report the rate.
A one in twenty result is still a real finding, and saying so honestly is better
than presenting it as deterministic.

The third is architectural. Before calling something safe, confirm a lock is not
hiding the race, most importantly PHP session locking. A negative result from a
single session proves nothing at all.

## Where else this shape appears

Any two step check and act. Coupon redemption, seat and inventory reservation,
2FA and OTP attempt counters, password reset token consumption, rate limits
themselves, file upload deduplication, follow and unfollow counters, and
withdrawal or transfer flows. Also anywhere a queue or a cron creates the window,
which is the deferred variant and the least tested of the four.

## Tooling named

Turbo Intruder, the Burp extension implementing the single packet attack, with
templates `race-single-packet-attack.py` and `email-link-extraction.py`. Burp
Repeater's send group in parallel option for manual work. Wireshark to confirm a
packet genuinely contained several requests, which is a verification step worth
doing once so you know your tooling does what you think.

## Provenance

PortSwigger Research, "Smashing the state machine: the true potential of web race
conditions", James Kettle. Read at
`https://portswigger.net/research/smashing-the-state-machine`, accessed
2026-08-12. Public research article, read only, nothing executed.

**Sourced deliberately rather than opportunistically.** The ledger flagged that
business logic would never arrive through an advisory feed and that a future Pass
C should spend a card here on purpose instead of taking whatever was published
that week. This run did that.
