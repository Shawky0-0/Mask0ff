---
tags: [security, flash, advisories, entry, apids, api, authentication, webauthn, api2]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-wg23-69c2-gjc8 accessed 2026-08-12"
---

# APIDS-0008: Craft CMS accepts a replayed passkey login because the challenge comes from the request

**A one time cryptographic assertion turned into a reusable bearer token.** Related:
the API folder, the ledger,
APIDS-0004, the other authentication entry.

```yaml
id: APIDS-0008
component:
  type: framework
  ecosystem: composer
  name: craftcms/cms
  version_scope: "passkey and WebAuthn login"
affected:
  introduced: "5.0.0-RC1"
  fixed_in: "5.10.5"
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: ">= 5.0.0-RC1, < 5.10.5"
identifiers:
  cve: "___ , the advisory reached this run carried no CVE number"
  ghsa: GHSA-wg23-69c2-gjc8
  osv: ___
  vendor_id: "Craft CMS 5.10.5"
class:
  owasp_api: "API2:2023 broken authentication"
  owasp_2025: "A07 identification and authentication failures"
  cwe: "CWE-294 authentication bypass by capture replay"
  family: server accepts a client supplied challenge, defeating a replay defence
protocol: rest
auth_required: >
  none, given a captured request. The attacker needs one observed successful login, not a
  credential.
entry_point:
  route: "the passkey login endpoint"
  method: POST
  parameter: "requestOptions and response in the request body"
  header: n/a
object_graph:
  which_request_creates_the_object: >
    A legitimate passkey login creates the assertion. It is created by the victim's
    authenticator and is meant to be valid exactly once.
  who_owns_it: "the victim, for one authentication event"
  who_should_reach_it: >
    Nobody twice. The whole design intent of the WebAuthn challenge and signature counter is
    that a captured assertion is worthless on replay.
  what_the_tested_account_got: >
    Anyone holding a copy of one successful login request body could replay it verbatim and
    receive additional authenticated sessions as that user, indefinitely.
root_cause:
  where: "the passkey login handler"
  the_missing_decision: >
    Two defects that only become critical together. First, the system accepts WebAuthn
    requestOptions directly from the unauthenticated login request body instead of generating
    the challenge server side and remembering it. Second, after a successful assertion the
    updated credential counter is never persisted, so the stored counter stays stale. Quoting
    the advisory: "A captured passkey login request body can therefore be replayed because the
    old challenge is accepted again, and the stored credential counter remains stale." The
    missing decision, singular, is that the server must be the one that decides what makes a
    login attempt fresh.
signal: >
  The signal is a challenge, nonce or state value that arrives in the same request as the
  response it is supposed to validate. If the caller supplies both the question and the answer,
  the pairing proves nothing. That is a reviewable property and it does not need a working
  exploit to spot. The second signal is a counter or high water mark that is read and compared
  but never written back, which is a general shape worth grepping for.
safe_proof: >
  Read only in this sweep. In a disposable lab, with a test account and a passkey belonging to
  the tester: capture your own successful login request, then send the identical body again and
  see whether a second session is issued. Your own account and your own captured request only.
  A second valid session is the proof; stop there and do not use it.
controls:
  negative: >
    Alter one byte of the signed response and replay. It must fail. If it succeeds, the
    signature is not being verified at all and the finding is larger and different.
  differential: >
    Repeat against 5.10.5, where the replay must be refused.
  false_positive: >
    Two. A session cookie issued on the first request and simply reused would look like a second
    session but is not a replay; make the second request with a clean client that carries no
    cookies. And confirm the second session is genuinely usable rather than a 200 with an
    unusable body, because a handler that returns success without establishing a session is a
    different and much smaller bug.
fix:
  commit_url: "___ , not reached this run"
  invariant: >
    Generate the challenge server side, store it against the session or the user, and validate
    the assertion against the stored value rather than the submitted one. Persist the credential
    counter after every successful assertion. Stated from the advisory's root cause description,
    not from a patch this sweep read.
hardening: >
  The class killer is a rule, not a control: never accept from the client the value you intend
  to use to validate the client. Challenges, nonces, state parameters and PKCE verifiers all
  share this. The counter persistence is the defence in depth layer underneath, and the fact
  that it was also broken is why the first defect became critical rather than merely wrong.
detection: >
  Repeated login requests with byte identical bodies, and successful authentications where the
  presented credential counter does not exceed the stored one. The second is only visible if
  the counter is actually being written, which is precisely what was missing.
variant_rule: >
  Every challenge response flow: OAuth state and PKCE, SAML request IDs and assertion replay
  caches, CSRF tokens validated against a submitted rather than stored value, signed webhook
  timestamps compared against a value in the payload itself, and any "nonce" the client is
  allowed to choose. Also check anywhere a monotonic counter is used as a freshness defence,
  since a counter never written back is a defence that only appears to exist.
lab:
  snapshot: "snapshot first"
  teardown: "restore the snapshot"
provenance:
  source: "GitHub Security Advisory"
  accessed: 2026-08-12
  license_note: "summarised from public advisory, one sentence quoted and attributed"
```

## What happens

Passkeys work on a challenge and response. The server invents a random challenge, the
authenticator signs it, and the server checks the signature against the challenge it invented.
Because the challenge is fresh each time, a captured login cannot be replayed.

Craft took the challenge from the login request body. The caller sent both the challenge and
the signature over it. Those two agree with each other perfectly on a replay, because they are
the same pair that agreed the first time.

Underneath that there is a second failure. WebAuthn authenticators keep a signature counter
that goes up with each use, and the server is meant to store it and reject anything that does
not exceed the stored value. Craft validated the assertion and then never wrote the new counter
back, so the stored value stayed where it was and never refused anything.

## Why it works

Because both the primary defence and the backstop failed, and they failed independently.

That combination is what makes this critical rather than merely wrong. Accepting a client
supplied challenge is a serious design error, but a correctly persisted counter would have
caught the replay anyway. A stale counter is a quiet bug that does nothing visible on its own.
Together they turn a one time cryptographic proof into a bearer token that works forever.

It is worth noticing what the attacker needs: one captured login request body. Not a password,
not the authenticator, not the private key. Anywhere that request body is observable or logged,
the account is reusable.

## How you would reproduce it

In a lab, with your own account and your own passkey. Capture your own successful login request.
Send the same body again from a clean client with no cookies. If a second usable session comes
back, the replay defence is not there.

Use a client with no cookies, or the first session will fool you into thinking you replayed
something when you only reused a session you already had.

## What the fix is, and why the obvious fix would not work

Generate the challenge on the server, store it, validate against the stored copy, and persist
the counter after every success.

The obvious fix is to fix the counter, since that is the mechanism WebAuthn provides against
replay and it was visibly broken. It would close this instance and leave the design error
intact. A server that accepts a client supplied challenge has no idea whether a login attempt is
fresh; it is relying entirely on a backstop to notice. The counter is defence in depth, and
some authenticators do not implement it meaningfully at all, so leaning on it is leaning on
something that may not be there.

The other tempting fix is to bind the challenge to a timestamp and reject old ones. That narrows
the replay window without changing who chose the value, so a captured request is still replayable
inside the window, and now there is a window to argue about.
