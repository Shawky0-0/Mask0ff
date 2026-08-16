---
tags: [security, flash, advisories, appsec, authentication, session, replay, webds]
updated: 2026-08-16
sources:
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-vqfp-p66c-xrp9, accessed 2026-08-16"
---

# WEBDS-0027: Etherpad's device to device token handoff can be redeemed forever

```yaml
id: WEBDS-0027
component:
  type: package
  ecosystem: npm
  name: ep_etherpad-lite
  version_scope: "the /tokenTransfer endpoint, added for moving a session between devices"
affected:
  introduced: "2.6.0, released 2025-11-18, from commit 41cb680 in pull request 7228"
  fixed_in: "3.1.0"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-55088
  ghsa: GHSA-vqfp-p66c-xrp9
  osv: "___, api.osv.dev returned 404 for this id on 2026-08-16"
  snyk: ___
  vendor_id: "PR 7784, fix commit 8c6104c"
class:
  owasp_2025: "identification and authentication failures"
  owasp_api: "API2, broken authentication"
  owasp_llm: n/a
  cwe: "CWE-294 authentication bypass by capture replay, and CWE-200 exposure of sensitive information"
  family: session handoff and replay
  corpus_directory: 03-authentication-session-oauth-jwt/
auth_required: none
entry_point: "GET /tokenTransfer/{uuid}"
root_cause: >
  Three missing decisions in one handler, and each one alone would have been survivable.
  First, the record stores a createdAt timestamp and nothing ever reads it, so the transfer
  never expires. Second, the database record is not removed after a successful redemption,
  so the same uuid can be redeemed an unlimited number of times. Third, the handler ends
  with res.send(tokenData), which serialises the whole stored record, and the cleartext
  author token is a field of that record. The advisory quotes this directly. The endpoint
  is also unauthenticated by design, which is what makes the other three matter.
signal: >
  A feature described as "move your session to another device". That phrase means a secret
  is being handed across a channel the application does not control, which forces the
  question of what makes the handoff one time. Read the handler and look for two things:
  a timestamp written but never compared, and a delete that happens after the response
  rather than before it. A stored createdAt with no reader is the strongest single tell.
safe_proof: >
  Lab instance only. Start a transfer, redeem it once through the intended flow, then issue
  the identical GET a second time. The canary is the second response: a 200 carrying the
  same body proves both the replay and the token exposure at once. Then wait past whatever
  the documented lifetime is and redeem a third time to show expiry is not enforced.
  Never do this against an account you do not own.
controls: >
  Negative control: request a uuid that was never issued and confirm it fails, which proves
  the second 200 came from the stored record rather than from a handler that returns 200 for
  everything. Differential control: compare the response body against the patched 3.1.0
  response, which the advisory says is {ok: true, prefsHttp}. If your build already returns
  that shape, you are not looking at the vulnerable code path. Time control: a replay that
  fails only after several minutes may be hitting a proxy cache rather than the endpoint.
fix:
  commit_url: "https://github.com/ether/etherpad-lite/commit/8c6104c, referenced in the advisory as the fix for pull request 7784. Commit page not opened this run"
  invariant: >
    Per the advisory the patch enforces three things at once: records older than a five
    minute TRANSFER_TTL_MS return HTTP 410 Gone, the record is deleted before the success
    response rather than after, and the response body no longer contains the token. The
    invariant is that a handoff artefact is valid for exactly one redemption inside a short
    window, and that the artefact never carries the secret it authorises.
hardening: >
  A transfer identifier should be a pointer, not a container. The redeeming device presents
  the uuid and the server sets its own session cookie in the response; the token itself never
  crosses the wire in a readable body. That single change removes the exposure whatever
  happens to expiry and single use.
detection: >
  Two or more successful GETs on the same /tokenTransfer/{uuid} in the access log is the
  whole detection, and it needs no payload inspection. A second signal is a long gap between
  the issue time and the redemption time. Nothing here looks abnormal to a WAF.
variant_rule: >
  The same shape lives in every "magic link", QR code login, password reset link, email
  confirmation, invite link and device pairing code. Ask three questions of each: does it
  expire, is it deleted on use, and does the response body contain the thing it authorises.
  The third question is the one people forget, and it is the one that turns a leaked URL in
  browser history or a screenshot of a QR code into a permanent account takeover.
lab:
  install: "docker run of ep_etherpad-lite at 3.0.0, two browser profiles to play the two devices"
  snapshot: "container snapshot before the first transfer"
  teardown: "remove the container and its volume"
provenance:
  source: "https://github.com/ether/etherpad-lite/security/advisories/GHSA-vqfp-p66c-xrp9"
  accessed: 2026-08-16
  license_note: "GitHub advisory text, read only"
```

## What happens

Etherpad has a feature for moving your logged in session from one device to another. You start
a transfer on the first device, you get a link with a random identifier in it, and the second
device opens that link and receives your session.

The link never stops working. It can be opened any number of times. And the page it returns
prints your session token in plain text in the response body.

So anyone who ever sees that link owns the account. Not for five minutes. Permanently.

## Why it works

Three separate small decisions were skipped, and it takes all three to get to permanent
takeover.

The code writes down when the transfer was created. Nothing ever reads that field, so there is
no expiry. The code looks up the record and hands it back, and then does not delete it, so
there is no single use. And the handler returns the whole stored record rather than a chosen
subset, so the token itself is in the reply.

That third one is the interesting one. `res.send(tokenData)` is not a security decision that
somebody got wrong. It is the absence of a decision: whoever wrote it sent the object they had
rather than building the object the client needs. The token was in the object because the
object is the database row.

This is worth sitting with, because it is the most common way secrets escape. Not through a
bug in a check, but through a handler that returns a record instead of a response.

## How you would reproduce it

Do the transfer once, normally. Then send the exact same GET again. If the second one succeeds
and the body still carries the token, you have all three problems in one request.

## What the fix is, and why the obvious fix would not work

The patch adds a five minute lifetime, deletes the record before responding, and cuts the token
out of the response body.

The obvious fix is to make the identifier longer and harder to guess. That does nothing here.
Nobody was guessing it. The identifier reaches the attacker because it travelled through
browser history, a screenshot, a chat message or a server log, which is exactly what a transfer
link is designed to do. Unguessability protects against search; it does not protect against
disclosure. The controls that protect against disclosure are expiry and single use, which is why
the patch adds both rather than either.

The ordering detail is worth copying too: the record is deleted **before** the success response,
not after. Deleting after leaves a window where two concurrent requests both read the record
and both succeed. That is a race, and it is the same shape as
MTH-WEB-004.

Related: WEBDS-0031, a passkey replay with the
same CWE and a different mechanism, and
WEBDS-0026 from the same audit batch.
