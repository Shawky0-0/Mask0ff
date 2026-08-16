---
tags: [security, flash, advisories, appsec, authentication, webauthn, passkey, replay, webds]
updated: 2026-08-16
sources:
  - "https://github.com/craftcms/cms/security/advisories/GHSA-wg23-69c2-gjc8, accessed 2026-08-16"
  - "https://github.com/advisories?query=sort%3Apublished-desc+ecosystem%3Acomposer, accessed 2026-08-16"
---

# WEBDS-0031: Craft CMS lets the client bring its own WebAuthn challenge, then forgets to save the counter

```yaml
id: WEBDS-0031
component:
  type: framework
  ecosystem: composer
  name: craftcms/cms
  version_scope: "the passkey login path"
affected:
  introduced: "5.0.0-RC1"
  fixed_in: "5.10.5"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: "___, none assigned as of the advisory page read on 2026-08-16"
  ghsa: GHSA-wg23-69c2-gjc8
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "identification and authentication failures"
  owasp_api: "API2, broken authentication"
  owasp_llm: n/a
  cwe: CWE-294, authentication bypass by capture replay
  family: replay of a challenge response exchange
  corpus_directory: 03-authentication-session-oauth-jwt/
auth_required: none
entry_point: "the unauthenticated passkey login request, whose body carries PublicKeyCredentialRequestOptions"
root_cause: >
  Two failures that cancel each of WebAuthn's two replay defences. First, the server accepts
  PublicKeyCredentialRequestOptions straight out of the unauthenticated login request body
  rather than generating a fresh challenge itself and remembering it. So the old challenge
  stays acceptable. Second, after a successful assertion the server does not persist the
  updated PublicKeyCredentialSource that the validation library hands back, which carries the
  incremented signature counter. So the stored counter never moves and the same counter value
  keeps validating. The missing decision, stated once: the server never took ownership of the
  freshness state.
signal: >
  A login request body containing a structure the protocol says the server should have
  generated. Read the request in the browser's network tab and ask, for every field, who is
  supposed to have authored it. A challenge that arrives from the client is the loudest
  possible signal, and it is visible without any tooling. The second signal is a counter,
  version, nonce or sequence number that the protocol defines and the application stores but
  never writes back after a successful use.
safe_proof: >
  Lab instance, on an account you created. Capture your own successful passkey login request
  body, then send exactly that body again as a fresh request. The canary is a second valid
  session from a byte identical request. That is the whole demonstration, and it never
  touches another person's account or credential.
controls: >
  Negative control: replay the body with one byte of the signature altered, which must fail.
  If the altered body also succeeds, signature verification is not running at all and the
  finding is a different, larger one. Differential control: replay against a patched 5.10.5
  build and confirm rejection, so you are measuring the defect rather than a configuration.
  Timing control: replay after several minutes as well as immediately, because a short lived
  session cache can make an early replay look successful when it is only reusing your
  existing session. Log out and clear cookies between attempts.
fix:
  commit_url: "___, the advisory lists no commit or pull request URL"
  invariant: "___, no diff available to read"
hardening: >
  The server generates the challenge, stores it against the session or a short lived record,
  and deletes it on first use. The signature counter is written back inside the same
  transaction that creates the session, and a counter that does not increase is a hard
  failure. Both controls are one time state owned by the server, which is the property that
  matters: freshness cannot be delegated to the party you are trying to authenticate.
detection: >
  Two successful authentications with an identical signature counter value on one credential.
  That is the signal the WebAuthn specification puts the counter there to give, and it is
  only available if the counter is actually stored and compared. Identical request bodies in
  an access log are a second, cruder version of the same thing.
variant_rule: >
  Any challenge response protocol where the server can be talked into accepting a challenge
  it did not mint. OAuth state and PKCE code_verifier, CSRF tokens supplied in both a cookie
  and a body without comparison, SAML InResponseTo, one time password windows that accept a
  previously used code, and nonce fields in signed webhook payloads. Then the sibling family:
  any monotonic counter the protocol defines and the implementation reads but never writes.
lab:
  install: "craftcms/cms 5.10.4 in docker with a passkey enrolled against a lab account, using a virtual authenticator in the browser developer tools"
  snapshot: "compose snapshot before enrolment"
  teardown: "remove the container and its database volume"
provenance:
  source: "https://github.com/craftcms/cms/security/advisories/GHSA-wg23-69c2-gjc8"
  accessed: 2026-08-16
  license_note: "GitHub advisory text, read only. Credited to angrybrad, published 2026-07-25"
```

## What happens

Craft CMS supports passkeys. You log in with your fingerprint or your security key instead of a
password.

Capture one successful passkey login request. Send the same request again. You get another
session. Send it a hundred times and you get a hundred sessions.

Passkeys are supposed to make that impossible. This implementation removed both of the reasons
it is impossible.

## Why it works

WebAuthn stops replay with two things, and they are independent on purpose.

The first is the challenge. The server invents a fresh random value, sends it to you, and your
device signs it. Because the server invented it and remembers it, the signature is only good
once. Craft took the challenge structure out of the incoming request body instead. So the
attacker's captured challenge is presented back to the server, and the server accepts it,
because it never had an opinion about which challenge was current.

The second is the counter. The authenticator counts how many times it has signed anything, and
sends the count. The server stores the last count it saw and rejects anything not higher. Craft
did not save the updated value the library handed back, so the stored count never moved, and the
old count kept passing.

Both defences exist so that losing one still leaves you protected. Losing both at once is what
makes this critical rather than theoretical.

The single sentence version: **the server let the client hold the freshness state.** You cannot
ask the party you are authenticating to tell you whether their proof is fresh.

## How you would reproduce it

On your own lab account. Capture your login request. Send it again. Two sessions from one
request body is the finding.

The control that matters is flipping one byte of the signature and confirming that fails. Without
it you have not shown a replay, you have only shown that requests get responses.

## What the fix is, and why the obvious fix would not work

The advisory names no commit, so the invariant is `___`.

The obvious fix is to store the counter properly. That is half. It closes replay against
authenticators that implement counters, and plenty do not: the specification allows a counter of
zero always, and several popular platform authenticators use it. Against those, the counter
defence was never available and the challenge is the only thing standing there. So a
counter only fix would look correct in a test suite with a virtual authenticator and fail in the
field.

The other half, and the one that must be there, is that the server generates and remembers the
challenge. That is not an optimisation of the protocol, it is the protocol.

Related: WEBDS-0027, the same CWE-294 reached by a
completely different route, and MTH-WEB-008, on
authentication functions that fail to a constant.
