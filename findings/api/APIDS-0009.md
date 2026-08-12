---
tags: [security, flash, advisories, api, entry, webhook, api10, symfony, php]
updated: 2026-08-12
sources:
  - "https://symfony.com/blog/cve-2026-47212-twilio-notifier-webhook-parser-never-verifies-the-x-twilio-signature-hmac-unauthenticated-webhook-event-injection, accessed 2026-08-12"
  - "https://github.com/advisories/GHSA-55rj-x2vc-4whq, accessed 2026-08-12"
  - "https://github.com/symfony/symfony/commit/8545fb2af6c07dfb5ef0fc8d9bccf86db2c94356, accessed 2026-08-12"
---

# APIDS-0009: the webhook parser is handed the secret and never reads it

**The first webhook entry in this folder, and the first `API10`.** Both rows sat at zero
after two runs. Related: the API folder,
MTH-API-005, the secret that is never read,
the ledger.

```yaml
id: APIDS-0009
component:
  type: library
  ecosystem: Composer
  name: symfony/twilio-notifier, and symfony/symfony which ships it
  version_scope: the Twilio notifier bridge only, not Symfony as a whole
affected:
  introduced: ___ . Present at least from 6.4.0, the oldest affected branch named
  fixed_in: 6.4.40, 7.4.12, 8.0.12
  tested_on: not tested. Read only sweep
identifiers:
  cve: CVE-2026-47212
  ghsa: GHSA-55rj-x2vc-4whq
  osv: ___
  vendor_id: symfony.com/cve-2026-47212
class:
  owasp_api: API10 unsafe consumption of APIs, primary. API2 broken authentication, secondary
  owasp_2025: ___
  cwe: CWE-306 missing authentication for critical function, and CWE-347 improper verification of cryptographic signature
  family: inbound webhook authenticity
protocol: webhook
auth_required: none
entry_point: >
  Whatever route the application mounts the Twilio webhook consumer on. Symfony does not fix
  the path, the application chooses it. The request is a POST carrying Twilio status callback
  parameters and an X-Twilio-Signature header. The header is the thing that is ignored.
object_graph: >
  The object here is a message delivery status event, and the interesting part is that it is
  not created by any account on the application at all. Twilio creates it, out of band, and
  POSTs it in. So the ownership question is not "which user owns this row", it is "did this
  event come from Twilio or from anybody on the internet who knows the URL". The only thing
  that ever distinguished the two was the HMAC header, and the parser did not look at it.
  A tester account and an anonymous caller therefore reach exactly the same outcome, which is
  the differential that makes this provable without touching another tenant's data.
root_cause: >
  Symfony\Component\Notifier\Bridge\Twilio\Webhook\TwilioRequestParser::doParse(). The method
  signature is doParse(Request $request, #[\SensitiveParameter] string $secret). It receives
  the configured secret as a parameter and the body never references that parameter. It
  decodes the payload and returns it unconditionally. The missing decision is not buried in a
  helper or a config branch: it is an argument that is accepted and then dropped.
signal: >
  A function that takes a secret and does not use it. This is greppable and it is the whole
  discovery signal. See MTH-API-005.
safe_proof: >
  Lab only, against your own install. Configure the notifier with a signing secret. Send the
  webhook route a POST carrying a canary value in a status field, for example a MessageSid of
  APIDS0009CANARY, with no X-Twilio-Signature header at all. If the canary reaches the
  application's handler, the parser accepted an unsigned event. Nothing is destroyed, nothing
  is exfiltrated, and the canary string makes the entry unambiguous in the log.
controls: >
  Two, and both are needed before calling it. Negative control: send the same request to a
  patched build, 6.4.40 or later, with the secret configured. It must be rejected with the
  406 RejectWebhookException, and if it is not, your test rig is wrong rather than the target
  being vulnerable. Differential control: send a request with a deliberately wrong
  X-Twilio-Signature header. On the vulnerable build it is accepted just the same, which
  proves the header is ignored rather than merely optional. Without that second control you
  have only shown that you did not send a header, which is a much weaker claim.
fix:
  commit_url: https://github.com/symfony/symfony/commit/8545fb2af6c07dfb5ef0fc8d9bccf86db2c94356
  invariant: >
    If a secret is configured then the request must carry an X-Twilio-Signature header, and
    that header must equal the base64 of hash_hmac('sha1', requestUri concatenated with the
    payload parameters sorted alphabetically by key, secret, true), compared with hash_equals.
    Anything else is rejected as RejectWebhookException with status 406.
hardening: >
  Verify inbound webhooks at one chokepoint that every consumer passes through, rather than
  inside each bridge. The class dies when no handler can be reached without a verification
  step having already run.
detection: >
  On the vulnerable build there is nothing to see: an accepted forged event looks exactly like
  a real one, which is what makes this class quiet. After patching, a burst of 406 responses
  on a webhook route is the signal. A gateway can key on requests to webhook routes that carry
  no signature header at all.
variant_rule: >
  Every other inbound webhook the fleet consumes. GoHighLevel CRM callbacks and WhatsApp
  Business API callbacks are both named in the company stack and both are exactly this shape.
  The question to ask of each is not "is there a secret configured" but "is the secret read".
  Also check the other Symfony notifier bridges, since the parser interface is shared, and
  check payment and mail provider callbacks in any Laravel application.
lab:
  install: A disposable Symfony application with symfony/twilio-notifier pinned below the fixed version
  snapshot: VM snapshot before configuring the webhook route
  teardown: Revert the snapshot. No third party is involved at any point, and no request goes to Twilio
provenance:
  source: Symfony security blog, the GitHub advisory, and the fix commit
  accessed: 2026-08-12
  license_note: Facts and version ranges only. No advisory text reproduced at length
```

## What happens

Twilio POSTs a status callback to your application every time a message is delivered, fails,
or is rejected. To prove the POST really came from Twilio, Twilio signs it: it takes the full
request URL, appends the POST parameters sorted alphabetically by key, computes an HMAC SHA1
over that with your account auth token as the key, base64 encodes it, and sends the result in
the `X-Twilio-Signature` header.

Symfony's Twilio bridge has a parser whose job is to check that header and decode the payload.
It was handed the secret. It never looked at it. It decoded the payload and handed it back to
the application every time.

## Why it works

The bug is not a weak comparison or a flawed HMAC. There was no comparison at all. The secret
arrives as a parameter named `$secret` and the method body simply does not mention it again.

That matters for how you find it, and it is the reason this entry exists rather than a dozen
others. Most authorisation bugs need you to reason about who owns what. This one is visible by
reading a single function and asking whether every argument it accepts is used.

## How you would reproduce it

In a lab, with your own disposable Symfony application, and never against a live endpoint.
Stand up the notifier with a secret configured, POST a status payload carrying a canary
identifier to the webhook route, and send no signature header. On an affected version the
event is accepted. Then repeat with a junk signature header. It is accepted too, and that
second result is the one that proves the header is ignored rather than optional.

## What the fix is, and why the obvious fix would not work

The patch adds a private `verifySignature()` method and calls it from `doParse()` when a
secret is configured. It rebuilds the signed string, computes `hash_hmac('sha1', ...)`,
base64 encodes it, and compares with `hash_equals()`. Missing header and bad header both raise
`RejectWebhookException` with a 406.

The obvious fix would be to compare with `==`. That leaks the answer through timing, which is
why `hash_equals()` is there instead. The less obvious trap is in the advisory rather than the
diff: the signature covers the **full request URL**, so an application sitting behind a TLS
terminating reverse proxy will rebuild the wrong URL and reject every legitimate event until
`framework.trusted_proxies` and `framework.trusted_headers` are set. A team that hits that will
be tempted to turn verification back off, which lands them exactly where they started. Worth
knowing before recommending the upgrade to anyone.

**Gate G5.** Whether anything on the YZH or ECMworx fleet consumes this bridge is Ahmed's call.
The repo records Laravel rather than Symfony, and Laravel ships Symfony components but not this
notifier by default. The reason this entry matters here is the pattern, not the package.
