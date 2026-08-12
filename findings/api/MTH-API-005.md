---
tags: [security, flash, advisories, api, method, api10, webhook, hmac, signature]
updated: 2026-08-12
sources:
  - "https://symfony.com/blog/cve-2026-47212-twilio-notifier-webhook-parser-never-verifies-the-x-twilio-signature-hmac-unauthenticated-webhook-event-injection, accessed 2026-08-12"
  - "https://github.com/symfony/symfony/commit/8545fb2af6c07dfb5ef0fc8d9bccf86db2c94356, accessed 2026-08-12"
---

# MTH-API-005: read the verifier, not the documentation

**The method for `API10` and for inbound webhooks**, two rows that were both at zero. Related:
APIDS-0009, the worked case,
the API folder,
the ledger.

## The technique in one line

For every inbound webhook, find the function that verifies it and check that the secret it is
handed is actually read.

## The discovery signal

The narrowest and most mechanical signal in this folder, which is what makes it worth having.

**A function that receives a secret and never mentions it again.**

In the Symfony case the signature was:

```
doParse(Request $request, #[\SensitiveParameter] string $secret)
```

The parameter is there. It is even annotated as sensitive, so somebody thought carefully enough
about it to mark it for redaction in stack traces. The body then decoded the payload and
returned it, without ever using `$secret`.

Everything about the code says verification is happening. The parameter exists, the
configuration asks for a secret, the documentation describes signature checking, the deployment
guide tells you where to get the token. The only thing missing is the four lines that compare
anything.

This generalises past webhooks: **an argument that is accepted and not used is a decision that
was designed and not implemented.** It is greppable, it survives refactors badly, and no
scanner looks for it because the code compiles and every test passes.

The second signal, for when source is not available: configure a secret, then send a request
with no signature header at all. A system that verifies rejects it. A system that does not
cannot tell the difference.

## The mechanism

An inbound webhook is a request from a third party that carries authority. It says a message was
delivered, a payment succeeded, a contact was updated, a subscription lapsed. The application
then acts on it.

Nothing about the request itself proves who sent it. The URL is often guessable and frequently
appears in the provider's dashboard, in logs, in error reports and in support tickets. The only
thing separating the provider from anyone else is a signature.

Typically the provider computes an HMAC over a canonical string built from the request, keyed
with a shared secret, and puts the result in a header. Twilio uses HMAC SHA1 over the full
request URL concatenated with the POST parameters sorted alphabetically by key, base64 encoded,
in `X-Twilio-Signature`.

If nobody checks that header, the endpoint accepts events from anyone who knows the URL. And
because the application trusts webhooks by design, a forged event goes straight into whatever
automation sits behind it.

That is what `API10` means. The vulnerability is not in the third party API. It is in treating
its output as trusted without establishing that it came from them.

## Which OWASP API class

`API10`, unsafe consumption of APIs, primary. `API2`, broken authentication, secondary, since
what is missing is authentication of the caller. CWE-306 and CWE-347 together.

## Which protocols

Webhooks first. The same reasoning applies to any inbound callback: OAuth redirect handlers,
payment provider return URLs, SMS and email status callbacks, CI build notifications, and
server to server postbacks of any kind. Also to signed messages on a queue, where the consumer
may or may not verify the signature the producer attached.

## Transferability to web and API targets

This method applies directly to any inbound callback consumer:

* **CRM callbacks.** Contact and pipeline updates arriving from a CRM can write false data into
  downstream workflows when origin verification is absent.
* **Messaging-platform callbacks.** Forged delivery or inbound-message events can reach any
  automation behind the consumer.

The first target-specific question is whether the application consumes these callbacks at all,
and at what URL. Never infer deployment from a generic technology inventory.

The question to ask of each, and it is deliberately not "is a secret configured":

1. Is there a secret configured?
2. **Is the secret read?**
3. Is the comparison constant time?
4. Is there a replay window, a timestamp or a nonce, so a captured valid event cannot be sent
   again tomorrow?

Question 2 is the one this card exists for. Question 4 is the one that survives a correct answer
to question 2, and it is worth asking separately: a signature proves origin, not freshness.

## A safe way to test for it

Reading the code is the primary method, and it is free of any authorisation problem at all
because it is reading, not probing.

For a lab test, on a researcher-controlled disposable install:

1. Configure the webhook consumer with a signing secret.
2. POST a payload carrying a canary value in a field the application will log, with **no**
   signature header.
3. Then POST the same payload with a **deliberately wrong** signature header.
4. Check whether the canary reached the handler in either case.

Step 3 is not optional and it is the step people skip. See below.

Never against a live endpoint, never against a production system, and never send anything to the
real provider.

## The control that catches a false positive

**The wrong signature test is the control.** Sending no header at all proves very little on its
own: plenty of implementations treat a missing header as "verification not in use" and accept
it, which is a configuration weakness rather than a verification failure, and some deployments
genuinely have no secret configured, in which case there is nothing to verify and no finding.

A request carrying a header that is present and wrong has only one correct outcome. If it is
accepted, the comparison is not happening. That is the claim worth making.

The second control is the negative one: run the same two requests against a patched build with
the secret configured. Both must be rejected, with 406 in Symfony's case. If they are not, the
test rig is wrong rather than the target being vulnerable.

## Where else this shape appears

* Any verification function: JWT validation that decodes without verifying the signature, TLS
  clients with certificate checking disabled, package signature checks that fetch the key from
  the same place as the package.
* The wider version of the greppable signal: any parameter accepted and unused. A `$permissions`
  argument that is never consulted, a `$scope` that is never compared, a `$tenantId` that is
  passed down three layers and dropped.
* The reverse direction, outbound: an application calling a provider and trusting the response body
  without checking status, shape or bounds. That is the other half of `API10` and this folder
  still has no entry for it.

**One trap worth carrying into any upgrade conversation.** The Twilio signature covers the full
request URL. An application behind a TLS terminating reverse proxy will rebuild the wrong URL,
reject every legitimate event, and the team's fastest way out will be to switch verification off
again. Symfony's advisory says to set `framework.trusted_proxies` and
`framework.trusted_headers`. Knowing that in advance is the difference between a fix that sticks
and a fix that gets reverted on the first incident.

## Provenance

Symfony security advisory for CVE-2026-47212 and the fix commit
`8545fb2af6c07dfb5ef0fc8d9bccf86db2c94356`, both accessed 2026-08-12. The invariant in this card
was read from the diff rather than from the advisory summary.
