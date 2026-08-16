---
tags: [security, flash, advisories, method, authentication, authorisation, appsec]
updated: 2026-08-16
sources:
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-qfmh-fph3-mw8q, accessed 2026-08-16"
---

# MTH-WEB-010: find the guard that asks whether the field exists, never what it says

## The technique in one line

Read every authorisation check and mark the ones that name a privileged field without a
comparison operator anywhere near it, because a presence test and a value test look identical
in English and behave completely differently in code.

## The discovery signal

**A privileged field name that appears exactly once in the codebase, and appears inside a list
rather than inside an `if`.**

That is the whole signal, and it is greppable. Search the codebase for the word that means
privilege in this product: `admin`, `is_admin`, `role`, `superuser`, `scope`, `tier`. Then look
at what surrounds each hit. A hit inside a comparison is doing work. A hit inside a
configuration array, a required list, a schema, or an argument to a library helper is a
question mark.

In the Etherpad case the whole bug is one line:

```
requiredClaims: ["admin"]
```

Read that aloud and it says "require admin". Read the library documentation and it says the
option verifies a claim is **present**, not what it holds. A non admin user's token carries
`{"admin": false}`, the field is present, and the check passes. The advisory rates it CVSS 9.9.

The second signal is softer and worth having: **a product that supports two authentication
methods where only one is used in development.** Etherpad's advisory says the flaw only affects
instances where `authenticationMethod` is anything other than `apikey`. The path that every
developer runs locally was fine. The path that production runs was not, and nothing in the test
suite went near it.

## The mechanism

There are two different questions that a security check can ask:

* Is this field here?
* Does this field say yes?

English collapses them. "Require admin" is a sentence that means both. So does "check for the
admin claim", "validate the role", and "the token must have admin".

Libraries do not collapse them, and library authors usually document the difference clearly. The
failure is at the seam: somebody reads a configuration option name, forms an English sentence
from it, and never checks which of the two questions the option actually asks.

Once you know the shape, it is everywhere, because almost every language has a cheap way to ask
the first question and a slightly less cheap way to ask the second:

| Language or library | Asks "is it here" | What people think it means |
|---|---|---|
| jose, JavaScript | `requiredClaims: ["admin"]` | the caller is an admin |
| PHP | `isset($claims['admin'])`, `array_key_exists()` | the caller is an admin |
| JavaScript | `Object.hasOwn(c, 'admin')`, `'admin' in c` | the caller is an admin |
| Python | `'admin' in claims` | the caller is an admin |
| JSON Schema | `"required": ["admin"]` | admin must be true |
| Any language | `if (user.role)` | the role is the privileged one |

The last row is the sneakiest, because it looks like a value test. It is a truthiness test, and
in JavaScript the string `"false"` is truthy, `"0"` is truthy, and an empty object is truthy.

## Which class this belongs to

Authentication, session, OAuth and JWT, `03-authentication-session-oauth-jwt/`. It reaches
broken access control too, because the consequence is authorisation, but the mistake lives in
how the token is read.

## Which stacks it applies to, and whether it reaches Ahmed's

**Yes, directly, and on the component with the highest confidence in the repo.**

* **PHP and Laravel.** `isset()` used as a permission test is the single most common instance of
  this shape in PHP. Laravel's own Gate and Policy classes are value based and safe, so the risk
  sits in hand written middleware and in any custom JWT handling around the API.
* **JWT anywhere.** Every library that offers a "required claims" option offers this bug.
* **Node.js and npm**, which is where the Etherpad case lives. Confidence on Node in the stack
  table is `___`, so this is a reason to ask at the sit down rather than a confirmed exposure.
* **The AI surfaces.** Anything that decides what a model or an agent is allowed to do based on
  a field in a token is the same check, and those guards are new code written fast.

## A safe way to test for it

Reading first, and it is free. Grep for the privilege word and look at what surrounds each hit.
This is a code review technique before it is a testing technique, and that is a point in its
favour: it needs no traffic, no target, and no authorisation gate.

Behavioural test, on a lab instance only, and in this exact order:

1. Get a token for a low privilege account through the normal flow.
2. Call an endpoint that should refuse you. **The canary is the status code.** A 200 where a 401
   belongs is the entire finding.
3. Stop. Do not write, delete or move anything to prove the point further.

## The control that would catch a false positive

Two controls, and neither is optional.

**Negative control: strip the field out of the token entirely and repeat.** If that also
succeeds, the guard is not running at all. That is a bigger finding and a different one, and
reporting it as a presence versus value bug would be wrong.

**Differential control: repeat in the configuration the advisory says is unaffected.** Etherpad
says `apikey` mode is safe. If the 401 never appears in either mode, the lab instance is
misconfigured and you are measuring your own setup.

**Third, before writing anything down: read the library documentation for the option you think is
wrong.** The claim "this option only checks presence" is a claim about somebody else's code and
it needs a citation. The Etherpad advisory cites jose's documentation. Do the same.

## Where else this shape appears

* **JWT `alg` handling.** Checking that an algorithm is specified rather than that it is on an
  allow list. That is the classic `alg: none` bug and it is the same sentence.
* **Signature verification that checks a signature is present.** Same shape, worse outcome.
* **Feature flags used as permission.** `if (flags.beta_admin)` where the flag object holds
  `false`.
* **HTTP header checks.** A gateway that forwards a request when `X-Authenticated-User` exists,
  without checking who it names, or whether the client set it.
* **Schema validation standing in for authorisation.** A request passes validation because the
  required fields are present, and something downstream reads that as approval.
* **The inverse, which is worth knowing:** checking that a field is absent as proof of safety.
  Absence is easy for an attacker to arrange.

## Provenance

Source: `https://github.com/ether/etherpad-lite/security/advisories/GHSA-qfmh-fph3-mw8q`,
accessed 2026-08-16. Advisory for `CVE-2026-55089` in `ep_etherpad-lite`, affected
`>= 2.1.0, <= 3.0.0`, fixed in `3.1.0`, CVSS 9.9, CWE-863. The fix quoted in the advisory is
`if (verified.admin !== true) throw`. The fix commit `8c6104c` was named but **not opened this
run**, so everything above about the patch comes from the advisory's own quotation of it.

Related: WEBDS-0026 is the entry,
MTH-WEB-008 is the neighbouring idea that a
security function which fails open fails to a constant, and
MTH-WEB-005 is the other card about reading a
guard's condition rather than its name.
