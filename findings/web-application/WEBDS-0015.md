---
tags: [security, flash, advisories, webds, npm, supply-chain, entropy, crypto]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-rg76-677x-56q9, accessed 2026-08-12"
---

# WEBDS-0015, crypto-js weak random number generator, and why upgrading does not fix it

**First entry in the components and supply chain class, which was at zero.**
Related: the web advisories folder,
WEBDS-0011, the other client side library item.

```yaml
id: WEBDS-0015
component:
  type: library
  ecosystem: npm
  name: crypto-js
  version_scope: CryptoJS.lib.WordArray.random()
affected:
  introduced: "3.1.2-4, June 2014, per the advisory"
  fixed_in: "4.0.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-71851
  ghsa: GHSA-rg76-677x-56q9
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: cryptographic failures
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-331 insufficient entropy, CWE-334 small space of random values, CWE-338 use of a cryptographically weak PRNG"
  family: predictable secrets from a non cryptographic PRNG
  corpus_directory: 09-components-supply-chain/
auth_required: none
entry_point: >
  not a request at all. Any code path in the application that calls
  CryptoJS.lib.WordArray.random() to produce something that must be
  unguessable: a session token, a password reset token, an API key, a salt, an
  IV, a recovery phrase. The entry point is a line of your own code, usually
  reached through a transitive dependency you did not choose.
root_cause: >
  crypto-js replaced the random source with a hand written Multiply With Carry
  PRNG seeded from Math.random(). Math.random() is not a cryptographic
  generator, and the seeding narrowed the output space far below what the caller
  asked for. The advisory states it plainly: "Nominal requests for 128 or 256
  bits of entropy produce effective search spaces of approximately 2^39 and 2^47
  possibilities, small enough to enumerate on commodity hardware." The missing
  decision lives in the library, not the application: nobody decided that a
  function named random() in a crypto library must be cryptographically random.
  The caller asked for 256 bits and was given roughly 47.
signal: >
  For a tester, this one is not observed in traffic, it is read in a lockfile.
  The signal is crypto-js at any version below 4.0.0 appearing anywhere in
  package-lock.json or yarn.lock, including as a transitive dependency several
  levels down. A second signal, much weaker, is tokens in the application that
  look short, or that share a visible prefix across separate generations.
safe_proof: >
  Offline and entirely local. In a disposable Node project, install a vulnerable
  crypto-js, generate a large batch of values from WordArray.random(), and
  measure the distribution: count collisions, and check whether the values
  correlate with a known Math.random() sequence from the same seed. The proof is
  statistical, not an exploit. Never attempt to predict a token belonging to a
  real system, in a lab or otherwise, because the target of that test is
  somebody's live secret.
controls: >
  Negative control: run the identical batch and the identical measurement
  against crypto-js 4.0.0 or against Node's own crypto.randomBytes(), and show
  the collisions disappear. Without that comparison a collision count is a
  number with nothing to mean. Differential control: confirm the application
  actually calls WordArray.random() for the value in question, rather than
  merely having the library present. A dependency in the lockfile is not proof
  that the vulnerable function is reached.
fix:
  commit_url: ___
  invariant: >
    4.0.0 replaced the custom generator with the platform's native
    cryptographic API, meaning crypto.randomBytes() in Node and
    crypto.getRandomValues() in the browser. The invariant is that the entropy
    comes from the operating system's CSPRNG and never from Math.random().
    The commit was not read, so the URL stays unknown.
hardening: >
  Never let an application level library be the source of randomness for a
  secret. Call the platform CSPRNG directly. It is one line, it is in every
  runtime, and it removes an entire dependency from the trust path for your
  secrets.
detection: >
  Dependency scanning, not runtime detection. Nothing about this appears in a
  log, in a WAF, or in a scanner pointed at the running site, and that is the
  most important operational fact about it. npm audit and a lockfile review are
  the only things that find it.
variant_rule: >
  Any use of a language's default random for a security purpose. PHP's rand()
  and mt_rand() rather than random_bytes(). Python's random rather than secrets.
  Java's Random rather than SecureRandom. Go's math/rand rather than
  crypto/rand. The generic tell is a function named random used to make
  something that must be unguessable. Also look for the second pattern this bug
  teaches: a library that quietly swapped its implementation in a patch release,
  here in 3.1.2-4, and carried the weakness for six years.
lab:
  install: "npm install crypto-js@3.3.0 in a throwaway directory, offline analysis only"
  snapshot: "not needed, nothing is modified outside the directory"
  teardown: "delete the directory"
provenance:
  source: "GitHub Advisory GHSA-rg76-677x-56q9, which cites the Coinspect Ill Bloom investigation"
  accessed: 2026-08-12
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

A library used to encrypt and hash things in JavaScript also offers a function
to generate random bytes. Applications used it to create secrets. For six years
that function was not producing anything like the amount of randomness it
claimed.

Ask it for 256 bits and you get, in practice, a value drawn from a pool of about
2^47. That sounds enormous. It is not. A pool of 2^47 is something an ordinary
computer can work through.

## Why it works

Two separate mistakes stacked.

The generator was a Multiply With Carry PRNG written by hand. That is a fine
choice for a simulation or a game and a bad one for a secret, because its whole
future output follows from its internal state.

The state was seeded from `Math.random()`. `Math.random()` is explicitly not
cryptographic in any JavaScript engine. So the real secret was never the 256
bits, it was the much smaller seed, and everything after was arithmetic.

The advisory's own framing is the useful one for a tester: the function honoured
the *shape* of the request, 256 bits of output, while silently failing the
*substance*, 256 bits of unpredictability. Output length and entropy are not the
same measurement, and only one of them is visible by looking.

## The part that matters more than the bug

The advisory says: "Updating an affected library or wallet does not strengthen a
previously generated secret."

This is the sentence to remember, and it generalises well past crypto-js. For
almost every vulnerability, patching ends the exposure. For a weak randomness
bug, patching only fixes secrets generated *after* the patch. Every token, key,
salt and recovery phrase minted during the vulnerable years is still weak, still
in the database, and still valid. The fix is a rotation, not an upgrade, and the
upgrade is the easy half.

Coinspect's investigation documented coordinated theft against addresses derived
from affected phrases, with over five million dollars measured stolen as of
2026-07-13. That figure is what a 2^47 search space is worth to someone willing
to run it.

## How you would reproduce it

Do the statistical version, offline, in a throwaway directory. Generate a large
batch from a vulnerable version, count collisions, compare against 4.0.0 and
against `crypto.randomBytes`. The collisions in the first set and their absence
in the other two is the finding.

Do not attempt to predict any real token anywhere. There is no version of that
test that is not an attack on a live secret.

## What the fix is, and why the obvious fix would not work

Move to 4.0.0 or later, which uses the platform CSPRNG. Then rotate every secret
generated by the old code, which is the part that will actually cost time.

The obvious fix, seeding the same PRNG better, does not work. A Multiply With
Carry generator is still fully determined by its state no matter how well you
seed it, so recovering one output still reveals the rest. The generator itself
had to go.

The obvious *testing* fix does not work either. You cannot find this by testing the running application. The
tokens look fine. They are the right length, they pass every format check, and
nothing in a response, a log, or a scanner result hints at it. This class is
found by reading dependencies, which is why supply chain sits in its own class
in this corpus and why it needs a different habit from the rest of the sweep.
