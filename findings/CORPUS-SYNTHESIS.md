---
tags: [security, flash, advisories, digest, synthesis, methods]
updated: 2026-08-13
sources:
  - "the 34 method cards and 79 records in security/advisories*/, read 2026-08-13"
  - security/advisories-digest/2026-08-12.md
  - security/advisories-digest/2026-08-13.md
---

# CORPUS-SYNTHESIS: what the sweep corpus has actually learned

**Read this before hunting, not after.** It is the judgement layer over
the sweeps: 34 method cards and 79 records, compressed
into the shapes that repeat. The mechanical list of every card is `METHOD-INDEX.md`. This page
is the part that no single card says, because each card only knows its own lane.

**Every record behind this page is desk research from a published source.** It is a cited
hypothesis, not a reproduced finding. Most were never run in a lab and fewer than one in five
had a fix diff read behind them. **Use these to decide where to look. Never use one to claim a
target is affected.**

**How to use it.** Pick the shapes that match the surface in front of you, ask their question,
and only then open the named cards for the mechanism and the false positive control.

---

## The nine shapes, ranked by how often the corpus hit them

### 1. Two readers, one input, and they disagree

**The question: who else parses this same string, and do they agree?**

**The biggest pattern in the corpus, and it is the only one that appears in all four lanes.**
A defect does not need a broken parser. It needs two pieces of code that both read the same
value and reach different conclusions, and an input that lands in the gap.

* `MTH-WP-001` two sanitisers applied to one value, described the same way, written years apart.
* `MTH-WEB-001` and `MTH-WEB-002` the front end and the back end disagree about where one HTTP
  message ends and the next begins.
* `MTH-WEB-009` the filter reads a string and the socket reads an address, so the same
  destination written as NAT64 IPv6 passes a check that blocks it in IPv4.
* `MTH-API-003` nginx URL decodes the path during normalisation and the upstream does not.
* `MTH-W3-008` the request is normalised by one function and the rule by another, so the gate
  never matches the door. Uppercase in a Nuxt route rule silently disabled the auth gate.

**Where to point it:** anywhere a value crosses a boundary and is inspected on both sides. Proxy
to origin, WAF to application, allow list to fetcher, router to handler, client to contract.

### 2. The guard exists, and it is not on every path

**The question: I found the check. Now how many paths reach the dangerous operation without
crossing it?**

Assume the product validates, because it usually does. The defect is the route around it.

* `MTH-API-008` find the validator, then count every call site of the dangerous operation and
  subtract the ones that call it. **Needs no traffic at all, it is pure static reading.**
* `MTH-WP-003` the authorisation check and the action take different arguments. One resolves a
  path to an object and checks the object; the other serves the path.
* `MTH-WEB-005` open the route file and find the middleware that was explicitly removed or
  conditionally skipped, then ask what condition the attacker controls.
* `MTH-API-002` validation walks the batch and execution walks it again, joined by index, so
  breaking one item makes the others answer for each other.
* `MTH-API-006` routes whose names promise they do nothing (`preview`, `validate`, `test`,
  `check`) are the ones nobody guarded, and the name is why.

**The strongest live instance:** batch endpoints. `APIDS-0002` in WordPress core and `APIDS-0020`
in parse-server are the same defect in unrelated products, both bypassing a path based rule
through batch sub requests. **On any site with edge rules, test them through `/wp-json/batch/v1`.**

### 3. The key a guard is computed over, not the guard

**The question: this control is a counter or a cache. What is its name made of, and who writes
each piece of that name?**

All the attention goes to the threshold, because that is the number in the config. The key is
built in a helper nobody reviews.

* `MTH-API-007` three ways a rate limit key fails: it contains caller data, it is finer grained
  than the identity it tracks (an IPv6 /64 is 2^64 free counters), or the limiter never ran.
* `MTH-W3-009` write out the cache key in full, then list every input the cached computation
  actually read. **If the second list is longer, that is a cross user disclosure**, and one user
  testing alone can never see it.

**Four records in three lanes are the same cache key bug:** `APIDS-0005`, `WEBDS-0008` and
`W3DS-0021` are one hono advisory caching server rendered output on props alone, and `APIDS-0024`
is a Directus cache collision on a null user id. **A black box tell for the rate limit case: the
limit is documented and you never hit it.** Most testers read that as generous. Read it as a
fresh counter per request.

### 4. What comes back when there is nothing there

**The question: what does this lookup return on a miss, and is that value distinguishable from a
real answer?**

Absence has a representation, the representation is usually zero or empty, and zero is often a
valid input somewhere downstream. **Three lanes, three ecosystems, one idea.**

* `MTH-W3-007` an out of range committee id returned a zero public key, and a zero signature
  verifies against it because zero is the BLS identity element. That was about $9 million.
* `MTH-WEB-008` a security function swallows an exception and uses an empty value, so the check's
  answer becomes a constant, and a constant can be precomputed once for every install on earth.
* `MTH-WP-002` a page reads a JavaScript variable it never defines, so an injected element with
  that `id` makes the browser define it for you.

### 5. The vendor's claim about its own fix is not evidence

**The question: did the patch fix the reported case, or state a rule?**

**The corpus caught this twice on one day, in two unrelated lanes, on unrelated products.**

* `MTH-WP-006` treat `fixed in` as a claim and bisect the tags. First use found Bookly's real fix
  two releases later than every advisory said, so 27.6 and 27.7 read as patched and are not.
* `MTH-WEB-007` read the diff and decide which it did: added the reported case to a list, or
  stated a rule covering cases nobody reported. A longer list means the siblings are still open.
* `MTH-WEB-006` open the fix commit rather than the advisory, and **read the changed tests before
  the changed code**, because the test names carry the attack the vendor's prose will not.

**Corpus health warning attached to this shape.** Across the 26 records written on 2026-08-13,
**four had a patch read behind them.** Every other `fix.invariant` is inferred from the defect
description. That is the single weakest property of this corpus and it is exactly the property
these three cards say not to trust.

### 6. The supplier you already trust

**The question: what would it take for someone to put content into a channel this system does not
check, because the channel is its own?**

* `MTH-WP-004` a plugin renders JSON from its vendor's own endpoint without escaping. The
  BdThemes campaign owned sites this way and **no plugin file was ever modified**, so file
  integrity scanning reports the site clean while it is compromised.
* `MTH-W3-002` stop asking whether a dependency's code is good and ask what it would take for a
  stranger to publish into your build.
* `MTH-W3-003` the served front end is a security boundary. Who can replace it, and would anyone
  notice?
* `MTH-W3-005` for every field read out of a signed or encoded blob, write down who chose the
  value it is compared against, the server or the sender.

### 7. Signatures, and the moment consent was given

**The question: which of the two questions does this code actually ask, and what could the signer
see when they signed?**

* `MTH-W3-001` separate "is the sender authorised" from "is this value possible". Code usually
  asks only the first.
* `MTH-W3-004` for every signature, token or approval: when was it made, what could the person
  actually see, and what stops it being spent elsewhere later.
* `MTH-API-005` **read the verifier, not the documentation.** `APIDS-0009` is a Symfony webhook
  parser that is handed the signing secret and never reads it. **This is the closest thing in the
  corpus to a signal for a CRM or messaging callback layer.**

### 8. Go where the code is newest and thinnest

**The question: what did this product grow most recently, and who reviewed it?**

* `MTH-WP-007` review the AI feature first. It is the newest code, written fastest, and by its
  nature it fetches URLs, reads files and calls out, so it needs exactly the primitives an
  attacker wants. `WEBDS-0019` is that shape in the wild: a filter blocks the cloud metadata
  address and the fetcher reaches it anyway as NAT64 IPv6.
* `MTH-WP-005` when the application is too small to have bugs, audit the library it hands files
  to, because that library decides for itself what those files are. That is `WPDS-0008`: a
  PostScript upload reaching Ghostscript through Imagick.

**The corpus is unusually strong here and it is worth saying why.** Six records sit in AI and RAG
endpoint authorisation, and **none of them is an AI vulnerability in any interesting sense.** They
are missing authorisation checks on ordinary HTTP routes that happen to sit in front of a model.
Two share one shape: an endpoint that promises to validate, and validates by running.

### 9. Send it twice, and benchmark before you believe the result

**The question: does the interface only ever send this once?**

* `MTH-API-004` find a request the UI sends once, send two at the same instant, see if the effect
  lands twice.
* `MTH-WEB-004` treat every request as passing through hidden intermediate states, and **judge
  the result against a sequential benchmark rather than against your expectation**. Without the
  benchmark a timing difference is noise wearing a finding's clothes.

---

## What this corpus does not cover

Stated so nothing here is mistaken for coverage it does not have.

* **Fix diffs, the weakest property.** Four of 26 records written on 2026-08-13 had a patch read.
  Treat every other `fix.invariant` as inference.
* **No second identifier source on any record.** NVD has returned HTTP 502 for four runs. INCIBE
  and the Red Hat tracker were opened on 2026-08-13 and have not been applied backwards.
* **Reproduction.** Nothing in this corpus was run in a lab. Zero records carry a `tested_on`.
* **Thin classes:** WordPress themes (0 records), API `API8` misconfiguration and `API9` inventory
  as a primary cause (0 each), smart contract logic (1), and authentication as a web class (1
  record against two method cards).
* **No feed exists for GoHighLevel or the WhatsApp Business API.** Four runs looked. If that holds,
  a CRM and messaging layer built on them has no upstream vulnerability signal at all, and the
  only route to one is `MTH-API-005` applied to the callback handler by hand.

## Provenance

Built from the four daily intelligence sweeps, whose per lane ledgers, watchlists and daily run
files stay in Ahmed's vault and never cross into this repository, because they map one company's
estate. What crosses is the technique and the published advisory behind it. Regenerated on a
schedule, currently every two weeks, alongside the mechanical `METHOD-INDEX.md`.
