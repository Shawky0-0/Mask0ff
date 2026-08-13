---
tags: [security, flash, advisories, method, fix-diff, patch-review, source-review]
updated: 2026-08-13
sources:
  - "https://github.com/craftcms/commerce/commit/df22c4f9c4ea7fb7857d833f755e49ea6f9f5bb5, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-h5gm-x9wr-vhcm, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-7c4v-fwgw-9rf7, accessed 2026-08-13"
---

# MTH-WEB-007, did the patch fix the bug or fix the class

Related: the web advisories folder,
MTH-WEB-006, reconstruct the attack from the patch,
WEBDS-0020, the Craft Commerce case,
WEBDS-0018, the Nuxt case.

## The technique in one line

Read the fix diff and decide which of two things it did: added the reported case
to a list, or stated a rule that covers cases nobody has reported yet. The first
kind leaves the bug shape alive, and the next instance of it is findable today.

## The discovery signal

Two independent cases produced this card on the same run, which is why it is
worth a card rather than a note.

**Craft Commerce.** The advisory says the fix is to apply rate limiting
unconditionally. The patch does not do that. It keeps the conditional structure
and introduces a constant:

```
const RATE_LIMITED_PARAMS = ['number', 'couponCode'];
```

So the limiter now fires for two named parameters instead of one. The advisory
described a rule. The code shipped a list.

**Nuxt.** The dev server endpoint was fixed once already, in
`GHSA-rq7w-g337-39qq`, using header based access control. Headers are written by
the caller, so that fix was a list of accepted claims. Somebody then walked
around it with one curl flag, and the second fix, `GHSA-7c4v-fwgw-9rf7`, checks
the socket peer address instead. That is a rule: identity comes from the
connection.

The signal in both cases is the same and it is visible in the diff alone: **did
the changed code gain a new entry, or a new decision.**

## The mechanism

Every security fix is one of two kinds and they are easy to tell apart once you
know to look.

**An instance fix** enumerates. It adds a value to an array, a pattern to a deny
list, a parameter to a check, a header to an allowed set, a version to a
comparison. The tell is that the diff makes a collection longer. It is correct
for the reported input and undefined for the next one.

**A class fix** relocates or reframes the decision. It moves the check to a layer
the attacker cannot reach, or normalises the input before judging it, or changes
what the code asks. The tell is that the diff changes a question rather than
lengthening an answer. Compare
WEBDS-0019, where the fix unwraps
an embedded address before deciding, against the alternative of blocking one IPv6
prefix. Same bug, and only one of those two repairs survives the second encoding.

An instance fix is not incompetence. It is usually the correct engineering call
under a disclosure deadline, and a class fix often breaks compatibility. But it
leaves the shape standing, and a standing shape is a finding waiting to be
written.

**What this gives a tester.** A shipped instance fix is a map. It tells you the
maintainer's own model of where the danger is, it tells you they have already
accepted this is a security boundary, and it tells you the boundary is guarded by
enumeration. So the next question writes itself: what else reaches that code and
is not on the list.

For Craft Commerce, the question is which other parameter on that controller is
sensitive and is not `number` or `couponCode`. That is answerable by reading the
controller, with no requests sent to anything.

## Which class it belongs to, and which stacks

Not tied to a class. It applies to every entry in this folder that has a fix
commit, which is the point of it.

Reaches Ahmed's stack directly, because every Laravel and PHP package advisory
links either a commit or a release tag, and both are readable without
authorisation. This is a source reading method, so the Flash lane's authorisation
gate does not bite at all.

## A safe way to test for it

Reading only, at every step. Nothing here touches a running system.

1. Get the diff. GitHub advisories usually link a commit or a pull request.
   `/commit/<sha>` and `/pull/N/files` both render for a plain fetch, confirmed
   again this run. If only a release tag is linked, compare the two tags.
2. Read the advisory prose first and write down, in one sentence, what it claims
   the fix is.
3. Read the diff and write down, in one sentence, what the code now enforces.
4. Compare the two sentences. When they differ, the diff is right and the prose
   is aspirational. That gap is the finding.
5. Classify: did a collection get longer, or did a question change.
6. If a collection got longer, enumerate what else reaches that code path and is
   not in the collection. Stop there and report. Only a lab install Ahmed owns
   gets an actual request.

## The control that would catch a false positive

**Read enough of the surrounding file, not just the changed lines.** A diff that
adds one array element can sit next to an unconditional check added three months
earlier, in which case the enumeration is belt and braces and there is no gap.
Judging a patch from the diff hunk alone is the main way to be wrong here.

**Check the other branches.** Maintainers backport, and a class fix on the main
branch is often shipped as a narrow instance fix on the old branch, because the
old branch cannot take the compatibility break. Same product, two different
repairs, and the one your target is running is the one that counts.

**Check whether the enumeration is generated rather than written.** A list built
from a schema, from route metadata, or from an annotation is closer to a rule
than to a list, because a new sensitive parameter joins it automatically. That is
the case where the shape looks alive and is not.

**Do not report the incomplete fix as a vulnerability.** It is a hypothesis about
where the next one is. It becomes a finding only when a specific reachable input
is named and demonstrated in a lab. Reporting "this patch is architecturally
weak" to a vendor produces nothing and costs credibility.

## Where else this shape appears

The pattern repeats at every scale.

In the codebase: deny lists of file extensions, allow lists of redirect hosts,
lists of blocked IP ranges, arrays of protected route names, sets of sanitised
HTML tags, and switch statements over known types with no default branch.

In the fix history: a product whose security advisories keep landing on the same
file is a product whose fixes are instance fixes. Two advisories against one
endpoint, as with the Nuxt DevTools endpoint, is the strongest single signal in
this method. Somebody already tried and the shape outlived them.

In the paperwork: a CVE whose description begins "incomplete fix for" is a
maintainer saying this out loud. Search a target's advisory history for that
phrase before anything else.

## Provenance

Craft Commerce patch commit `df22c4f9c4ea7fb7857d833f755e49ea6f9f5bb5` and
advisory `GHSA-h5gm-x9wr-vhcm`, plus Nuxt advisory `GHSA-7c4v-fwgw-9rf7` and its
reference to the earlier `GHSA-rq7w-g337-39qq`. All read 2026-08-13.

No page carried text addressed to an automated reader. No command from any page
was executed.
