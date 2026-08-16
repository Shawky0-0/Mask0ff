---
tags: [security, flash, advisories, method, wordpress, supply-chain, provenance]
updated: 2026-08-16
sources:
  - "https://plugins.svn.wordpress.org/advanced-responsive-video-embedder/tags/, accessed 2026-08-16"
  - "https://plugins.svn.wordpress.org/advanced-responsive-video-embedder/tags/10.8.9/readme.txt, accessed 2026-08-16"
---

# MTH-WP-008: read the tag list as an incident record

## The technique in one line

A version that an advisory names but the plugin's own SVN tag list does not contain is a
**purged release**, and a purged release means somebody deleted a build instead of patching
it, which is what a supply chain compromise looks like from the outside.

## The discovery signal, what made anybody look there

This one came from the vault's own standing lesson rather than from a researcher's writeup:
"the tag list is evidence, and a version missing from a plugin's SVN tags, with no changelog
entry to match, is worth a second look." That lesson was written after
MTH-WP-006, the tag bisect, found a wrong
`fixed_in` on a stack component.

On 2026-08-16 it fired for real. The Wordfence weekly report named Advanced Responsive Video
Embedder versions **10.8.7 to 10.8.8** as carrying a hardcoded backdoor. The tag list read:

```
10.8.0  10.8.1  10.8.2  10.8.3  10.8.4  10.8.5  10.8.6  10.8.9  10.9.0  10.9.4
```

Both named versions were absent. `tags/10.8.7/` returned HTTP 404.

The signal is a **gap in a monotonic sequence, at exactly the place an advisory points**.
Nothing else is needed to notice it. It costs one fetch.

## The mechanism

The WordPress plugin repository is append only in normal operation. A release is tagged, the
tag stays, and the next release gets the next number. Sites only ever move forward, so a
vendor cannot un-ship a version by re-releasing the same number.

That leaves exactly one way to withdraw a bad build: **delete the tag and publish the last
known good code under a higher number.** Which is what happened here. The changelog for
10.8.9 says it in the vendor's own words:

> a re-release of version 10.8.6, nothing besides this readme and the version numbers changed

So the sequence of facts, all readable from two fetches and no privileged access:

1. Advisory names versions X and X+1.
2. Those tags do not exist.
3. The next existing tag's changelog says it is a re-release of the tag *before* X.

Together those three say: **there was no patch, there was a removal.** And a removal, rather
than a fix, is the signature of code that should never have shipped, which in practice means
a compromised maintainer account rather than a developer mistake.

The complementary reading is the changelog language. "Re-release", "reverted", "rolled back",
or a version whose notes claim nothing changed, are all the vendor saying the same thing in
public while saying nothing about why.

## Does it transfer to WordPress, and how

It **is** a WordPress technique, and it works because of a WordPress specific fact: every
free plugin's complete release history is published, unauthenticated, at a predictable URL.

```
https://plugins.svn.wordpress.org/<slug>/tags/
```

The ledger records that `plugins.trac.wordpress.org` returns HTTP 403 to this sweep and
`plugins.svn.wordpress.org` does not. Use SVN.

It transfers off WordPress too, wherever release history is public and immutable by
convention: npm (a version that is `unpublished` leaves a hole in the version list), PyPI
(yanked releases are marked rather than deleted, which is a strictly better design and makes
the same signal easier to read), Packagist, and GitHub release and tag lists. The question is
always the same: **does the version named in the advisory still exist, and if not, who
removed it and what did they say about it.**

## A safe way to test for it

It is read only and there is no target involved, which makes it one of the safest checks in
the folder. Two fetches:

1. `GET https://plugins.svn.wordpress.org/<slug>/tags/` and read the sequence.
2. If a gap sits where an advisory points, `GET .../tags/<missing-version>/` and record the
   HTTP status.

Then a third, which is the one that turns a curiosity into a finding:

3. `GET https://plugins.svn.wordpress.org/<slug>/tags/<next-existing-version>/readme.txt`
   and read the changelog for what the vendor says about the gap.

No requests to any live site, no scanning, nothing against a target. This is reading a
published file directory.

## The control that catches a false positive

Three of them, and the first is the one people skip.

**Gaps are common and usually innocent.** Plugin authors bump versions and abandon releases
routinely. The Kali Forms tag list read this same day is missing 2.4.12, and the AI Engine
list is missing 0.9.1, and neither means anything. So: **a gap on its own is not evidence.**
Before treating one as a signal, fetch two or three unrelated plugins' tag lists and confirm
for yourself that ragged sequences are normal. The evidence is a gap **that an advisory
points at**, not a gap.

**Second: distinguish "never tagged" from "tag deleted".** A version that was released
through the repository but never tagged in SVN is a vendor process failure, not a withdrawal.
The changelog is what separates them: if the missing version has a changelog entry describing
features, it existed and was removed. If it has no entry at all, it may never have shipped.

**Third: an advisory can simply be wrong about a version number.** Before concluding a
purge, check whether a second source names the same versions. Here the Wordfence weekly
report said 10.8.7 to 10.8.8 while other coverage read this run named only 10.8.7. That
disagreement is recorded in WPDS-0010 rather than
resolved, and it does not change the conclusion, because both named versions are absent.

## Where else this shape appears

* **A plugin closed and then reopened in the directory.** The directory listing page says so,
  and the reason is usually not published, so the tag list is again the readable part.
* **A version whose zip is unavailable while its tag exists**, which is the inverse and
  points at a distribution problem rather than a withdrawal.
* **A `fixed_in` that cannot be trusted**, which is 
  MTH-WP-006, the sibling of this card. That one bisects tags to find where a fix actually
  landed. This one reads the same list for where a release stopped existing. Same fetch, two
  different questions, and both worth asking every time.
* **Any ecosystem where an incident is announced but the postmortem is not.** The release
  history is the part the vendor cannot quietly edit, because sites depend on it.

## Why the card exists

Because the alternative to this check is believing a news article. The ARVE story was covered
widely, and the coverage was not consistent about which versions were affected. Two fetches
against the vendor's own repository settled the material question, which was not "which
versions" but "what did the vendor actually do", and the answer, a rollback rather than a
patch, is not in any of the coverage.

**It also generalises the vault's most useful habit: fix the source rather than route around
it, then read the primary artefact rather than the summary of it.**

Related: WPDS-0010 is the entry this came from,
MTH-WP-006 is the sibling tag technique, and
MTH-WP-004 is the other supply chain card in this
folder.
</content>
