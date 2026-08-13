---
tags: [security, flash, advisories, method, wordpress, patch-analysis, verification]
updated: 2026-08-13
sources:
  - "extracted from this sweep's own work on 2026-08-13, WPDS-0007"
  - "https://plugins.svn.wordpress.org/bookly-responsive-appointment-booking-tool/tags/, accessed 2026-08-13"
  - "https://www.booking-wp-plugin.com/change-log/, accessed 2026-08-13"
---

# MTH-WP-006, treat `fixed in` as a claim and bisect the tags

Related: the advisories folder,
WPDS-0007, where this came from,
MTH-WP-003, also extracted from a diff,
the sweep ledger.

**Extracted from this sweep's own work rather than from a writeup**, the same way
MTH-WP-003 was. It is written down because it
found something on its first use.

## The technique in one line

Do not read an advisory's fixed version as a fact. Find the sanitising line in the patched
release, then walk backwards through the version tags until it disappears, and the release
where it first appears is the real fix.

## The discovery signal

Two things make a `fixed_in` field worth checking rather than believing.

**The advisory states a range and not a release.** "All versions up to and including 27.5" is
a statement about what is broken. Everyone reads it as a statement about what is fixed, and
those are different claims. The person who wrote the range tested a vulnerable build. They did
not necessarily test the next one.

**The changelog for the supposed fix release does not mention security.** This is the strong
signal. If a vendor says 27.6 fixed a SQL injection and the 27.6 changelog says "new table
design", one of those is wrong, and it is usually not the changelog.

A third, weaker signal: the vendor publishes releases faster than advisories get written. When
a plugin ships six releases in the time it takes one CVE to be published, the mapping between
them is guesswork by whoever filed the record.

## The mechanism, which is just a bisect

It works because a security fix is a specific line, and a line is either present in a tag or
it is not. That makes it a decidable question rather than a matter of opinion.

1. **Read the patched version and find the sanitising line.** Not the advisory's description
   of the fix, the actual line. In WPDS-0007 it was
   `array_map( 'intval', (array) $staff_ids )` in the setter.
2. **Read the same file at the version the advisory calls vulnerable.** Confirm the line is
   absent. If it is present there too, you are looking at the wrong line and the bisect is
   already telling you something.
3. **Bisect between them.** Each check is one fetch of one file. Six tags cost six fetches.
4. **Check both ends of the data flow.** A fix that only appears at the sink and not the source
   is a different fix from one that appears at both, and the difference tells you how much the
   vendor understood about their own bug.
5. **Read the vendor changelog for every version in the range.** It either corroborates the
   bisect or contradicts it, and both are useful.

On WordPress plugins the whole thing runs off one URL pattern, which is why it is cheap:

```
https://plugins.svn.wordpress.org/<slug>/tags/                    the version list
https://plugins.svn.wordpress.org/<slug>/tags/<version>/<path>    the file at that version
```

## What it found the first time it was used

Bookly, CVE-2026-14516. Every published source says versions up to and including 27.5, which
reads as fixed in 27.6.

The setter stores the array raw at 27.5, 27.6 and 27.7. It casts at 27.8, 27.9 and 28.0. The
query builder agrees: no cast at 27.5 or 27.6, cast at 27.8 and 28.0. The changelog agrees
too, because 27.6 is a table redesign and 27.7 is a display fix, while 27.8 claims only to add
Divi widgets and is in fact the release carrying the security fix.

So two releases sit in a gap where every scanner and every version check calls them patched.

## Does it transfer to WordPress, and how

It is native to WordPress. The plugin directory keeps every released tag on public SVN
forever, which is unusual and very useful. Most ecosystems make you clone a repository or hunt
a release artifact. Here it is one fetch per version.

It also applies to WordPress core, where the branch table in a GHSA record lists two dozen
"patched" versions. Those are generated from the backport branches, so they are more
trustworthy than a plugin's, but the same check is available.

## A safe way to test for it

There is nothing to test. This method reads published source code from a public repository. No
installation, no request to any live site, no target of any kind. It is the safest thing in
this folder and it produced the most consequential correction of the day, which is worth
noticing when planning where to spend a run.

## The control that would catch a false positive

The failure mode is real and it is easy to fall into: **concluding "not fixed" from "my line is
not here".** A vendor can fix a bug by a completely different mechanism, in a file you did not
read, and your bisect will confidently report the wrong thing.

Controls that actually help:

* **Check at least two points on the data flow**, source and sink. Agreement between them is
  much stronger than either alone.
* **Read the vendor changelog independently.** If it names a security fix at a version your
  bisect calls unfixed, your bisect is wrong.
* **Say what you read.** The honest claim is never "27.6 is vulnerable". It is "the specific
  sanitisation the advisory describes is absent from 27.6 in the two files named by the CERT
  reference list". Those are different sentences and only one of them is supported.
* **Prefer the reference list over guessing at files.** The CERT record for WPDS-0007 named
  `Ajax.php`, `ChainItem.php` and `Finder.php`. That is the entry point, the source and the
  sink, handed over for free. Advisory reference lists are routinely ignored and they are
  often a map of the bug.

## Where else this shape appears

* **Any "fixed in" claim anywhere.** Vendor advisories, CVE records, scanner databases, and the
  version constraints in dependency alerts.
* **Silent security fixes**, which is what this really detects. A vendor that fixes quietly and
  ships the fix inside a feature release breaks every consumer who trusts the changelog.
* **Backport claims.** A patch said to be backported to eight branches is eight separate
  claims, each independently checkable, and the oldest branches are the least tested.
* **Incomplete fixes**, the sibling case. Same method, different question: instead of asking
  which release has the line, ask whether the line covers every path that reaches the sink.
  Bookly casting at both ends is a vendor who got this right. Plenty do not.
* **Reintroduced fixes.** Run the bisect forwards past the fix as well. A cast that appears at
  27.8 and vanishes at 29.1 during a refactor is the same bug with a new CVE waiting for it.

## Provenance

| Field | Value |
|---|---|
| Origin | this sweep, 2026-08-13, during the backfill of the Bookly item |
| Sources used | `https://plugins.svn.wordpress.org/bookly-responsive-appointment-booking-tool/tags/`, six version tags of `lib/ChainItem.php` and four of `lib/slots/Finder.php`, and `https://www.booking-wp-plugin.com/change-log/` |
| Accessed | 2026-08-13 |
| Cost | eleven fetches from first suspicion to a confirmed version boundary |
| Licence note | public repository and public vendor changelog, read only |
</content>
