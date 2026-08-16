---
tags: [security, flash, advisories, method, research-technique, ai-testing, appsec]
updated: 2026-08-16
sources:
  - "https://github.com/ether/etherpad-lite/security/advisories, accessed 2026-08-16"
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-qfmh-fph3-mw8q, accessed 2026-08-16"
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-vqfp-p66c-xrp9, accessed 2026-08-16"
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-fjgc-3mj7-8rg8, accessed 2026-08-16"
---

# MTH-WEB-011: when one project publishes seven advisories at once, read them as one document

## The technique in one line

A batch of advisories published on the same day by the same project, all pointing at one fix
commit, is the output of a single audit, and reading the batch tells you what the auditor looked
for and what it never looked at, which is worth more than any one of the bugs.

## The discovery signal

**Look at the date column on a project's advisory listing page.** Not at the titles. Dates that
repeat are the signal.

Etherpad's listing on 2026-08-16 showed seven advisories all dated 2026-06-10, then one from
2021. Seven on one day is not seven discoveries. It is one piece of work.

Opening three of them confirmed it in one line each: every one names the same fix commit,
`8c6104c`, in the same pull request, `7784`. And every one carries the same credit line, quoted
here exactly: **"Reported during internal security audit by Claude"**, via the project
maintainer.

So the batch is an AI assisted audit of one codebase, fixed in one commit, published in one go.

## The mechanism

Two things follow from a batch, and the second is the valuable one.

**First: one diff explains all of them.** Normally you read a fix commit to understand one bug.
Here one commit closes seven, so the diff is a map of the audit. It costs one fetch to
understand seven findings instead of seven fetches. This lane's own note from 2026-08-13 said
the diff is worth more than the prose; a shared diff multiplies that.

**Second, and this is the part to keep: the batch tells you what the auditor is good at.** Sort
the findings by class and the pattern is immediate. From the seven Etherpad titles:

| What it found | How many |
|---|---|
| Authorisation and token logic: a presence only JWT check, a replayable token transfer | 2 |
| Output encoding: stored XSS in HTML export, XSS in the admin pages | 2 |
| Weak randomness and predictable paths: `Math.random()` for temp files, weak token RNG | 2 |
| Header handling: `x-proxy-path` reflected, and glued into a redirect | 1 |

Every one is a local defect. Every one is visible by reading a single function and asking
whether that function does what its name claims.

**Nothing in the batch is a multi step chain.** No finding requires state built across several
requests, a race between two of them, a business rule violated over time, or a disagreement
between two systems that each behave correctly on their own. Not one is a logic bug about what
the product is *for*.

That is a hypothesis about a single batch, not a proven rule, and it is written here so a later
run can test it against another AI audit batch. But if it holds, it says exactly where a human
tester's time is worth most on a codebase that has already been audited this way: **the bugs that
need two things to be true at once.**

## Which class this belongs to

None of the ten. It is a research technique that changes how you spend a run, like
MTH-WEB-006 and
MTH-WEB-007. It feeds every class, and it feeds
business logic hardest by telling you where the gap is.

## Which stacks it applies to, and whether it reaches Ahmed's

Stack independent. It is about reading advisory listings, not about a technology.

**It reaches Ahmed's work at a different angle than usual, and this is the reason the card
exists.** He is building an evidence engine and he tracks AI testing systems. This is a public,
dated, citable record of an AI audit's actual output on a real codebase: seven findings, all
shipped, all with CVEs, all credited. Not a vendor claim about what such a system can do, but
the artefacts themselves.

The useful conclusion for his own engine is the shape of the gap, not the count. An automated
pass over a codebase is good at "this function does not do what its name says". It did not
produce anything of the shape "this sequence of correct steps produces a wrong outcome". If that
holds up, the engine should stop competing on the first kind and start being built for the
second.

## A safe way to test for it

Reading only, no target involved.

1. Open the project's advisory listing at `github.com/<org>/<repo>/security/advisories`.
2. Look for repeated dates. Three or more on one date is a batch.
3. Open two or three and check whether they share a fix commit and a credit line. If they do, it
   is one audit.
4. Read the shared diff once. Then classify the titles and write down which classes are **absent**.

Step 4 is the whole technique. Steps 1 to 3 are just how you find something to do it to.

## The control that would catch a false positive

**A shared publication date is not proof of a shared audit.** Projects also batch publication for
housekeeping reasons: an embargo lifting, a release going out, or a maintainer clearing a queue
of unrelated reports. Confirm with the fix commit and the credit line before drawing any
conclusion, which is the check that was done here.

**A shared fix commit is not proof of a shared root cause.** Etherpad's seven share `8c6104c`
because they were fixed together, not because they are the same bug. Do not merge them into one
entry.

**Absence in one batch is not absence in general.** The claim above, that AI audits find local
defects and miss multi step logic, rests on a single batch from a single tool on a single
codebase. It is a hypothesis with an `n` of one. Treat it that way until another batch either
confirms or breaks it, and record which.

**And the ordinary one:** the credit line says the audit was internal. What that audit's scope
was, how it was run, and what it looked at and rejected are all `___`. The advisories say what
was found. They do not say what was searched.

## Where else this shape appears

* **A vendor's release notes for a "security release".** Same idea, less structure: several
  fixes, one version, and the set tells you what somebody swept for.
* **A bug bounty program's disclosed reports, sorted by date.** A cluster from one researcher in
  one week is one methodology applied repeatedly, and the methodology is the prize.
* **Any pull request labelled "security hardening" that touches many files.** Read the file list
  before the diff: the file list is the auditor's checklist.
* **Static analysis rule releases.** A new rule ships and a wave of advisories follows in
  products using that language. The wave tells you the rule; the rule tells you what to grep for
  yourself.
* **CVE clusters against one product from one reporter.** Same shape as the batch, spread over
  weeks instead of published together.

## Provenance

Source: `https://github.com/ether/etherpad-lite/security/advisories` and the three individual
advisories `GHSA-qfmh-fph3-mw8q`, `GHSA-vqfp-p66c-xrp9` and `GHSA-fjgc-3mj7-8rg8`, all accessed
2026-08-16. Seven advisories dated 2026-06-10 on the repository listing; the GitHub global
advisory database lists the same items as published 2026-08-13. **Both dates are recorded and
they disagree**, which matches this lane's standing note that listing dates and advisory page
dates do not always agree.

The fix commit `8c6104c` and pull request `7784` are named in all three advisories read and
**neither was opened this run**. Reading that diff is the obvious next step and it is on the
debt list.

Related: WEBDS-0026,
WEBDS-0027 and
WEBDS-0028 are the three entries taken from this
batch. the AI testing systems page is where the wider thread
lives.
