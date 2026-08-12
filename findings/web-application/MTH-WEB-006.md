---
tags: [security, flash, advisories, method, patch-diff, laravel, source-review]
updated: 2026-08-12
sources:
  - "https://github.com/laravel/framework/pull/60137/files, accessed 2026-08-12"
  - "https://github.com/laravel/framework/security/advisories/GHSA-crmm-hgp2-wgrp, accessed 2026-08-12"
---

# MTH-WEB-006, reconstruct the attack from the patch, and read the tests first

Related: the web advisories folder,
WEBDS-0012, the worked example,
MTH-WEB-005.

## The technique in one line

Open the fix commit rather than the advisory, read the changed tests before the
changed code, and let the test names tell you the attack the vendor's prose
would not.

## The discovery signal

The signal here is a property of the advisory, not of a target: **a security
advisory whose description is vague about mechanism.**

GHSA-crmm-hgp2-wgrp says a signed URL "can be interpreted differently by the
server than intended at signing time". That is true and it is nearly useless.
Interpreted differently how? By what? Which character? You cannot build a test
from it, you cannot tell whether an application is affected, and you certainly
cannot write a lab reproduction.

Vendors write advisories this way deliberately. They have to disclose enough to
justify the upgrade and little enough to slow down exploitation. The consequence
is that the CVE description is usually the worst available account of the bug,
and the patch is the best. This sweep's brief calls the diff "the highest value
and most skipped source", and three runs of this sweep skipped it before this
one, which is a fair demonstration of how easily it gets skipped.

## The mechanism

A security patch has to do two things: change the behaviour, and prove the change
works. The second half is where the information is.

For PR 60137 the changed files were:

```
src/Illuminate/Filesystem/LocalFilesystemAdapter.php     4 changes
tests/Integration/Filesystem/ReceiveFileTest.php        27 changes
tests/Integration/Filesystem/ServeFileTest.php          24 changes
```

Four lines of code, fifty one lines of test. That ratio is normal for a security
fix and it tells you where to look.

The code change is two substitutions:

```
['path' => $path]                  becomes  ['path' => rawurlencode($path)]
['path' => $path, 'upload' => true] becomes ['path' => rawurlencode($path), 'upload' => true]
```

From the code alone you learn the fix is percent encoding, which implies the bug
involved a character that meant something in a URL. You do not learn which
character, or what went wrong when it was not encoded.

The tests tell you both. They cover files "with URI delimiters in paths", they
use a concrete example, `receive-file-test.txt?pad=x`, and, critically, one of
them asserts that **expired URLs with URI delimiters cannot bypass signature
verification**.

That last test name is the actual vulnerability. The advisory buried expiry
bypass in a list of possible impacts. The test asserts it as the thing that must
not happen, which is the vendor stating the security property in the least
ambiguous language they have.

## The reading order, and why it is this order

1. **The test names.** They are written as assertions about what must not
   happen. That is a vulnerability description in the clearest form you will get.
2. **The test fixtures.** `?pad=x` is a working attack string, handed over.
   Fixtures answer "what input triggers this" without any guessing.
3. **The code change.** Now that you know what it must prevent, the change tells
   you how.
4. **The advisory prose.** Last, as a cross check on version ranges and impact.
   Reading it first anchors you to the vendor's framing before you have your own.

Most people do exactly the reverse, and stop after step 4.

## Which class it belongs to, and which stacks

Not a vulnerability class. It is a research method that feeds every class, and it
belongs alongside the corpus rather than inside one directory.

Stack independent, but it needs a public repository and a linked fix. It works well for
public ecosystems such as Laravel, Symfony, CodeIgniter, PHP, nginx, MariaDB, and npm. It does
not reach closed-source services or integrations, and that is worth noting as a
structural limit on this whole sweep rather than a gap in one run.

## A safe way to test for it

There is nothing to make safe. This is reading public source code. No target, no
request, no authorisation gate. It is the safest technique in the folder and one
of the most productive, which is an unusual combination worth exploiting.

Practically: from a GHSA page, follow the patch or pull request link. If the
advisory does not link one, compare the two release tags directly on GitHub with
`/compare/v12.61.0...v12.61.1` and read the diff. Filter to the test files first.

## The control that would catch a false positive

The risk with this method is not a false positive finding, it is a **confident
misreading**. Three controls:

1. **Does your account of the bug explain every changed line?** If the patch
   touched something your story does not need, your story is incomplete. Here,
   two call sites changed, so the bug must exist on both the serve path and the
   upload path, and it does.
2. **Does the follow up match?** This fix took three pull requests, 60137 then
   60230 then 60350. One line changed three times means the first attempt was
   incomplete or broke something. Reading only the first commit would give a
   confident and wrong account of the final invariant. **Always check whether
   the fix commit is the last word.**
3. **Reproduce before you assert.** A patch reading is a hypothesis. It becomes a
   finding when the lab shows the behaviour. Record it as a hypothesis until then
   and say which it is.

## Where else this shape appears

Wherever a fix is public. GHSA "patch" links, the `references` array in an OSV
record, Symfony's security advisories, which link the commit directly, PHP's
`git.php.net` commits referenced from a changelog, and any GitHub release
comparison between two tags.

Two adjacent variants worth knowing. **Patch gapping** is the same idea applied
to a silent fix: a project that fixes a bug without an advisory still leaves the
commit in the log, and diffing releases finds it. **The regression test as a
disclosure** is the sharper version: even when a project refuses to describe an
issue, the test added alongside the fix usually describes it exactly, because a
test cannot be vague and still pass.

## Provenance

laravel/framework pull request 60137, files view, read at
`https://github.com/laravel/framework/pull/60137/files`, accessed 2026-08-12.
Advisory GHSA-crmm-hgp2-wgrp accessed the same day. Public repository, read only,
nothing cloned and nothing executed. No text on either page was addressed to an
automated reader.
