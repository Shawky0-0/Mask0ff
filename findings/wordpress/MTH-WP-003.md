---
tags: [security, flash, advisories, method, wordpress, access-control, desync]
updated: 2026-08-12
sources:
  - "https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.15/src/Controller/Frontend/RedirectController.php accessed 2026-08-12"
  - "https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.16/src/Controller/Frontend/RedirectController.php accessed 2026-08-12"
  - "security/advisories/entries/WPDS-0001.md, whose root cause is the same shape"
---

# MTH-WP-003: Authorise the object, serve the path

**The technique in one line.** Find code that resolves user input into an identifier, makes the
security decision about that identifier, and then acts on something else derived from the same
input, and attack the gap between the two.

Related: WPDS-0004, where this was extracted from a
real patch, WPDS-0001, the same shape in core,
MTH-WP-001, the parser differential, which is this
method's close cousin.

## Where this came from

Not from a researcher writeup. **This one was extracted by diffing a plugin at two tags**, which
is the thing the dataset plan calls the highest value and most skipped source, and which this
sweep had never once done before today. The diff is User Access Manager 2.3.15 against 2.3.16,
and the whole method is visible in the shape of the change.

## The discovery signal, what makes you look

You are reading a handler and you notice that the security check and the action take different
arguments.

```
checkObjectAccess( $type, $id )      <- decides using an ID
FileHandler::getFile( $path )        <- acts using a path
```

Both `$id` and `$path` came from the same string the user sent. That is the signal. It does not
matter how good the access check is. It is answering a question about a different object.

The louder version of the signal: the resolution step can FAIL. `getPostIdByUrl()` might find
nothing. Ask what the code does when resolution fails, because a check that has nothing to
check often quietly passes.

## The mechanism

Three steps and a gap.

1. **Resolve.** User input, a URL or a path or a name, is turned into a domain object: a post
   ID, a user, an attachment, an order.
2. **Decide.** The authorisation call is made about that resolved object. This step is usually
   correct, which is why the bug survives review. The reviewer reads the capability check, sees
   it is right, and moves on.
3. **Act.** The action is performed on something derived from the ORIGINAL input rather than
   from the resolved object.

The gap is that nothing asserts step 3 is operating on step 2's object. Traversal, encoding,
size suffixes, or simply a value that resolves to nothing, and the two diverge.

## The invariant that closes it

After every layer of resolution and normalisation, **the thing about to be acted on must be
provably the same thing the decision was made about**, or must be provably inside the boundary
the decision assumed.

In the User Access Manager patch that is `isInsideUploadDirectory()`: `realpath()` on the file,
`realpath()` on the uploads base, then require the file path to start with the base plus a
directory separator. Canonical on both sides, compared once, no string filtering anywhere.

## Does it transfer to WordPress? Yes, and it is everywhere

WordPress hands you this pattern by design. `url_to_postid()`,
`wp_attachment_url_to_post_id()`, `get_page_by_path()`, and every plugin's own lookup helper
take a string and give you an object. The capability system then works on IDs. So the split
between "an ID I checked" and "a string I received" is built into the platform, and any plugin
that serves files, exports, or reports lives on that split.

Concrete places to look on a typical WordPress or education-platform stack:

* gated course material and lesson attachment delivery in an LMS
* membership and paywall download handlers
* invoice, receipt and certificate PDF delivery
* export file download endpoints, which usually take a filename
* any handler with a parameter whose name contains file, path, url, doc, download or attachment

## A safe way to test for it

Plant a canary and aim at the canary. Never aim at a real secret.

1. Put a plain text file with a unique marker somewhere the handler should not reach.
2. Send the request with input that resolves badly: traversal, encoded traversal, a value that
   matches no object at all, a value with a suffix stripped by the normaliser.
3. The finding is that the marker comes back, or that the action happened, with no valid
   object behind it.

Reading a marker proves the boundary failed exactly as well as reading a credential does, and
it does not put a secret in a log, a screenshot or an evidence bundle. That distinction is
worth holding to even in a researcher-controlled lab.

## The control that catches a false positive

Two, and both are needed.

**The differential control.** Send a legitimate request that should succeed, with no traversal,
and confirm it does. Without this you cannot tell "the boundary failed" from "this endpoint
returns that file to everybody anyway", which is a different finding with a different fix.

**The negative control.** Same request against the patched version. If it still works, whatever
you think you found is not what the patch fixed, and your explanation is wrong even if your
request is interesting.

There is also an environmental trap specific to this class: these handlers frequently only run
when some mode is enabled. User Access Manager's file route requires file protection to be
switched on. Test with the feature off and you get silence, which reads exactly like safety.

## Where else this shape appears

* **The loop version.** Two loops over the same array, one validating and one executing, which
  is WPDS-0001. Same gap, iterated.
* **The parser version.** Two functions reading the same string and disagreeing about it, which
  is MTH-WP-001. That is this method where the two
  steps are both parsers.
* **Time of check to time of use.** The classic name for the version where the gap is time
  rather than representation. Check the file, then open the file, and something moved in
  between.
* **Outside WordPress entirely.** Object storage signed URLs where the signature covers one key
  and the fetch uses another, API gateways that authorise on a parsed path and proxy the raw
  one, and reverse proxy path confusion generally.

**The generalisation worth carrying:** whenever you see an authorisation check, do not ask "is
this check correct". Ask "**is this check about the same thing as the next line**".
