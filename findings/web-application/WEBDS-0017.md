---
tags: [security, flash, advisories, webds, codeigniter, path-traversal, file-upload]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-hhmc-q9hp-r662, accessed 2026-08-12"
---

# WEBDS-0017, CodeIgniter path traversal in UploadedFile::move()

Related: the web advisories folder,
WEBDS-0016, the validation bypass in the same release,
WEBDS-0012, the other path handling item.

```yaml
id: WEBDS-0017
component:
  type: framework
  ecosystem: composer
  name: codeigniter4/framework
  version_scope: "UploadedFile::move(), when called without a second argument"
affected:
  introduced: ___
  fixed_in: "4.7.4"
  tested_on: ___
identifiers:
  cve: CVE-2026-63222
  ghsa: GHSA-hhmc-q9hp-r662
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: broken access control
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-22, improper limitation of a pathname to a restricted directory"
  family: attacker chooses the destination, not just the contents
  corpus_directory: 06-server-side-injection-file-data/
auth_required: user
entry_point: >
  any upload handler calling $file->move($targetDirectory) with no second
  argument. The controlled input is the uploaded file's client supplied
  filename, which move() then uses as the destination name.
root_cause: >
  Called with one argument, move() defaults the destination filename to the
  client supplied name and did not sanitise it. A name containing ../ therefore
  resolves outside the target directory. The missing decision is in the default:
  the one argument form looks like the safe convenience call, and it was the
  unsafe one. The advisory is precise about the boundary of the fix, and this
  part matters: 4.7.4 "specifically addresses sanitization when no filename
  argument is provided", while developers who explicitly pass a client supplied
  name "remain responsible for their own sanitization". So the patch narrows
  the hole, it does not close the pattern.
signal: >
  An upload where the resulting file appears somewhere other than the configured
  upload directory, or where a filename containing ../ is accepted rather than
  rejected. Frequently invisible from the outside, which is why this one is
  usually found by reading code rather than by probing.
safe_proof: >
  In a disposable lab, upload a file named with a traversal sequence pointing at
  a writable location inside the lab web root, containing only a canary string.
  The proof is the canary file existing at the traversed path. Choose a target
  path that does not already exist, so nothing is overwritten. Never aim a
  traversal proof at a real file, in a lab or otherwise: overwriting is
  destructive, and a proof that destroys something is not a safe proof.
controls: >
  Negative control: upload the same file with an ordinary name and confirm it
  lands in the configured directory. Differential control: list the target
  directory before and after, so the new file is shown to be absent beforehand.
  Without the before listing you cannot rule out a file that was already there,
  which is the commonest false positive in traversal testing.
fix:
  commit_url: "https://github.com/codeigniter4/CodeIgniter4/commit/20ebcf4694d96d3c97fbc3938e360730e4f54618"
  invariant: >
    ___ in detail, the commit was located but its diff was not read line by
    line. What the advisory states is that the default filename, used when no
    second argument is given, is sanitised in 4.7.4. The invariant is scoped to
    the default path only. The explicit path is documented as the caller's
    responsibility.
hardening: >
  Call getRandomName(), or pass an explicit server generated name, every time.
  Then resolve the final path with realpath() and assert it is still inside the
  intended directory before writing. That assertion is the control that kills
  the class, because it does not care how the attacker constructed the name.
detection: >
  Files appearing outside the uploads directory with the web user as owner.
  At the request layer, a multipart filename field containing ../, ..\ or an
  encoded form of either.
variant_rule: >
  Any place a client supplied name becomes part of a filesystem path. Archive
  extraction, which is the zip slip variant and worth noting given
  @avlidienbrunn's Archive Alchemist tool found in the watchlist sweep. Also log
  file naming, export and report generation, temporary file creation, and
  profile picture handling. The general rule: find every API whose convenient
  short form defaults to trusting the client, because those defaults are where
  this class lives.
lab:
  install: "CodeIgniter4 below 4.7.4 in Docker, isolated network"
  snapshot: "container snapshot before the first upload, and a directory listing recorded as the before state"
  teardown: "drop the container and the volume"
provenance:
  source: "GitHub Security Advisory GHSA-hhmc-q9hp-r662"
  accessed: 2026-08-12
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

An application saves an upload with `$file->move('writable/uploads')`. That
reads as: put it in the uploads folder. It does not read as: and let the browser
decide the rest of the path. But that is what it did.

Send a file whose name is `../../public/shell.php` and the file lands two
directories up, in a folder the web server serves.

## Why it works

`move()` takes the directory from the developer and, in the one argument form,
the filename from the client. Filesystems resolve `..` as "go up one". Nothing
was checking whether the finished path was still where the developer meant.

This pairs with WEBDS-0016 in an unpleasant way. That one lets an attacker
control *what* gets saved past a content check. This one lets them control
*where*. Together, on the same release, they cover both halves of the upload
problem: the bytes and the destination. Either alone is serious; the two in one
codebase is why 4.7.4 is not an optional upgrade.

## The detail most people will skim past

Read the fix boundary again, because it is the most useful sentence in the
advisory. 4.7.4 sanitises the default name. If the application explicitly passes
a client supplied name as the second argument, it is still vulnerable, and
upstream says so.

That means "we upgraded to 4.7.4" is not an answer to "are we affected". Someone
has to look at the call sites. This is exactly the kind of thing a version
number check will report as fixed while the application is still exposed, and it
is worth carrying as a general suspicion: a patch that fixes a default
does not fix an override.

## How you would reproduce it

Vulnerable CodeIgniter in a container. Record a directory listing of the
intended traversal target first, so you have a before state. Upload a file named
with a traversal sequence, pointing at a path inside the lab that does not
already exist, containing nothing but a canary string. List the target directory
again and look for the canary.

Then upload the same thing with an ordinary name and confirm it lands where it
should.

## What the fix is, and why the obvious fix would not work

Upgrade to 4.7.4, and separately audit every `move()` call for an explicit
client supplied second argument.

The obvious fix is to strip `../` from the filename. It fails on the first
variant anyone tries. Strip it once and `....//` collapses into `../` after your
own strip. Handle that and encoded forms arrive, `%2e%2e%2f`, then double
encoded ones, then backslashes on Windows. Every filter of this shape has lost
this argument eventually.

The fix that holds does not inspect the input at all. Resolve the final path,
then check where it actually points, and refuse if it is outside the intended
directory. That check is indifferent to how clever the encoding was, because it
runs after all the cleverness has been resolved away. Deciding based on the
resolved result rather than on the raw input is the same principle behind the
encoding fix in WEBDS-0012, and it is the single most transferable idea in both
entries.
