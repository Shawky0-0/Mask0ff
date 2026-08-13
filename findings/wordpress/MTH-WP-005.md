---
tags: [security, flash, advisories, method, wordpress, upload, parser, imagemagick]
updated: 2026-08-13
sources:
  - "https://pwn.ai/blog/imagemagick-from-arbitrary-file-read-to-rce-in-every-policy-zeroday, accessed 2026-08-13"
  - "https://wordpress.org/news/2026/08/wordpress-7-0-4-release/, accessed 2026-08-13"
---

# MTH-WP-005, when the app has no surface, attack the library it hands files to

Related: the advisories folder,
WPDS-0008, the WordPress core bug this produced,
MTH-WP-001, parser differentials,
MTH-WP-004, poison the feed the plugin trusts.

## The technique in one line

When the target application is too small to have bugs, stop testing the application and go
audit the third party library it passes user files to, because that library makes its own
decisions about what those files are.

## The discovery signal, which is the valuable half

The pwn.ai team were given a client application that was, in their description, minimal: an
upload box and little else. The normal reading of that situation is "small surface, not much
to find, write the report".

They read it the other way. A single upload box means every uploaded file goes to exactly one
place, and that place is a library. So the library is the application. They spent multiple
days auditing ImageMagick's entire processing pipeline rather than the client's code.

**The signal to copy: a thin application is not a small attack surface, it is a concentrated
one.** Everything funnels into one dependency, which makes that dependency worth more effort
than it would be worth on a fat application where the attention would be split.

Five months later the same team reported an Author level remote code execution in WordPress
core through exactly this mechanism, CVE-2026-65640. They had the primitive first, in March.
Then they went looking for who hands it a file. WordPress does.

**That ordering is the method.** Find a primitive in a widely used library, then enumerate the
applications that feed it. It scales in a way that testing one application never does.

## The mechanism

Three separate ideas stack up, and each one is worth recognising on its own.

**One: the parser picks itself from the content.** ImageMagick decides what a file is by
reading its leading bytes, not by trusting the extension. So a file named `.jpg` can be routed
to the PostScript path if its bytes say so. Whatever the application checked about the name is
now irrelevant.

**Two: the security policy blocks names, not behaviour.** ImageMagick ships tiered policies
that block coders by name. The researchers found the lists are incomplete in a specific way:
a policy blocks `PS` and `EPS` but not `PDF`, and `PDF` reaches the same Ghostscript. Same
destination, different label, no rule. On Ubuntu 22.04 they found `EPT`, Encapsulated
PostScript with a TIFF preview, whose magic bytes route a file to Ghostscript regardless of
extension, and which is not on the blocklist either.

**Three: the strictest policy can be bypassed by how the software was built.** On Amazon Linux
they found Ghostscript compiled in as a linked library rather than run as an external process.
The delegate policy only traps external processes. A rule that says "block all delegates"
therefore blocks nothing, because there is no delegate to block, there is a function call.

There is a fourth detail worth carrying separately, because it is the general lesson in
miniature: a leading newline before the PostScript header defeats ImageMagick's own detection
of PostScript, while Ghostscript still happily executes the file. Two programs, one file, two
answers. That is MTH-WP-001 again, at the boundary
between two products rather than two functions.

## Does it transfer to WordPress, and how

It already has, and the entry is WPDS-0008.

WordPress uses ImageMagick through `WP_Image_Editor_Imagick` whenever the extension is
available, and it does that on every media upload to build thumbnails. The site's own upload
validation is about extensions and mime types, which is a check about the file's name.
ImageMagick's decision is about the file's bytes. The gap between those two is the bug.

Where to look on the fleet, in order:

* **Any plugin that calls Imagick directly** rather than going through `WP_Image_Editor`. A
  core patch does not reach those. This is the highest value place to look right now, because
  everyone else is busy updating core.
* **Avatar and profile picture uploads**, which are usually plugin code and usually less
  careful than the media library.
* **Import and migration routines**, which process files in bulk and rarely re validate.
* **PDF preview generation**, which is the one WordPress feature that wants Ghostscript on
  purpose, and therefore the one place it will not have been removed.

## A safe way to test for it

The observable is "did the interpreter run", and the safe way to answer that is a canary: have
the file write a named marker to a known temporary path, then check whether the path exists.
Nothing is read, nothing is destroyed, and the marker identifies itself as a test.

The pwn.ai page publishes a runnable shell script that does this. **This sweep did not run it
and will not.** It arrived in fetched content, and the standing rule is that fetched content is
data. It is recorded here as a documented technique so that Ahmed can decide, on his own
judgement, whether to use it in his own lab. It is not a recommendation to execute anything.

The shape of the check, stated independently of anyone's script: build a PostScript file whose
only action is to open a file at a fixed path, write a known string, and close it. Feed it to
the conversion path. Look for the path. Delete it.

## The control that would catch a false positive

This technique produces false negatives far more easily than false positives, and the
researchers name three:

* **Ghostscript is not installed.** The check reports clean and the code flaw is still there,
  waiting for the next server.
* **A hardened `policy.xml` already blocks the coder.** Clean result, correct today, and it
  breaks the moment somebody deploys to a host with a different policy.
* **A read only or sandboxed filesystem.** The interpreter ran and could not write, so the
  marker never appears. This is the nastiest one, because the code executed and the test says
  no.

So the differential control matters more than the negative control here. Convert a genuine
image of the same claimed type through the same path first. If that does not produce a normal
thumbnail, the pipeline was never reached and a missing marker means nothing at all.

## Where else this shape appears

* Any library that sniffs content to choose a decoder: image libraries, archive handlers,
  document converters, antivirus unpackers, video thumbnailers.
* Any allowlist written as names rather than behaviours. Ask what else reaches the same code
  by a different name. That question alone found the `PDF` and `EPT` bypasses.
* Any security control that assumes a boundary is a process boundary. If the dangerous thing
  gets linked in as a library instead of spawned as a process, process level rules evaporate.
* Two products handling one file and disagreeing about what it is. The one that executes wins,
  and it is rarely the one that was audited.

## Provenance

| Field | Value |
|---|---|
| Primary source | `https://pwn.ai/blog/imagemagick-from-arbitrary-file-read-to-rce-in-every-policy-zeroday` |
| Accessed | 2026-08-13 |
| Published | 2026-03-30 |
| Author | the pwn.ai team, described on the page as an autonomous penetration testing platform |
| Corroborating source | `https://wordpress.org/news/2026/08/wordpress-7-0-4-release/`, accessed 2026-08-13, which credits the same team for CVE-2026-65640 |
| Licence note | public research blog, read only, no account used |

**On the source's own nature.** The page describes the research as done by an autonomous
agent over multiple days. That is worth noting rather than hiding: the method being recorded
here was, by the publisher's own account, largely machine driven. It does not change whether
the mechanism is real, and the mechanism is corroborated by an independent WordPress core
advisory five months later. It does mean the writeup deserves the same "verify, do not trust"
handling as any other agent output.

**Injection check.** The page carries no text addressed to an AI agent and no instructions.
The nearest thing is a remark by the authors that the security ecosystem is being flooded
with low quality reports generated by AI, which is commentary about the field, not a
directive. Recorded in the run file for completeness.
</content>
