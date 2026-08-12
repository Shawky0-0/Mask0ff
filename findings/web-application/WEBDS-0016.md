---
tags: [security, flash, advisories, webds, codeigniter, file-upload, rce]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-mmj4-63m4-r6h5, accessed 2026-08-12"
---

# WEBDS-0016, CodeIgniter upload validation bypass in is_image and mime_in

Related: the web advisories folder,
WEBDS-0017, the path traversal in the same release,
WEBDS-0006, the CodeIgniter SQL injection.

```yaml
id: WEBDS-0016
component:
  type: framework
  ecosystem: composer
  name: codeigniter4/framework
  version_scope: the is_image and mime_in file validation rules
affected:
  introduced: ___
  fixed_in: "4.7.4"
  tested_on: ___
identifiers:
  cve: CVE-2026-63223
  ghsa: GHSA-mmj4-63m4-r6h5
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: insecure design
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-434, unrestricted upload of file with dangerous type"
  family: content check standing in for an extension check
  corpus_directory: 06-server-side-injection-file-data/
auth_required: user
entry_point: >
  any upload handler validated with the is_image or mime_in rules. The
  controlled input is the uploaded file: its bytes, its declared MIME type, and
  its filename.
root_cause: >
  is_image and mime_in answer a question about the file's content type. Neither
  answers a question about the extension the file will be saved under. An
  application that validates with one of these rules and then saves under the
  client supplied filename has checked one thing and relied on another. The
  advisory names all three conditions that must hold together: the application
  "validate[s] uploads using is_image or mime_in without an independent safe
  extension check", it saves "using the client-supplied filename", and it places
  uploads "in a web-accessible directory where PHP files can execute". The
  missing decision is who owns the extension. The validator does not, and the
  application assumed it did.
signal: >
  An upload feature that returns the stored path or URL, and where that path
  ends in the extension you supplied rather than one the server chose. If you
  upload something.png and get back something.png, the server is trusting your
  filename. If you get back a hash or a UUID, it is not.
safe_proof: >
  In a disposable lab, upload a file that passes the image check but carries a
  PHP extension, where the PHP body does nothing but echo a canary string.
  Request the stored URL. The canary in the response is the proof that the file
  executed. A file that echoes one constant is the safest possible payload: it
  reads nothing, writes nothing, and takes no input. Never upload a shell, not
  even in a lab, because a lab with a shell in it is one misconfigured network
  rule away from being a real problem.
controls: >
  Negative control: upload the same bytes with a .png extension and request it,
  confirming you get the raw bytes back rather than execution. That separates
  "the server executes what I name" from "the server executes everything".
  Differential control: upload a plain text file with a .php extension and no
  image header, and confirm it is rejected by validation. That shows the image
  check is genuinely running and you bypassed it, rather than there being no
  validation at all, which would be a different and more basic finding.
fix:
  commit_url: "https://github.com/codeigniter4/CodeIgniter4/commit/b6e9a4fa1dca2df3d3f261bdf61532df8c6420aa"
  invariant: >
    ___ in detail, the commit was located but its diff was not read line by
    line. What the advisory states is that 4.7.4 addresses the bypass in the
    is_image and mime_in rules. The workarounds it lists say what the intended
    invariant is: the client extension must be validated against both
    getClientExtension() and guessExtension(), meaning the name and the content
    must agree before the file is accepted.
hardening: >
  Never save under a client supplied name. Generate the name server side with
  getRandomName() or store(), and derive the extension from the detected content
  rather than the declared one. Then put uploads outside the web root and serve
  them through a controller. Any one of those three breaks the chain; all three
  makes the class impossible rather than unlikely.
detection: >
  Web server access logs showing a request for a file inside an uploads
  directory with a .php, .phtml or .phar extension. At upload time, a filename
  whose extension disagrees with its detected MIME type is worth logging on its
  own, whether or not it is rejected.
variant_rule: >
  Every language with a content check that people mistake for a name check.
  Look for double extensions, shell.php.png and shell.png.php; for null bytes
  and trailing dots and spaces in older stacks; for polyglot files that are a
  valid image and a valid script at once; and for the case where the web server
  and the application disagree about which extension in a multi dotted name
  decides the handler. That last one is the same parser disagreement mechanism
  as WEBDS-0012, in a different grammar.
lab:
  install: "CodeIgniter4 below 4.7.4 in Docker with Apache and mod_php, isolated network"
  snapshot: "container snapshot before the first upload"
  teardown: "drop the container and the uploads volume, and confirm the canary file is gone"
provenance:
  source: "GitHub Security Advisory GHSA-mmj4-63m4-r6h5"
  accessed: 2026-08-12
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

An application accepts image uploads. It validates them properly: it checks the
file really is an image, using the framework's own rule for exactly that. Then
it saves the file under whatever name the browser sent, in a folder the web
server serves.

An attacker sends a file that genuinely is a valid image, and names it
`avatar.php`. It passes validation, because it is a valid image. It gets saved
as `avatar.php`, because that is the name that came in. Then it is requested,
and Apache does not care in the slightest that the contents start with a PNG
header. It sees `.php` and runs it.

CVSS 9.8, and the reason it is that high is the last step: this is remote code
execution.

## Why it works

There are two independent facts about an uploaded file, and everyone conflates
them.

What the file *is*, meaning its bytes. That is what `is_image` and `mime_in`
inspect, and they inspect it correctly.

What the file will be *treated as*, meaning its extension once it lands on disk.
Nothing in either rule touches that.

A PHP file is not required to be pure PHP. Anything outside `<?php ... ?>` is
sent through as output. So a file can open with a real PNG signature, satisfy
every image check ever written, and still contain a PHP block further down. The
image check is not wrong. It is answering a question nobody needed the answer
to.

This is why the advisory lists three conditions rather than one. The validation
bypass alone is harmless. It becomes RCE only when combined with a client
supplied filename and an executable directory. That is worth internalising: most
serious upload bugs are three ordinary decisions that are each defensible on
their own.

## How you would reproduce it

Stand up a vulnerable CodeIgniter behind Apache with PHP enabled, on an isolated
network. Build a file that is a valid PNG followed by a PHP block that echoes a
canary string and does nothing else. Name it with a `.php` extension. Upload it
through a handler that validates with `is_image`. Note that it is accepted.
Request the stored URL and look for the canary.

Then run both controls. Same bytes named `.png`, which should come back as raw
data. Plain text named `.php`, which should be rejected at validation. The three
results together are the finding; the first one alone is not.

## What the fix is, and why the obvious fix would not work

Upgrade to 4.7.4. Separately, and more importantly, stop saving under client
supplied names.

The obvious fix is to block `.php`. It fails, and it fails in a way that has
been failing for twenty years. The handler mapping is a server configuration, so
the list of executable extensions is not fixed: `.phtml`, `.php5`, `.phar`, and
whatever a given Apache config has been told to hand to PHP. Miss one and the
denial list is decorative. Worse, on a misconfigured server the executable
extension might not even be a PHP one.

The obvious fix number two is to check the MIME type harder. That is the exact
mistake the bug is made of. The MIME type describes the content, and the content
was never the problem.

The fix that actually holds is to take the name away from the client. If the
server picks the name and derives the extension from what it detected, the
attacker has nothing left to influence, and the three conditions can never line
up again.
