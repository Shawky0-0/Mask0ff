---
tags: [security, flash, advisories, webds, client-side, xss, php, librenms, escaping]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-jmqm-f8q4-v7wx, accessed 2026-08-13"
---

# WEBDS-0023, strip_tags cannot protect a JavaScript string, because no tag is needed

Related: the web advisories folder,
WEBDS-0011, the other client side entry,
MTH-WEB-003, test what the browser does, not what the sanitiser believes.

```yaml
id: WEBDS-0023
component:
  type: package
  ecosystem: composer
  name: librenms/librenms
  version_scope: "the legacy application pages, Proxmox module"
affected:
  introduced: ___
  fixed_in: "26.5.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-45694
  ghsa: GHSA-jmqm-f8q4-v7wx
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: injection
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-79, cross site scripting"
  family: escaping chosen for the wrong grammar
  corpus_directory: 05-client-side-browser/
auth_required: user
entry_point: >
  GET /apps?app=proxmox, parameters instance and vmid. Both are filtered with
  strip_tags() and then interpolated into a JavaScript statement. Any
  authenticated session, and the victim has to follow the link, so it is
  reflected and needs user interaction.
root_cause: >
  The value lands inside a single quoted JavaScript string literal:
  document.title = '$title';. The only filter applied is strip_tags(), which
  removes HTML elements. Inside a JavaScript string there are no elements to
  remove and none are needed. A single quote closes the string and everything
  after it is code. The missing decision is: nobody decided which grammar this
  value was entering. The code is at LegacyController.php line 75 and
  proxmox.inc.php lines 38 and 42.
signal: >
  A page title that echoes a query parameter. Then view source and look for the
  parameter inside a script block rather than inside the HTML body. The signal
  that this specific bug is present is that angle brackets come back stripped
  while a single quote comes back intact. That asymmetry names the filter for
  you.
safe_proof: >
  On your own LibreNMS below 26.5.0, request the page with the parameter set to
  a value that closes the string and calls a harmless marker, for example
  setting document.title to a unique string, or a console log. The canary is a
  string only you chose appearing where only executed code could put it. Do not
  use document.cookie, do not exfiltrate anything, do not aim the link at
  another person. Proving execution is the finding, reading a session is not
  needed and makes the report worse.
controls: >
  Negative control: send an HTML payload such as an image tag with an error
  handler and confirm it is stripped. That is what shows strip_tags() is running
  and that you did not merely find an unfiltered field. Differential control:
  send the same value with the single quote removed and confirm nothing
  executes, so the quote is demonstrably the break out character. Third control:
  confirm the value really is inside a script block by reading the rendered
  source, since a reflection in the HTML body would be a different bug with a
  different fix.
fix:
  commit_url: "___, the advisory links the 26.5.0 release rather than a commit"
  invariant: >
    Not read as a diff. The correct invariant for this shape is that a value
    entering a JavaScript string literal is encoded for JavaScript, or better,
    is not interpolated into script at all but passed as data and read by the
    script. Whether 26.5.0 does that or only adds a quote escape is unknown here.
hardening: >
  Never build script by string concatenation. Put the value in a data attribute
  or a JSON block that the browser parses as data, and have the script read it:
  document.title = document.body.dataset.pageTitle. Then a Content Security
  Policy without unsafe-inline, so an injected script has nowhere to run even if
  somebody does concatenate again.
detection: >
  Request logs where a query parameter value contains a single quote followed by
  a semicolon, or the substring ';//. A WAF will key on that pattern, though it
  is also the pattern that produces false alarms on any field where an
  apostrophe is legitimate, which is most of them.
variant_rule: >
  Every place a server side value is written into a script. The set of sinks is
  short and worth memorising: document.title, document.location, window.name,
  inline event handler attributes, a var initialised from a template, JSON
  embedded in a script tag without proper encoding, and anything built with
  string concatenation inside a Blade, Twig or Smarty template. The wider rule
  is the family name: the escaper has to match the grammar the value is entering.
  htmlspecialchars() protects HTML, not JavaScript. addslashes() protects a
  quoted string, not a URL. strip_tags() protects nothing at all, because it
  removes elements rather than escaping characters.
lab:
  install: "LibreNMS container pinned at or below 26.4.0, isolated network, no real devices added"
  snapshot: "not needed, nothing is written"
  teardown: "drop the container"
provenance:
  source: "GitHub Security Advisory GHSA-jmqm-f8q4-v7wx, reported to the LibreNMS project"
  accessed: 2026-08-13
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

LibreNMS sets the browser tab title with a line of JavaScript. The title text
comes from the URL. Before it goes in, the code runs `strip_tags()` on it, which
removes anything that looks like an HTML element.

Then it writes the result between two single quotes inside a script. Put a
single quote in the parameter and the string ends early. Whatever you write next
is code, and the browser runs it.

## Why it works

`strip_tags()` was chosen because it is the function people reach for when they
think "make this safe". It does one specific thing: it deletes HTML elements.

That is the right tool if the value is going into the page body, where an attack
needs a tag. It is completely useless here, because the value is going into a
JavaScript string, where an attack needs a **quote**, and quotes are not tags.

So the filter runs, does exactly what it was written to do, and stops nothing.

The rule, and it is the one that matters far beyond this product:

**An escaper is defined by the grammar it is escaping for. A value crossing into
HTML gets HTML escaping. A value crossing into JavaScript gets JavaScript
escaping. Using the wrong one is not partial protection, it is none.**

## Why the severity is moderate and not higher

Three things hold it down, and each one is worth being able to state.

You need to be signed in already, so this is not a pre auth bug. The victim has
to click your link, so you need to deliver it. And it is reflected, meaning the
payload lives in the URL rather than in the database, so it hits one person at a
time instead of everyone who loads a page.

The CVSS vector does carry a changed scope, `S:C`, because script running in the
page acts with the victim's session rather than the attacker's.

## How you would reproduce it

Your own instance, below 26.5.0. Request the Proxmox page with `instance` set to
a value that closes the quote and runs something that only you can recognise.
Then send the same request with an HTML tag payload instead and watch it get
stripped. That pair is the report: one shows the filter is present, the other
shows the filter is aimed at the wrong grammar.

Use a marker, not a cookie read. The proof needed is "arbitrary script ran". A
report that includes someone's session token is a worse report and a worse thing
to have done.

## What the fix is, and why the obvious fix would not work

26.5.0 fixes it. The exact change was not read here, so record it as unknown.

The obvious fix is to add `addslashes()`, or to strip single quotes. Escaping the
quote does stop this particular payload, and it is what most projects ship. It is
still fragile, because a JavaScript string can be broken out of in more than one
way depending on where it sits: a `</script>` sequence ends the whole block
regardless of quoting, and a line separator character can terminate a string in
some contexts. Each of those becomes a new patch.

The fix that ends the class is not to build script from strings at all. Put the
title in a data attribute, let the HTML escaper handle it, which is a job it is
actually designed for, and have the script read the attribute. Then the value
never enters JavaScript grammar, so no JavaScript escaping question exists.
