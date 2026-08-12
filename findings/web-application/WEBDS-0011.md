---
tags: [security, flash, advisories, entry, web, xss, client-side, sanitiser, dompurify]
updated: 2026-08-12
sources:
  - "https://github.com/cure53/DOMPurify/security/advisories/GHSA-55q2-fjhq-7xh7 accessed 2026-08-12"
---

# WEBDS-0011: DOMPurify leaves a removed element's children armed in IN_PLACE mode

Related: the CSS in email method card,
the web advisories folder.

```yaml
id: WEBDS-0011
component: { type: library, ecosystem: npm, name: dompurify, version_scope: "3.x" }
affected: { introduced: ___, fixed_in: "3.4.13", tested_on: "not tested, desk research only" }
identifiers: { cve: "___, none assigned", ghsa: GHSA-55q2-fjhq-7xh7, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "injection, cross site scripting", owasp_api: not_applicable, owasp_llm: not_applicable, cwe: "CWE-79", family: "sanitiser early return leaves a subtree unprocessed", corpus_directory: 05-client-side-browser }
auth_required: "none, but the application must use IN_PLACE mode with a hook that removes elements"
entry_point: "attacker supplied HTML passed to sanitize() in IN_PLACE mode, containing a resource element with an event handler inside a container the hook will remove"
root_cause: >
  _sanitizeElements() returns immediately when a hook has detached a node, without calling
  _neutralizeSubtree() on it. Detaching a node removes it from the document. It does not
  disarm it: an img with an onload handler inside that detached subtree still fires when the
  resource loads. The missing decision is that removal must imply neutralisation of everything
  beneath the removed node, and the early return is what skips it. Rated low, and the low
  rating reflects the preconditions rather than the impact if they are met.
signal: >
  Any early return in a security loop. When a sanitiser, validator or filter has a branch that
  says "this element is gone, nothing more to do here", ask what was underneath it. More
  generally the signal is a security control that operates on a tree but returns on a node.
  On a running application the observable signal is script executing after a sanitiser has
  already returned a value the code treats as clean.
safe_proof: >
  In a lab page, call sanitize() in IN_PLACE mode with a hook that removes a container, on
  markup holding an img with an onload that writes a canary string into a variable. Then check
  the variable. A canary write, never an alert and never anything that touches a cookie or
  sends a request.
controls:
  - "Negative control: the same markup on 3.4.13 must leave the canary unwritten."
  - "Differential control: run the same markup without IN_PLACE mode. It must be clean, which proves the mode and not the payload is the variable."
  - "False positive to rule out: the handler firing because the markup was inserted into the document somewhere else in your test harness. The advisory is explicit that the dirty root does not need to be connected to the DOM beforehand, so keep the harness minimal enough to be sure."
fix: { commit_url: ___, invariant: "a hook that detaches a node must still have that node's subtree neutralised. The early return is replaced by a path that neutralises before returning" }
hardening: >
  Prefer returning a new sanitised tree over sanitising in place, because in place mutation is
  what creates the possibility of a half processed document existing at all. Behind that, a
  Content Security Policy without unsafe-inline stops event handler based execution regardless
  of which sanitiser bug is current, which is the control that does not depend on the library
  being correct.
detection: >
  Nothing server side. This executes in the victim's browser and leaves no request signature
  worth alerting on. The realistic detector is a regression test in the application's own suite
  that feeds known dangerous markup through the exact sanitiser configuration in use.
variant_rule: >
  Sanitiser bypasses cluster around three shapes and this is the third. One, parser
  differentials, where the sanitiser and the browser disagree about what the bytes mean. Two,
  mutation XSS, where the markup is safe until the browser reserialises it. Three, incomplete
  traversal, where the sanitiser simply did not visit part of the tree. Whenever a sanitiser
  offers hooks, ask what the hook is allowed to do to the tree while the sanitiser is walking
  it, because a hook that mutates during traversal can move nodes out of the walk.
lab: { install: "a static HTML page loading dompurify 3.4.12 from a local file, one hook that removes a container element", snapshot: "the page and the pinned library file", teardown: "delete the files, nothing persists" }
provenance: { source: "https://github.com/cure53/DOMPurify/security/advisories/GHSA-55q2-fjhq-7xh7", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

DOMPurify is the sanitiser most applications reach for when they have to render HTML somebody
else wrote. It supports hooks, so an application can say "also remove any footer element", and
it supports an `IN_PLACE` mode that cleans an existing tree rather than returning a new one.
When a hook removes an element, DOMPurify noted the node was gone and returned early from that
branch, without disarming what was inside it. An `img` with an `onload` handler nested in the
removed container survives detached and still fires. `sanitize()` returns, the application
treats the result as clean, and then the handler runs.

## Why it works

Removing a node from a document and making a node harmless are two different operations, and it
is very natural to assume the first implies the second. It does not: a detached subtree is still
live, still owned by the JavaScript engine, and an image inside it will still load and still
call its handler. The early return reads as an optimisation, and an optimisation is exactly
where this kind of bug hides, because there is no missing check to spot, only a check that is
skipped.

The preconditions keep the score low. You need `IN_PLACE`, a removing hook, and control of the
markup. That combination is not the common configuration, which is why this is rated low rather
than critical, and it is worth writing down honestly rather than inflating.

## How you would reproduce it

A static lab page. Configure a hook that removes a container, sanitise markup with an armed
`img` inside that container, and have the handler set a canary variable. Read the variable after
`sanitize()` returns.

## What the fix is, and why the obvious fix is not enough

The obvious fix is to upgrade, which is correct and which you will have to do again next time,
because sanitiser bypasses are a permanent stream rather than an event. The control that does
not depend on the library being correct is a Content Security Policy without `unsafe-inline`:
then an event handler in surviving markup cannot execute whatever the sanitiser missed. Treat
the sanitiser as one layer and never as the only one.
