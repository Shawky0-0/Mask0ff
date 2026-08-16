---
tags: [security, flash, advisories, method, client-side, browser, xss, parser, appsec]
updated: 2026-08-16
sources:
  - "https://x.com/kinugawamasato, timeline read in the in app browser 2026-08-16"
  - "https://x.com/kevin_mizu, timeline read in the in app browser 2026-08-16"
---

# MTH-WEB-012: a new HTML element changes where your payload ends up, and the sanitiser was written before it existed

## The technique in one line

Read the list of elements and attributes browsers have shipped recently, and for each one ask
what it does to content that is already on the page, because a sanitiser's safety argument is a
claim about a parser that has since changed underneath it.

## The discovery signal

**A browser feature whose job is to move, copy or re render content that is already in the
document.** Not a feature that adds a new sink. A feature that changes where existing content
ends up.

The example that produced this card is `<selectedcontent>`, a new element used inside a
customisable `<select>`. Its job is to mirror the chosen option's content into the closed
control. So it takes markup from one place in the tree and renders it in another.

Masato Kinugawa posted two consequences of that on 2026-07-06 and 2026-07-07, both read in full
on his timeline. Both are complete, both are short, and each breaks a different assumption.

The first breaks the assumption that a script needs a closing tag:

```
<select>
<selectedcontent></selectedcontent>
<option>
<script>alert()//executed without the closing tag
```

The second breaks the assumption that you need `/`, `=` or whitespace to execute anything:

```
<select>
<button><selectedcontent>
<button>
<option>
<svg><script>alert()<foo>
```

His own words on that second one, quoted: "so this can execute js without using "/", "=" and
whitespaces."

The following day he applied it to a PortSwigger lab documented as unexploitable, the one filed
under "innerHTML assignment where you can't use `=`", and solved it. Kévin Gervot, who works at
Assetnote, replied that this makes a Cloudflare image endpoint into a valid client side path
traversal to `innerHTML` gadget. Two researchers, two different products, one new element.

## The mechanism

A sanitiser is a filter with a theory about the parser. It removes what it believes the parser
would treat as dangerous, and leaves what it believes is inert.

That theory has a date on it. Browsers ship new elements and attributes continuously, and some of
them change parsing and re parenting rules. When they do, the sanitiser's theory becomes a
statement about a browser that no longer exists, while the sanitiser's code stays exactly the
same and its test suite keeps passing, because the test suite encodes the same old theory.

Three specific assumptions are the ones that break, and they are the three to hunt for:

1. **"This is not a tag, so it is text."** Re parenting can move content into a context where it
   parses differently from where it was written.
2. **"An unterminated element is harmless."** Some new elements imply a close, so the parser
   ends the element for you and the content that follows becomes live.
3. **"They cannot build a payload without these characters."** Character based restrictions are
   arguments about a grammar, and new elements add new grammar.

The reason this class is worth a card rather than a note: the vulnerability is not in the
application, and it is not in the sanitiser either. It is in the gap between when the sanitiser
was reasoned about and when the browser was updated. Nobody committed a bug. The world moved.

## Which class this belongs to

Client side and browser, `05-client-side-browser/`. That class sits at two entries in this
folder and this is the second card touching it.

## Which stacks it applies to, and whether it reaches Ahmed's

**Every stack, because it is a browser property, not a server one.** Anything that takes rich
text or HTML from one user and shows it to another is in scope, whatever the backend is.

For Ahmed's fleet specifically: an education platform is full of this shape. Course descriptions,
forum posts, comments, quiz content, message bodies, and anything with a rich text editor. It
also reaches the AI surfaces, where model output is often rendered as HTML or Markdown and the
model can be talked into producing whatever the attacker wants, which makes model output an
untrusted HTML source with a very cooperative author.

DOMPurify is already in this folder at
WEBDS-0011, for a different reason, so the
sanitiser layer is a live concern here rather than a theoretical one.

## A safe way to test for it

Lab page only, never a live target.

1. Build a static page that runs your application's sanitiser over an input and writes the result
   into the DOM the same way your application does.
2. Feed it the payload with an inert canary instead of anything active. A function that sets a
   variable, or writes a marker into a hidden element, is enough. There is no reason for a
   payload in a repo to contain a network call.
3. **The canary is that the marker ran, not that a dialog appeared.**
4. Run the same page in more than one browser and record the versions, because the whole point is
   that behaviour is version dependent.

## The control that would catch a false positive

**Record the browser and version on every result, every time.** A payload that works in Chrome
139 and not in Firefox is a true finding with a narrow scope, and reporting it without the
version turns a precise result into a vague one.

**Check whether the element is behind a flag.** Kévin Gervot's 2026-07-21 post says the CSS
version of a related feature sits behind an experimental flag. Something that only works with a
flag enabled is research, not a finding against production users, and calling it a finding would
be wrong.

**Test the sanitiser in isolation from the application.** If the payload survives your full
application but not the bare sanitiser, the bug is in how the application calls it, which is a
different finding with a different fix.

**And the honest limit on this card, stated plainly.** The source is two social media posts, read
in full, with complete payloads and the author's own description of what they do. It is not a
long form writeup, and no specification page was opened. **The parsing rule that makes these work
is `___` in this card**, and reading the HTML specification for `<selectedcontent>` is the next
step before anyone builds on this.

## Where else this shape appears

* **Any element that re parents content.** `<template>`, shadow DOM slots, `<slot>`, and
  declarative partial updates.
* **Namespace transitions.** Content moving between HTML, SVG and MathML parsing, which is what
  the `<svg><script>` in the second payload is doing and is the oldest reliable member of this
  family.
* **New attributes that create sinks.** Kinugawa's 2026-07-03 post uses `<template for="script">`
  to attach content by name, which is a new way for one place in a document to reach another.
  Mathias Karlsson's `onbeforematch` work, already noted in this folder's watchlist, is the same
  idea from the event handler direction.
* **Import maps and module loading**, from Kévin Gervot's 2026-07-21 post: poisoning an import
  map through `DOMParser`. Not XSS, but it blocks module loading, which is a denial of a feature.
* **Server side HTML parsers disagreeing with the browser.** The reverse direction, and it is
  where MTH-WEB-001 and
  MTH-WEB-002 already live.
* **Email clients**, which run their own ageing sanitisers against markup, and are the subject of
  Gareth Heyes' Black Hat 2026 talk already recorded on this folder's watchlist.

## Provenance

Sources, both read in the in app browser on 2026-08-16 because `WebFetch` cannot read x.com:

* `https://x.com/kinugawamasato`. Masato Kinugawa, 15.4K followers, blog at
  `masatokinugawa.l0.cm`. Posts of 2026-07-03, 2026-07-06 and 2026-07-07 read in full.
* `https://x.com/kevin_mizu`. Kévin Gervot, vulnerability researcher at Assetnote, 6,650
  followers, blog at `mizu.re`. Posts of 2026-07-07 and 2026-07-21 read in full.

Both timelines were public and needed no login. The payloads above are quoted as read and
**neither was executed**, in a browser, a sandbox or anywhere else, per the lane rules.

Related: WEBDS-0011 and
MTH-WEB-003, on testing what the browser does
rather than what the sanitiser believes, which is the same argument one layer up.
